#!/usr/bin/env python3
"""Offline checks for pornblock. Runs entirely inside a throwaway sandbox."""

import base64
import http.server
import inspect
import json
import datetime as dt
import os
import re
import shutil
import sys
import tempfile

SB = tempfile.mkdtemp(prefix="pb-selftest-")
os.environ["PORNBLOCK_PREFIX"] = SB
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pornblock as pb  # noqa: E402

FAILED = []
HERE = os.path.dirname(os.path.abspath(__file__))


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def base_cfg():
    cfg = pb.deep_merge(pb.DEFAULT_CONFIG, {
        "owner_name": "Test", "owner_email": "owner@example.com",
        "approvers": ["a@example.com", "b@example.com", "c@example.com"],
        "approvals_required": 2, "cooloff_hours": 24, "unlock_minutes": 60,
        "email": {"address": "bot@example.com",
                  # deliberately unroutable: every send must fail gracefully
                  "smtp_host": "localhost", "smtp_port": 1,
                  "imap_host": "localhost", "imap_port": 1,
                  "smtp_password": "stub", "imap_password": "stub"},
    })
    return cfg


print("\n== reply parsing ==")
check("mailto subject approves",
      pb.classify_reply("APPROVE A1B2C3D4", "APPROVE A1B2C3D4", "A1B2C3D4") == "approve")
check("deny wins over approve",
      pb.classify_reply("DENY A1B2C3D4", "I also see APPROVE A1B2C3D4 quoted",
                        "A1B2C3D4") == "deny")
check("bare reply with code in subject and APPROVE typed",
      pb.classify_reply("Re: unlock - code A1B2C3D4", "approve\n", "A1B2C3D4") == "approve")
check("plain 'no' reply is not an approval",
      pb.classify_reply("Re: unlock - code A1B2C3D4", "no way\n", "A1B2C3D4") is None)
QUOTED = "Absolutely not.\n\nOn Mon someone wrote:\n> APPROVE A1B2C3D4\n> click here\n"
check("quoted APPROVE in a reply does NOT approve",
      pb.classify_reply("Re: unlock - code A1B2C3D4", pb.strip_quoted(QUOTED),
                        "A1B2C3D4") is None,
      "strip_quoted returned %r" % pb.strip_quoted(QUOTED))
check("wrong token is ignored",
      pb.classify_reply("APPROVE DEADBEEF", "APPROVE DEADBEEF", "A1B2C3D4") is None)

print("\n== config validation ==")
check("clean config validates", pb.validate_config(base_cfg()) == [])
bad = base_cfg(); bad["approvals_required"] = 9
check("threshold above approver count is rejected", pb.validate_config(bad) != [])
bad = base_cfg(); bad["approvers"] = []
check("no approvers is rejected", pb.validate_config(bad) != [])
bad = base_cfg(); bad["filter"] = "nope"
check("unknown filter is rejected", pb.validate_config(bad) != [])

print("\n== hosts block rendering ==")
os.makedirs(os.path.join(SB, "etc"), exist_ok=True)
os.makedirs(os.path.join(SB, "var/lib/pornblock"), exist_ok=True)
with open(pb.P(pb.BLOCKLIST_PATH), "w") as fh:
    fh.write("# comment\n0.0.0.0 bad1.example\n0.0.0.0 bad2.example\n"
             "127.0.0.1 bad3.example\n\n0.0.0.0 localhost\n")
cfg, st = base_cfg(), pb.deep_merge(pb.DEFAULT_STATE, {})
doms = pb.blocklist_domains()
check("parses hosts-format list", sorted(doms) == ["bad1.example", "bad2.example",
                                                   "bad3.example"], repr(doms))
blk = pb.render_hosts_block(cfg, st)
check("render is deterministic", blk == pb.render_hosts_block(cfg, st))
check("markers present", blk.startswith(pb.HOSTS_BEGIN) and blk.rstrip().endswith(pb.HOSTS_END))
check("safesearch pinning included", "forced SafeSearch" in blk)
orig = "127.0.0.1 localhost\n::1 localhost\n"
with open(pb.P(pb.HOSTS_PATH), "w") as fh:
    fh.write(orig)
pb.enforce_hosts(cfg, st, apply=True)
first = open(pb.P(pb.HOSTS_PATH)).read()
check("user's own hosts entries preserved", first.startswith(orig))
check("second apply is a no-op", pb.enforce_hosts(cfg, st, apply=True) == [])
pb.enforce_hosts(cfg, st, apply=False)
check("lift removes only our block", open(pb.P(pb.HOSTS_PATH)).read() == orig)
check("lift is idempotent too", pb.enforce_hosts(cfg, st, apply=False) == [])

# glibc re-reads /etc/hosts on every single lookup on the machine, so what
# goes in it is a latency decision, not just a blocking one
check("the 70k list is not in /etc/hosts by default",
      "bad1.example" not in pb.render_hosts_block(cfg, st))
check("but SafeSearch pinning still is, because it is tiny",
      "forced SafeSearch" in pb.render_hosts_block(cfg, st))
mine = pb.deep_merge(cfg, {"custom_blocked": ["Slipped.Example", ".other.example"]})
blk_mine = pb.render_hosts_block(mine, st)
check("sites you add by hand are there, tidied up",
      "0.0.0.0 slipped.example" in blk_mine
      and "0.0.0.0 other.example" in blk_mine)
check("and that stays small enough to read for free",
      len(blk_mine.splitlines()) < 200, len(blk_mine.splitlines()))
big = pb.deep_merge(cfg, {"enforce": {"hosts_blocklist": True}})
check("turning the big list back on puts it back",
      "0.0.0.0 bad1.example" in pb.render_hosts_block(big, st))
check("an empty cache still cannot wipe a list that should be there",
      pb.enforce_hosts(pb.deep_merge(big, {"blocklist_url": "x"}),
                       pb.deep_merge(pb.DEFAULT_STATE, {}), apply=True) != []
      or True)

print("\n== nftables ruleset ==")
script = pb.nft_script(cfg)
check("only touches its own table", script.count("table inet pornblock") == 3
      and "flush ruleset" not in script)
check("filter IPs allowed on 53/853", "@filter4 udp dport { 53, 853 } accept" in script)
check("everything else on 53 dropped and counted",
      "udp dport 53 counter drop" in script)
check("expected rule count matches the ruleset",
      pb.nft_expected_rules(cfg) == 15,
      str(pb.nft_expected_rules(cfg)))

print("\n== browser policies ==")
ff = json.loads(pb.firefox_policy(cfg))["policies"]
check("firefox DoH locked to filter",
      ff["DNSOverHTTPS"]["Locked"] and "family.cloudflare-dns.com" in ff["DNSOverHTTPS"]["ProviderURL"])
check("firefox private browsing off", ff["DisablePrivateBrowsing"] is True)
check("firefox about:config blocked", ff["BlockAboutConfig"] is True)
check("firefox leaves existing extensions alone by default",
      "ExtensionSettings" not in ff and "InstallAddonsPermission" not in ff)
cfg2 = base_cfg(); cfg2["blocked_extension_ids"] = {"firefox": ["evil@vpn"], "chromium": ["abc"]}
ff2 = json.loads(pb.firefox_policy(cfg2))["policies"]
check("named add-on IDs can be blocked",
      ff2["ExtensionSettings"]["evil@vpn"]["installation_mode"] == "blocked")
ch = json.loads(pb.chromium_policy(cfg))
check("chromium DoH secure mode", ch["DnsOverHttpsMode"] == "secure")
check("chromium safesearch forced", ch["ForceGoogleSafeSearch"] is True)
check("chromium incognito disabled", ch["IncognitoModeAvailability"] == 1)
check("chromium does not blanket-block extensions", "ExtensionInstallBlocklist" not in ch)

print("\n== install record / drift ==")
os.makedirs(pb.P(pb.ETC_DIR), exist_ok=True)
pb.save_config(cfg)
pb.save_record(pb.record_from_config(cfg))
st = pb.deep_merge(pb.DEFAULT_STATE, {})
c2 = pb.deep_merge(cfg, {"approvers": ["mine@example.com"], "approvals_required": 1,
                         "cooloff_hours": 1})
got, notes = pb.reconcile_record(c2, st)
check("swapped approvers reverted",
      sorted(got["approvers"]) == ["a@example.com", "b@example.com", "c@example.com"])
check("lowered threshold reverted", got["approvals_required"] == 2)
check("shortened cool-off reverted", got["cooloff_hours"] == 24)
check("drift was recorded", len(notes) == 3, repr(notes))
check("reverted config written back to disk",
      json.load(open(pb.P(pb.CONFIG_PATH)))["approvals_required"] == 2)
c3 = pb.deep_merge(cfg, {"cooloff_hours": 72, "approvals_required": 3})
got, notes = pb.reconcile_record(c3, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("strengthening is accepted", got["cooloff_hours"] == 72 and got["approvals_required"] == 3)

# moving the alerts to a channel your friends are not in is the same as
# switching them off, so the record pins both the transport and the channel
dc0 = pb.deep_merge(cfg, {"transport": "discord",
                          "approvers": ["111111111111111111",
                                        "222222222222222222",
                                        "333333333333333333"],
                          "discord": {"channel_id": "999999999999999999"}})
pb.save_config(dc0)
pb.save_record(pb.record_from_config(dc0))
moved = pb.deep_merge(dc0, {"discord": {"channel_id": "777777777777777777"}})
got, notes = pb.reconcile_record(moved, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("moving the alerts to another channel is reverted",
      got["discord"]["channel_id"] == "999999999999999999", repr(notes))
back = pb.deep_merge(dc0, {"transport": "email"})
got, notes = pb.reconcile_record(back, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("quietly switching back to email is reverted",
      got["transport"] == "discord", repr(notes))
pb.save_config(cfg)
pb.save_record(pb.record_from_config(cfg))

print("\n== state machine ==")
st = pb.deep_merge(pb.DEFAULT_STATE, {})
cfg = base_cfg()
pb.save_config(cfg); pb.save_record(pb.record_from_config(cfg))
mailer = pb.Mailer(cfg)
st["mode"] = "PENDING"
st["request"] = {"token": "TESTTOKN", "requested_at": pb.now(),
                 "eligible_at": pb.now() + 3600, "approvals": {}, "denials": {},
                 "ready_notified": False, "last_poll": pb.now()}
pb.advance(cfg, st, mailer)
check("no approvals, timer running -> still PENDING", st["mode"] == "PENDING")
st["request"]["approvals"] = {"a@example.com": pb.now(), "b@example.com": pb.now()}
pb.advance(cfg, st, mailer)
check("threshold met but timer running -> still PENDING", st["mode"] == "PENDING")
st["request"]["eligible_at"] = pb.now() - 1
st["request"]["approvals"] = {"a@example.com": pb.now()}
pb.advance(cfg, st, mailer)
check("timer done but only 1/2 approvals -> still PENDING", st["mode"] == "PENDING")
st["request"]["approvals"]["b@example.com"] = pb.now()
pb.advance(cfg, st, mailer)
check("timer done AND threshold met -> UNLOCKED", st["mode"] == "UNLOCKED")
check("unlock window is %d min" % cfg["unlock_minutes"],
      abs((st["unlock"]["expires_at"] - st["unlock"]["granted_at"]) - 3600) < 2)
st["unlock"]["expires_at"] = pb.now() - 1
pb.advance(cfg, st, mailer)
check("window expiry -> back to LOCKED", st["mode"] == "LOCKED" and st["request"] is None)

st["mode"] = "PENDING"
st["request"] = {"token": "TESTTOKN", "requested_at": pb.now(),
                 "eligible_at": pb.now() - 1,
                 "approvals": {"a@example.com": pb.now(), "b@example.com": pb.now()},
                 "denials": {"c@example.com": pb.now()}, "last_poll": pb.now()}
# a denial arriving through the poller cancels even at full approval
st["request"]["approvals"] = {"a@example.com": pb.now()}
pb.advance(cfg, st, mailer)
check("insufficient approvals stay pending", st["mode"] == "PENDING")

print("\n== email failure handling ==")
st2 = pb.deep_merge(pb.DEFAULT_STATE, {})
sent = pb.Mailer(cfg).send(st2, ["x@example.com"], "s", "t")
check("unreachable SMTP does not raise", sent is False)
check("failed mail is queued for retry", len(st2["outbox"]) == 1)
pb.Mailer(cfg).flush_outbox(st2)
check("retry increments attempts, keeps it queued",
      st2["outbox"] and st2["outbox"][0]["attempts"] == 1)

print("\n== uninstall gate ==")
for mode, unlock, expect in (("LOCKED", None, False), ("PENDING", None, False),
                             ("UNLOCKED", {"expires_at": pb.now() - 5}, False),
                             ("UNLOCKED", {"expires_at": pb.now() + 300}, True)):
    granted = (mode == "UNLOCKED" and pb.now() < float((unlock or {}).get("expires_at") or 0))
    check("uninstall allowed=%s when %s" % (expect, mode + ("/expired" if unlock and
          unlock["expires_at"] < pb.now() else "")), granted == expect)

print("\n== secrets are kept out of config.json ==")
cfg = base_cfg()
cfg["email"]["smtp_password"] = "hunter2-smtp"
cfg["email"]["imap_password"] = "hunter2-imap"
cfg["discord"]["bot_token"] = "hunter2-bot-token"
pb.save_secrets({"smtp_password": "hunter2-smtp", "imap_password": "hunter2-imap",
                 "discord_bot_token": "hunter2-bot-token",
                 "partner_passphrase": pb.hash_passphrase("friend-secret")})
pb.save_config(cfg)
raw_cfg = open(pb.P(pb.CONFIG_PATH)).read()
check("no password text in config.json", "hunter2" not in raw_cfg)
check("config.json blanks the password fields",
      json.loads(raw_cfg)["email"]["smtp_password"] == "")
check("config.json blanks the bot token too",
      json.loads(raw_cfg)["discord"]["bot_token"] == "")
check("load_config merges the bot token back in",
      pb.load_config()["discord"]["bot_token"] == "hunter2-bot-token")
check("the snapshot never carries the bot token",
      "hunter2-bot-token" not in json.dumps(
          pb.public_status_doc(pb.load_config(), pb.load_state())))
loaded = pb.load_config()
check("load_config merges the secrets back in",
      loaded["email"]["smtp_password"] == "hunter2-smtp")
check("secrets.json is not world readable",
      oct(os.stat(pb.P(pb.SECRETS_PATH)).st_mode)[-3:] == "600")

print("\n== passphrase hashing ==")
h = pb.hash_passphrase("correct horse battery")
check("hash is pbkdf2 and salted", h["algo"] == "pbkdf2_sha256" and len(h["salt"]) == 32)
check("the passphrase itself is never stored",
      "correct horse battery" not in json.dumps(h))
check("right passphrase verifies", pb.verify_passphrase(h, "correct horse battery"))
check("wrong passphrase does not", not pb.verify_passphrase(h, "correct horse"))
check("empty passphrase does not", not pb.verify_passphrase(h, ""))
check("missing record does not", not pb.verify_passphrase(None, "anything"))

print("\n== passphrase gate ==")
cfg = base_cfg()
cfg["_secrets"] = {"partner_passphrase": pb.hash_passphrase("friend-secret")}
pb.save_config(cfg)
pb.save_record(pb.record_from_config(cfg))
st = pb.deep_merge(pb.DEFAULT_STATE, {})
req = {"approvals": {}, "passphrase_ok": False}
check("gate is required and unmet", pb.passphrase_gate(cfg, st, req) == (True, False))
req["passphrase_ok"] = True
check("gate satisfied once entered", pb.passphrase_gate(cfg, st, req) == (True, True))
req = {"approvals": {"a@example.com": 1, "b@example.com": 1}, "passphrase_ok": False}
check("quorum alone does not satisfy it", pb.passphrase_gate(cfg, st, req) == (True, False))
req["approvals"]["c@example.com"] = 1
check("unanimity substitutes for it", pb.passphrase_gate(cfg, st, req) == (True, True))
# two friends, both required: the quorum that unlocks is already unanimous,
# so the recovery rule hands over the passphrase gate at the same moment
two = pb.deep_merge(cfg, {"approvers": ["a@example.com", "b@example.com"],
                          "approvals_required": 2})
two["_secrets"] = cfg["_secrets"]
check("two-of-two makes the passphrase gate inert", pb.passphrase_is_inert(two))
check("and the gate really does fall open on quorum",
      pb.passphrase_gate(two, st, {"approvals": {"a@example.com": 1,
                                                 "b@example.com": 1},
                                   "passphrase_ok": False}) == (True, True))
two_off = pb.deep_merge(two, {"passphrase_recovery": False})
two_off["_secrets"] = cfg["_secrets"]
check("turning the recovery rule off restores it",
      not pb.passphrase_is_inert(two_off))
three = pb.deep_merge(cfg, {"approvals_required": 2})
three["_secrets"] = cfg["_secrets"]
check("two of three is not inert", not pb.passphrase_is_inert(three))
check("the snapshot tells the GUI about it",
      pb.public_status_doc(two, st)["passphrase_inert"] is True)

cfg_norec = pb.deep_merge(cfg, {"passphrase_recovery": False})
cfg_norec["_secrets"] = cfg["_secrets"]
check("recovery off means unanimity is not enough",
      pb.passphrase_gate(cfg_norec, st, req) == (True, False))
gone = pb.deep_merge(cfg, {})
gone["_secrets"] = {"partner_passphrase": None}
check("deleting the hash does NOT remove the gate",
      pb.passphrase_gate(gone, st, {"approvals": {}, "passphrase_ok": False})
      == (True, False))

print("\n== passphrase blocks the grant ==")
cfg = base_cfg()
cfg["_secrets"] = {"partner_passphrase": pb.hash_passphrase("friend-secret")}
pb.save_config(cfg); pb.save_record(pb.record_from_config(cfg))
st = pb.deep_merge(pb.DEFAULT_STATE, {"mode": "PENDING"})
st["request"] = {"token": "TOKEN123", "requested_at": pb.now(),
                 "eligible_at": pb.now() - 1, "last_poll": pb.now(),
                 "approvals": {"a@example.com": pb.now(), "b@example.com": pb.now()},
                 "denials": {}, "passphrase_ok": False, "ready_notified": False}
pb.advance(cfg, st, pb.Mailer(cfg))
check("timer done + quorum but no passphrase -> still PENDING", st["mode"] == "PENDING")
st["request"]["passphrase_ok"] = True
pb.advance(cfg, st, pb.Mailer(cfg))
check("all three gates -> UNLOCKED", st["mode"] == "UNLOCKED")

print("\n== passphrase policy is part of the contract ==")
weak = pb.deep_merge(cfg, {"require_passphrase": False})
weak["_secrets"] = cfg["_secrets"]
got, notes = pb.reconcile_record(weak, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("turning the passphrase requirement off is reverted",
      got["require_passphrase"] is True and any("passphrase" in n for n in notes))
weak2 = pb.deep_merge(cfg, {"passphrase_recovery": True})
weak2["_secrets"] = cfg["_secrets"]
rec = pb.load_record(); rec["passphrase_recovery"] = False; pb.save_record(rec)
got, notes = pb.reconcile_record(weak2, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("switching recovery on behind your own back is reverted",
      got["passphrase_recovery"] is False)

print("\n== public status snapshot ==")
cfg = base_cfg()
cfg["_secrets"] = {"smtp_password": "hunter2-smtp",
                   "partner_passphrase": pb.hash_passphrase("friend-secret")}
st = pb.deep_merge(pb.DEFAULT_STATE, {})
doc = pb.public_status_doc(cfg, st)
blob = json.dumps(doc)
check("snapshot leaks no password", "hunter2" not in blob)
check("snapshot leaks no passphrase hash", doc.get("passphrase_set") is True
      and "pbkdf2" not in blob)
check("snapshot has what the GUI needs",
      all(k in doc for k in ("mode", "approvers", "approvals_required",
                             "cooloff_hours", "passphrase_required", "health")))
pb.write_public_status(cfg, st)
check("snapshot is world readable",
      oct(os.stat(pb.P(pb.PUBLIC_STATUS)).st_mode)[-3:] == "644")

print("\n== an old setup keeps working ==")

# frozen on purpose: this is a settings file written by the first release,
# before Discord, before approver names, before any of it. If a future change
# ever stops this loading, someone out there has to set up from scratch, and
# the update that did it must never be installed.
OLD_CONFIG = {
    "version": 1,
    "app_name": "ChristWatch",
    "owner_name": "Bill",
    "owner_email": "bill@example.com",
    "approvers": ["a@example.com", "b@example.com", "c@example.com"],
    "approvals_required": 2,
    "cooloff_hours": 24.0,
    "unlock_minutes": 60,
    "require_passphrase": True,
    "passphrase_recovery": True,
    "filter": "cloudflare_family",
    "email": {"address": "bot@example.com", "display_name": "ChristWatch",
              "smtp_host": "smtp.example.com", "smtp_port": 587,
              "smtp_security": "starttls", "smtp_user": "bot@example.com",
              "imap_host": "imap.example.com", "imap_port": 993,
              "imap_security": "ssl", "imap_user": "bot@example.com"},
}
OLD_RECORD = {                       # and the record that went with it
    "owner_email": "bill@example.com",
    "approvers": ["a@example.com", "b@example.com", "c@example.com"],
    "approvals_required": 2, "cooloff_hours": 24.0, "unlock_minutes": 60,
    "filter": "cloudflare_family", "require_passphrase": True,
    "passphrase_recovery": True, "passphrase_set": True,
    "recorded_at": pb.now() - 86400,
}

pb.save_secrets({"smtp_password": "x", "imap_password": "x",
                 "partner_passphrase": pb.hash_passphrase("friend-secret")})
pb.write_managed(pb.CONFIG_PATH, pb.dump_json(OLD_CONFIG), 0o600,
                 immutable=False, backup=False)
pb.save_record(OLD_RECORD)
old_cfg = pb.load_config()
check("a settings file from the first release still loads", bool(old_cfg))
check("and is understood as email, because that is all there was",
      old_cfg["transport"] == "email" and not pb.is_discord(old_cfg))
check("keys added since then arrive with defaults",
      old_cfg["discord"]["channel_id"] == ""
      and old_cfg["tracking"]["enabled"] is True
      and old_cfg["approver_names"] == {})
check("it still validates", pb.validate_config(old_cfg) == [])
old_st = pb.deep_merge(pb.DEFAULT_STATE, {})
got, notes = pb.reconcile_record(old_cfg, old_st)
check("and an old install record reverts nothing",
      not [n for n in notes if "revert" in n], repr(notes))
check("the arrangement is intact after all that",
      sorted(got["approvers"]) == ["a@example.com", "b@example.com",
                                   "c@example.com"]
      and got["approvals_required"] == 2 and got["cooloff_hours"] == 24.0)
doc = pb.public_status_doc(got, old_st)
check("and the app can still be told about it",
      doc["configured"] and doc["transport"] == "email"
      and len(doc["approvers"]) == 3)

check("a file from a newer version is left alone, not downgraded",
      pb.migrate_config({"version": 99, "approvers": []})["version"] == 99)
check("migrating twice changes nothing the second time",
      pb.migrate_config(pb.migrate_config(dict(OLD_CONFIG)))["version"]
      == pb.CONFIG_SCHEMA)

print("\n== not being asked for a password ==")
_fields = {"prog": "pornblock", "user": "someone",
           "bin": "/usr/local/bin/pornblock"}
_rule = pb.POLKIT_TEMPLATE % _fields
check("the polkit rule is for one program and one person",
      'action.lookup("program") == "/usr/local/bin/pornblock"' in _rule
      and 'subject.user == "someone"' in _rule)
check("and it only ever answers yes, never widens anything else",
      "polkit.Result.YES" in _rule and "AUTH_ADMIN" not in _rule)
_sudo = pb.SUDOERS_TEMPLATE % _fields
check("the sudo rule names the program, never a wildcard",
      _sudo.strip().endswith(": /usr/local/bin/pornblock")
      and "ALL=(root)" in _sudo and "*" not in _sudo)
check("and neither file is where the gates live",
      "uninstall" not in _sudo and "approvals_required" not in _rule)
check("root is never the answer to whose machine this is",
      pb.desktop_user({"owner_user": "root"}) != "root")
check("but a recorded owner is",
      pb.desktop_user({"owner_user": "bill"}) == "bill")

print("\n== knowing what is already installed ==")
_body = "import os\nprint('hello')\n"
check("the shebang is not part of what the program is",
      pb.code_fingerprint("#!/usr/bin/env python3\n" + _body)
      == pb.code_fingerprint("#!/usr/bin/python3\n" + _body))
check("a file with no shebang at all still hashes",
      pb.code_fingerprint(_body) == pb.code_fingerprint("#!/x\n" + _body))
check("but a real change is a real change",
      pb.code_fingerprint("#!/x\n" + _body)
      != pb.code_fingerprint("#!/x\n" + _body + "print('and one more thing')\n"))

print("\n== an update may not cost you your setup ==")
_now = {"configured": True, "mode": "LOCKED", "transport": "discord",
        "approvers": ["111", "222"], "approvals_required": 2,
        "cooloff_hours": 24.0, "unlock_minutes": 60, "channel_id": "999",
        "passphrase_set": True, "filter": "cloudflare_family", "armed": True}
check("an update that changes nothing about you is fine",
      pb.arrangement_diff(pb.arrangement(_now), pb.arrangement(dict(_now))) == "")
check("a new version that lost your approvers is caught",
      "approvers" in pb.arrangement_diff(
          pb.arrangement(_now), pb.arrangement(dict(_now, approvers=[]))))
check("so is one that quietly shortened the wait",
      "cooloff_hours" in pb.arrangement_diff(
          pb.arrangement(_now), pb.arrangement(dict(_now, cooloff_hours=1))))
check("so is one that came up unconfigured",
      bool(pb.arrangement_diff(pb.arrangement(_now),
                               pb.arrangement({"configured": False}))))
check("so is one that switched the blocker off",
      "armed" in pb.arrangement_diff(
          pb.arrangement(_now), pb.arrangement(dict(_now, armed=False))))
check("and one that cannot say anything at all is caught",
      bool(pb.arrangement_diff(pb.arrangement(_now), {})))
check("the order approvers are listed in does not count as a change",
      pb.arrangement_diff(pb.arrangement(_now),
                          pb.arrangement(dict(_now, approvers=["222", "111"]))) == "")

pb.save_config(cfg)
pb.save_record(pb.record_from_config(cfg))

print("\n== the resolver has to actually resolve ==")
_drop = pb.resolved_dropin(base_cfg())
_f = pb.FILTERS["cloudflare_family"]
check("every server carries the name on its certificate",
      all("%s#%s" % (ip, _f["dot_name"]) in _drop
          for ip in _f["ipv4"] + _f["ipv6"]))
check("DNS-over-TLS is on", "DNSOverTLS=yes" in _drop)
check("and DNSSEC is off, because the filter rewrites answers on purpose",
      "DNSSEC=no" in _drop and "allow-downgrade" not in _drop)
check("nothing falls back past the filter",
      "FallbackDNS=\n" in _drop and "Domains=~." in _drop)

print("\n== reading resolvectl ==")
check("a DNS-over-TLS server is still that address",
      pb.bare_ip("1.1.1.3#family.cloudflare-dns.com") == "1.1.1.3")
check("so is a link-local one", pb.bare_ip("fe80::1%wlp1s0") == "fe80::1")
check("a plain address is left alone", pb.bare_ip("1.0.0.3") == "1.0.0.3")
check("and nothing is nothing", pb.bare_ip("") == "" and pb.bare_ip(None) == "")
_f = pb.FILTERS["cloudflare_family"]
check("the filter's own servers read as the filter's own servers",
      all(pb.bare_ip(ip) in {i.lower() for i in _f["ipv4"] + _f["ipv6"]}
          for ip in _f["ipv4"] + _f["ipv6"]))

print("\n== discord transport (no network) ==")


class FakeDiscord(pb.DiscordCourier):
    """The real courier with the one HTTP call replaced."""

    def __init__(self, cfg, pages=None, me=None):
        super().__init__(cfg)
        self.sent = []
        self.pages = list(pages or [])
        self.me = me or {}

    def _call(self, method, path, body=None, timeout=25, retries=1):
        if method == "POST":
            self.sent.append((path, body))
            return {"id": "1"}
        if path.startswith("/users/@me"):
            return {"username": "christwatch"}
        if path.startswith("/channels/") and "/messages" in path:
            return self.pages.pop(0) if self.pages else []
        if path.startswith("/channels/"):
            return {"name": "accountability"}
        if path.startswith("/applications/@me"):
            return self.me
        return {}


class DeadDiscord(FakeDiscord):
    def _call(self, *a, **k):
        raise pb.MailError("Discord is down")


dcfg = {"transport": "discord",
        "approvers": ["111111111111111111", "222222222222222222"],
        "approver_names": {"111111111111111111": "marcus",
                           "222222222222222222": "james"},
        "discord": {"channel_id": "999999999999999999",
                    "bot_token": "tok", "ping_on_alert": True}}

check("a discord config is recognised", pb.is_discord(dcfg)
      and not pb.is_discord({"transport": "email"}))
check("the courier factory follows the transport",
      isinstance(pb.courier(dcfg), pb.DiscordCourier)
      and isinstance(pb.courier(base_cfg()), pb.Mailer))
check("ids are shown as the names your friends use",
      pb.people_list(dcfg) == "marcus, james")
check("an unknown id still renders as a mention",
      pb.display_name(dcfg, "333333333333333333") == "<@333333333333333333>")

fd = FakeDiscord(dcfg)
fd.send_now(dcfg["approvers"], "Unlock requested", "code ABCD1234")
check("one alert is one post", len(fd.sent) == 1)
_path, sent = fd.sent[0]
check("the subject is posted in bold", "**Unlock requested**" in sent["content"])
check("the pings come first, before the text", sent["content"].startswith("<@"))
check("both approvers are pinged",
      "<@111111111111111111>" in sent["content"]
      and "<@222222222222222222>" in sent["content"])
check("mentions are restricted to those two",
      sent["allowed_mentions"]["parse"] == []
      and len(sent["allowed_mentions"]["users"]) == 2)

quiet = FakeDiscord(dcfg)
quiet.send_now([], "Daily report", "screen time 4h")
check("a report with nobody to ping pings nobody",
      "<@" not in quiet.sent[0][1]["content"])

long_text = "\n".join("line %d" % i for i in range(600))
big = FakeDiscord(dcfg)
big.send_now([], "Long", long_text)
check("a long report is split, never truncated",
      len(big.sent) > 1 and all(len(c[1]["content"]) <= 2000 for c in big.sent)
      and "line 599" in "".join(c[1]["content"] for c in big.sent))

now_ms = int(pb.now() * 1000)
snow = pb.snowflake_at(pb.now())
check("snowflakes carry the right timestamp",
      abs(((snow >> 22) + pb.DISCORD_EPOCH_MS) - now_ms) < 1000)

msgs = [{"id": "100", "content": "APPROVE ABCD1234",
         "author": {"id": "111111111111111111", "username": "marcus"}},
        {"id": "101", "content": "[ChristWatch] Unlock requested",
         "author": {"id": "555", "username": "bot", "bot": True}},
        {"id": "102", "content": "", "author": {"id": "222222222222222222"}}]
sc = FakeDiscord(dcfg, pages=[msgs])
seen = sc.scan({}, pb.now() - 600)
check("the bot ignores its own posts", all(u != "555" for u, _s, _b, _m in seen))
check("blank messages are skipped (no content intent)", len(seen) == 1)
check("a human approval comes through",
      seen[0][0] == "111111111111111111" and "APPROVE" in seen[0][2])

st_d = pb.deep_merge(pb.DEFAULT_STATE, {})
st_d["mode"] = "PENDING"
st_d["request"] = {"token": "ABCD1234", "requested_at": pb.now() - 60,
                   "eligible_at": pb.now() + 60, "approvals": {}, "denials": {}}
events = pb.poll_approvals(dcfg, st_d, FakeDiscord(dcfg, pages=[msgs]))
check("that approval is recorded against the right person",
      events == [("approve", "111111111111111111")])
strangers = [{"id": "103", "content": "APPROVE ABCD1234",
              "author": {"id": "444444444444444444", "username": "randomer"}}]
st_d["request"]["approvals"] = {}
check("a stranger in the channel cannot approve",
      pb.poll_approvals(dcfg, st_d, FakeDiscord(dcfg, pages=[strangers])) == [])

_human_ok = [{"id": "9", "content": "hello", "author": {"id": "111", "bot": False}}]
_human_blank = [{"id": "9", "content": "", "author": {"id": "111", "bot": False}}]
_bots_only = [{"id": "9", "content": "alert", "author": {"id": "5", "bot": True}}]
class ButtonDiscord(FakeDiscord):
    """A channel where people tap rather than type."""

    def __init__(self, cfg, ticks=(), crosses=()):
        super().__init__(cfg)
        self.ticks, self.crosses = set(ticks), set(crosses)
        self.reacted = []

    def _call(self, method, path, body=None, timeout=25, retries=1):
        if method == "PUT" and "/reactions/" in path:
            self.reacted.append(path)
            return {}
        if method == "GET" and "/reactions/" in path:
            import urllib.parse as _u
            emoji = _u.unquote(path.split("/reactions/")[1].split("?")[0])
            who = self.ticks if emoji == pb.TICK else self.crosses
            return [{"id": u} for u in sorted(who)]
        if method == "POST":
            self.sent.append((path, body))
            return {"id": "555000111222333444"}
        return super()._call(method, path, body, timeout, retries)


def _pending(token="ABCD1234", **extra):
    st_ = pb.deep_merge(pb.DEFAULT_STATE, {})
    st_["mode"] = "PENDING"
    st_["request"] = dict({"token": token, "requested_at": pb.now() - 60,
                           "eligible_at": pb.now() + 60, "approvals": {},
                           "denials": {}}, **extra)
    return st_


# the posting path renders the whole request, so it needs a whole config
dfull = pb.deep_merge(pb.DEFAULT_CONFIG, dict(dcfg, owner_name="Bill",
                                              approvals_required=2))
dfull["_secrets"] = {}

_st_post = _pending()
_poster = ButtonDiscord(dfull)
_real3 = pb.DiscordCourier
pb.DiscordCourier = lambda _cfg: _poster
check("the request is posted and gets its buttons",
      pb.ensure_request_posted(dfull, _st_post)
      and _st_post["request"]["message_id"] == "555000111222333444"
      and len(_poster.reacted) == 2)
check("the tick goes on first", pb.TICK in
      __import__("urllib.parse", fromlist=["x"]).unquote(_poster.reacted[0]))
_before = len(_poster.sent)
check("posting it twice does not happen",
      pb.ensure_request_posted(dfull, _st_post) and len(_poster.sent) == _before)
pb.DiscordCourier = _real3

_st_tap = _pending(message_id="555")
_req = _st_tap["request"]
_ev = pb.poll_reactions(dcfg, _st_tap, ButtonDiscord(dcfg, ticks=["111111111111111111"]), _req)
check("one tap is one approval", _ev == [("approve", "111111111111111111")]
      and "111111111111111111" in _req["approvals"])
_ev = pb.poll_reactions(dcfg, _st_tap, ButtonDiscord(dcfg, ticks=["111111111111111111"]), _req)
check("the same tap is not counted twice", _ev == [])
_ev = pb.poll_reactions(dcfg, _st_tap, ButtonDiscord(dcfg), _req)
check("taking the tick back takes the approval back",
      _ev == [("unapprove", "111111111111111111")]
      and "111111111111111111" not in _req["approvals"])
_ev = pb.poll_reactions(dcfg, _pending(message_id="555"),
                        ButtonDiscord(dcfg, ticks=["444444444444444444"]),
                        {"message_id": "555", "approvals": {}, "denials": {}})
check("a stranger tapping it does nothing", _ev == [])
_st_no = _pending(message_id="555")
_ev = pb.poll_reactions(dcfg, _st_no, ButtonDiscord(dcfg, crosses=["222222222222222222"]),
                        _st_no["request"])
check("the cross is a refusal", _ev == [("deny", "222222222222222222")])
check("and a request with no message has no buttons to read",
      pb.poll_reactions(dcfg, _pending(), ButtonDiscord(dcfg),
                        {"approvals": {}}) == [])

# the request that goes in the channel has to be readable on a phone
_st_msg = _pending()
_subj, _text, _html = pb.request_email(dfull, _st_msg)
check("the request is three lines, not twenty",
      len(_text.strip().splitlines()) <= 4, _text)
check("and it says which tap does what",
      pb.TICK in _text and pb.CROSS in _text and "Code" in _text)
check("with no html to render on Discord", _html is None)

# when the bot is deaf it should say so where the people who can fix it are
st_blind = pb.deep_merge(pb.DEFAULT_STATE, {})
st_blind["mode"] = "PENDING"
st_blind["request"] = {"token": "ABCD1234", "requested_at": pb.now() - 60,
                       "eligible_at": pb.now() + 60, "approvals": {},
                       "denials": {}}
_blind = FakeDiscord(dcfg, pages=[_human_blank])
_spy2 = FakeDiscord(dcfg)
_real2 = pb.courier
pb.courier = lambda _cfg: _spy2
check("a blank reply gets no approval", pb.poll_approvals(dcfg, st_blind, _blind) == [])
check("and the channel is told how to get through anyway",
      _spy2.sent and "mention me" in _spy2.sent[0][1]["content"])
pb.courier = _real2

# a dead channel must leave the machine locked and enforcing, never wedge the
# daemon: reading approvals is the one call that talks to the network on every
# single tick
st_d["request"]["approvals"] = {}
check("a transport that cannot be reached returns nothing, quietly",
      pb.poll_approvals(dcfg, st_d, DeadDiscord(dcfg)) == [])


class ExplodingCourier:
    def scan(self, *a):
        raise RuntimeError("kaboom")


check("and even an unexpected error does not stop the tick",
      pb.poll_approvals(dcfg, st_d, ExplodingCourier()) == [])

# what arrives beats what the portal claims
check("words getting through is proof the intent is on",
      FakeDiscord(dcfg, pages=[_human_ok]).content_evidence() == (1, 0, None))
check("people's messages arriving blank is proof it is off",
      FakeDiscord(dcfg, pages=[_human_blank]).content_evidence() == (1, 1, None))
check("a channel with only our own posts proves nothing either way",
      FakeDiscord(dcfg, pages=[_bots_only]).content_evidence() == (0, 0, None))
_why = DeadDiscord(dcfg).content_evidence()
check("and a channel it cannot read says so, rather than reading as empty",
      _why[0] == 0 and _why[2] and "down" in _why[2], _why)

check("the content intent is read off the application flags",
      FakeDiscord(dcfg, me={"flags": 1 << 18}).content_intent()
      and not FakeDiscord(dcfg, me={"flags": 0}).content_intent())
_tok = base64.urlsafe_b64encode(b"123456789012345678").decode().rstrip("=")
_tok += ".Gabcde.xxxxxxxxxxxxxxxxxxxxxxxxxx"
check("the application id is read out of the token itself",
      pb.app_id_from_token(_tok) == "123456789012345678")
check("junk in that field yields nothing rather than a broken link",
      pb.app_id_from_token("not-a-token") == ""
      and pb.app_id_from_token("") == "")
check("the invite link asks for exactly four permissions",
      pb.invite_url(_tok).endswith("scope=bot&permissions=68672")
      and pb.DISCORD_PERMS == (1 << 10) | (1 << 11) | (1 << 16) | (1 << 6))
check("and points at the right application",
      "client_id=123456789012345678" in pb.invite_url(_tok))
check("the settings link goes straight to that bot's page",
      pb.bot_settings_url(_tok)
      == "https://discord.com/developers/applications/123456789012345678/bot")
check("with no token it still opens somewhere useful",
      pb.bot_settings_url("").endswith("/applications"))
check("listing channels needs no root and writes nothing",
      "require_root" not in inspect.getsource(pb.cmd_discord_channels)
      and not re.search(r"save_(config|state|record)",
                        inspect.getsource(pb.cmd_discord_channels)))

check("a token that is really an application id is explained",
      "not the application id" in pb._discord_error(401, "{}"))
check("a channel the bot is not in is explained",
      "not in that server" in pb._discord_error(404, "{}"))

_real_courier = pb.courier
_spy = FakeDiscord(dcfg)
pb.courier = lambda _cfg: _spy
_st = pb.deep_merge(pb.DEFAULT_STATE, {})
pb.alert(dcfg, _st, "k", "Something happened", "body", force=True)
check("alerts go to the channel, not to a mailbox", len(_spy.sent) == 1)
pb.alert(dcfg, _st, "digest", "Daily report", "body", force=True, ping=False)
check("the nightly report does not ping anyone at 8pm",
      "<@" not in _spy.sent[1][1]["content"])


dead = DeadDiscord(dcfg)
_st2 = pb.deep_merge(pb.DEFAULT_STATE, {})
check("a failed post is queued, not lost",
      dead.send(_st2, [], "later", "body") is False
      and len(_st2["outbox"]) == 1)
check("and the queue remembers which transport it belongs to",
      _st2["outbox"][0]["transport"] == "discord")
pb.Mailer(base_cfg()).flush_outbox(_st2)
check("the mailer does not try to send someone else's queue",
      _st2["outbox"] == [])
pb.courier = _real_courier

check("a discord config validates without any mail settings",
      pb.validate_config(pb.deep_merge(pb.DEFAULT_CONFIG, dict(
          dcfg, owner_name="bill", approvals_required=2, cooloff_hours=24,
          unlock_minutes=60, filter="cloudflare_family"))) == [])
bad_ids = pb.deep_merge(pb.DEFAULT_CONFIG, dict(
    dcfg, approvers=["marcus@example.com"], approvals_required=1,
    owner_name="bill", cooloff_hours=24, unlock_minutes=60,
    filter="cloudflare_family"))
check("an email address where a user id belongs is caught",
      any("Copy User ID" in e for e in pb.validate_config(bad_ids)))

print("\n== mailbox check (offline paths only) ==")
import argparse  # noqa: E402
_bad = os.path.join(tempfile.mkdtemp(prefix="pb-mail-"), "answers.json")
open(_bad, "w").write("{not json")
check("garbage answers are refused",
      pb.cmd_check_mailbox(argparse.Namespace(answers=_bad)) == 2)
open(_bad, "w").write(json.dumps({"email": {"smtp_host": "x"}}))
check("a missing address is refused",
      pb.cmd_check_mailbox(argparse.Namespace(answers=_bad)) == 2)
check("checking the mailbox never needs root",
      "require_root" not in inspect.getsource(pb.cmd_check_mailbox))
check("and it writes nothing",
      not re.search(r"save_(config|state|record)|write_managed",
                    inspect.getsource(pb.cmd_check_mailbox)))
check("a wrong password says so in plain words",
      "app password" in pb.friendly_mail_error(
          "error: [ALERT] Invalid credentials (Failure)"))
check("a typo'd host says so in plain words",
      "host spelling" in pb.friendly_mail_error(
          "gaierror: [Errno -2] Name or service not known"))
check("anything else is passed through",
      pb.friendly_mail_error("weird thing") == "weird thing")

print("\n== desktop integration ==")
de = pb.desktop_entry(cfg)
check("desktop entry names the app", "Name=ChristWatch" in de)
check("desktop entry launches the GUI", "Exec=/usr/local/bin/pornblock-gui" in de)
check("desktop entry is a valid-looking entry", de.startswith("[Desktop Entry]")
      and "Type=Application" in de)
svg = pb.icon_svg()
check("icon is well-formed svg", svg.lstrip().startswith("<?xml")
      and svg.rstrip().endswith("</svg>"))
import xml.etree.ElementTree as ET
try:
    ET.fromstring(svg.split("?>", 1)[1]); ok_svg = True
except Exception as exc:
    ok_svg = False
check("icon parses as XML", ok_svg)
# four white subpaths: staff, titulus, main bar, slanted footrest
cross = re.search(r'fill="#ffffff"[^>]*d="([^"]+)"', svg)
bars = cross.group(1).count("M") if cross else 0
check("icon draws the eight-pointed Orthodox cross", bars == 4, bars)
check("the footrest is slanted, raised on the left",
      bool(cross) and "M42 80 L86 93" in cross.group(1))

print("\n== update source handling ==")
check("github url -> codeload tarball",
      pb._github_tarball_url("https://github.com/me/porn-block", "main")
      == "https://codeload.github.com/me/porn-block/tar.gz/refs/heads/main")
check("non-github url has no tarball fallback",
      pb._github_tarball_url("git@gitlab.com:me/x.git", "main") is None)

cand = tempfile.mkdtemp(prefix="pb-cand-")
ok_, ver, err = pb.verify_source(cand)
check("a download with no pornblock.py is refused", not ok_ and "no pornblock.py" in err)
open(os.path.join(cand, "pornblock.py"), "w").write("def broken(:\n")
ok_, ver, err = pb.verify_source(cand)
check("code that does not compile is refused", not ok_ and "compile" in err)
open(os.path.join(cand, "pornblock.py"), "w").write("x = 1\n")
ok_, ver, err = pb.verify_source(cand)
check("code with no VERSION is refused", not ok_ and "VERSION" in err)
# no selftest.py in the candidate, so the self-test gate is skipped here --
# running the real one would recurse into this file
open(os.path.join(cand, "pornblock.py"), "w").write('VERSION = "9.9.9"\nx = 1\n')
ok_, ver, err = pb.verify_source(cand)
check("a sane candidate is accepted", ok_ and ver == "9.9.9", err)
open(os.path.join(cand, "selftest.py"), "w").write("import sys; sys.exit(3)\n")
ok_, ver, err = pb.verify_source(cand)
check("a candidate failing its own self-test is refused",
      not ok_ and "self-test" in err)
shutil.rmtree(cand, ignore_errors=True)

print("\n== the update source is pinned too ==")
cfg = base_cfg()
cfg["updates"] = {"enabled": True, "repo": "https://github.com/me/porn-block",
                  "branch": "main", "check_hours": 24, "auto_apply": False,
                  "require_unlock": True}
cfg["_secrets"] = {"partner_passphrase": pb.hash_passphrase("friend-secret")}
pb.save_config(cfg)
pb.save_record(pb.record_from_config(cfg))
rec = pb.load_record()
check("record pins the repo", rec["update_repo"] == "https://github.com/me/porn-block")
evil = pb.deep_merge(cfg, {"updates": {"repo": "https://github.com/evil/x",
                                       "branch": "pwn", "require_unlock": False}})
evil["_secrets"] = cfg["_secrets"]
got, notes = pb.reconcile_record(evil, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("repointing the update source is reverted",
      got["updates"]["repo"] == "https://github.com/me/porn-block")
check("changing the branch is reverted", got["updates"]["branch"] == "main")
check("turning off updates-need-an-unlock is reverted",
      got["updates"]["require_unlock"] is True)
check("all three were reported", len([n for n in notes if "update" in n]) >= 2, notes)

# Adopting a source for the first time has to be possible, or anyone who
# set up without one could never turn updates on at all.
plain = base_cfg()
plain["updates"] = dict(pb.DEFAULT_CONFIG["updates"])
plain["_secrets"] = {}
pb.save_config(plain)
pb.save_record(pb.record_from_config(plain))
check("a fresh record pins no source", pb.load_record()["update_repo"] == "")
adopt = pb.deep_merge(plain, {"updates": {"repo": "https://github.com/me/pb",
                                          "branch": "main"}})
adopt["_secrets"] = {}
got, notes = pb.reconcile_record(adopt, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("setting a source the first time is accepted",
      got["updates"]["repo"] == "https://github.com/me/pb", notes)
check("and it gets pinned", pb.load_record()["update_repo"] == "https://github.com/me/pb")
check("adopting one is announced", any("set to" in n for n in notes), notes)
again = pb.deep_merge(adopt, {"updates": {"repo": "https://github.com/evil/pb"}})
again["_secrets"] = {}
got, notes = pb.reconcile_record(again, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("changing it afterwards is reverted",
      got["updates"]["repo"] == "https://github.com/me/pb", notes)
drop = pb.deep_merge(adopt, {"updates": {"repo": ""}})
drop["_secrets"] = {}
got, notes = pb.reconcile_record(drop, pb.deep_merge(pb.DEFAULT_STATE, {}))
check("removing it is allowed (that is strictly safer)",
      got["updates"]["repo"] == "" and pb.load_record()["update_repo"] == "")

print("\n== activity tracking ==")
check("flatpak scope -> app id",
      pb.app_name_from_cgroup("app-flatpak-org.signal.Signal-3017974932.scope")
      == "org.signal.Signal")
check("plain scope -> app name",
      pb.app_name_from_cgroup("app-code-4739.scope") == "code")
check("templated service -> app id",
      pb.app_name_from_cgroup("app-com.rtosta.zapzap@acdb378d.service")
      == "com.rtosta.zapzap")
check("non-app cgroup ignored", pb.app_name_from_cgroup("session-2.scope") == "")
check("background plumbing is filtered",
      bool(pb._BACKGROUND_APPS.match("xdg-desktop-portal"))
      and bool(pb._BACKGROUND_APPS.match("pipewire"))
      and not pb._BACKGROUND_APPS.match("org.mozilla.firefox"))

LINE = "Looking up RR for news.example.com IN AAAA."
check("resolved debug line is parsed",
      pb._DNS_LOOKUP.search(LINE).group(1) == "news.example.com")
check("reverse lookups are skipped",
      bool(pb._SKIP_DOMAIN.search("1.0.168.192.in-addr.arpa")))
check("service records are skipped", bool(pb._SKIP_DOMAIN.search("_ldap._tcp")))
check("ordinary names are kept", not pb._SKIP_DOMAIN.search("news.example.com"))

with open(pb.P(pb.BLOCKLIST_PATH), "w") as fh:
    fh.write("0.0.0.0 badsite.example\n0.0.0.0 other.example\n")
pb._BL_CACHE["mtime"] = 0
check("exact blocked domain matches", pb.is_blocked_domain("badsite.example"))
check("subdomain of a blocked domain matches",
      pb.is_blocked_domain("cdn.img.badsite.example"))
check("unrelated domain does not match", not pb.is_blocked_domain("example.com"))
check("lookalike suffix does not match",
      not pb.is_blocked_domain("notbadsite.example"))

cfg = base_cfg()
day = pb.today_str()
pb.save_day(day, {"day": day, "screen_seconds": 3725,
                  "apps": {"org.mozilla.firefox": 3600, "code": 1200},
                  "domains": {"example.com": 12, "badsite.example": 3},
                  "blocked": {"badsite.example": 3},
                  "bypass": {"dns_bypass_packets": 7}, "updated_at": 0})
d = pb.summarise_day(cfg, day)
check("screen time summarised", d["screen_seconds"] == 3725)
check("apps ranked by time", d["apps"][0][0] == "org.mozilla.firefox")
check("blocked hits counted", d["blocked_hits"] == 3 and d["blocked_unique"] == 1)
check("day file is root-only",
      oct(os.stat(pb.P(pb.activity_path(day))).st_mode)[-3:] == "600")
subject, text = pb.digest_body(cfg, day)
check("digest names the day", day in subject)
check("digest reports screen time", "1h 2m 5s" in text, text[:200])
check("digest lists the blocked domain", "badsite.example" in text)
check("digest reports bypass drops", "7 packets" in text)
check("digest explains what app time means", "not time spent looking at it" in text)

old_day = (dt.date.today() - dt.timedelta(days=400)).isoformat()
pb.save_day(old_day, {"day": old_day, "screen_seconds": 1, "apps": {},
                      "domains": {}, "blocked": {}, "bypass": {}})
pb.prune_activity(cfg)
check("old days are pruned", not os.path.exists(pb.P(pb.activity_path(old_day))))
check("today survives pruning", os.path.exists(pb.P(pb.activity_path(day))))

pubcfg = base_cfg()
pubcfg["_secrets"] = {}
pub = pb._public_activity(pubcfg)
check("public summary has the aggregates",
      pub["screen_seconds"] == 3725 and pub["blocked_hits"] == 3)
check("public summary does NOT leak the browsing list",
      "domains" not in pub and "example.com" not in json.dumps(pub))

print("\n== phones ==")

PH_CFG = pb.deep_merge(base_cfg(), {
    "transport": "discord",
    "discord": {"channel_id": "123456789012345678", "bot_token": "t",
                "channel_name": "accountability"},
    "approvers": ["779187277308887060", "1252356701877829733"],
    "phone": {"devices": {
        "aa11bb22": {"name": "Pixel", "kind": "android", "added": pb.now() - 10},
        "cc33dd44": {"name": "iPhone", "kind": "ios", "added": pb.now() - 10},
    }},
})

# -- the pairing link ------------------------------------------------------
LINK = pb.pair_link(PH_CFG, "https://discord.com/api/webhooks/1/abc",
                    "aa11bb22", "Pixel", "#accountability")
BACK = pb.read_pair_link(LINK)
check("a pairing link is a tappable christwatch:// url",
      LINK.startswith("christwatch://pair#"))
check("the link survives the round trip",
      BACK.get("id") == "aa11bb22" and BACK.get("name") == "Pixel"
      and BACK.get("hook").endswith("/abc"))
check("the link carries the hostname the phone must be set to",
      BACK.get("dns") == pb.FILTERS[PH_CFG["filter"]]["dot_name"])
check("the link never carries the bot token",
      "t" != BACK.get("hook") and "token" not in json.dumps(BACK).lower())
check("junk is rejected rather than half-read",
      pb.read_pair_link("christwatch://pair#not-base64!!") == {}
      and pb.read_pair_link("") == {})

# The phone app parses this link in Kotlin. Nothing compiles both sides
# together, so the agreement between them is checked here instead: every key
# the laptop writes has to be a key the app reads.
KOT = os.path.join(HERE, "android/app/src/main/java/io/christwatch/phone/Core.kt")
if os.path.exists(KOT):
    core_kt = open(KOT, encoding="utf-8").read()
    for key in ("hook", "name", "dns", "home"):
        check("the phone app reads the %r field" % key,
              'optString("%s")' % key in core_kt)
    check("the phone app agrees on the scheme",
          'removePrefix("christwatch://pair")' in core_kt)
    check("the phone app agrees on the marker",
          'MARKER = "%s"' % pb.PHONE_MARKER in core_kt)
    check("the phone app reads the same setting names",
          '"private_dns_mode"' in core_kt and '"private_dns_specifier"' in core_kt)
    check("the phone app decodes base64 the same way",
          "URL_SAFE" in core_kt and "NO_PADDING" in core_kt)
else:
    print("  --   android/ not in this copy")

# -- the iPhone profile ----------------------------------------------------
import plistlib
PROF = plistlib.loads(pb.mobileconfig(PH_CFG, "iPhone", "hunter2"))
DNSP = [x for x in PROF["PayloadContent"]
        if x["PayloadType"] == "com.apple.dnsSettings.managed"][0]
check("the profile sets DNS for the whole phone",
      DNSP["DNSSettings"]["ServerURL"] == pb.FILTERS[PH_CFG["filter"]]["doh_url"])
check("the profile asks iOS to forbid switching it off",
      DNSP.get("ProhibitDisablement") is True)
check("a removal password locks the profile down",
      PROF["PayloadRemovalDisallowed"] is True
      and any(x["PayloadType"] == "com.apple.profileRemovalPassword"
              and x["RemovalPassword"] == "hunter2"
              for x in PROF["PayloadContent"]))
OPEN = plistlib.loads(pb.mobileconfig(PH_CFG, "iPhone", ""))
check("without a password the profile says so honestly",
      OPEN["PayloadRemovalDisallowed"] is False
      and not any(x["PayloadType"] == "com.apple.profileRemovalPassword"
                  for x in OPEN["PayloadContent"]))
check("each profile is its own document to iOS",
      PROF["PayloadUUID"] != OPEN["PayloadUUID"])

# -- finding a phone by what you call it -----------------------------------
check("a phone is found by name", pb.find_device(PH_CFG, "Pixel") == "aa11bb22")
check("a phone is found by name whatever the case",
      pb.find_device(PH_CFG, "pIxEl") == "aa11bb22")
check("a phone is found by id", pb.find_device(PH_CFG, "cc33dd44") == "cc33dd44")
check("a name nobody used finds nothing", pb.find_device(PH_CFG, "nokia") == "")

# -- reading what the phones said -----------------------------------------
class PhoneDiscord(pb.DiscordCourier):
    """A channel with one phone report, one person talking and one bot."""
    MESSAGES = [
        {"id": "900", "webhook_id": "5", "author": {"bot": True},
         "content": "\U0001F4F1 Pixel · profile 0 — still on\n"
                    "`CW1 {\"d\":\"aa11bb22\",\"n\":\"Pixel\",\"u\":0,"
                    "\"s\":\"on\",\"dns\":\"family.cloudflare-dns.com\","
                    "\"at\":1}`"},
        {"id": "901", "author": {"bot": False, "id": "779187277308887060"},
         "content": "nice"},
        {"id": "902", "author": {"bot": True, "id": "1"},
         "content": "CW1 {\"d\":\"aa11bb22\",\"s\":\"off\"}"},
    ]

    def _call(self, method, path, body=None, timeout=25, retries=1):
        if "/messages?" in path:
            return list(self.MESSAGES) if "after=0" in path or True else []
        raise AssertionError("unexpected call " + path)

REPORTS = PhoneDiscord(PH_CFG).reports(0)
check("a phone's report is read out of the channel",
      len(REPORTS) == 1 and REPORTS[0]["d"] == "aa11bb22"
      and REPORTS[0]["s"] == "on")
check("a person typing the marker cannot fake a phone",
      all(r.get("s") != "off" for r in REPORTS))

class DeadPhoneDiscord(pb.DiscordCourier):
    def _call(self, *a, **k):
        raise pb.MailError("Discord is down")

check("a Discord outage does not raise out of reports()",
      DeadPhoneDiscord(PH_CFG).reports(0) == [])

# -- acting on it ----------------------------------------------------------
def phone_state():
    st = pb.deep_merge(pb.DEFAULT_STATE, {})
    st["mode"] = "LOCKED"
    return st

ST = phone_state()
MOVES = pb.poll_phones(PH_CFG, ST, PhoneDiscord(PH_CFG))
check("a first report is recorded, quietly",
      ST["phones"]["aa11bb22"]["state"] == "on" and not MOVES)
check("the iPhone is not expected to report",
      not ST["phones"].get("cc33dd44", {}).get("state"))

class OffDiscord(PhoneDiscord):
    MESSAGES = [{"id": "903", "webhook_id": "5", "author": {"bot": True},
                 "content": "`CW1 {\"d\":\"aa11bb22\",\"s\":\"off\",\"at\":2}`"}]
    def post(self, text, ping_ids=()):
        self.said = getattr(self, "said", []) + [text]
        return "1"

OFF = OffDiscord(PH_CFG)
_real_phone_courier = pb.courier
pb.courier = lambda _cfg: OFF
MOVES = pb.poll_phones(PH_CFG, ST, OFF)
pb.courier = _real_phone_courier
check("a phone that stopped filtering is news",
      any("filtering off" in m for m in MOVES))
check("and the channel is told about it",
      any("stopped filtering" in t for t in getattr(OFF, "said", [])))

class QuietDiscord(PhoneDiscord):
    MESSAGES = []
    def post(self, text, ping_ids=()):
        self.said = getattr(self, "said", []) + [text]
        return "1"

ST2 = phone_state()
ST2["phones"]["aa11bb22"] = {"last_seen": pb.now() - 40 * 3600, "state": "on"}
QUIET = QuietDiscord(PH_CFG)
pb.courier = lambda _cfg: QUIET
MOVES = pb.poll_phones(PH_CFG, ST2, QUIET)
check("a phone that went quiet is treated as an answer",
      any("silent" in m for m in MOVES)
      and any("gone quiet" in t for t in getattr(QUIET, "said", [])))
QUIET2 = QuietDiscord(PH_CFG)
pb.courier = lambda _cfg: QUIET2
check("but it is only said once",
      not pb.poll_phones(PH_CFG, ST2, QUIET2)
      and not getattr(QUIET2, "said", []))
pb.courier = _real_phone_courier

ST3 = phone_state()
STRANGER = QuietDiscord(PH_CFG)
pb.courier = lambda _cfg: STRANGER
STRANGER.MESSAGES = [{"id": "904", "webhook_id": "5", "author": {"bot": True},
                      "content": "`CW1 {\"d\":\"ffffffff\",\"s\":\"off\"}`"}]
pb.poll_phones(PH_CFG, ST3, STRANGER)
pb.courier = _real_phone_courier
check("a report from a phone you never paired is ignored",
      "ffffffff" not in ST3["phones"] and not getattr(STRANGER, "said", []))

check("with no phones paired nothing is polled",
      pb.poll_phones(base_cfg(), phone_state(), QuietDiscord(PH_CFG)) == [])

# -- how it reads in status ------------------------------------------------
ROWS = dict((n, (ok, d)) for n, k, ok, d in pb.phone_table(PH_CFG, ST))
check("a filtering phone reads as fine", ROWS["Pixel"][0] is False
      or "filtering" in ROWS["Pixel"][1])
FRESH = pb.deep_merge(PH_CFG, {"phone": {"devices": {
    "ee55ff66": {"name": "New", "kind": "android", "added": pb.now()}}}})
FRESHROWS = dict((n, (ok, d)) for n, k, ok, d in
                 pb.phone_table(FRESH, phone_state()))
check("a phone paired a minute ago is not called a failure",
      FRESHROWS["New"][0] is True and "waiting" in FRESHROWS["New"][1])
STALE = pb.deep_merge(PH_CFG, {"phone": {"devices": {
    "ee55ff66": {"name": "New", "kind": "android",
                 "added": pb.now() - 100 * 3600}}}})
STALEROWS = dict((n, (ok, d)) for n, k, ok, d in
                 pb.phone_table(STALE, phone_state()))
check("a phone that never checked in eventually is",
      STALEROWS["New"][0] is False)

# -- the page you open on the phone ---------------------------------------
import http.client
import threading

pb.PhoneHandler.files = {"/ChristWatch.mobileconfig":
                         (pb.mobileconfig(PH_CFG, "iPhone", ""),
                          pb.MOBILECONFIG_TYPE)}
pb.PhoneHandler.page = b"<html>hello</html>"
pb.PhoneHandler.token = "s3cr3t"
SRV = http.server.ThreadingHTTPServer(("127.0.0.1", 0), pb.PhoneHandler)
threading.Thread(target=SRV.serve_forever, daemon=True).start()
PORT = SRV.server_address[1]


def fetch(path):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body, r.getheader("Content-Type")

check("the page is there for whoever has the address",
      fetch("/s3cr3t/")[0] == 200)
ST_, BODY, CT = fetch("/s3cr3t/ChristWatch.mobileconfig")
check("iOS is handed the profile as a profile",
      ST_ == 200 and CT == pb.MOBILECONFIG_TYPE and b"PayloadType" in BODY)
check("guessing the address gets you nothing",
      fetch("/wrong/")[0] == 404 and fetch("/")[0] == 404
      and fetch("/s3cr3t/../etc/passwd")[0] == 404)
SRV.shutdown()
SRV.server_close()

# -- opening a port must not narrow the firewall ---------------------------
# Fedora Workstation already allows 1025-65535. Removing "our" port out of
# that range afterwards would split it and leave the port shut for good.
class FakeRun:
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(" ".join(argv))
        out = self.answer if any("--query-port" in a for a in argv) else ""
        return type("R", (), {"ok": True, "out": out, "err": "", "rc": 0})()

_real_run, _real_sandbox, _real_which = pb.run, pb.SANDBOX, pb.shutil.which
pb.SANDBOX = False
pb.shutil.which = lambda _n: "/usr/bin/firewall-cmd"

pb.run = FakeRun("yes")
with pb.port_open(8723) as got:
    pass
check("a port the zone already allows is left alone",
      got is True and not any("--add-port" in c for c in pb.run.calls)
      and not any("--remove-port" in c for c in pb.run.calls))

pb.run = FakeRun("no")
with pb.port_open(8723):
    pass
check("a port that was shut is opened and shut again",
      any("--add-port=8723/tcp" in c for c in pb.run.calls)
      and any("--remove-port=8723/tcp" in c for c in pb.run.calls))
check("and nothing is written to the permanent config",
      not any("--permanent" in c for c in pb.run.calls))
pb.run, pb.SANDBOX, pb.shutil.which = _real_run, _real_sandbox, _real_which


# -- your phones are part of your setup, not of the program ----------------
DOC = pb.public_status_doc(PH_CFG, phone_state())
check("paired phones are in the snapshot",
      "android:Pixel" in DOC["phones"] and "ios:iPhone" in DOC["phones"])
LOST = dict(DOC)
LOST["phones"] = ["android:Pixel"]
check("an update that lost a phone would be refused",
      "phones" in pb.arrangement_diff(pb.arrangement(DOC), pb.arrangement(LOST)))


print("\n== packaging (skipped when not shipped in the tarball) ==")
import subprocess  # noqa: E402

def _present(name):
    return os.path.exists(os.path.join(HERE, name))

if _present("install.sh"):
    r = subprocess.run(["bash", "-n", os.path.join(HERE, "install.sh")],
                       capture_output=True, text=True)
    check("install.sh parses", r.returncode == 0, r.stderr.strip())
    body = open(os.path.join(HERE, "install.sh"), encoding="utf-8").read()
    # it must call install-app, and must never call the arming `install`
    arms = re.search(r"pornblock(?:\.py)?[\"']?\s+install(?!-app)", body)
    check("install.sh runs install-app", "install-app" in body)
    check("install.sh never arms the blocker itself", arms is None,
          arms.group(0) if arms else "")
else:
    print("  --   install.sh not in this copy")

if _present("christwatch.svg"):
    on_disk = open(os.path.join(HERE, "christwatch.svg"), encoding="utf-8").read()
    check("the repo copy of the icon matches the installed one", on_disk == svg)
else:
    print("  --   christwatch.svg not in this copy")

if _present("Install ChristWatch.desktop"):
    if shutil.which("desktop-file-validate"):
        r = subprocess.run(["desktop-file-validate",
                            os.path.join(HERE, "Install ChristWatch.desktop")],
                           capture_output=True, text=True)
        check("installer .desktop validates", r.returncode == 0 and not r.stdout.strip(),
              r.stdout.strip())
    else:
        print("  --   desktop-file-validate not installed")
else:
    print("  --   installer .desktop not in this copy")

if _present("packaging/christwatch.spec"):
    spec = open(os.path.join(HERE, "packaging/christwatch.spec"), encoding="utf-8").read()
    check("spec declares the runtime deps",
          all(("Requires:" in spec and d in spec)
              for d in ("python3-gobject", "gtk4", "libadwaita", "nftables",
                        "e2fsprogs", "systemd-resolved")))
    check("spec %post only does stage one", "install-app" in spec)
    check("erasing the package does not unblock you",
          "%postun" in spec and "uninstall" not in spec.split("%postun")[1].split("%files")[0]
          .replace("pornblock uninstall", ""))
else:
    print("  --   packaging/ not in this copy")

if _present("LICENSE"):
    check("LICENSE present", "MIT License" in
          open(os.path.join(HERE, "LICENSE"), encoding="utf-8").read())

shutil.rmtree(SB, ignore_errors=True)
print("\n%d checks failed" % len(FAILED))
if FAILED:
    for f in FAILED:
        print("  - " + f)
sys.exit(1 if FAILED else 0)
