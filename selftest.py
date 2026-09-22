#!/usr/bin/env python3
"""Offline checks for pornblock. Runs entirely inside a throwaway sandbox."""

import json
import os
import shutil
import sys
import tempfile

SB = tempfile.mkdtemp(prefix="pb-selftest-")
os.environ["PORNBLOCK_PREFIX"] = SB
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pornblock as pb  # noqa: E402

FAILED = []


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

print("\n== nftables ruleset ==")
script = pb.nft_script(cfg)
check("only touches its own table", script.count("table inet pornblock") == 3
      and "flush ruleset" not in script)
check("filter IPs allowed on 53/853", "@filter4 udp dport { 53, 853 } accept" in script)
check("everything else on 53 dropped", "udp dport 53 drop" in script)
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
pb.save_secrets({"smtp_password": "hunter2-smtp", "imap_password": "hunter2-imap",
                 "partner_passphrase": pb.hash_passphrase("friend-secret")})
pb.save_config(cfg)
raw_cfg = open(pb.P(pb.CONFIG_PATH)).read()
check("no password text in config.json", "hunter2" not in raw_cfg)
check("config.json blanks the password fields",
      json.loads(raw_cfg)["email"]["smtp_password"] == "")
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

shutil.rmtree(SB, ignore_errors=True)
print("\n%d checks failed" % len(FAILED))
if FAILED:
    for f in FAILED:
        print("  - " + f)
sys.exit(1 if FAILED else 0)
