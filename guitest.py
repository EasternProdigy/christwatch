#!/usr/bin/env python3
"""
Smoke test for the ChristWatch desktop app. Needs a display; run headless with

    gtk4-broadwayd :9 &
    GDK_BACKEND=broadway BROADWAY_DISPLAY=:9 python3 guitest.py

Kept out of selftest.py on purpose: that one has to stay display-free because
the updater runs it to vet a candidate version.
"""

import json
import os
import re
import sys
import time
import traceback

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pornblock_gui as G  # noqa: E402

FAILED = []


RAN = 0


def check(name, cond, detail=""):
    global RAN
    RAN += 1
    print(("  ok   " if cond else "  FAIL ") + name +
          (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def doc(mode, avail=False):
    t = time.time()
    d = {"schema": 1, "configured": True, "mode": mode, "hostname": "box",
         "version": "1.0.0", "app_name": "ChristWatch",
         "approvers": ["a@x.com", "b@x.com", "c@x.com"],
         "approvals_required": 2, "cooloff_hours": 24, "unlock_minutes": 60,
         "filter_label": "Cloudflare for Families", "passphrase_set": True,
         "passphrase_required": mode == "PENDING", "passphrase_satisfied": False,
         "recovery_enabled": True, "queued_emails": 0,
         "blocklist": {"domains": 76775, "fetched_at": t - 100},
         "health": [{"name": "/etc/hosts blocklist", "ok": True, "detail": "76775"},
                    {"name": "nftables DNS lockdown", "ok": False, "detail": "0 rules"}],
         "update": {"enabled": True, "repo": "https://github.com/x/y",
                    "branch": "main", "installed_sha": "abc123def456",
                    "last_check": t - 60, "last_error": "",
                    "available": ({"version": "1.1.0", "sha": "f02e8058d9c7",
                                   "subject": "new thing"} if avail else None)},
         "armed": True,
         "tracking": {"enabled": True, "day": "2026-09-21", "screen_seconds": 14820,
                      "apps": [["org.mozilla.firefox", 9000], ["code", 5400],
                               ["org.kde.konsole", 1800]],
                      "unique_domains": 214, "blocked_hits": 4, "blocked_unique": 2,
                      "blocked": [["badsite.example", 3], ["other.example", 1]],
                      "bypass": {"dns_bypass_packets": 12},
                      "digest_hour": 20, "dns_log": True},
         "request": None, "unlock": None, "history": []}
    if mode == "PENDING":
        d["request"] = {"token": "A1B2C3D4", "requested_at": t - 60,
                        "eligible_at": t + 3600,
                        "approvals": {"a@x.com": t}, "denials": {}, "reason": ""}
    if mode == "UNLOCKED":
        d["unlock"] = {"granted_at": t, "expires_at": t + 3600,
                       "approved_by": ["a@x.com"]}
    return d


class Stub:
    def toast(self, *a):
        pass


def run(app):
    try:
        print("\n== icon names ==")
        src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "pornblock_gui.py"), encoding="utf-8").read()
        names = sorted(set(re.findall(r'"([a-z0-9-]+-symbolic)"', src)))
        disp = Gdk.Display.get_default()
        settings = Gtk.Settings.get_for_display(disp)
        # Adwaita is the baseline every GTK install has. Checking only the
        # local theme is how you ship icons that work on KDE (breeze has
        # nearly everything) and render as broken squares on GNOME.
        for theme_name in ("Adwaita", "hicolor+Adwaita"):
            settings.set_property("gtk-icon-theme-name", theme_name.split("+")[0])
            theme = Gtk.IconTheme.get_for_display(disp)
            missing = [n for n in names if not theme.has_icon(n)]
            check("all %d symbolic icons resolve in %s"
                  % (len(names), theme_name.split("+")[0]), not missing, missing)
            break
        settings.set_property("gtk-icon-theme-name", "Adwaita")
        theme = Gtk.IconTheme.get_for_display(disp)
        missing = [n for n in names if not theme.has_icon(n)]
        check("no icon is breeze-only", not missing, missing)

        print("\n== setup wizard ==")
        sv = G.SetupView(Stub())
        for i in range(len(sv.page_names)):
            sv.show_page(i)
        check("all %d pages build" % len(sv.page_names), True)
        tex = G.app_icon()
        check("the shield-and-cross icon loads", tex is not None
              and tex.get_width() > 0)
        def find(widget, cls):
            if isinstance(widget, cls):
                return widget
            kid = widget.get_first_child()
            while kid is not None:
                hit = find(kid, cls)
                if hit is not None:
                    return hit
                kid = kid.get_next_sibling()
            return None
        sp = find(sv.stack.get_child_by_name("welcome"), Adw.StatusPage)
        check("the welcome page shows it rather than a themed icon",
              sp is not None and sp.get_paintable() is not None)
        check("empty name is rejected", bool(sv.validate(1)))
        sv.e_name.set_text("Bill")
        sv.e_email.set_text("bill@example.com")
        check("valid details accepted", sv.validate(1) is None, sv.validate(1))

        print("\n== setup wizard: the Discord way ==")
        check("Discord is what it offers first", sv.transport() == "discord")
        check("no mailbox password is asked for", not sv.g_mailpass.get_visible())
        check("a missing bot token is caught", bool(sv.validate(2)))
        check("the invite link waits for a token",
              not sv.b_invite.get_sensitive())
        sv.p_token.set_text("a.bot.token")
        check("a token that is not shaped like one unlocks nothing",
              not sv.b_invite.get_sensitive())
        import base64 as _b64
        real = _b64.urlsafe_b64encode(b"123456789012345678").decode().rstrip("=")
        sv.p_token.set_text(real + ".Gabcde.xxxxxxxxxxxxxxxxxxxxxxxxxxx")
        import importlib.util as _il
        _spec = _il.spec_from_file_location("pbcore", os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "pornblock.py"))
        _core = _il.module_from_spec(_spec)
        _spec.loader.exec_module(_core)
        check("the app and the helper agree on the inconclusive wording",
              G.INCONCLUSIVE == _core.INCONCLUSIVE,
              (G.INCONCLUSIVE, _core.INCONCLUSIVE))
        check("the app and the daemon read a token the same way",
              _core.app_id_from_token(real + ".x.y")
              == G.app_id_from_token(real + ".x.y") == "123456789012345678")
        check("a real-shaped token builds the invite link itself",
              sv.b_invite.get_sensitive()
              and sv.b_intent.get_sensitive()
              and "client_id=123456789012345678" in sv._invite_url()
              and "permissions=68608" in sv._invite_url(), sv._invite_url())
        sv.e_channel.set_text("not-a-number")
        check("a channel name where an id belongs is caught", bool(sv.validate(2)))
        sv.e_channel.set_text("999999999999999999")
        check("a pasted id is accepted", sv.validate(2) is None, sv.validate(2))
        sv._channels = [{"id": "888888888888888888", "name": "general",
                         "server": "the lads"}]
        sv.c_channel.set_model(Gtk.StringList.new(["the lads  \u2022  #general"]))
        sv.c_channel.set_selected(0)
        pretty = json.dumps({"channels": [
            {"id": "1467054089291563226", "name": "general",
             "server": "the lads", "position": 0}]}, indent=2)
        check("a pretty-printed reply is read, not just its last line",
              (G.read_json_output(pretty) or {}).get("channels"))
        check("noise before the json does not break it",
              G.read_json_output("warning: something\n" + pretty) is not None)
        check("and nonsense comes back as nothing, not a crash",
              G.read_json_output("not json at all") is None
              and G.read_json_output("") is None)
        check("picking one from the list wins over the box",
              sv.channel_id() == "888888888888888888")
        sv._channels = []
        check("token and channel accepted", sv.validate(2) is None, sv.validate(2))
        check("nobody is an approver until they check in",
              "check in" in (sv.validate(3) or ""))
        check("there are two ways to ask them",
              sv.b_checkin.get_sensitive() and sv.b_private.get_sensitive())
        fresh = sv.apply_checkin({"members": [
            {"id": "111111111111111111", "name": "marcus"},
            {"id": "222222222222222222", "name": "james"}]})
        check("whoever checks in becomes an approver", fresh == 2
              and sv.approvers() == ["111111111111111111", "222222222222222222"])
        check("the same person checking in twice is not added twice",
              sv.apply_checkin({"members": [
                  {"id": "111111111111111111", "name": "marcus"}]}) == 0)
        sv.apply_checkin({"members": [], "failed": {
            "333": "cannot send them a direct message"}})
        check("someone with their DMs shut is explained, not swallowed",
              "direct message" in sv.l_checkin.get_label())
        sv.apply_checkin({"error": "the bot token was rejected"})
        check("and an outright failure is shown as one",
              "rejected" in sv.l_checkin.get_label())
        check("checked-in friends become the approvers",
              sv.approvers() == ["111111111111111111", "222222222222222222"])
        check("and their names are kept for the emails and the app",
              sv.approver_names()["222222222222222222"] == "james")
        sv.add_discord_person("marcus#1234", "typo")
        check("something that is not a user id is caught",
              "Copy User ID" in (sv.validate(3) or ""))
        sv._people_rows[-1].get_last_child()      # keep the row referenced
        sv.discord_people.pop()
        sv.s_threshold.set_value(2)
        check("two of two accepted", sv.validate(3) is None, sv.validate(3))
        check("the friend only has a passphrase to type",
              sv.validate(5) is None, sv.validate(5))
        a = sv.answers()
        check("the answers say Discord, with the channel and the token",
              a["transport"] == "discord"
              and a["discord"]["channel_id"] == "999999999999999999"
              and a["discord"]["bot_token"].startswith(real))
        check("and carry the names alongside the ids",
              a["approver_names"]["111111111111111111"] == "marcus")

        print("\n== setup wizard: the email way ==")
        sv.c_transport.set_selected(1)
        check("switching to email brings the mailbox password back",
              sv.transport() == "email" and sv.g_mailpass.get_visible())
        sv.approver_rows[0].set_text("a@x.com")
        sv.approver_rows[1].set_text("b@x.com")
        sv.add_approver("c@x.com")
        check("approvers can be added", len(sv.approvers()) == 3)
        sv.s_threshold.set_value(9)
        check("impossible quorum is rejected", bool(sv.validate(3)))
        sv.s_threshold.set_value(2)
        check("workable quorum accepted", sv.validate(3) is None)
        check("the mailbox page starts on a real provider, already filled in",
              sv.e_smtp_host.get_text() == "smtp.gmail.com"
              and sv.e_imap_host.get_text() == "imap.gmail.com",
              sv.e_smtp_host.get_text())
        check("server settings start folded away", not sv.x_servers.get_expanded())
        check("it says how to get an app password",
              "app password" in sv.l_howto.get_label().lower())
        sv.c_provider.set_selected(len(G.PROVIDER_CHOICES) - 1)   # something else
        check("picking 'something else' opens the server settings",
              sv.x_servers.get_expanded())
        sv.c_provider.set_selected(2)                             # fastmail
        check("picking a provider fills it in and folds them away",
              sv.e_smtp_host.get_text() == "smtp.fastmail.com"
              and not sv.x_servers.get_expanded(), sv.e_smtp_host.get_text())
        check("a hand-picked provider is not overridden by the address",
              (sv.e_mailbox.set_text("bot@gmail.com") or
               sv.e_smtp_host.get_text()) == "smtp.fastmail.com")
        sv._provider_manual = False
        sv.e_mailbox.set_text("bot2@gmail.com")
        check("but an untouched picker follows the address",
              sv.e_smtp_host.get_text() == "smtp.gmail.com"
              and int(sv.s_imap_port.get_value()) == 993, sv.e_smtp_host.get_text())
        sv.e_mailbox.set_text("bot@gmail.com")
        check("mailbox page accepted", sv.validate(2) is None, sv.validate(2))
        sv.p_mailpass.set_text("app-pw")
        sv.p_phrase1.set_text("secret-phrase")
        sv.p_phrase2.set_text("typo")
        check("mismatched passphrases rejected", bool(sv.validate(5)))
        sv.p_phrase2.set_text("secret-phrase")
        sv.p_phrase1.set_text("short")
        sv.p_phrase2.set_text("short")
        check("short passphrase rejected", bool(sv.validate(5)))
        check("the mailbox can be tried before installing",
              sv.b_check.get_sensitive() and not sv.l_check.get_visible())
        sv.p_phrase1.set_text("secret-phrase")
        sv.p_phrase2.set_text("secret-phrase")
        sv.s_threshold.set_value(3)          # 3 of 3 with recovery on
        sv.check_inert()
        check("wizard warns when the passphrase gate would be inert",
              sv.l_inert.get_visible())
        sv.s_threshold.set_value(2)          # 2 of 3
        sv.check_inert()
        check("and drops the warning once a quorum is short of everyone",
              not sv.l_inert.get_visible())
        sv.s_threshold.set_value(3)
        sv.sw_recovery.set_active(False)
        check("turning the recovery rule off clears it too",
              not sv.l_inert.get_visible())
        sv.sw_recovery.set_active(True)
        sv.s_threshold.set_value(2)
        sv.p_phrase1.set_text("")
        sv.p_phrase2.set_text("")
        check("blank passphrase is allowed (set it later)", sv.validate(5) is None)
        check("blank passphrase is omitted from the answers",
              "partner_passphrase" not in sv.answers())
        sv.p_phrase1.set_text("secret-phrase")
        sv.p_phrase2.set_text("secret-phrase")
        check("friend page accepted", sv.validate(5) is None, sv.validate(5))
        a = sv.answers()
        check("answers carry the friend's secrets",
              a["partner_passphrase"] == "secret-phrase"
              and a["email"]["smtp_password"] == "app-pw")
        sv.e_repo.set_text("https://github.com/me/porn-block")
        sv.e_branch.set_text("main")
        a = sv.answers()
        check("wizard collects the update source",
              a["updates"]["repo"] == "https://github.com/me/porn-block"
              and a["updates"]["enabled"] is True, a.get("updates"))
        sv.e_repo.set_text("")
        check("blank repo switches updates off",
              sv.answers()["updates"]["enabled"] is False)
        sv.e_repo.set_text("https://github.com/me/porn-block")
        a = sv.answers()
        check("answers carry the arrangement",
              a["approvals_required"] == 2 and len(a["approvers"]) == 3
              and a["require_passphrase"] is True)

        print("\n== dashboard ==")
        d = G.Dashboard(Stub())
        d.update(doc("LOCKED"))
        check("locked state", d.l_mode.get_label() == "Locked")
        nop = doc("LOCKED")
        nop["passphrase_set"] = False
        # a broken enforcement layer is more urgent, so clear it for this check
        for h in nop["health"]:
            h["ok"] = True
        d.update(nop)
        check("missing passphrase is nagged about",
              d.banner.get_revealed() and "one gate short" in d.banner.get_title(),
              d.banner.get_title())
        nop["health"][1]["ok"] = False
        d.update(nop)
        check("a broken layer outranks the passphrase nag",
              "Not fully enforced" in d.banner.get_title())
        d.update(doc("LOCKED"))
        check("only the ask button shows",
              d.b_request.get_visible() and not d.b_cancel.get_visible())
        check("gates hidden when nothing is pending", not d.g_gates.get_visible())
        d.update(doc("LOCKED", avail=True))
        check("update banner appears", d.banner.get_revealed()
              and "1.1.0" in d.banner.get_title())
        d.update(doc("PENDING"))
        d.tick()
        check("pending state", d.l_mode.get_label() == "Waiting")
        check("gates shown", d.g_gates.get_visible())
        check("countdown counts down", "until the cool-off" in d.l_count_cap.get_label())
        check("approvals gate reads 1 of 2", d.r_appr.get_subtitle() == "1 of 2 received")
        check("passphrase gate prompts", d.b_phrase.get_visible()
              and "ask your friend" in d.r_pass.get_subtitle())
        check("reply code is shown", d.l_code.get_label() == "A1B2C3D4")
        check("cancel offered", d.b_cancel.get_visible())
        pend = doc("PENDING")
        pend["passphrase_satisfied"] = True
        d.update(pend)
        check("satisfied passphrase hides the button", not d.b_phrase.get_visible())
        check("health failure is surfaced", "Not fully enforced" in d.banner.get_title()
              or d.banner.get_revealed())
        print("\n== today panel ==")
        d.update(doc("LOCKED"))
        check("today panel shown", d.g_today.get_visible())
        titles0 = [w.get_title() for w in d._kids["today"]]
        subs0 = [w.get_subtitle() or "" for w in d._kids["today"]]
        check("digest time explained", any("20:00" in t for t in titles0), titles0)
        check("says all browsing is included",
              any("every domain looked up" in x.lower() for x in subs0), subs0)
        check("today rows populated", len(d._kids["today"]) >= 6,
              len(d._kids["today"]))
        titles = [w.get_title() for w in d._kids["today"]]
        check("screen time row", "Screen time" in titles)
        check("blocked attempts row", "Blocked attempts" in titles)
        check("blocked domains listed", any("badsite.example" in t for t in titles))
        check("bypass attempts surfaced",
              any("DNS bypass" in t for t in titles))
        check("apps listed", any("firefox" in t for t in titles))
        off = doc("LOCKED"); off["tracking"] = {"enabled": False}
        d.update(off)
        check("panel hides when tracking is off", not d.g_today.get_visible())
        check("no stale rows left behind", len(d._kids["today"]) == 0)

        print("\n== dashboard (continued) ==")
        d.update(doc("UNLOCKED"))
        d.tick()
        check("unlocked state", d.l_mode.get_label() == "Unlocked")
        check("re-lock countdown", "switches back on" in d.l_count_cap.get_label())
        for _ in range(3):
            d.update(doc("PENDING"))
            d.update(doc("LOCKED"))
        check("repeated refreshes do not duplicate rows",
              len(d._kids["people"]) == 3)
    except Exception:
        traceback.print_exc()
        FAILED.append("exception")
    GLib.idle_add(app.quit)


app = G.App()
# without this a ChristWatch window already open on this desktop owns the bus
# name, our process becomes a remote instance, activate never fires here and
# the run "passes" having tested nothing
app.set_application_id(G.APP_ID + ".selftest")
app.set_flags(Gio.ApplicationFlags.NON_UNIQUE)
app.connect("activate", run)
app.run([])
print("\n%d checks failed" % len(FAILED))
for f in FAILED:
    print("  - " + f)
if RAN < 30:
    print("ONLY %d checks ran -- the suite did not execute" % RAN)
    sys.exit(1)
sys.exit(1 if FAILED else 0)
