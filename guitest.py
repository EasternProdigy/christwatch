#!/usr/bin/env python3
"""
Smoke test for the ChristWatch desktop app. Needs a display; run headless with

    gtk4-broadwayd :9 &
    GDK_BACKEND=broadway BROADWAY_DISPLAY=:9 python3 guitest.py

Kept out of selftest.py on purpose: that one has to stay display-free because
the updater runs it to vet a candidate version.
"""

import os
import re
import sys
import time
import traceback

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, GLib, Gtk  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pornblock_gui as G  # noqa: E402

FAILED = []


def check(name, cond, detail=""):
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
        check("empty name is rejected", bool(sv.validate(1)))
        sv.e_name.set_text("Bill")
        sv.e_email.set_text("bill@example.com")
        check("valid details accepted", sv.validate(1) is None, sv.validate(1))
        sv.approver_rows[0].set_text("a@x.com")
        sv.approver_rows[1].set_text("b@x.com")
        sv.add_approver("c@x.com")
        check("approvers can be added", len(sv.approvers()) == 3)
        sv.s_threshold.set_value(9)
        check("impossible quorum is rejected", bool(sv.validate(2)))
        sv.s_threshold.set_value(2)
        check("workable quorum accepted", sv.validate(2) is None)
        sv.e_mailbox.set_text("bot@gmail.com")
        check("provider autofill", sv.e_smtp_host.get_text() == "smtp.gmail.com"
              and int(sv.s_imap_port.get_value()) == 993, sv.e_smtp_host.get_text())
        check("mailbox page accepted", sv.validate(4) is None, sv.validate(4))
        sv.p_mailpass.set_text("app-pw")
        sv.p_phrase1.set_text("secret-phrase")
        sv.p_phrase2.set_text("typo")
        check("mismatched passphrases rejected", bool(sv.validate(5)))
        sv.p_phrase2.set_text("secret-phrase")
        sv.p_phrase1.set_text("short")
        sv.p_phrase2.set_text("short")
        check("short passphrase rejected", bool(sv.validate(5)))
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
app.connect("activate", run)
app.run([])
print("\n%d checks failed" % len(FAILED))
for f in FAILED:
    print("  - " + f)
sys.exit(1 if FAILED else 0)
