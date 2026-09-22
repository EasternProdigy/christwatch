#!/usr/bin/env python3
"""
ChristWatch - the desktop front end for pornblock.

Runs as your normal user. It never reads anything privileged: the daemon
publishes a secret-free snapshot to /run/pornblock/status.json, and every
action that actually changes something is handed to `pkexec pornblock ...`,
so you get the system's own authentication dialog.

Secrets typed into the setup wizard (the mailbox app password and the partner
passphrase) are piped to the privileged helper over stdin and never touch
disk in this process.
"""

import json
import os
import sys
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

APP_ID = "io.github.christwatch"
PREFIX = os.environ.get("PORNBLOCK_PREFIX", "").rstrip("/")


def P(path):
    return os.path.join(PREFIX, path.lstrip("/")) if PREFIX else path


STATUS_PATH = P("/run/pornblock/status.json")
CORE_BIN = "/usr/local/bin/pornblock"

PROVIDERS = {
    "gmail.com": ("smtp.gmail.com", 587, "starttls", "imap.gmail.com", 993, "ssl"),
    "googlemail.com": ("smtp.gmail.com", 587, "starttls", "imap.gmail.com", 993, "ssl"),
    "outlook.com": ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993, "ssl"),
    "hotmail.com": ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993, "ssl"),
    "live.com": ("smtp-mail.outlook.com", 587, "starttls", "outlook.office365.com", 993, "ssl"),
    "yahoo.com": ("smtp.mail.yahoo.com", 587, "starttls", "imap.mail.yahoo.com", 993, "ssl"),
    "fastmail.com": ("smtp.fastmail.com", 465, "ssl", "imap.fastmail.com", 993, "ssl"),
    "zoho.com": ("smtp.zoho.com", 587, "starttls", "imap.zoho.com", 993, "ssl"),
    "icloud.com": ("smtp.mail.me.com", 587, "starttls", "imap.mail.me.com", 993, "ssl"),
    "me.com": ("smtp.mail.me.com", 587, "starttls", "imap.mail.me.com", 993, "ssl"),
    "proton.me": ("127.0.0.1", 1025, "starttls", "127.0.0.1", 1143, "starttls"),
    "protonmail.com": ("127.0.0.1", 1025, "starttls", "127.0.0.1", 1143, "starttls"),
}

FILTERS = [
    ("cloudflare_family", "Cloudflare for Families (1.1.1.3)"),
    ("cleanbrowsing_adult", "CleanBrowsing Adult Filter"),
]

CSS = b"""
.mode-pill { font-size: 26px; font-weight: 800; padding: 14px 8px; }
.mode-locked   { color: #2ec27e; }
.mode-pending  { color: #e5a50a; }
.mode-unlocked { color: #e01b24; }
.big-timer { font-size: 34px; font-weight: 800; font-feature-settings: "tnum"; }
.dim { opacity: 0.65; }
.logview { font-family: monospace; font-size: 12px; }
"""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def core_argv():
    """How to invoke the privileged core."""
    if os.path.exists(CORE_BIN):
        return [CORE_BIN]
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pornblock.py")
    if os.path.exists(local):
        return [sys.executable, local]
    return ["pornblock"]


def read_status():
    try:
        with open(STATUS_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def human_delta(seconds):
    seconds = int(max(0, seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return "%dd %02dh %02dm" % (d, h, m)
    if h:
        return "%dh %02dm %02ds" % (h, m, s)
    return "%dm %02ds" % (m, s)


def stamp(epoch):
    if not epoch:
        return "-"
    return time.strftime("%a %d %b, %H:%M", time.localtime(epoch))


def run_privileged(argv, stdin_text=None, on_done=None):
    """pkexec the core asynchronously; on_done(ok, combined_output)."""
    flags = Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_MERGE
    if stdin_text is not None:
        flags |= Gio.SubprocessFlags.STDIN_PIPE
    full = ["pkexec"] + core_argv() + argv
    try:
        proc = Gio.Subprocess.new(full, flags)
    except GLib.Error as exc:
        if on_done:
            on_done(False, "could not launch pkexec: %s" % exc.message)
        return

    def done(p, res):
        try:
            ok_, out, _err = p.communicate_utf8_finish(res)
            text = out or ""
            success = p.get_exit_status() == 0
        except GLib.Error as exc:
            text, success = exc.message, False
        if on_done:
            on_done(success, text)

    proc.communicate_utf8_async(stdin_text, None, done)


def row(title, subtitle=None, icon=None):
    r = Adw.ActionRow(title=title)
    if subtitle:
        r.set_subtitle(subtitle)
    if icon:
        r.add_prefix(Gtk.Image.new_from_icon_name(icon))
    return r


# ---------------------------------------------------------------------------
# Setup wizard
# ---------------------------------------------------------------------------

class SetupView(Gtk.Box):
    """Six pages: you, your friends, the friction, the mailbox, your friend's
    turn at the keyboard, and the install itself."""

    def __init__(self, window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.page = 0

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT,
                               vexpand=True)
        self.append(self.stack)

        self.progress = Gtk.ProgressBar(show_text=False)
        self.progress.add_css_class("osd")
        self.append(self.progress)

        bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8,
                      margin_top=10, margin_bottom=14, margin_start=18,
                      margin_end=18)
        self.back_btn = Gtk.Button(label="Back")
        self.back_btn.connect("clicked", lambda *_: self.go(-1))
        bar.append(self.back_btn)
        bar.append(Gtk.Box(hexpand=True))
        self.next_btn = Gtk.Button(label="Next")
        self.next_btn.add_css_class("suggested-action")
        self.next_btn.connect("clicked", self._next_clicked)
        bar.append(self.next_btn)
        self.append(bar)

        for builder in (self._p_welcome, self._p_you, self._p_friends,
                        self._p_friction, self._p_mailbox, self._p_friend,
                        self._p_install):
            name, widget = builder()
            sw = Gtk.ScrolledWindow(vexpand=True,
                                    hscrollbar_policy=Gtk.PolicyType.NEVER)
            sw.set_child(Adw.Clamp(maximum_size=620, margin_top=24,
                                   margin_bottom=24, margin_start=16,
                                   margin_end=16, child=widget))
            self.stack.add_named(sw, name)
        self.page_names = ["welcome", "you", "friends", "friction", "mailbox",
                           "friend", "install"]
        self.show_page(0)

    # -- pages ------------------------------------------------------------

    def _p_welcome(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        sp = Adw.StatusPage(
            icon_name="security-high-symbolic",
            title="ChristWatch",
            description="Blocking porn is the easy half. This sets up the hard "
                        "half: turning it back off needs a 24-hour wait AND "
                        "your friends' permission.")
        sp.set_vexpand(False)
        b.append(sp)
        g = Adw.PreferencesGroup(title="What you will need")
        g.add(row("Two or three friends", "Their email addresses. They get every "
                  "alert and they vote on every unlock.", "system-users-symbolic"))
        g.add(row("A spare mailbox", "A dedicated account with an app password. "
                  "It sends the alerts and reads the APPROVE replies.",
                  "mail-unread-symbolic"))
        g.add(row("One of those friends, next to you", "There is a step near the "
                  "end where they take the keyboard and type two secrets you "
                  "should not know.", "dialog-password-symbolic"))
        b.append(g)
        return "welcome", b

    def _p_you(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        g = Adw.PreferencesGroup(title="You",
                                 description="Your name goes in the emails your "
                                             "friends receive, so they know who "
                                             "is asking.")
        self.e_name = Adw.EntryRow(title="Your name")
        self.e_email = Adw.EntryRow(title="Your email address")
        g.add(self.e_name)
        g.add(self.e_email)
        b.append(g)
        return "you", b

    def _p_friends(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.g_friends = Adw.PreferencesGroup(
            title="Your approvers",
            description="Everyone here gets every alert. Pick people who will "
                        "actually ask you why.")
        add = Gtk.Button(icon_name="list-add-symbolic", valign=Gtk.Align.CENTER)
        add.add_css_class("flat")
        add.set_tooltip_text("Add another approver")
        add.connect("clicked", lambda *_: self.add_approver())
        self.g_friends.set_header_suffix(add)
        b.append(self.g_friends)
        self.approver_rows = []
        for _ in range(2):
            self.add_approver()

        g2 = Adw.PreferencesGroup(
            title="How many must agree",
            description="Requiring two means no single friend can wave you "
                        "through on a bad day.")
        self.s_threshold = Adw.SpinRow.new_with_range(1, 10, 1)
        self.s_threshold.set_title("Approvals needed")
        self.s_threshold.set_value(2)
        g2.add(self.s_threshold)
        b.append(g2)
        return "friends", b

    def add_approver(self, text=""):
        r = Adw.EntryRow(title="Approver %d" % (len(self.approver_rows) + 1))
        r.set_text(text)
        rm = Gtk.Button(icon_name="list-remove-symbolic", valign=Gtk.Align.CENTER)
        rm.add_css_class("flat")

        def remove(*_):
            if len(self.approver_rows) <= 1:
                self.window.toast("You need at least one approver")
                return
            self.g_friends.remove(r)
            self.approver_rows.remove(r)
            for i, rr in enumerate(self.approver_rows, 1):
                rr.set_title("Approver %d" % i)
        rm.connect("clicked", remove)
        r.add_suffix(rm)
        self.g_friends.add(r)
        self.approver_rows.append(r)

    def _p_friction(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        g = Adw.PreferencesGroup(
            title="The friction",
            description="The delay is the part that actually works. The urge "
                        "that makes you ask will not be the same urge a day later.")
        self.s_cooloff = Adw.SpinRow.new_with_range(0.25, 168, 1)
        self.s_cooloff.set_title("Cool-off before an unlock can be granted")
        self.s_cooloff.set_subtitle("hours")
        self.s_cooloff.set_value(24)
        self.s_window = Adw.SpinRow.new_with_range(5, 480, 5)
        self.s_window.set_title("How long blocking stays off once granted")
        self.s_window.set_subtitle("minutes, then it re-arms itself")
        self.s_window.set_value(60)
        g.add(self.s_cooloff)
        g.add(self.s_window)
        b.append(g)

        g2 = Adw.PreferencesGroup(title="Filtering resolver")
        self.c_filter = Adw.ComboRow(
            title="DNS filter",
            model=Gtk.StringList.new([label for _k, label in FILTERS]))
        g2.add(self.c_filter)
        b.append(g2)
        return "friction", b

    def _p_mailbox(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        g = Adw.PreferencesGroup(
            title="The approval mailbox",
            description="A dedicated account. It sends the alerts and watches "
                        "for APPROVE replies. Common providers fill themselves in.")
        self.e_mailbox = Adw.EntryRow(title="Mailbox address")
        self.e_mailbox.connect("changed", self._autofill)
        g.add(self.e_mailbox)
        b.append(g)

        adv = Adw.PreferencesGroup(title="Server settings")
        self.e_smtp_host = Adw.EntryRow(title="SMTP host")
        self.s_smtp_port = Adw.SpinRow.new_with_range(1, 65535, 1)
        self.s_smtp_port.set_title("SMTP port")
        self.s_smtp_port.set_value(587)
        self.c_smtp_sec = Adw.ComboRow(title="SMTP security",
                                       model=Gtk.StringList.new(["starttls", "ssl", "plain"]))
        self.e_imap_host = Adw.EntryRow(title="IMAP host")
        self.s_imap_port = Adw.SpinRow.new_with_range(1, 65535, 1)
        self.s_imap_port.set_title("IMAP port")
        self.s_imap_port.set_value(993)
        self.c_imap_sec = Adw.ComboRow(title="IMAP security",
                                       model=Gtk.StringList.new(["ssl", "starttls"]))
        for w in (self.e_smtp_host, self.s_smtp_port, self.c_smtp_sec,
                  self.e_imap_host, self.s_imap_port, self.c_imap_sec):
            adv.add(w)
        b.append(adv)
        return "mailbox", b

    def _autofill(self, entry):
        addr = entry.get_text().strip().lower()
        dom = addr.split("@")[-1] if "@" in addr else ""
        g = PROVIDERS.get(dom)
        if not g:
            return
        sh, sp, ss, ih, ip_, isec = g
        self.e_smtp_host.set_text(sh)
        self.s_smtp_port.set_value(sp)
        self.c_smtp_sec.set_selected(["starttls", "ssl", "plain"].index(ss))
        self.e_imap_host.set_text(ih)
        self.s_imap_port.set_value(ip_)
        self.c_imap_sec.set_selected(["ssl", "starttls"].index(isec))

    def _p_friend(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        banner = Adw.Banner(title="Hand the keyboard to your friend now")
        banner.set_revealed(True)
        b.append(banner)
        lbl = Gtk.Label(
            wrap=True, xalign=0,
            label="These two secrets are the ones you are not supposed to "
                  "know.\n\n"
                  "•  The mailbox password. If you know it, you can log "
                  "into the approval mailbox and approve your own requests.\n"
                  "•  The partner passphrase. Even after the timer runs "
                  "out and your friends approve, an unlock needs this typed "
                  "in — so they have to be willing to say it out loud.\n\n"
                  "Neither is ever shown again. The passphrase is stored only "
                  "as a hash.")
        lbl.add_css_class("dim")
        b.append(lbl)

        g = Adw.PreferencesGroup(title="Typed by your friend")
        self.p_mailpass = Adw.PasswordEntryRow(title="Mailbox app password")
        self.p_phrase1 = Adw.PasswordEntryRow(title="Partner passphrase")
        self.p_phrase2 = Adw.PasswordEntryRow(title="Partner passphrase again")
        for w in (self.p_mailpass, self.p_phrase1, self.p_phrase2):
            g.add(w)
        b.append(g)

        g2 = Adw.PreferencesGroup(
            title="If the passphrase is ever lost",
            description="Without a way back, a friend who moves away would "
                        "leave this machine locked for good.")
        self.sw_recovery = Adw.SwitchRow(
            title="Unanimous approval can substitute for it",
            subtitle="All approvers saying yes unlocks without the passphrase")
        self.sw_recovery.set_active(True)
        g2.add(self.sw_recovery)
        b.append(g2)
        return "friend", b

    def _p_install(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.install_status = Adw.StatusPage(
            icon_name="emblem-system-symbolic",
            title="Ready to install",
            description="This writes the config, installs the service and the "
                        "watchdog, downloads the blocklist and switches "
                        "blocking on. You will be asked for your password once.")
        b.append(self.install_status)
        self.log_buf = Gtk.TextBuffer()
        tv = Gtk.TextView(buffer=self.log_buf, editable=False, monospace=True,
                          wrap_mode=Gtk.WrapMode.WORD_CHAR)
        tv.add_css_class("logview")
        sw = Gtk.ScrolledWindow(min_content_height=220, vexpand=True)
        sw.set_child(tv)
        frame = Gtk.Frame()
        frame.set_child(sw)
        b.append(frame)
        return "install", b

    # -- navigation & validation -----------------------------------------

    def show_page(self, idx):
        self.page = idx
        self.stack.set_visible_child_name(self.page_names[idx])
        self.progress.set_fraction(idx / float(len(self.page_names) - 1))
        self.back_btn.set_sensitive(idx > 0)
        self.next_btn.set_label("Install now" if idx == len(self.page_names) - 1
                                else "Next")

    def go(self, delta):
        if delta > 0:
            if self.page == len(self.page_names) - 1:
                self.do_install()
                return
            err = self.validate(self.page)
            if err:
                self.window.toast(err)
                return
        self.show_page(max(0, min(len(self.page_names) - 1, self.page + delta)))

    @staticmethod
    def _ok_email(a):
        a = (a or "").strip()
        return "@" in a and "." in a.split("@")[-1] and " " not in a and len(a) > 5

    def approvers(self):
        return [r.get_text().strip() for r in self.approver_rows
                if r.get_text().strip()]

    def validate(self, page):
        if page == 1:
            if not self.e_name.get_text().strip():
                return "Put your name in - it goes in the emails"
            if not self._ok_email(self.e_email.get_text()):
                return "That does not look like an email address"
        if page == 2:
            appr = self.approvers()
            if not appr:
                return "You need at least one approver"
            for a in appr:
                if not self._ok_email(a):
                    return "%s does not look like an email address" % a
            if int(self.s_threshold.get_value()) > len(appr):
                return ("You are asking for %d approvals from %d people - it "
                        "could never unlock"
                        % (int(self.s_threshold.get_value()), len(appr)))
        if page == 4:
            if not self._ok_email(self.e_mailbox.get_text()):
                return "The mailbox address does not look right"
            if not self.e_smtp_host.get_text().strip():
                return "SMTP host is empty"
            if not self.e_imap_host.get_text().strip():
                return "IMAP host is empty"
        if page == 5:
            if not self.p_mailpass.get_text():
                return "Your friend needs to enter the mailbox password"
            if self.p_phrase1.get_text() != self.p_phrase2.get_text():
                return "The two passphrases do not match"
            if len(self.p_phrase1.get_text()) < 8:
                return "The passphrase needs at least 8 characters"
        return None

    def answers(self):
        sec_smtp = ["starttls", "ssl", "plain"][self.c_smtp_sec.get_selected()]
        sec_imap = ["ssl", "starttls"][self.c_imap_sec.get_selected()]
        return {
            "app_name": "ChristWatch",
            "owner_name": self.e_name.get_text().strip(),
            "owner_email": self.e_email.get_text().strip(),
            "approvers": self.approvers(),
            "approvals_required": int(self.s_threshold.get_value()),
            "cooloff_hours": float(self.s_cooloff.get_value()),
            "unlock_minutes": int(self.s_window.get_value()),
            "filter": FILTERS[self.c_filter.get_selected()][0],
            "require_passphrase": True,
            "passphrase_recovery": bool(self.sw_recovery.get_active()),
            "partner_passphrase": self.p_phrase1.get_text(),
            "email": {
                "address": self.e_mailbox.get_text().strip(),
                "display_name": "ChristWatch",
                "smtp_host": self.e_smtp_host.get_text().strip(),
                "smtp_port": int(self.s_smtp_port.get_value()),
                "smtp_security": sec_smtp,
                "smtp_user": self.e_mailbox.get_text().strip(),
                "smtp_password": self.p_mailpass.get_text(),
                "imap_host": self.e_imap_host.get_text().strip(),
                "imap_port": int(self.s_imap_port.get_value()),
                "imap_security": sec_imap,
                "imap_user": self.e_mailbox.get_text().strip(),
                "imap_password": self.p_mailpass.get_text(),
            },
        }

    def do_install(self):
        payload = json.dumps(self.answers())
        self.next_btn.set_sensitive(False)
        self.back_btn.set_sensitive(False)
        self.install_status.set_title("Installing…")
        self.install_status.set_description("Authenticate when your desktop "
                                            "asks, then give it a moment to "
                                            "download the blocklist.")
        self.log_buf.set_text("")

        def via_file():
            """Fallback if stdin did not survive pkexec: a 0600 file in the
            user's own runtime dir, deleted the moment the call returns."""
            rt = GLib.get_user_runtime_dir() or "/tmp"
            path = os.path.join(rt, "christwatch-answers.json")
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(payload)
            except OSError as exc:
                done(False, "could not stage the answers: %s" % exc)
                return

            def cleanup(ok, out):
                try:
                    os.unlink(path)
                except OSError:
                    pass
                done(ok, out)
            run_privileged(["setup", "--answers", path, "--install"],
                           on_done=cleanup)

        def first(ok, out):
            text = out or ""
            if not ok and ("not valid JSON" in text or "Expecting value" in text
                           or not text.strip()):
                self.log_buf.set_text(
                    text + "\n\nThe answers did not reach the helper over "
                    "stdin. Retrying through a private file...\n")
                via_file()
                return
            done(ok, out)

        def done(ok, out):
            self.log_buf.set_text(out or "(no output)")
            self.back_btn.set_sensitive(True)
            self.next_btn.set_sensitive(True)
            if ok:
                self.install_status.set_icon_name("emblem-ok-symbolic")
                self.install_status.set_title("Installed and locked")
                self.install_status.set_description(
                    "Blocking is live and the watchdog is running.")
                self.next_btn.set_label("Open ChristWatch")
                self.next_btn.disconnect_by_func(self._next_clicked)
                self.next_btn.connect("clicked", lambda *_: self.window.refresh())
            else:
                self.install_status.set_icon_name("dialog-error-symbolic")
                self.install_status.set_title("Install failed")
                self.install_status.set_description(
                    "Nothing was locked down. The output below says why.")
                self.window.toast("Install failed")

        run_privileged(["setup", "--answers", "-", "--install"],
                       stdin_text=payload, on_done=first)

    def _next_clicked(self, *_):
        self.go(1)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

MODE_TEXT = {
    "LOCKED": ("LOCKED", "mode-locked",
               "Blocking is on. Nothing is pending."),
    "PENDING": ("WAITING", "mode-pending",
                "You have asked to unlock. The clock is running."),
    "UNLOCKED": ("UNLOCKED", "mode-unlocked",
                 "Blocking is OFF. It re-arms itself automatically."),
}


class Dashboard(Gtk.Box):
    def __init__(self, window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.doc = {}

        sw = Gtk.ScrolledWindow(vexpand=True,
                                hscrollbar_policy=Gtk.PolicyType.NEVER)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                        margin_top=8, margin_bottom=24, margin_start=16,
                        margin_end=16)

        self.banner = Adw.Banner()
        self.append(self.banner)

        hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2,
                       margin_top=10)
        self.l_mode = Gtk.Label(label="…")
        self.l_mode.add_css_class("mode-pill")
        self.l_sub = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER)
        self.l_sub.add_css_class("dim")
        self.l_timer = Gtk.Label(label="")
        self.l_timer.add_css_class("big-timer")
        self.l_timer_cap = Gtk.Label(label="")
        self.l_timer_cap.add_css_class("dim")
        for w in (self.l_mode, self.l_sub, self.l_timer, self.l_timer_cap):
            hero.append(w)
        outer.append(hero)

        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10,
                       halign=Gtk.Align.CENTER, margin_top=6)
        self.b_request = Gtk.Button(label="Ask to unlock")
        self.b_request.connect("clicked", self.on_request)
        self.b_cancel = Gtk.Button(label="Cancel and stay locked")
        self.b_cancel.add_css_class("suggested-action")
        self.b_cancel.connect("clicked", self.on_cancel)
        self.b_phrase = Gtk.Button(label="Enter passphrase")
        self.b_phrase.connect("clicked", self.on_passphrase)
        for w in (self.b_request, self.b_phrase, self.b_cancel):
            btns.append(w)
        outer.append(btns)

        self.g_request = Adw.PreferencesGroup(title="Your open request")
        outer.append(self.g_request)
        self.g_setup = Adw.PreferencesGroup(title="The arrangement")
        outer.append(self.g_setup)
        self.g_health = Adw.PreferencesGroup(
            title="Enforcement",
            description="Re-applied every 45 seconds, whatever you do to it.")
        outer.append(self.g_health)

        foot = Gtk.Box(spacing=10, halign=Gtk.Align.CENTER, margin_top=6)
        b_mail = Gtk.Button(label="Test email")
        b_mail.connect("clicked", self.on_test_email)
        foot.append(b_mail)
        outer.append(foot)

        sw.set_child(Adw.Clamp(maximum_size=640, child=outer))
        self.append(sw)

        self._rows = {"request": [], "setup": [], "health": []}

    # -- rendering --------------------------------------------------------

    def _clear(self, key, group):
        for r in self._rows[key]:
            group.remove(r)
        self._rows[key] = []

    def _add(self, key, group, widget):
        group.add(widget)
        self._rows[key].append(widget)

    def update(self, doc):
        self.doc = doc or {}
        mode = self.doc.get("mode", "LOCKED")
        label, css, sub = MODE_TEXT.get(mode, ("?", "dim", ""))
        self.l_mode.set_label(label)
        for c in ("mode-locked", "mode-pending", "mode-unlocked"):
            self.l_mode.remove_css_class(c)
        self.l_mode.add_css_class(css)
        self.l_sub.set_label(sub)

        self.b_request.set_visible(mode == "LOCKED")
        self.b_cancel.set_visible(mode in ("PENDING", "UNLOCKED"))
        self.b_phrase.set_visible(
            mode == "PENDING" and self.doc.get("passphrase_required")
            and not self.doc.get("passphrase_satisfied"))

        bad = [h for h in self.doc.get("health") or [] if not h.get("ok")]
        if mode != "UNLOCKED" and bad:
            self.banner.set_title("Not fully enforced: %s"
                                  % ", ".join(h["name"] for h in bad[:3]))
            self.banner.set_revealed(True)
        elif self.doc.get("queued_emails"):
            self.banner.set_title("%d alert email(s) could not be sent yet"
                                  % self.doc["queued_emails"])
            self.banner.set_revealed(True)
        else:
            self.banner.set_revealed(False)

        self.g_request.set_visible(mode == "PENDING")
        self._clear("request", self.g_request)
        req = self.doc.get("request") or {}
        if mode == "PENDING" and req:
            got = {k.lower() for k in (req.get("approvals") or {})}
            need = self.doc.get("approvals_required", 1)
            r = row("Code your friends reply with", req.get("token", "?"),
                    "dialog-password-symbolic")
            self._add("request", self.g_request, r)
            self._add("request", self.g_request,
                      row("Approvals", "%d of %d" % (len(got), need),
                          "emblem-ok-symbolic" if len(got) >= need
                          else "content-loading-symbolic"))
            for a in self.doc.get("approvers") or []:
                done_ = a.strip().lower() in got
                self._add("request", self.g_request,
                          row(a, "approved" if done_ else "waiting",
                              "emblem-ok-symbolic" if done_
                              else "content-loading-symbolic"))
            if self.doc.get("passphrase_required"):
                ok_ = self.doc.get("passphrase_satisfied")
                self._add("request", self.g_request,
                          row("Partner passphrase",
                              "entered" if ok_ else "not entered yet",
                              "emblem-ok-symbolic" if ok_
                              else "dialog-password-symbolic"))

        self._clear("setup", self.g_setup)
        self._add("setup", self.g_setup,
                  row("Approvers", ", ".join(self.doc.get("approvers") or []) or "-",
                      "system-users-symbolic"))
        self._add("setup", self.g_setup,
                  row("Approvals needed",
                      "%s of %s" % (self.doc.get("approvals_required"),
                                    len(self.doc.get("approvers") or [])),
                      "object-select-symbolic"))
        self._add("setup", self.g_setup,
                  row("Cool-off", "%g hours" % self.doc.get("cooloff_hours", 24),
                      "alarm-symbolic"))
        self._add("setup", self.g_setup,
                  row("Unlock window", "%s minutes" % self.doc.get("unlock_minutes"),
                      "preferences-system-time-symbolic"))
        self._add("setup", self.g_setup,
                  row("Resolver", self.doc.get("filter_label", "?"),
                      "network-server-symbolic"))
        self._add("setup", self.g_setup,
                  row("Partner passphrase",
                      ("set by your friend" if self.doc.get("passphrase_set")
                       else "not set"),
                      "dialog-password-symbolic"))
        bl = self.doc.get("blocklist") or {}
        self._add("setup", self.g_setup,
                  row("Blocklist", "%s domains, updated %s"
                      % (bl.get("domains", 0), stamp(bl.get("fetched_at"))),
                      "view-list-symbolic"))

        self._clear("health", self.g_health)
        for h in self.doc.get("health") or []:
            self._add("health", self.g_health,
                      row(h.get("name", "?"), h.get("detail", ""),
                          "emblem-ok-symbolic" if h.get("ok")
                          else "dialog-warning-symbolic"))
        self.tick()

    def tick(self):
        """Once a second: just the countdown."""
        mode = self.doc.get("mode")
        if mode == "PENDING":
            req = self.doc.get("request") or {}
            left = float(req.get("eligible_at") or 0) - time.time()
            if left > 0:
                self.l_timer.set_label(human_delta(left))
                self.l_timer_cap.set_label("until the cool-off is over")
            else:
                self.l_timer.set_label("timer done")
                need = self.doc.get("approvals_required", 1)
                got = len(req.get("approvals") or {})
                waiting = []
                if got < need:
                    waiting.append("%d more approval(s)" % (need - got))
                if self.doc.get("passphrase_required") and \
                        not self.doc.get("passphrase_satisfied"):
                    waiting.append("the partner passphrase")
                self.l_timer_cap.set_label("waiting on " + (" and ".join(waiting)
                                                            or "nothing"))
        elif mode == "UNLOCKED":
            unl = self.doc.get("unlock") or {}
            self.l_timer.set_label(human_delta(float(unl.get("expires_at") or 0)
                                               - time.time()))
            self.l_timer_cap.set_label("until blocking switches back on")
        else:
            self.l_timer.set_label("")
            self.l_timer_cap.set_label("")

    # -- actions ----------------------------------------------------------

    def _dialog(self, heading, body, confirm_label, destructive=True,
                extra=None, on_yes=None):
        d = Adw.AlertDialog(heading=heading, body=body)
        if extra is not None:
            box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            box.add_css_class("boxed-list")
            box.append(extra)
            d.set_extra_child(box)
        d.add_response("no", "Not now")
        d.add_response("yes", confirm_label)
        d.set_response_appearance(
            "yes", Adw.ResponseAppearance.DESTRUCTIVE if destructive
            else Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("no")
        d.set_close_response("no")
        d.connect("response", lambda _d, r: on_yes() if r == "yes" else None)
        d.present(self.window)
        return d

    def on_request(self, *_):
        entry = Adw.EntryRow(title="Why? (they will read this)")
        need = self.doc.get("approvals_required", 1)
        hours = self.doc.get("cooloff_hours", 24)
        extra_gate = (" and the partner passphrase"
                      if self.doc.get("passphrase_set") else "")

        def send():
            args = ["request-unlock", "--yes"]
            reason = entry.get_text().strip()
            if reason:
                args += ["--reason", reason]
            self.window.toast("Sending…")
            run_privileged(args, on_done=self.window.after_action)

        self._dialog(
            "Ask your friends to unlock?",
            "All %d of them get an email with your name on it, immediately.\n\n"
            "Nothing unlocks for %g hours even if everyone says yes, and it "
            "will still need %d approval(s)%s."
            % (len(self.doc.get("approvers") or []), hours, need, extra_gate),
            "Send the request", True, entry, send)

    def on_cancel(self, *_):
        def do():
            self.window.toast("Cancelling…")
            run_privileged(["cancel"], on_done=self.window.after_action)
        mode = self.doc.get("mode")
        self._dialog(
            "Back out and stay locked?" if mode == "PENDING"
            else "End the unlock window now?",
            "Your approvers get told that you withdrew it yourself. That is a "
            "much better email for them to receive than the other one."
            if mode == "PENDING" else
            "Blocking switches straight back on.",
            "Yes, stay locked", False, None, do)

    def on_passphrase(self, *_):
        entry = Adw.PasswordEntryRow(title="Partner passphrase")

        def submit():
            phrase = entry.get_text()
            if not phrase:
                self.window.toast("Nothing entered")
                return
            self.window.toast("Checking…")
            run_privileged(["passphrase", "--stdin"], stdin_text=phrase + "\n",
                           on_done=self.window.after_action)

        self._dialog(
            "Enter the partner passphrase",
            "Your friend set this. Five wrong tries locks entry for 15 "
            "minutes and emails all of your approvers.",
            "Check it", False, entry, submit)

    def on_test_email(self, *_):
        self.window.toast("Sending test email…")

        def done(ok, out):
            self.window.show_output(
                "Email test " + ("passed" if ok else "failed"), out)
            self.window.refresh()
        run_privileged(["test-email", "--no-roundtrip"], on_done=done)


# ---------------------------------------------------------------------------
# Window and application
# ---------------------------------------------------------------------------

class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="ChristWatch",
                         default_width=660, default_height=840)
        self.current = None
        self.dash = None

        self.toasts = Adw.ToastOverlay()
        self.view = Adw.ToolbarView()
        hb = Adw.HeaderBar()
        self.title_w = Adw.WindowTitle(title="ChristWatch", subtitle="")
        hb.set_title_widget(self.title_w)
        rb = Gtk.Button(icon_name="view-refresh-symbolic")
        rb.set_tooltip_text("Refresh now")
        rb.connect("clicked", lambda *_: self.refresh())
        hb.pack_end(rb)
        self.view.add_top_bar(hb)
        self.toasts.set_child(self.view)
        self.set_content(self.toasts)

        self.refresh()
        GLib.timeout_add_seconds(1, self._tick)
        GLib.timeout_add_seconds(3, self._poll)

    # -- feedback ---------------------------------------------------------

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast.new(text))

    def show_output(self, title, text):
        buf = Gtk.TextBuffer()
        buf.set_text(text or "(no output)")
        tv = Gtk.TextView(buffer=buf, editable=False, monospace=True,
                          wrap_mode=Gtk.WrapMode.WORD_CHAR)
        sw = Gtk.ScrolledWindow(min_content_height=300, min_content_width=520)
        sw.set_child(tv)
        d = Adw.AlertDialog(heading=title)
        d.set_extra_child(sw)
        d.add_response("ok", "Close")
        d.set_close_response("ok")
        d.present(self)

    def after_action(self, ok, out):
        if not ok:
            self.show_output("That did not work", out)
        elif out and out.strip():
            self.toast(out.strip().splitlines()[-1][:80])
        self.refresh()

    # -- view switching ---------------------------------------------------

    def refresh(self):
        doc = read_status()
        if doc and doc.get("configured"):
            if self.current != "dash":
                self.dash = Dashboard(self)
                self.view.set_content(self.dash)
                self.current = "dash"
            self.title_w.set_subtitle(doc.get("hostname", ""))
            self.dash.update(doc)
            return
        if os.path.exists(P("/etc/systemd/system/pornblock.service")):
            if self.current != "wait":
                sp = Adw.StatusPage(
                    icon_name="content-loading-symbolic",
                    title="Waiting for the service",
                    description="ChristWatch is installed but the background "
                                "service has not reported in yet. This is "
                                "normal for a few seconds after a reboot.")
                b = Gtk.Button(label="Check again", halign=Gtk.Align.CENTER)
                b.add_css_class("pill")
                b.add_css_class("suggested-action")
                b.connect("clicked", lambda *_: self.refresh())
                sp.set_child(b)
                self.view.set_content(sp)
                self.current = "wait"
            return
        if self.current != "setup":
            self.view.set_content(SetupView(self))
            self.current = "setup"

    def _tick(self):
        if self.current == "dash" and self.dash:
            self.dash.tick()
        return GLib.SOURCE_CONTINUE

    def _poll(self):
        doc = read_status()
        if doc and doc.get("configured"):
            if self.current != "dash":
                self.refresh()
            else:
                self.title_w.set_subtitle(doc.get("hostname", ""))
                self.dash.update(doc)
        elif self.current == "wait":
            self.refresh()
        return GLib.SOURCE_CONTINUE


class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID,
                         flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_startup(self):
        Adw.Application.do_startup(self)
        provider = Gtk.CssProvider()
        try:
            provider.load_from_string(CSS.decode("utf-8"))
        except AttributeError:
            provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    def do_activate(self):
        win = self.props.active_window or MainWindow(self)
        win.present()


def main():
    GLib.set_prgname("christwatch")
    GLib.set_application_name("ChristWatch")
    return App().run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
