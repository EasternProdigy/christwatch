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

CSS = """
.hero { padding: 26px 18px; }
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

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

# Symbolic icons for "not done yet" are a minefield: checkbox-symbolic draws
# a tick and radio-symbolic draws an actual radio set. So an unmet gate shows
# no marker at all - the row's subtitle already says what is outstanding, and
# the group is titled "What still has to happen".

MODES = {
    "LOCKED": ("Locked", "security-high-symbolic", "success",
               "Blocking is on and nothing is pending."),
    "PENDING": ("Waiting", "alarm-symbolic", "warning",
                "You have asked to unlock. The clock is running."),
    "UNLOCKED": ("Unlocked", "security-low-symbolic", "error",
                 "Blocking is off. It re-arms itself automatically."),
}


def card(*classes):
    b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    b.add_css_class("card")
    b.add_css_class("hero")
    for c in classes:
        b.add_css_class(c)
    return b


def gate_row(title, icon):
    r = Adw.ActionRow(title=title)
    img = Gtk.Image.new_from_icon_name(icon)
    r.add_prefix(img)
    state = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
    state.add_css_class("success")
    r.add_suffix(state)
    return r, state


class Dashboard(Gtk.Box):
    def __init__(self, window):
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.window = window
        self.doc = {}

        self.banner = Adw.Banner()
        self.banner.connect("button-clicked", self._on_banner)
        self._banner_action = None
        self.append(self.banner)

        sw = Gtk.ScrolledWindow(vexpand=True,
                                hscrollbar_policy=Gtk.PolicyType.NEVER)
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                      margin_top=18, margin_bottom=28,
                      margin_start=14, margin_end=14)

        # -- hero -----------------------------------------------------
        hero = card()
        self.i_mode = Gtk.Image.new_from_icon_name("security-high-symbolic")
        self.i_mode.set_pixel_size(56)
        self.l_mode = Gtk.Label()
        self.l_mode.add_css_class("title-1")
        self.l_sub = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER)
        self.l_sub.add_css_class("dim-label")
        for w in (self.i_mode, self.l_mode, self.l_sub):
            hero.append(w)

        self.act_box = Gtk.Box(halign=Gtk.Align.CENTER, spacing=10, margin_top=14)
        self.b_request = Gtk.Button(label="Ask to unlock")
        self.b_request.add_css_class("pill")
        self.b_request.connect("clicked", self.on_request)
        self.b_cancel = Gtk.Button(label="Cancel and stay locked")
        self.b_cancel.add_css_class("pill")
        self.b_cancel.add_css_class("suggested-action")
        self.b_cancel.connect("clicked", self.on_cancel)
        self.act_box.append(self.b_request)
        self.act_box.append(self.b_cancel)
        hero.append(self.act_box)
        col.append(hero)

        # -- countdown ------------------------------------------------
        self.count_card = card()
        self.l_count = Gtk.Label()
        self.l_count.add_css_class("title-1")
        self.l_count.add_css_class("numeric")
        self.l_count_cap = Gtk.Label()
        self.l_count_cap.add_css_class("dim-label")
        self.bar = Gtk.ProgressBar(margin_top=12, margin_start=20,
                                   margin_end=20, show_text=False)
        for w in (self.l_count, self.l_count_cap, self.bar):
            self.count_card.append(w)
        col.append(self.count_card)

        # -- the three gates ------------------------------------------
        self.g_gates = Adw.PreferencesGroup(
            title="What still has to happen",
            description="All three. Missing any one of them means no unlock.")
        self.r_timer, self.s_timer = gate_row("Cool-off timer", "alarm-symbolic")
        self.r_appr, self.s_appr = gate_row("Approvals from your friends",
                                            "system-users-symbolic")
        self.r_pass, self.s_pass = gate_row("Partner passphrase",
                                            "dialog-password-symbolic")
        self.b_phrase = Gtk.Button(label="Enter", valign=Gtk.Align.CENTER)
        self.b_phrase.connect("clicked", self.on_passphrase)
        self.r_pass.add_suffix(self.b_phrase)
        self.r_code = Adw.ActionRow(title="Code your friends reply with")
        self.r_code.add_prefix(Gtk.Image.new_from_icon_name("mail-send-symbolic"))
        self.l_code = Gtk.Label()
        self.l_code.add_css_class("title-3")
        self.l_code.add_css_class("monospace")
        self.r_code.add_suffix(self.l_code)
        b_copy = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER)
        b_copy.add_css_class("flat")
        b_copy.set_tooltip_text("Copy the code")
        b_copy.connect("clicked", self._copy_code)
        self.r_code.add_suffix(b_copy)
        for r in (self.r_timer, self.r_appr, self.r_pass, self.r_code):
            self.g_gates.add(r)
        col.append(self.g_gates)

        # -- who ------------------------------------------------------
        self.g_people = Adw.PreferencesGroup(title="Your approvers")
        col.append(self.g_people)

        # -- collapsible detail ---------------------------------------
        self.g_detail = Adw.PreferencesGroup()
        self.x_setup = Adw.ExpanderRow(title="The arrangement")
        self.x_setup.add_prefix(Gtk.Image.new_from_icon_name("document-properties-symbolic"))
        self.x_health = Adw.ExpanderRow(title="Enforcement")
        self.x_health.add_prefix(Gtk.Image.new_from_icon_name("channel-secure-symbolic"))
        self.x_update = Adw.ExpanderRow(title="Updates")
        self.x_update.add_prefix(Gtk.Image.new_from_icon_name("system-software-update-symbolic"))
        for x in (self.x_setup, self.x_health, self.x_update):
            self.g_detail.add(x)
        col.append(self.g_detail)

        sw.set_child(Adw.Clamp(maximum_size=620, child=col))
        self.append(sw)
        self._kids = {"setup": [], "health": [], "people": [], "update": []}

    # -- helpers ----------------------------------------------------------

    def _copy_code(self, *_):
        tok = ((self.doc.get("request") or {}).get("token") or "")
        if tok:
            self.get_clipboard().set(tok)
            self.window.toast("Code %s copied" % tok)

    def _reset(self, key, parent, expander=False):
        for w in self._kids[key]:
            parent.remove(w)
        self._kids[key] = []

    def _put(self, key, parent, w, expander=False):
        if expander:
            parent.add_row(w)
        else:
            parent.add(w)
        self._kids[key].append(w)

    @staticmethod
    def _mark(img, ok):
        img.set_visible(bool(ok))

    def _on_banner(self, *_):
        if self._banner_action == "update":
            self.window.do_update()

    # -- rendering --------------------------------------------------------

    def update(self, doc):
        self.doc = doc or {}
        mode = self.doc.get("mode", "LOCKED")
        title, icon, style, sub = MODES.get(mode, MODES["LOCKED"])

        self.i_mode.set_from_icon_name(icon)
        for w in (self.i_mode, self.l_mode):
            for c in ("success", "warning", "error"):
                w.remove_css_class(c)
            w.add_css_class(style)
        self.l_mode.set_label(title)
        self.l_sub.set_label(sub)
        self.b_request.set_visible(mode == "LOCKED")
        self.b_cancel.set_visible(mode in ("PENDING", "UNLOCKED"))

        # banner: updates first, then enforcement problems
        upd = self.doc.get("update") or {}
        avail = upd.get("available")
        bad = [h for h in self.doc.get("health") or [] if not h.get("ok")]
        if avail:
            self.banner.set_title("Version %s is available" % avail.get("version"))
            self.banner.set_button_label("Install")
            self._banner_action = "update"
            self.banner.set_revealed(True)
        elif mode != "UNLOCKED" and bad:
            self.banner.set_title("Not fully enforced: %s"
                                  % ", ".join(h["name"] for h in bad[:3]))
            self.banner.set_button_label(None)
            self._banner_action = None
            self.banner.set_revealed(True)
        elif self.doc.get("queued_emails"):
            self.banner.set_title("%d alert email(s) still waiting to send"
                                  % self.doc["queued_emails"])
            self.banner.set_button_label(None)
            self._banner_action = None
            self.banner.set_revealed(True)
        else:
            self.banner.set_revealed(False)

        pending = mode == "PENDING"
        self.g_gates.set_visible(pending)
        self.count_card.set_visible(mode in ("PENDING", "UNLOCKED"))
        req = self.doc.get("request") or {}
        need = int(self.doc.get("approvals_required") or 1)
        got = {k.lower() for k in (req.get("approvals") or {})}

        if pending:
            self.r_appr.set_subtitle("%d of %d received" % (len(got), need))
            self._mark(self.s_appr, len(got) >= need)
            p_req = bool(self.doc.get("passphrase_required"))
            p_ok = bool(self.doc.get("passphrase_satisfied"))
            self.r_pass.set_visible(p_req)
            if p_req:
                self.r_pass.set_subtitle("entered" if p_ok
                                         else "ask your friend for it")
                self._mark(self.s_pass, p_ok)
                self.b_phrase.set_visible(not p_ok)
            self.l_code.set_label(req.get("token") or "-")

        # approvers
        self._reset("people", self.g_people)
        self.g_people.set_visible(True)
        for a in self.doc.get("approvers") or []:
            done_ = a.strip().lower() in got
            r = Adw.ActionRow(title=a)
            r.add_prefix(Gtk.Image.new_from_icon_name("avatar-default-symbolic"))
            if pending:
                r.set_subtitle("approved" if done_ else "waiting")
                if done_:
                    img = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
                    img.add_css_class("success")
                    r.add_suffix(img)
            self._put("people", self.g_people, r)

        # detail: the arrangement
        self._reset("setup", self.x_setup, True)
        for t, v in (
                ("Approvals needed", "%s of %s" % (need, len(self.doc.get("approvers") or []))),
                ("Cool-off", "%g hours" % self.doc.get("cooloff_hours", 24)),
                ("Unlock window", "%s minutes" % self.doc.get("unlock_minutes")),
                ("Resolver", self.doc.get("filter_label", "?")),
                ("Partner passphrase", "set by your friend"
                 if self.doc.get("passphrase_set") else "not set"),
                ("Unanimity can replace it", "yes"
                 if self.doc.get("recovery_enabled") else "no"),
                ("Blocklist", "%s domains, updated %s"
                 % ((self.doc.get("blocklist") or {}).get("domains", 0),
                    stamp((self.doc.get("blocklist") or {}).get("fetched_at")))),
        ):
            self._put("setup", self.x_setup, row(t, v), True)

        # detail: enforcement
        self._reset("health", self.x_health, True)
        health = self.doc.get("health") or []
        oks = sum(1 for h in health if h.get("ok"))
        self.x_health.set_subtitle("%d of %d layers healthy" % (oks, len(health)))
        for h in health:
            r = Adw.ActionRow(title=h.get("name", "?"), subtitle=h.get("detail", ""))
            img = Gtk.Image.new_from_icon_name(
                "emblem-ok-symbolic" if h.get("ok") else "dialog-warning-symbolic")
            img.add_css_class("success" if h.get("ok") else "warning")
            r.add_prefix(img)
            self._put("health", self.x_health, r, True)

        # detail: updates
        self._reset("update", self.x_update, True)
        if upd.get("enabled") and upd.get("repo"):
            self.x_update.set_subtitle(
                "%s available" % avail["version"] if avail else "up to date")
            self._put("update", self.x_update,
                      row("Source", "%s (%s)" % (upd["repo"], upd.get("branch"))), True)
            self._put("update", self.x_update,
                      row("Installed commit",
                          (upd.get("installed_sha") or "unknown")[:12]), True)
            self._put("update", self.x_update,
                      row("Last checked", stamp(upd.get("last_check"))), True)
            if upd.get("last_error"):
                self._put("update", self.x_update,
                          row("Last problem", upd["last_error"].splitlines()[0]), True)
        else:
            self.x_update.set_subtitle("switched off")
            self._put("update", self.x_update,
                      row("Updates", "No repo configured in config.json"), True)
        self.tick()

    def tick(self):
        mode = self.doc.get("mode")
        if mode == "PENDING":
            req = self.doc.get("request") or {}
            start = float(req.get("requested_at") or 0)
            end = float(req.get("eligible_at") or 0)
            left = end - time.time()
            span = max(1.0, end - start)
            self.bar.set_fraction(min(1.0, max(0.0, 1.0 - left / span)))
            if left > 0:
                self.l_count.set_label(human_delta(left))
                self.l_count_cap.set_label("until the cool-off is over")
                self.r_timer.set_subtitle("%s left" % human_delta(left))
                self._mark(self.s_timer, False)
            else:
                self.l_count.set_label("Timer done")
                self.r_timer.set_subtitle("elapsed %s" % stamp(end))
                self._mark(self.s_timer, True)
                need = int(self.doc.get("approvals_required") or 1)
                got = len((req.get("approvals") or {}))
                waiting = []
                if got < need:
                    waiting.append("%d more approval(s)" % (need - got))
                if self.doc.get("passphrase_required") and \
                        not self.doc.get("passphrase_satisfied"):
                    waiting.append("the partner passphrase")
                self.l_count_cap.set_label("waiting on " + (" and ".join(waiting)
                                                            or "nothing"))
        elif mode == "UNLOCKED":
            unl = self.doc.get("unlock") or {}
            start = float(unl.get("granted_at") or 0)
            end = float(unl.get("expires_at") or 0)
            left = end - time.time()
            span = max(1.0, end - start)
            self.bar.set_fraction(min(1.0, max(0.0, left / span)))
            self.l_count.set_label(human_delta(left))
            self.l_count_cap.set_label("until blocking switches back on")

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

    def on_request(self, *_):
        entry = Adw.EntryRow(title="Why? (they will read this)")
        need = self.doc.get("approvals_required", 1)
        hours = self.doc.get("cooloff_hours", 24)
        extra_gate = (" and the partner passphrase"
                      if self.doc.get("passphrase_set") else "")

        def send():
            args = ["request-unlock", "--yes"]
            if entry.get_text().strip():
                args += ["--reason", entry.get_text().strip()]
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
        pending = self.doc.get("mode") == "PENDING"
        self._dialog(
            "Back out and stay locked?" if pending else "End the unlock now?",
            "Your approvers get told you withdrew it yourself. That is a much "
            "better email for them to receive than the other one."
            if pending else "Blocking switches straight back on.",
            "Yes, stay locked", False, None, do)

    def on_passphrase(self, *_):
        entry = Adw.PasswordEntryRow(title="Partner passphrase")

        def submit():
            if not entry.get_text():
                self.window.toast("Nothing entered")
                return
            self.window.toast("Checking…")
            run_privileged(["passphrase", "--stdin"],
                           stdin_text=entry.get_text() + "\n",
                           on_done=self.window.after_action)

        self._dialog(
            "Enter the partner passphrase",
            "Your friend set this. Five wrong tries locks entry for 15 minutes "
            "and emails all of your approvers.",
            "Check it", False, entry, submit)


# ---------------------------------------------------------------------------
# Window and application
# ---------------------------------------------------------------------------

class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="ChristWatch",
                         default_width=660, default_height=860)
        self.set_icon_name("christwatch")
        self.current = None
        self.dash = None

        for name, fn in (("update", self.do_update),
                         ("checkupdate", self.check_update),
                         ("testmail", self.do_test_email),
                         ("activity", self.show_activity),
                         ("about", self.show_about)):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", lambda *_a, f=fn: f())
            self.add_action(act)

        menu = Gio.Menu()
        s1 = Gio.Menu()
        s1.append("Check for updates", "win.checkupdate")
        s1.append("Send a test email", "win.testmail")
        menu.append_section(None, s1)
        s2 = Gio.Menu()
        s2.append("Recent activity", "win.activity")
        s2.append("About ChristWatch", "win.about")
        menu.append_section(None, s2)

        self.toasts = Adw.ToastOverlay()
        self.view = Adw.ToolbarView()
        hb = Adw.HeaderBar()
        self.title_w = Adw.WindowTitle(title="ChristWatch", subtitle="")
        hb.set_title_widget(self.title_w)
        rb = Gtk.Button(icon_name="view-refresh-symbolic")
        rb.set_tooltip_text("Refresh now")
        rb.connect("clicked", lambda *_: self.refresh())
        hb.pack_start(rb)
        hb.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic",
                                   menu_model=menu, tooltip_text="Menu"))
        self.view.add_top_bar(hb)
        self.toasts.set_child(self.view)
        self.set_content(self.toasts)

        self.refresh()
        GLib.timeout_add_seconds(1, self._tick)
        GLib.timeout_add_seconds(3, self._poll)

    # -- feedback ---------------------------------------------------------

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast.new(text))

    def show_output(self, title, text, body=None):
        buf = Gtk.TextBuffer()
        buf.set_text(text or "(no output)")
        tv = Gtk.TextView(buffer=buf, editable=False, monospace=True,
                          wrap_mode=Gtk.WrapMode.WORD_CHAR,
                          top_margin=8, bottom_margin=8,
                          left_margin=8, right_margin=8)
        sw = Gtk.ScrolledWindow(min_content_height=320, min_content_width=520)
        sw.set_child(tv)
        sw.add_css_class("card")
        d = Adw.AlertDialog(heading=title, body=body or "")
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

    # -- menu actions -----------------------------------------------------

    def check_update(self):
        self.toast("Checking for updates…")

        def done(ok, out):
            self.refresh()
            line = (out or "").strip().splitlines()
            self.toast(line[-1].strip()[:90] if line else
                       ("Check finished" if ok else "Check failed"))
        run_privileged(["update", "--check"], on_done=done)

    def do_update(self):
        doc = read_status() or {}
        upd = doc.get("update") or {}
        avail = upd.get("available") or {}
        d = Adw.AlertDialog(
            heading="Install version %s?" % (avail.get("version") or "?"),
            body="This replaces the program that enforces your blocking, and "
                 "it runs as root.\n\n"
                 "Source: %s (%s)\nCommit: %s\n%s\n\n"
                 "The candidate has already passed the project's own "
                 "self-test. Every applied update emails all of your "
                 "approvers — because whoever controls that repository "
                 "controls what runs as root here."
                 % (upd.get("repo", "?"), upd.get("branch", "?"),
                    (avail.get("sha") or "?")[:12],
                    avail.get("subject") or ""))
        d.add_response("no", "Not now")
        d.add_response("yes", "Install it")
        d.set_response_appearance("yes", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("no")
        d.set_close_response("no")

        def resp(_d, r):
            if r != "yes":
                return
            self.toast("Updating…")
            run_privileged(["update"], on_done=lambda ok, out:
                           self.show_output("Update " + ("applied" if ok
                                                         else "failed"), out)
                           or self.refresh())
        d.connect("response", resp)
        d.present(self)

    def do_test_email(self):
        self.toast("Sending test email…")
        run_privileged(["test-email", "--no-roundtrip"], on_done=lambda ok, out:
                       self.show_output("Email test " + ("passed" if ok
                                                         else "failed"), out))

    def show_activity(self):
        doc = read_status() or {}
        lines = ["%s  %s" % (stamp(h.get("at")), h.get("event"))
                 for h in (doc.get("history") or [])]
        self.show_output("Recent activity", "\n".join(reversed(lines))
                         or "Nothing has happened yet.",
                         "Everything below was also emailed to your approvers.")

    def show_about(self):
        doc = read_status() or {}
        upd = doc.get("update") or {}
        about = Adw.AboutDialog(
            application_name="ChristWatch",
            application_icon="christwatch",
            version=doc.get("version", ""),
            developer_name="Accountability, self-hosted",
            comments="Content blocking you cannot quietly switch off.\n\n"
                     "An unlock needs three things at once: a cool-off timer, "
                     "approval by email from your friends, and a passphrase "
                     "only they know. Every request, approval, denial and "
                     "tamper attempt is emailed to all of them.\n\n"
                     "It is friction and social cost, not cryptography. You "
                     "are root on this machine and could take it apart — "
                     "but not quietly, and not quickly.",
            website=upd.get("repo") or "")
        about.add_credit_section("Held by", doc.get("approvers") or [])
        about.present(self)

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
            provider.load_from_string(CSS)
        except AttributeError:
            provider.load_from_data(CSS.encode("utf-8"))
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
