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

import base64
import binascii
import contextlib
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


ICON_FILE = P("/usr/share/icons/hicolor/scalable/apps/christwatch.svg")
STATUS_PATH = P("/run/pornblock/status.json")
SOURCE_HINT = P("/run/pornblock/source-hint.json")
CORE_BIN = "/usr/local/bin/pornblock"
# the helper says this when the channel has nothing in it to judge by yet
INCONCLUSIVE = "not proven yet"

def app_icon():
    """The installed shield-and-cross, or None when running uninstalled."""
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "christwatch.svg")
    for path in (ICON_FILE, here):
        if os.path.exists(path):
            try:
                return Gdk.Texture.new_from_filename(path)
            except GLib.Error:
                pass
    return None


FRIEND_INTRO_EMAIL = (
    "These two secrets are the ones you are not supposed to know.\n\n"
    "\u2022  The mailbox password. Without it you cannot read the replies "
    "your friends send, or quietly stop them arriving.\n"
    "\u2022  The partner passphrase. Even after the timer runs out and your "
    "friends approve, an unlock needs this typed in \u2014 so they have to be "
    "willing to say it out loud.\n\n"
    "Neither is ever shown again. The passphrase is stored only as a hash.")

FRIEND_INTRO_DISCORD = (
    "Your friend types one thing here: a passphrase.\n\n"
    "Even after the wait is over and they have approved in the channel, an "
    "unlock needs this typed in. So somebody has to be willing to say it out "
    "loud.\n\n"
    "It is never shown again, and only a hash of it is kept. The bot token is "
    "different: it lets this machine post and read in the channel, but it can "
    "never approve anything.")

PROVIDER_CHOICES = [
    ("Gmail", "gmail.com",
     "Make a fresh Gmail account for this, not your own. In that account turn "
     "on 2-Step Verification, then go to myaccount.google.com/apppasswords and "
     "create an app password. The 16-character password it shows you is what "
     "your friend types on the next page."),
    ("iCloud Mail", "icloud.com",
     "Sign in at account.apple.com, open Sign-In and Security, and create an "
     "app-specific password. That is what your friend types on the next page."),
    ("Fastmail", "fastmail.com",
     "Settings, then Privacy & Security, then App passwords. Give it access to "
     "Mail (IMAP and SMTP). The password is shown once, so copy it then."),
    ("Yahoo Mail", "yahoo.com",
     "Account Security, then Generate app password. The password is shown "
     "once, so copy it then."),
    ("Zoho Mail", "zoho.com",
     "Settings, then Security, then App passwords - and switch IMAP access on "
     "in the Mail settings as well."),
    ("Outlook or Hotmail", "outlook.com",
     "Careful here: Microsoft has been moving personal accounts to sign-in-"
     "with-Microsoft only, and plain app passwords are often refused. Use the "
     "Check button on the next page before you rely on it. If it is refused, "
     "Gmail is the safe choice."),
    ("Proton Mail", "proton.me",
     "Only works with Proton Mail Bridge running on this computer, which needs "
     "a paid plan. These settings point at the Bridge; take the password from "
     "Bridge itself."),
    ("Something else", None,
     "Open Server settings below and put in your provider's own SMTP and IMAP "
     "details."),
]

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
.hero { padding: 30px 18px 26px 18px; }
.hero.state-locked {
  background-image: linear-gradient(to bottom,
      alpha(@success_bg_color, 0.22), alpha(@success_bg_color, 0.04));
}
.hero.state-pending {
  background-image: linear-gradient(to bottom,
      alpha(@warning_bg_color, 0.22), alpha(@warning_bg_color, 0.04));
}
.hero.state-unlocked {
  background-image: linear-gradient(to bottom,
      alpha(@error_bg_color, 0.24), alpha(@error_bg_color, 0.05));
}
.hero .title-1 { font-weight: 800; letter-spacing: -0.5px; }
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


def read_json_output(out):
    """
    First JSON object in a command's output, whatever else it printed.

    The helper pretty-prints, so its replies are many lines long - reading
    just the last one gets you a lonely closing brace.
    """
    text = (out or "").strip()
    start = text.find("{")
    if start < 0:
        return None
    try:
        value, _end = json.JSONDecoder().raw_decode(text[start:])
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def open_url(uri, parent=None):
    if not uri:
        return
    try:
        Gtk.UriLauncher.new(uri).launch(
            parent if isinstance(parent, Gtk.Window) else None, None, None, None)
        return
    except (AttributeError, TypeError, GLib.Error):
        pass
    with contextlib.suppress(GLib.Error):
        Gio.AppInfo.launch_default_for_uri(uri, None)


def app_id_from_token(token):
    """A bot token begins with its own application id, base64'd."""
    head = (token or "").strip().split(".")[0]
    if not head:
        return ""
    try:
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
    except (ValueError, binascii.Error):
        return ""
    text = raw.decode("ascii", "ignore").strip()
    return text if text.isdigit() and len(text) >= 15 else ""


def person(doc, ident):
    """Approvers are addresses on email and user ids on Discord."""
    ident = str(ident or "").strip()
    name = (doc.get("approver_names") or {}).get(ident)
    if name:
        return name
    if doc.get("transport") == "discord" and ident.isdigit():
        return "Discord user %s" % ident
    return ident


def read_status():
    try:
        with open(STATUS_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def read_source_hint():
    """Where this copy was installed from, so the wizard can offer it."""
    try:
        with open(SOURCE_HINT, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


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


def run_privileged(argv, stdin_text=None, on_done=None, as_root=True):
    """Run the core asynchronously; on_done(ok, combined_output).

    as_root=False skips pkexec entirely - used for the read-only commands that
    touch nothing, so trying a mailbox password does not need an auth dialog.
    """
    flags = Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_MERGE
    if stdin_text is not None:
        flags |= Gio.SubprocessFlags.STDIN_PIPE
    full = (["pkexec"] if as_root else []) + core_argv() + argv
    try:
        proc = Gio.Subprocess.new(full, flags)
    except GLib.Error as exc:
        if on_done:
            on_done(False, "could not launch the helper: %s" % exc.message)
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

        for builder in (self._p_welcome, self._p_you, self._p_channel,
                        self._p_friends, self._p_friction, self._p_friend,
                        self._p_install):
            name, widget = builder()
            sw = Gtk.ScrolledWindow(vexpand=True,
                                    hscrollbar_policy=Gtk.PolicyType.NEVER)
            sw.set_child(Adw.Clamp(maximum_size=620, margin_top=24,
                                   margin_bottom=24, margin_start=16,
                                   margin_end=16, child=widget))
            self.stack.add_named(sw, name)
        self.page_names = ["welcome", "you", "channel", "friends", "friction",
                           "friend", "install"]
        self._transport_chosen()        # every pane agrees on Discord first
        self.show_page(0)

    # -- pages ------------------------------------------------------------

    def _p_welcome(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        sp = Adw.StatusPage(
            title="ChristWatch",
            description="This blocks porn on this computer. Turning it back "
                        "off takes a day of waiting and a yes from your "
                        "friends, so it can't happen in the moment.")
        icon = app_icon()
        if icon is not None:
            sp.set_paintable(icon)
        else:
            sp.set_icon_name("security-high-symbolic")
        sp.set_vexpand(False)
        b.append(sp)
        g = Adw.PreferencesGroup(title="Before you start",
                                 description="Ten minutes or so.")
        g.add(row("A couple of friends", "Their email addresses. They hear "
                  "about it when you ask to unlock, and they are the ones who "
                  "decide.", "system-users-symbolic"))
        g.add(row("A Discord channel you are all in", "The app walks you "
                  "through making a bot for it. Email works too if you would "
                  "rather.", "user-available-symbolic"))
        g.add(row("One friend sitting with you", "Near the end they type a "
                  "passphrase you are not meant to know.",
                  "dialog-password-symbolic"))
        b.append(g)
        note = Gtk.Label(
            wrap=True, xalign=0,
            label="Nothing on this computer changes until the last step.")
        note.add_css_class("dim-label")
        note.add_css_class("caption")
        b.append(note)
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
        self.fstack = Gtk.Stack(vhomogeneous=False)
        self.fstack.add_named(self._friends_discord(), "discord")
        self.fstack.add_named(self._friends_email(), "email")
        b.append(self.fstack)

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

    # -- approvers, the email way: you type their addresses ---------------

    def _friends_email(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.g_friends = Adw.PreferencesGroup(
            title="Your approvers",
            description="Everyone here gets every alert. Pick people who will "
                        "actually ask you why.")
        add = Gtk.Button(icon_name="list-add-symbolic", valign=Gtk.Align.CENTER)
        add.add_css_class("flat")
        add.set_tooltip_text("Add another approver")
        add.connect("clicked", lambda *_: self.add_approver())
        self.g_friends.set_header_suffix(add)
        box.append(self.g_friends)
        self.approver_rows = []
        for _ in range(2):
            self.add_approver()
        return box

    # -- approvers, the Discord way: they check in and it fills itself ----

    def _friends_discord(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.discord_people = []
        self.g_checkin = Adw.PreferencesGroup(
            title="Your approvers",
            description="Ask them in the channel and whoever answers lands "
                        "here. Nobody has to copy any ids.")
        self.r_checkin = Adw.ActionRow(
            title="Ask them to check in",
            subtitle="Posts in the channel and listens for two minutes, "
                     "or message a few people directly instead")
        self.r_checkin.add_prefix(
            Gtk.Image.new_from_icon_name("system-users-symbolic"))
        self.b_private = Gtk.Button(label="Privately", valign=Gtk.Align.CENTER)
        self.b_private.set_tooltip_text(
            "Direct-message the people you pick, instead of posting in the "
            "channel")
        self.b_private.connect("clicked", self.on_checkin_private)
        self.r_checkin.add_suffix(self.b_private)
        self.b_checkin = Gtk.Button(label="Ask them", valign=Gtk.Align.CENTER)
        self.b_checkin.add_css_class("suggested-action")
        self.b_checkin.connect("clicked", self.on_checkin)
        self.r_checkin.add_suffix(self.b_checkin)
        self.g_checkin.add(self.r_checkin)
        box.append(self.g_checkin)

        self.g_people = Adw.PreferencesGroup(title="Checked in")
        manual = Gtk.Button(icon_name="list-add-symbolic",
                            valign=Gtk.Align.CENTER)
        manual.add_css_class("flat")
        manual.set_tooltip_text("Add someone by user id instead")
        manual.connect("clicked", lambda *_: self.add_discord_person("", ""))
        self.g_people.set_header_suffix(manual)
        self._people_rows = []
        box.append(self.g_people)
        self.l_checkin = Gtk.Label(wrap=True, xalign=0, visible=False)
        self.l_checkin.add_css_class("caption")
        box.append(self.l_checkin)
        return box

    def add_discord_person(self, uid, name):
        person = {"id": str(uid or ""), "name": name or ""}
        self.discord_people.append(person)
        r = Adw.EntryRow(title=name or "Discord user id")
        r.set_text(person["id"])
        r.connect("changed", lambda e, pp=person: pp.update(
            {"id": e.get_text().strip()}))
        r.add_prefix(Gtk.Image.new_from_icon_name("avatar-default-symbolic"))
        rm = Gtk.Button(icon_name="list-remove-symbolic", valign=Gtk.Align.CENTER)
        rm.add_css_class("flat")

        def drop(*_):
            self.g_people.remove(r)
            self._people_rows.remove(r)
            if person in self.discord_people:
                self.discord_people.remove(person)
            self.check_inert()
        rm.connect("clicked", drop)
        r.add_suffix(rm)
        self.g_people.add(r)
        self._people_rows.append(r)
        self.check_inert()

    def on_checkin(self, *_):
        err = self.validate(2)
        if err:
            self.window.toast(err)
            self.show_page(2)
            return
        payload = json.dumps({"discord": self.answers()["discord"]})
        self.b_checkin.set_sensitive(False)
        self.b_checkin.set_label("Listening\u2026")
        self.l_checkin.set_visible(True)
        for c in ("success", "error"):
            self.l_checkin.remove_css_class(c)
        self.l_checkin.set_label(
            "Posted in the channel. Whoever says the word in the next two "
            "minutes becomes an approver.")

        def done(ok, out):
            self.b_checkin.set_sensitive(True)
            self.b_checkin.set_label("Ask them")
            self.apply_checkin(read_json_output(out) or {
                "error": (out or "").strip() or "nothing came back"})

        run_privileged(["discord-checkin", "--answers", "-", "--wait", "120"],
                       stdin_text=payload, on_done=done, as_root=False)

    def apply_checkin(self, res):
        """Fold whoever answered into the approver list."""
        for c in ("success", "error"):
            self.l_checkin.remove_css_class(c)
        self.l_checkin.set_visible(True)
        trouble = "  ".join(res.get("failed", {}).values())
        if res.get("error"):
            self.l_checkin.add_css_class("error")
            self.l_checkin.set_label(
                " ".join(x for x in (res["error"], trouble) if x))
            return 0
        fresh = 0
        have = {p["id"] for p in self.discord_people}
        for m in res.get("members") or []:
            if m.get("id") and m["id"] not in have:
                self.add_discord_person(m["id"], m.get("name") or "")
                fresh += 1
        self.l_checkin.add_css_class("success" if fresh else "error")
        if fresh:
            self.l_checkin.set_label(
                "%d checked in.%s" % (fresh, "  " + trouble if trouble else ""))
        else:
            self.l_checkin.set_label(
                trouble or ("Nobody answered in time. Try again, or add them "
                            "by user id below."))
        self.check_inert()
        return fresh

    # -- asking a few people quietly instead of the whole channel ---------

    def on_checkin_private(self, *_):
        err = self.validate(2)
        if err:
            self.window.toast(err)
            self.show_page(2)
            return
        payload = json.dumps({"discord": self.answers()["discord"]})
        self.b_private.set_sensitive(False)

        def listed(ok, out):
            self.b_private.set_sensitive(True)
            res = read_json_output(out) or {}
            people = res.get("people") or []
            if not people:
                self.window.toast(
                    res.get("error")
                    or "Nobody has spoken in that channel yet, so there is "
                       "nobody to pick. Ask in the channel instead.")
                return
            self._pick_people(people)

        run_privileged(["discord-people", "--answers", "-"],
                       stdin_text=payload, on_done=listed, as_root=False)

    def _pick_people(self, people):
        dlg = Adw.AlertDialog(
            heading="Ask them privately",
            body="Each one gets a direct message from the bot instead of a "
                 "post in the channel. They answer there and land in your "
                 "approver list.")
        group = Adw.PreferencesGroup()
        rows = {}
        for p in people[:25]:
            r = Adw.SwitchRow(title=p.get("name") or p["id"])
            group.add(r)
            rows[p["id"]] = r
        box = Gtk.ScrolledWindow(propagate_natural_height=True,
                                 max_content_height=320,
                                 hscrollbar_policy=Gtk.PolicyType.NEVER)
        box.set_child(group)
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Cancel")
        dlg.add_response("ask", "Message them")
        dlg.set_response_appearance("ask", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("ask")

        def answered(_d, response):
            if response != "ask":
                return
            picked = [uid for uid, r in rows.items() if r.get_active()]
            if not picked:
                self.window.toast("Nobody picked")
                return
            self.start_private_checkin(picked)

        dlg.connect("response", answered)
        dlg.present(self.window)

    def start_private_checkin(self, ids):
        payload = json.dumps({"discord": self.answers()["discord"],
                              "owner_name": self.e_name.get_text().strip()})
        self.b_private.set_sensitive(False)
        self.b_private.set_label("Waiting\u2026")
        self.l_checkin.set_visible(True)
        for c in ("success", "error"):
            self.l_checkin.remove_css_class(c)
        self.l_checkin.set_label(
            "Messaged %d of them. Whoever answers in the next two minutes "
            "becomes an approver." % len(ids))

        def done(ok, out):
            self.b_private.set_sensitive(True)
            self.b_private.set_label("Privately")
            self.apply_checkin(read_json_output(out) or {
                "error": (out or "").strip() or "nothing came back"})

        run_privileged(["discord-checkin", "--answers", "-", "--wait", "120",
                        "--dm", ",".join(ids)],
                       stdin_text=payload, on_done=done, as_root=False)

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

        hint = read_source_hint()
        g3 = Adw.PreferencesGroup(
            title="Updates",
            description="Where new versions are pulled from. Whoever controls "
                        "this repository can run code as root here, so a "
                        "friend's fork is safer than your own. Blank switches "
                        "updates off; you can add one later, but only once.")
        self.e_repo = Adw.EntryRow(title="Git repository URL")
        self.e_repo.set_text(hint.get("repo") or "")
        self.e_branch = Adw.EntryRow(title="Branch")
        self.e_branch.set_text(hint.get("branch") or "main")
        g3.add(self.e_repo)
        g3.add(self.e_branch)
        b.append(g3)
        return "friction", b

    def _p_channel(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        g = Adw.PreferencesGroup(
            title="How your friends hear about it",
            description="Requests, approvals, tamper alerts and the nightly "
                        "report all go one way. Their answers come back the "
                        "same way.")
        self.c_transport = Adw.ComboRow(
            title="Where it happens",
            model=Gtk.StringList.new(["A Discord channel", "Email"]))
        self.c_transport.connect("notify::selected", self._transport_chosen)
        g.add(self.c_transport)
        b.append(g)

        self.tstack = Gtk.Stack(vhomogeneous=False)
        self.tstack.add_named(self._discord_pane(), "discord")
        self.tstack.add_named(self._email_pane(), "email")
        b.append(self.tstack)
        return "channel", b

    def transport(self):
        return "discord" if self.c_transport.get_selected() == 0 else "email"

    def _transport_chosen(self, *_):
        name = self.transport()
        self.tstack.set_visible_child_name(name)
        self.fstack.set_visible_child_name(name)
        self.g_mailpass.set_visible(name == "email")
        self.l_friend_intro.set_label(
            FRIEND_INTRO_EMAIL if name == "email" else FRIEND_INTRO_DISCORD)
        self.check_inert()

    def _discord_pane(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self._channels = []
        g = Adw.PreferencesGroup(
            title="Make a bot",
            description="This is the fiddly bit and you only do it once. "
                        "Each step here opens the right page for you.")

        r1 = Adw.ActionRow(
            title="1.  Make it",
            subtitle="New Application, give it a name, then Bot, then Reset "
                     "Token and copy what it shows you")
        b1 = Gtk.Button(label="Open Discord", valign=Gtk.Align.CENTER)
        b1.connect("clicked", lambda *_: open_url(
            "https://discord.com/developers/applications", self.window))
        r1.add_suffix(b1)
        g.add(r1)

        self.p_token = Adw.PasswordEntryRow(title="2.  Paste the token here")
        self.p_token.connect("changed", lambda *_: self._token_changed())
        g.add(self.p_token)

        self.r_invite = Adw.ActionRow(
            title="3.  Put it in your server",
            subtitle="Paste the token first and this link builds itself")
        self.b_invite = Gtk.Button(label="Open the invite", valign=Gtk.Align.CENTER)
        self.b_invite.set_sensitive(False)
        self.b_invite.connect("clicked", lambda *_: open_url(self._invite_url(), self.window))
        self.r_invite.add_suffix(self.b_invite)
        g.add(self.r_invite)

        self.r_intent = Adw.ActionRow(
            title="4.  Let it read the channel",
            subtitle="On the Bot page, switch on Message Content Intent. "
                     "Without it the bot sees every message as blank")
        self.b_intent = Gtk.Button(label="Open its settings", valign=Gtk.Align.CENTER)
        self.b_intent.set_sensitive(False)
        self.b_intent.connect("clicked", lambda *_: open_url(
            "https://discord.com/developers/applications/%s/bot"
            % self._app_id(), self.window))
        self.r_intent.add_suffix(self.b_intent)
        g.add(self.r_intent)
        box.append(g)

        g2 = Adw.PreferencesGroup(title="5.  Pick the channel")
        self.b_find = Gtk.Button(label="Find channels", valign=Gtk.Align.CENTER)
        self.b_find.add_css_class("flat")
        self.b_find.connect("clicked", self.on_find_channels)
        g2.set_header_suffix(self.b_find)
        self.c_channel = Adw.ComboRow(
            title="Channel",
            model=Gtk.StringList.new(["press Find channels"]))
        self.c_channel.set_sensitive(False)
        g2.add(self.c_channel)
        self.x_manual = Adw.ExpanderRow(
            title="Or paste a channel id",
            subtitle="Developer Mode on, right-click the channel, Copy Channel ID")
        self.e_channel = Adw.EntryRow(title="Channel id")
        self.x_manual.add_row(self.e_channel)
        g2.add(self.x_manual)
        box.append(g2)

        row = Gtk.Box(spacing=10, halign=Gtk.Align.START)
        self.b_dcheck = Gtk.Button(label="Check it all")
        self.b_dcheck.add_css_class("suggested-action")
        self.b_dcheck.connect("clicked", self.on_check_discord)
        row.append(self.b_dcheck)
        box.append(row)
        self.l_dcheck = Gtk.Label(wrap=True, xalign=0, visible=False)
        self.l_dcheck.add_css_class("caption")
        box.append(self.l_dcheck)

        warn = Gtk.Label(
            wrap=True, xalign=0,
            label="Pick a channel they all actually read. Approving happens "
                  "there, where everyone can see it.")
        warn.add_css_class("dim-label")
        warn.add_css_class("caption")
        box.append(warn)
        return box

    # -- the bot's own id, straight out of the token ----------------------

    def _app_id(self):
        return app_id_from_token(self.p_token.get_text())

    def _invite_url(self):
        app = self._app_id()
        return ("https://discord.com/oauth2/authorize?client_id=%s&scope=bot"
                "&permissions=68608" % app) if app else ""

    def _token_changed(self):
        ok = bool(self._app_id())
        self.b_invite.set_sensitive(ok)
        self.b_intent.set_sensitive(ok)
        self.r_invite.set_subtitle(
            "Adds it with permission to see the channel, post, and read what "
            "was said" if ok else
            "Paste the token first and this link builds itself")

    def channel_id(self):
        """Whichever the person actually used: the picker or the box."""
        i = self.c_channel.get_selected()
        if self._channels and 0 <= i < len(self._channels):
            return self._channels[i]["id"]
        return self.e_channel.get_text().strip()

    def on_find_channels(self, *_):
        if not self.p_token.get_text().strip():
            self.window.toast("Paste the bot token first")
            return
        payload = json.dumps({"discord": {"bot_token":
                                          self.p_token.get_text().strip()}})
        self.b_find.set_sensitive(False)
        self.b_find.set_label("Looking\u2026")

        def done(ok, out):
            self.b_find.set_sensitive(True)
            self.b_find.set_label("Find channels")
            res = read_json_output(out) or {
                "error": (out or "").strip() or "nothing came back"}
            chans = res.get("channels") or []
            self._channels = chans
            if not chans:
                self.c_channel.set_sensitive(False)
                self.c_channel.set_model(
                    Gtk.StringList.new(["nothing found"]))
                self.l_dcheck.set_visible(True)
                for c in ("success", "error"):
                    self.l_dcheck.remove_css_class(c)
                self.l_dcheck.add_css_class("error")
                self.l_dcheck.set_label(
                    res.get("error") or "No channels came back."
                    + ("  Use step 3 to put the bot in your server first."
                       if res.get("invite") else ""))
                return
            self.c_channel.set_model(Gtk.StringList.new(
                ["%s  \u2022  #%s" % (c["server"], c["name"]) for c in chans]))
            self.c_channel.set_sensitive(True)
            self.window.toast("Found %d channel(s)" % len(chans))

        run_privileged(["discord-channels", "--answers", "-"],
                       stdin_text=payload, on_done=done, as_root=False)

    def on_check_discord(self, *_):
        if not self.p_token.get_text().strip():
            self.window.toast("Paste the bot token first")
            return
        if not self.channel_id().isdigit():
            self.window.toast("Pick a channel first")
            return
        payload = json.dumps({"discord": self.answers()["discord"]})
        self.b_dcheck.set_sensitive(False)
        self.b_dcheck.set_label("Checking\u2026")
        self.l_dcheck.set_visible(False)

        def done(ok, out):
            self.b_dcheck.set_sensitive(True)
            self.b_dcheck.set_label("Check the connection")
            text = (out or "").strip()
            for c in ("success", "warning", "error"):
                self.l_dcheck.remove_css_class(c)
            # "nothing to read back yet" is not a problem to solve, so do not
            # paint it like one
            self.l_dcheck.add_css_class(
                "warning" if INCONCLUSIVE in text else
                ("success" if ok else "error"))
            self.l_dcheck.set_label(text or "Nothing came back.")
            self.l_dcheck.set_visible(True)

        run_privileged(["check-discord", "--answers", "-"], stdin_text=payload,
                       on_done=done, as_root=False)

    def _email_pane(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        g = Adw.PreferencesGroup(
            title="The approval mailbox",
            description="One account used only for this. It sends your friends "
                        "the alerts and reads their APPROVE replies. Your "
                        "friend types its password, so it must not be an "
                        "account you can get into.")
        self.c_provider = Adw.ComboRow(
            title="Who hosts it",
            model=Gtk.StringList.new([p[0] for p in PROVIDER_CHOICES]))
        self.e_mailbox = Adw.EntryRow(title="Mailbox address")
        self.e_mailbox.connect("changed", self._autofill)
        g.add(self.c_provider)
        g.add(self.e_mailbox)
        b.append(g)

        self.l_howto = Gtk.Label(wrap=True, xalign=0)
        self.l_howto.add_css_class("dim-label")
        b.append(self.l_howto)

        adv = Adw.PreferencesGroup()
        self.x_servers = Adw.ExpanderRow(
            title="Server settings",
            subtitle="Filled in from the provider above")
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
            self.x_servers.add_row(w)
        adv.add(self.x_servers)
        b.append(adv)

        self._filling = True             # this first fill is not a choice
        self._provider_manual = False
        self.c_provider.connect("notify::selected", self._provider_chosen)
        self._provider_chosen()          # start on Gmail, already filled in
        self._filling = False
        return b

    def _apply_provider(self, dom):
        sh, sp, ss, ih, ip_, isec = PROVIDERS[dom]
        self.e_smtp_host.set_text(sh)
        self.s_smtp_port.set_value(sp)
        self.c_smtp_sec.set_selected(["starttls", "ssl", "plain"].index(ss))
        self.e_imap_host.set_text(ih)
        self.s_imap_port.set_value(ip_)
        self.c_imap_sec.set_selected(["ssl", "starttls"].index(isec))

    def _provider_chosen(self, *_):
        _label, dom, howto = PROVIDER_CHOICES[self.c_provider.get_selected()]
        if not self._filling:
            self._provider_manual = True
        self.l_howto.set_label(howto)
        if dom:
            self._apply_provider(dom)
            self.x_servers.set_expanded(False)
        else:
            self.x_servers.set_expanded(True)

    def _autofill(self, entry):
        """Typing a known address picks the provider, unless you picked one."""
        if self._provider_manual:
            return
        dom = entry.get_text().strip().lower().split("@")[-1]
        if dom not in PROVIDERS:
            return
        for i, (_label, pdom, _howto) in enumerate(PROVIDER_CHOICES):
            if pdom and PROVIDERS[pdom] == PROVIDERS[dom]:
                self._filling = True
                self.c_provider.set_selected(i)
                self._filling = False
                return

    def _p_friend(self):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        banner = Adw.Banner(title="Hand the keyboard to your friend now")
        banner.set_revealed(True)
        b.append(banner)
        self.l_friend_intro = Gtk.Label(wrap=True, xalign=0,
                                        label=FRIEND_INTRO_DISCORD)
        self.l_friend_intro.add_css_class("dim")
        b.append(self.l_friend_intro)

        self.g_mailpass = Gtk.Box(orientation=Gtk.Orientation.VERTICAL,
                                  spacing=10)
        gm = Adw.PreferencesGroup(title="The mailbox password")
        self.p_mailpass = Adw.PasswordEntryRow(title="Mailbox app password")
        gm.add(self.p_mailpass)
        self.g_mailpass.append(gm)
        # catch a wrong app password now, while the friend is still here
        check_box = Gtk.Box(spacing=10, halign=Gtk.Align.START)
        self.b_check = Gtk.Button(label="Check the mailbox now")
        self.b_check.connect("clicked", self.on_check_mailbox)
        check_box.append(self.b_check)
        self.g_mailpass.append(check_box)
        self.l_check = Gtk.Label(wrap=True, xalign=0, visible=False)
        self.l_check.add_css_class("caption")
        self.g_mailpass.append(self.l_check)
        b.append(self.g_mailpass)

        g = Adw.PreferencesGroup(title="The partner passphrase")
        self.p_phrase1 = Adw.PasswordEntryRow(title="Partner passphrase")
        self.p_phrase2 = Adw.PasswordEntryRow(title="Partner passphrase again")
        for w in (self.p_phrase1, self.p_phrase2):
            g.add(w)
        self.p_phrase1.connect("changed", lambda *_: self.check_inert())
        b.append(g)

        note = Gtk.Label(
            wrap=True, xalign=0,
            label="No friend next to you today? Leave the passphrase blank "
                  "and set it later \u2014 the app will keep reminding you. "
                  "Everything else still works; you would just be one gate "
                  "short.")
        note.add_css_class("dim-label")
        note.add_css_class("caption")
        b.append(note)

        g2 = Adw.PreferencesGroup(
            title="If the passphrase is ever lost",
            description="Without a way back, a friend who moves away would "
                        "leave this machine locked for good.")
        self.sw_recovery = Adw.SwitchRow(
            title="Unanimous approval can substitute for it",
            subtitle="All approvers saying yes unlocks without the passphrase")
        self.sw_recovery.set_active(True)
        self.sw_recovery.connect("notify::active", lambda *_: self.check_inert())
        g2.add(self.sw_recovery)
        b.append(g2)
        self.l_inert = Gtk.Label(wrap=True, xalign=0, visible=False)
        self.l_inert.add_css_class("warning")
        self.l_inert.add_css_class("caption")
        b.append(self.l_inert)
        return "friend", b

    def check_inert(self):
        """
        Two friends with 'both must agree' makes the passphrase gate pointless:
        the quorum that unlocks is already unanimous, so the recovery rule
        satisfies the passphrase at the same moment. Say so here, where it is
        still one click to fix.
        """
        people = len(self.approvers())
        need = int(self.s_threshold.get_value())
        inert = (self.sw_recovery.get_active() and people and need >= people
                 and bool(self.p_phrase1.get_text()))
        self.l_inert.set_visible(bool(inert))
        if inert:
            self.l_inert.set_label(
                "Heads up: you are asking for %d of %d, which is everyone. "
                "Because unanimous approval can stand in for the passphrase, "
                "your friends approving would satisfy it too - so it would "
                "never really be a third gate. Add another approver, lower "
                "the number needed, or turn the switch above off."
                % (need, people))

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
        if self.page_names[idx] == "friend":
            self.check_inert()
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
        if self.transport() == "discord":
            return [p["id"].strip() for p in self.discord_people
                    if p["id"].strip()]
        return [r.get_text().strip() for r in self.approver_rows
                if r.get_text().strip()]

    def approver_names(self):
        if self.transport() != "discord":
            return {}
        return {p["id"].strip(): p["name"] for p in self.discord_people
                if p["id"].strip() and p["name"]}

    def validate(self, page):
        discord = self.transport() == "discord"
        if page == 1:
            if not self.e_name.get_text().strip():
                return "Put your name in - it goes on every message"
            if not discord and not self._ok_email(self.e_email.get_text()):
                return "That does not look like an email address"
        if page == 2:                      # how they hear about it
            if discord:
                if not self.p_token.get_text().strip():
                    return "Paste the bot token"
                if not self.channel_id().isdigit():
                    return "Pick a channel, or paste its id"
            else:
                if not self._ok_email(self.e_mailbox.get_text()):
                    return "The mailbox address does not look right"
                if not self.e_smtp_host.get_text().strip():
                    return "SMTP host is empty"
                if not self.e_imap_host.get_text().strip():
                    return "IMAP host is empty"
        if page == 3:                      # who they are
            appr = self.approvers()
            if not appr:
                return ("Ask your friends to check in - nobody is an approver yet"
                        if discord else "You need at least one approver")
            for a in appr:
                if discord:
                    if not a.isdigit() or len(a) < 15:
                        return ("%s is not a Discord user id. Turn on "
                                "Developer Mode, right-click the person, "
                                "Copy User ID." % a)
                elif not self._ok_email(a):
                    return "%s does not look like an email address" % a
            if int(self.s_threshold.get_value()) > len(appr):
                return ("You are asking for %d approvals from %d people - it "
                        "could never unlock"
                        % (int(self.s_threshold.get_value()), len(appr)))
        if page == 5:
            if not discord and not self.p_mailpass.get_text():
                return "Your friend needs to enter the mailbox password"
            one, two = self.p_phrase1.get_text(), self.p_phrase2.get_text()
            if one or two:
                if one != two:
                    return "The two passphrases do not match"
                if len(one) < 8:
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
            "approver_names": self.approver_names(),
            "transport": self.transport(),
            "discord": {
                "channel_id": self.channel_id(),
                "bot_token": self.p_token.get_text().strip(),
            },
            "approvals_required": int(self.s_threshold.get_value()),
            "cooloff_hours": float(self.s_cooloff.get_value()),
            "unlock_minutes": int(self.s_window.get_value()),
            "filter": FILTERS[self.c_filter.get_selected()][0],
            "updates": {
                "enabled": bool(self.e_repo.get_text().strip()),
                "repo": self.e_repo.get_text().strip(),
                "branch": self.e_branch.get_text().strip() or "main",
                "check_hours": 24,
                "auto_apply": False,
                "require_unlock": False,
            },
            "require_passphrase": True,
            "passphrase_recovery": bool(self.sw_recovery.get_active()),
            # left out entirely when blank, so the gate simply is not armed
            **({"partner_passphrase": self.p_phrase1.get_text()}
               if self.p_phrase1.get_text() else {}),
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

    def on_check_mailbox(self, *_):
        """Log in to the mailbox with what has been typed. Sends nothing."""
        if not self.p_mailpass.get_text():
            self.window.toast("Your friend needs to type the password first")
            return
        err = self.validate(2)
        if err:
            self.window.toast(err)
            self.show_page(2)
            return
        payload = json.dumps({"email": self.answers()["email"]})
        self.b_check.set_sensitive(False)
        self.b_check.set_label("Checking\u2026")
        self.l_check.set_visible(False)

        def done(ok, out):
            self.b_check.set_sensitive(True)
            self.b_check.set_label("Check the mailbox now")
            for c in ("success", "error"):
                self.l_check.remove_css_class(c)
            self.l_check.add_css_class("success" if ok else "error")
            self.l_check.set_label(
                "This mailbox works. It can send and it can read replies."
                if ok else (out or "").strip() or "The check did not run.")
            self.l_check.set_visible(True)

        # no pkexec: this writes nothing and needs no privilege
        run_privileged(["check-mailbox", "--answers", "-"], stdin_text=payload,
                       on_done=done, as_root=False)

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
                self.install_status.set_icon_name("object-select-symbolic")
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
    state = Gtk.Image.new_from_icon_name("object-select-symbolic")
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
        hero = self.hero = card()
        self.i_mode = Gtk.Image.new_from_icon_name("security-high-symbolic")
        self.i_mode.set_pixel_size(64)
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

        self.g_today = Adw.PreferencesGroup(title="Today")
        report = Gtk.Button(label="Full report", valign=Gtk.Align.CENTER)
        report.add_css_class("flat")
        report.set_tooltip_text("Everything looked up today (asks for your password)")
        report.connect("clicked", lambda *_: self.window.full_report())
        self.g_today.set_header_suffix(report)
        col.append(self.g_today)

        # -- collapsible detail ---------------------------------------
        self.g_detail = Adw.PreferencesGroup()
        self.x_setup = Adw.ExpanderRow(title="The arrangement")
        self.x_setup.add_prefix(Gtk.Image.new_from_icon_name("document-properties-symbolic"))
        self.x_health = Adw.ExpanderRow(title="Enforcement")
        self.x_health.add_prefix(Gtk.Image.new_from_icon_name("channel-secure-symbolic"))
        self.x_update = Adw.ExpanderRow(title="Updates")
        self.x_update.add_prefix(Gtk.Image.new_from_icon_name("folder-download-symbolic"))
        for x in (self.x_setup, self.x_health, self.x_update):
            self.g_detail.add(x)
        col.append(self.g_detail)

        sw.set_child(Adw.Clamp(maximum_size=620, child=col))
        self.append(sw)
        self._kids = {"setup": [], "health": [], "people": [], "update": [],
                      "today": []}

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
        elif self._banner_action == "setphrase":
            self.window.set_passphrase()

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
        for c in ("state-locked", "state-pending", "state-unlocked"):
            self.hero.remove_css_class(c)
        self.hero.add_css_class("state-" + mode.lower())
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
        elif not self.doc.get("passphrase_set"):
            self.banner.set_title("No partner passphrase set \u2014 one gate short")
            self.banner.set_button_label("Set it")
            self._banner_action = "setphrase"
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
                if p_ok and self.doc.get("passphrase_inert"):
                    self.r_pass.set_subtitle("satisfied automatically - every "
                                             "quorum here is unanimous")
                else:
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
            r = Adw.ActionRow(title=person(self.doc, a))
            r.add_prefix(Gtk.Image.new_from_icon_name("avatar-default-symbolic"))
            if pending:
                r.set_subtitle("approved" if done_ else "waiting")
                if done_:
                    img = Gtk.Image.new_from_icon_name("object-select-symbolic")
                    img.add_css_class("success")
                    r.add_suffix(img)
            self._put("people", self.g_people, r)

        # today
        trk = self.doc.get("tracking") or {}
        self._reset("today", self.g_today)
        self.g_today.set_visible(bool(trk.get("enabled")))
        if trk.get("enabled"):
            self.g_today.set_description("What your approvers see tonight.")
            self._put("today", self.g_today,
                      row("Screen time", human_delta(trk.get("screen_seconds", 0)),
                          "preferences-desktop-display-symbolic"))
            hits = int(trk.get("blocked_hits") or 0)
            r = Adw.ActionRow(
                title="Blocked attempts",
                subtitle=("%d request(s) to %d blocked domain(s)"
                          % (hits, trk.get("blocked_unique", 0))) if hits
                else "nothing on the blocklist was asked for")
            img = Gtk.Image.new_from_icon_name(
                "dialog-warning-symbolic" if hits else "object-select-symbolic")
            img.add_css_class("warning" if hits else "success")
            r.add_prefix(img)
            self._put("today", self.g_today, r)
            for name, count in (trk.get("blocked") or [])[:5]:
                self._put("today", self.g_today,
                          row("    " + name, "%d request(s)" % count))
            self._put("today", self.g_today,
                      row("Sites looked up",
                          "%d unique domains" % trk.get("unique_domains", 0),
                          "network-server-symbolic"))
            byp = (trk.get("bypass") or {}).get("dns_bypass_packets")
            if byp:
                self._put("today", self.g_today,
                          row("DNS bypass attempts", "%d packets dropped" % byp,
                              "dialog-warning-symbolic"))
            for name, secs in (trk.get("apps") or [])[:6]:
                self._put("today", self.g_today,
                          row(name, human_delta(secs),
                              "application-x-executable-symbolic"))
            self._put("today", self.g_today,
                      row("Daily report at %02d:00" % int(trk.get("digest_hour", 20)),
                          "Includes every domain looked up, not only blocked ones"
                          if trk.get("dns_log") else
                          "Screen time, apps and blocked attempts",
                          "mail-send-symbolic"))

        # detail: the arrangement
        self._reset("setup", self.x_setup, True)
        for t, v in (
                ("Approvals needed", "%s of %s" % (need, len(self.doc.get("approvers") or []))),
                ("They are reached", "in Discord, channel %s"
                 % (self.doc.get("channel_id") or "?")
                 if self.doc.get("transport") == "discord" else "by email"),
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
                "object-select-symbolic" if h.get("ok") else "dialog-warning-symbolic")
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

        for name, fn in (("fullreport", self.full_report),
                         ("setsource", self.set_update_source),
                         ("setphrase", self.set_passphrase),
                         ("update", self.do_update),
                         ("checkupdate", self.check_update),
                         ("testmail", self.do_test_email),
                         ("activity", self.show_activity),
                         ("about", self.show_about)):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", lambda *_a, f=fn: f())
            self.add_action(act)

        menu = Gio.Menu()
        s1 = Gio.Menu()
        s1.append("Set the partner passphrase", "win.setphrase")
        s1.append("Set the update source", "win.setsource")
        s1.append("Check for updates", "win.checkupdate")
        s1.append("Send a test email", "win.testmail")
        menu.append_section(None, s1)
        s2 = Gio.Menu()
        s2.append("Today's full report", "win.fullreport")
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

    def set_update_source(self):
        doc = read_status() or {}
        upd = doc.get("update") or {}
        if upd.get("repo"):
            self.show_output(
                "Already pinned",
                "Updates already come from:\n\n  %s (%s)\n\n"
                "That is recorded in the immutable install record and cannot "
                "be repointed while the blocker is locked - otherwise it "
                "would be a way to feed this machine any code you liked."
                % (upd["repo"], upd.get("branch", "main")))
            return
        hint = read_source_hint()
        url = Adw.EntryRow(title="Git repository URL")
        url.set_text(hint.get("repo") or "")
        branch = Adw.EntryRow(title="Branch")
        branch.set_text(hint.get("branch") or "main")
        box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        box.add_css_class("boxed-list")
        box.append(url)
        box.append(branch)
        d = Adw.AlertDialog(
            heading="Where should updates come from?",
            body="You can only set this once without an unlock. Whoever "
                 "controls the repository can run code as root on this "
                 "machine - candidates have to pass the project's own "
                 "self-test, and all of your approvers are emailed when one "
                 "is applied.")
        d.set_extra_child(box)
        d.add_response("no", "Not now")
        d.add_response("yes", "Pin it")
        d.set_response_appearance("yes", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("no")
        d.set_close_response("no")

        def resp(_d, r):
            if r != "yes":
                return
            if not url.get_text().strip():
                self.toast("Nothing entered")
                return
            run_privileged(["update-source", url.get_text().strip(),
                            "--branch", branch.get_text().strip() or "main"],
                           on_done=self.after_action)
        d.connect("response", resp)
        d.present(self)

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

    def set_passphrase(self):
        doc = read_status() or {}
        if doc.get("passphrase_set"):
            self.show_output(
                "Already set",
                "A partner passphrase is already stored.\n\n"
                "Changing it is only possible during a granted unlock window - "
                "otherwise you could overwrite your friend's secret whenever "
                "you felt like it.")
            return
        one = Adw.PasswordEntryRow(title="Partner passphrase")
        two = Adw.PasswordEntryRow(title="Type it again")
        box = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        box.add_css_class("boxed-list")
        box.append(one)
        box.append(two)
        d = Adw.AlertDialog(
            heading="Hand the keyboard to your friend",
            body="They choose this and keep it. Once it is set, an unlock "
                 "needs the cool-off, the approvals AND this typed in.\n\n"
                 "It is stored only as a hash, and it can only be changed "
                 "again during a granted unlock window - so this is a "
                 "one-shot.")
        d.set_extra_child(box)
        d.add_response("no", "Later")
        d.add_response("yes", "Set it")
        d.set_response_appearance("yes", Adw.ResponseAppearance.SUGGESTED)
        d.set_default_response("no")
        d.set_close_response("no")

        def resp(_d, r):
            if r != "yes":
                return
            if one.get_text() != two.get_text():
                self.toast("They did not match")
                return
            if len(one.get_text()) < 8:
                self.toast("Use at least 8 characters")
                return
            run_privileged(["passphrase", "--set", "--stdin"],
                           stdin_text=one.get_text() + "\n",
                           on_done=self.after_action)
        d.connect("response", resp)
        d.present(self)

    def do_test_email(self):
        self.toast("Sending test email…")
        run_privileged(["test-email", "--no-roundtrip"], on_done=lambda ok, out:
                       self.show_output("Email test " + ("passed" if ok
                                                         else "failed"), out))

    def full_report(self):
        self.toast("Building today's report\u2026")
        run_privileged(["activity", "--domains"], on_done=lambda ok, out:
                       self.show_output("Today", out,
                                        "This is what your approvers get "
                                        "emailed tonight."))

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
        if doc and doc.get("configured") and not doc.get("armed"):
            if self.current != "arm":
                sp = Adw.StatusPage(
                    title="Set up, but not switched on",
                    description="Your approvers, the mailbox and the secrets "
                                "are saved. Nothing is being blocked yet and "
                                "nothing is being recorded yet.\n\n"
                                "Switching it on starts the blocking, the "
                                "watchdog and the daily report to your "
                                "friends. Switching it back off needs the "
                                "cool-off, their approval and the passphrase.")
                icon = app_icon()
                if icon is not None:
                    sp.set_paintable(icon)
                else:
                    sp.set_icon_name("security-medium-symbolic")
                b = Gtk.Button(label="Activate protection", halign=Gtk.Align.CENTER)
                b.add_css_class("pill")
                b.add_css_class("suggested-action")

                def arm(*_):
                    b.set_sensitive(False)
                    self.toast("Activating\u2026")
                    run_privileged(["install"], on_done=lambda ok, out:
                                   (self.show_output(
                                       "Activation " + ("complete" if ok
                                                        else "failed"), out)
                                    or self.refresh()))
                b.connect("clicked", arm)
                sp.set_child(b)
                self.view.set_content(sp)
                self.current = "arm"
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
