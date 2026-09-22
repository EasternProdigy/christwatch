#!/usr/bin/env python3
"""
pornblock - a self-hosted, accountability-gated content blocker for Linux.

Design honesty (read this before trusting it):
  You are root. Nothing here is cryptographically unremovable. The lock is
  SOCIAL + FRICTION: constant re-application, immutable files, a 24h cool-off,
  friends who must approve by email, and loud alerts to those friends whenever
  anything is tampered with. It is built so that bypassing it is slow, noisy
  and embarrassing -- not impossible.

Everything lives in one file on purpose: fewer moving parts to tamper with,
and the installed copy at /usr/local/bin/pornblock is byte-identical to the
copy in the repo.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import email
import email.header
import email.message
import email.utils
import getpass
import hashlib
import imaplib
import json
import os
import re
import secrets
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

VERSION = "1.0.0"
PROG = "pornblock"

# --------------------------------------------------------------------------
# Paths.  PORNBLOCK_PREFIX relocates every path under a sandbox root and puts
# the program in DRY-RUN mode (no chattr, no systemctl, no nft, no real files
# outside the prefix).  This is what `demo` uses so the full unlock cycle can
# be rehearsed without touching the machine.
# --------------------------------------------------------------------------

PREFIX = os.environ.get("PORNBLOCK_PREFIX", "").rstrip("/")
SANDBOX = bool(PREFIX)


def P(path: str) -> str:
    """Map an absolute system path into the active prefix."""
    if not PREFIX:
        return path
    return os.path.join(PREFIX, path.lstrip("/"))


ETC_DIR = "/etc/pornblock"
CONFIG_PATH = ETC_DIR + "/config.json"
RECORD_PATH = ETC_DIR + "/install-record.json"
NFT_CONF_PATH = ETC_DIR + "/nftables.conf"

STATE_DIR = "/var/lib/pornblock"
STATE_PATH = STATE_DIR + "/state.json"
BLOCKLIST_PATH = STATE_DIR + "/blocklist-porn.hosts"
BACKUP_DIR = STATE_DIR + "/backups"

LOG_PATH = "/var/log/pornblock.log"
BIN_PATH = "/usr/local/bin/pornblock"

HOSTS_PATH = "/etc/hosts"
RESOLV_CONF = "/etc/resolv.conf"
RESOLVED_STUB = "../run/systemd/resolve/stub-resolv.conf"
RESOLVED_DROPIN = "/etc/systemd/resolved.conf.d/90-pornblock.conf"
NM_DROPIN = "/etc/NetworkManager/conf.d/90-pornblock-dns.conf"

FIREFOX_POLICY = "/etc/firefox/policies/policies.json"
CHROMIUM_POLICY = "/etc/chromium/policies/managed/pornblock.json"
CHROME_POLICY = "/etc/opt/chrome/policies/managed/pornblock.json"

UNIT_SERVICE = "/etc/systemd/system/pornblock.service"
UNIT_WD_SERVICE = "/etc/systemd/system/pornblock-watchdog.service"
UNIT_WD_TIMER = "/etc/systemd/system/pornblock-watchdog.timer"

HOSTS_BEGIN = "# >>> PORNBLOCK BEGIN - managed automatically, do not edit >>>"
HOSTS_END = "# <<< PORNBLOCK END <<<"

BLOCKLIST_URL = ("https://raw.githubusercontent.com/StevenBlack/hosts/master/"
                 "alternates/porn-only/hosts")

# --------------------------------------------------------------------------
# Filtering resolvers
# --------------------------------------------------------------------------

FILTERS = {
    "cloudflare_family": {
        "label": "Cloudflare for Families (malware + adult)",
        "ipv4": ["1.1.1.3", "1.0.0.3"],
        "ipv6": ["2606:4700:4700::1113", "2606:4700:4700::1003"],
        "dot_name": "family.cloudflare-dns.com",
        "doh_url": "https://family.cloudflare-dns.com/dns-query",
        "forces_safesearch": False,
    },
    "cleanbrowsing_adult": {
        "label": "CleanBrowsing Adult Filter",
        "ipv4": ["185.228.133.11", "185.228.134.11"],
        "ipv6": ["2a0d:2a00:1::1", "2a0d:2a00:2::1"],
        "dot_name": "adult-filter-dns.cleanbrowsing.org",
        "doh_url": "https://doh.cleanbrowsing.org/doh/adult-filter/",
        "forces_safesearch": True,
    },
}

# Well-known public DoH/DNS endpoints that a non-browser app could use to
# tunnel around the filter.  Blocking 443 to these is cheap and catches the
# lazy cases.  It is NOT a general DoH defence -- see the README.
KNOWN_DOH_IPS4 = [
    "1.1.1.1", "1.0.0.1",            # Cloudflare (unfiltered)
    "8.8.8.8", "8.8.4.4",            # Google
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15",  # AdGuard
    "76.76.2.0", "76.76.10.0",       # ControlD
    "45.90.28.0", "45.90.30.0",      # NextDNS
]
KNOWN_DOH_IPS6 = [
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2620:fe::fe", "2620:fe::9",
]

# SafeSearch / Restricted-mode front ends (resolved live, these are fallbacks).
SAFESEARCH_DEFAULTS = {
    "forcesafesearch.google.com": "216.239.38.120",
    "restrict.youtube.com": "216.239.38.120",
    "strict.bing.com": "204.79.197.220",
}
GOOGLE_TLDS = [
    "com", "co.uk", "ca", "com.au", "de", "fr", "es", "it", "nl", "co.in",
    "com.br", "co.jp", "ru", "pl", "se", "no", "dk", "fi", "ch", "at", "be",
    "ie", "co.nz", "com.mx", "com.tr", "gr", "pt", "cz", "hu", "ro", "com.ar",
]
YOUTUBE_HOSTS = [
    "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
    "youtube.googleapis.com", "www.youtube-nocookie.com",
]
BING_HOSTS = ["www.bing.com", "bing.com"]

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "version": 1,
    "owner_name": "",
    "owner_email": "",
    "approvers": [],
    "approvals_required": 2,
    "cooloff_hours": 24.0,
    "unlock_minutes": 60,
    "request_ttl_hours": 168.0,
    "filter": "cloudflare_family",
    "youtube_restrict": "moderate",   # moderate | strict
    "loop_seconds": 45,
    "imap_poll_seconds": 60,
    "blocklist_url": BLOCKLIST_URL,
    "blocklist_refresh_hours": 24,
    "alert_min_interval_seconds": 900,
    "email": {
        "address": "",
        "display_name": "pornblock",
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_security": "starttls",   # starttls | ssl | plain
        "smtp_user": "",
        "smtp_password": "",
        "imap_host": "",
        "imap_port": 993,
        "imap_security": "ssl",        # ssl | starttls
        "imap_user": "",
        "imap_password": "",
        "imap_mailbox": "INBOX",
    },
    "enforce": {
        "hosts": True,
        "hosts_block_ipv6": False,
        "safesearch_hosts": True,
        "resolved": True,
        "networkmanager_dns": True,
        "nftables": True,
        "block_known_doh_ips": True,
        "firefox_policy": True,
        "chromium_policy": True,
        "block_extensions": False,        # blanket install block: off by default
        "block_extensions_strict": False, # also disable already-installed ones
        "disable_private_browsing": True,
    },
    "chromium_extension_allowlist": [],
    # Targeted blocking. Browsers have no notion of an extension's topic, so
    # there is no "block porn extensions" switch; the only thing you can do
    # is name individual add-on IDs. Proxy/VPN extensions are the ones that
    # would actually defeat this tool - list them here if you want them gone.
    "blocked_extension_ids": {"firefox": [], "chromium": []},
}

DEFAULT_STATE = {
    "mode": "LOCKED",
    "request": None,
    "unlock": None,
    "blocklist": {"fetched_at": 0, "domains": 0, "safesearch_ips": {}},
    "imap": {"uidvalidity": None, "seen_uids": []},
    "outbox": [],
    "alerts": {},
    "enforced_once": False,
    "history": [],
}

# --------------------------------------------------------------------------
# Terminal helpers
# --------------------------------------------------------------------------

_TTY = sys.stdout.isatty()


def c(code: str, text: str) -> str:
    if not _TTY:
        return text
    return "\033[%sm%s\033[0m" % (code, text)


def bold(t): return c("1", t)
def red(t): return c("31;1", t)
def green(t): return c("32;1", t)
def yellow(t): return c("33;1", t)
def blue(t): return c("36;1", t)
def dim(t): return c("2", t)


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

_LOG_MAX = 5 * 1024 * 1024


def log(msg: str, echo: bool = False) -> None:
    line = "%s %s" % (dt.datetime.now().astimezone().isoformat(timespec="seconds"), msg)
    path = P(LOG_PATH)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > _LOG_MAX:
            for i in (3, 2, 1):
                older, newer = "%s.%d" % (path, i + 1), "%s.%d" % (path, i)
                if os.path.exists(newer):
                    os.replace(newer, older)
            os.replace(path, path + ".1")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        os.chmod(path, 0o600)
    except OSError:
        pass
    if echo:
        print(line)


# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------

class Result:
    __slots__ = ("rc", "out", "err")

    def __init__(self, rc, out="", err=""):
        self.rc, self.out, self.err = rc, out, err

    @property
    def ok(self):
        return self.rc == 0


def run(cmd, timeout: int = 90, input_text: str | None = None) -> Result:
    """Run a command, never raise.  Returns Result."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=input_text)
        return Result(p.returncode, p.stdout or "", p.stderr or "")
    except FileNotFoundError:
        return Result(127, "", "not found: %s" % cmd[0])
    except subprocess.TimeoutExpired:
        return Result(124, "", "timeout: %s" % " ".join(cmd))
    except OSError as exc:
        return Result(1, "", str(exc))


def now() -> float:
    return time.time()


def human_delta(seconds: float) -> str:
    seconds = int(max(0, seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append("%dd" % d)
    if h or d:
        parts.append("%dh" % h)
    if m or h or d:
        parts.append("%dm" % m)
    parts.append("%ds" % s)
    return " ".join(parts)


def stamp(epoch: float | None) -> str:
    if not epoch:
        return "-"
    return dt.datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def is_root() -> bool:
    return os.geteuid() == 0


def require_root() -> None:
    if SANDBOX:
        return
    if not is_root():
        print(red("%s needs root." % PROG))
        print("Try:  sudo %s %s" % (PROG, " ".join(sys.argv[1:])))
        sys.exit(1)


def valid_email(addr: str) -> bool:
    return bool(re.fullmatch(r"[^@\s,;]+@[^@\s,;]+\.[A-Za-z]{2,}", (addr or "").strip()))


# --------------------------------------------------------------------------
# Immutability (chattr +i) and managed-file writing
# --------------------------------------------------------------------------

def _lsattr_flags(path: str) -> str:
    r = run(["lsattr", "-d", "--", path], timeout=15)
    if not r.ok or not r.out.strip():
        return ""
    return r.out.strip().split()[0]


def is_immutable(path: str) -> bool:
    if SANDBOX:
        # Nothing is really locked in a sandbox; pretend it is so the
        # idempotency checks converge instead of "fixing" it every tick.
        return os.path.exists(path)
    return "i" in _lsattr_flags(path)


def set_immutable(path: str, on: bool) -> bool:
    """Best-effort chattr.  Returns True when the flag now matches `on`."""
    if SANDBOX or not os.path.exists(path):
        return True
    if is_immutable(path) == on:
        return True
    r = run(["chattr", "+i" if on else "-i", "--", path], timeout=20)
    if not r.ok:
        log("chattr %s %s failed: %s" % ("+i" if on else "-i", path, r.err.strip()))
    return r.ok


@contextlib.contextmanager
def mutable(path: str):
    """Temporarily clear +i, restore it afterwards."""
    had = is_immutable(path)
    if had:
        set_immutable(path, False)
    try:
        yield
    finally:
        if had:
            set_immutable(path, True)


def backup_once(path: str) -> None:
    """Preserve a pre-existing file the first time we take it over."""
    real = P(path)
    if not os.path.exists(real):
        return
    bdir = P(BACKUP_DIR)
    os.makedirs(bdir, exist_ok=True)
    dest = os.path.join(bdir, path.strip("/").replace("/", "_") + ".orig")
    if os.path.exists(dest):
        return
    try:
        shutil.copy2(real, dest)
        os.chmod(dest, 0o600)
        log("backed up pre-existing %s -> %s" % (path, dest))
    except OSError as exc:
        log("backup of %s failed: %s" % (path, exc))


def atomic_write(path: str, content: str, mode: int = 0o644) -> None:
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".pb-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def write_managed(path: str, content: str, mode: int = 0o644,
                  immutable: bool = True, backup: bool = True) -> str:
    """
    Idempotently install `content` at `path` and (re)apply the immutable flag.

    Returns one of: "unchanged", "created", "rewritten", "relocked".
    """
    real = P(path)
    existed = os.path.exists(real)
    if backup and existed:
        backup_once(path)

    current = None
    if existed:
        try:
            with open(real, "r", encoding="utf-8", errors="replace") as fh:
                current = fh.read()
        except OSError:
            current = None

    if current == content:
        if immutable and not is_immutable(real):
            set_immutable(real, True)
            return "relocked"
        return "unchanged"

    set_immutable(real, False)
    atomic_write(real, content, mode)
    if immutable:
        set_immutable(real, True)
    return "rewritten" if existed else "created"


def remove_managed(path: str) -> bool:
    real = P(path)
    if not os.path.exists(real):
        return False
    set_immutable(real, False)
    with contextlib.suppress(OSError):
        os.unlink(real)
        return True
    return False


# --------------------------------------------------------------------------
# JSON documents on disk
# --------------------------------------------------------------------------

def load_json(path: str, default):
    real = P(path)
    try:
        with open(real, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return json.loads(json.dumps(default)) if default is not None else None


def dump_json(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=False) + "\n"


def deep_merge(base: dict, over: dict) -> dict:
    out = json.loads(json.dumps(base))
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict:
    raw = load_json(CONFIG_PATH, None)
    if raw is None:
        return None
    return deep_merge(DEFAULT_CONFIG, raw)


def save_config(cfg: dict) -> None:
    write_managed(CONFIG_PATH, dump_json(cfg), mode=0o600,
                  immutable=False, backup=False)


def load_record() -> dict | None:
    return load_json(RECORD_PATH, None)


def save_record(rec: dict) -> None:
    write_managed(RECORD_PATH, dump_json(rec), mode=0o600,
                  immutable=True, backup=False)


def record_from_config(cfg: dict) -> dict:
    return {
        "owner_email": cfg["owner_email"],
        "approvers": sorted(a.lower() for a in cfg["approvers"]),
        "approvals_required": int(cfg["approvals_required"]),
        "cooloff_hours": float(cfg["cooloff_hours"]),
        "unlock_minutes": int(cfg["unlock_minutes"]),
        "filter": cfg["filter"],
        "recorded_at": now(),
    }


def load_state() -> dict:
    st = deep_merge(DEFAULT_STATE, load_json(STATE_PATH, {}) or {})
    return st


def save_state(st: dict) -> None:
    real = P(STATE_PATH)
    os.makedirs(os.path.dirname(real), exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(os.path.dirname(real), 0o700)
    atomic_write(real, dump_json(st), mode=0o600)


def history(st: dict, event: str) -> None:
    st.setdefault("history", []).append({"at": now(), "event": event})
    st["history"] = st["history"][-200:]
    log(event)


# ==========================================================================
# Email
# ==========================================================================

class MailError(Exception):
    pass


def _addr_of(raw: str) -> str:
    return email.utils.parseaddr(raw or "")[1].strip().lower()


def _decode_header(raw) -> str:
    if raw is None:
        return ""
    try:
        parts = email.header.decode_header(raw)
    except Exception:
        return str(raw)
    out = []
    for chunk, enc in parts:
        if isinstance(chunk, bytes):
            out.append(chunk.decode(enc or "utf-8", "replace"))
        else:
            out.append(chunk)
    return "".join(out)


def _body_text(msg: email.message.Message) -> str:
    chunks = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() not in ("text/plain", "text/html"):
                continue
            try:
                payload = part.get_payload(decode=True) or b""
                chunks.append(payload.decode(part.get_content_charset() or "utf-8",
                                             "replace"))
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True) or b""
            chunks.append(payload.decode(msg.get_content_charset() or "utf-8",
                                         "replace"))
        except Exception:
            pass
    return "\n".join(chunks)


_QUOTE_MARKERS = re.compile(
    r"(^-{2,}\s*Original Message|^On .{0,120}wrote:\s*$|^_{5,}\s*$|^From:\s)",
    re.IGNORECASE | re.MULTILINE)


def strip_quoted(text: str) -> str:
    """
    Keep only what the human actually typed: drop quoted history, because our
    own request email contains the literal string 'APPROVE <token>' and a
    naive match on a quoted reply would approve unlocks nobody agreed to.
    """
    m = _QUOTE_MARKERS.search(text)
    if m:
        text = text[:m.start()]
    kept = [ln for ln in text.splitlines() if not ln.lstrip().startswith(">")]
    return "\n".join(kept)


class Mailer:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.e = cfg["email"]

    # -- outgoing ---------------------------------------------------------

    def _from(self) -> str:
        name = self.e.get("display_name") or PROG
        return email.utils.formataddr((name, self.e["address"]))

    def _build(self, to_list, subject, text, html=None) -> email.message.Message:
        if html:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(text, "plain", "utf-8"))
            msg.attach(MIMEText(html, "html", "utf-8"))
        else:
            msg = MIMEText(text, "plain", "utf-8")
        msg["From"] = self._from()
        msg["To"] = ", ".join(to_list)
        msg["Subject"] = subject
        msg["Date"] = email.utils.formatdate(localtime=True)
        msg["Message-ID"] = email.utils.make_msgid(domain="pornblock.local")
        msg["Reply-To"] = self.e["address"]
        msg["X-Pornblock"] = VERSION
        return msg

    def send_now(self, to_list, subject, text, html=None) -> None:
        """Send synchronously.  Raises MailError on any failure."""
        to_list = [a for a in dict.fromkeys(a.strip() for a in to_list) if a]
        if not to_list:
            raise MailError("no recipients")
        if not self.e.get("smtp_host"):
            raise MailError("SMTP not configured")
        msg = self._build(to_list, subject, text, html)
        host, port = self.e["smtp_host"], int(self.e["smtp_port"])
        sec = (self.e.get("smtp_security") or "starttls").lower()
        ctx = ssl.create_default_context()
        try:
            if sec == "ssl":
                srv = smtplib.SMTP_SSL(host, port, timeout=30, context=ctx)
            else:
                srv = smtplib.SMTP(host, port, timeout=30)
            with srv:
                srv.ehlo()
                if sec == "starttls":
                    srv.starttls(context=ctx)
                    srv.ehlo()
                user = self.e.get("smtp_user") or self.e["address"]
                if self.e.get("smtp_password"):
                    srv.login(user, self.e["smtp_password"])
                srv.sendmail(self.e["address"], to_list, msg.as_string())
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            raise MailError("%s: %s" % (type(exc).__name__, exc)) from exc
        log("email sent to %s :: %s" % (", ".join(to_list), subject))

    def send(self, st: dict, to_list, subject, text, html=None,
             queue_on_fail: bool = True) -> bool:
        """Send, and on failure park it in the outbox for the daemon to retry."""
        try:
            self.send_now(to_list, subject, text, html)
            return True
        except MailError as exc:
            log("email FAILED (%s) :: %s" % (exc, subject))
            if queue_on_fail and st is not None:
                st.setdefault("outbox", []).append({
                    "to": list(to_list), "subject": subject, "text": text,
                    "html": html, "queued_at": now(), "attempts": 0,
                    "last_error": str(exc),
                })
                st["outbox"] = st["outbox"][-100:]
            return False

    def flush_outbox(self, st: dict) -> None:
        box = st.get("outbox") or []
        if not box:
            return
        keep = []
        for item in box:
            if item.get("attempts", 0) >= 20:
                log("dropping undeliverable queued email :: %s" % item.get("subject"))
                continue
            try:
                self.send_now(item["to"], item["subject"], item["text"],
                              item.get("html"))
            except MailError as exc:
                item["attempts"] = item.get("attempts", 0) + 1
                item["last_error"] = str(exc)
                keep.append(item)
        st["outbox"] = keep

    # -- incoming ---------------------------------------------------------

    def _imap_connect(self):
        host = self.e.get("imap_host")
        if not host:
            raise MailError("IMAP not configured")
        port = int(self.e.get("imap_port") or 993)
        sec = (self.e.get("imap_security") or "ssl").lower()
        ctx = ssl.create_default_context()
        try:
            if sec == "ssl":
                conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx, timeout=30)
            else:
                conn = imaplib.IMAP4(host, port, timeout=30)
                conn.starttls(ssl_context=ctx)
            user = self.e.get("imap_user") or self.e["address"]
            conn.login(user, self.e.get("imap_password") or "")
            return conn
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            raise MailError("%s: %s" % (type(exc).__name__, exc)) from exc

    def probe(self) -> str:
        """Log in to IMAP and report the mailbox size.  Raises MailError."""
        conn = self._imap_connect()
        try:
            box = self.e.get("imap_mailbox") or "INBOX"
            typ, data = conn.select(box, readonly=True)
            if typ != "OK":
                raise MailError("cannot select mailbox %r" % box)
            return "%s contains %s message(s)" % (box, (data[0] or b"0").decode())
        finally:
            with contextlib.suppress(Exception):
                conn.logout()

    def scan(self, st: dict, since_epoch: float):
        """
        Return [(from_addr, subject, clean_body, uid)] for messages we have not
        processed yet.  Never raises: a flaky mailbox must not stop enforcement.
        """
        out = []
        try:
            conn = self._imap_connect()
        except MailError as exc:
            log("IMAP connect failed: %s" % exc)
            return out
        try:
            box = self.e.get("imap_mailbox") or "INBOX"
            typ, _ = conn.select(box)
            if typ != "OK":
                log("IMAP select %r failed" % box)
                return out

            typ, data = conn.status(box, "(UIDVALIDITY)")
            uidv = None
            if typ == "OK" and data:
                m = re.search(rb"UIDVALIDITY\s+(\d+)", data[0] or b"")
                if m:
                    uidv = int(m.group(1))
            imap_state = st.setdefault("imap", {"uidvalidity": None, "seen_uids": []})
            if uidv is not None and imap_state.get("uidvalidity") != uidv:
                imap_state["uidvalidity"] = uidv
                imap_state["seen_uids"] = []

            since = dt.datetime.fromtimestamp(max(0, since_epoch - 86400))
            crit = since.strftime("(SINCE %d-%b-%Y)")
            typ, data = conn.uid("SEARCH", None, crit)
            if typ != "OK":
                return out
            uids = (data[0] or b"").split()
            seen = set(imap_state.get("seen_uids") or [])
            fresh = [u.decode() for u in uids if u.decode() not in seen]
            for uid in fresh[-200:]:
                typ, fetched = conn.uid("FETCH", uid, "(RFC822)")
                imap_state.setdefault("seen_uids", []).append(uid)
                if typ != "OK" or not fetched or not isinstance(fetched[0], tuple):
                    continue
                msg = email.message_from_bytes(fetched[0][1])
                sender = _addr_of(msg.get("From"))
                subject = _decode_header(msg.get("Subject"))
                body = strip_quoted(_body_text(msg))
                out.append((sender, subject, body, uid))
            imap_state["seen_uids"] = imap_state["seen_uids"][-1000:]
        except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
            log("IMAP scan error: %s" % exc)
        finally:
            with contextlib.suppress(Exception):
                conn.logout()
        return out


# --------------------------------------------------------------------------
# Alerting helpers
# --------------------------------------------------------------------------

def everyone(cfg: dict) -> list:
    people = list(cfg.get("approvers") or [])
    if cfg.get("owner_email"):
        people.append(cfg["owner_email"])
    return list(dict.fromkeys(a.strip() for a in people if a.strip()))


def alert(cfg: dict, st: dict, key: str, subject: str, text: str,
          html: str | None = None, to=None, force: bool = False) -> bool:
    """
    Loud email to all approvers (+ owner).  `key` rate-limits repeats of the
    same kind of alert so a wedged machine cannot spam your friends into
    muting the thread -- which would defeat the whole point.
    """
    limit = float(cfg.get("alert_min_interval_seconds") or 900)
    last = (st.get("alerts") or {}).get(key, 0)
    if not force and (now() - last) < limit:
        return False
    st.setdefault("alerts", {})[key] = now()
    recipients = to if to is not None else everyone(cfg)
    prefix = "[pornblock DEMO] " if SANDBOX else "[pornblock] "
    return Mailer(cfg).send(st, recipients, prefix + subject, text, html)


# ==========================================================================
# Blocklist
# ==========================================================================

_HOSTS_LINE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([A-Za-z0-9_.-]+)\s*$")


def blocklist_domains() -> list:
    path = P(BLOCKLIST_PATH)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return []
    seen = {}
    for line in raw.splitlines():
        line = line.split("#", 1)[0]
        m = _HOSTS_LINE.match(line)
        if not m:
            continue
        d = m.group(1).lower().rstrip(".")
        if d and d not in ("localhost", "0.0.0.0", "broadcasthost"):
            seen[d] = True
    return list(seen)


def refresh_blocklist(cfg: dict, st: dict, force: bool = False) -> str:
    """Download the porn-only hosts list at most once a day.  Never fatal."""
    meta = st.setdefault("blocklist", {"fetched_at": 0, "domains": 0,
                                       "safesearch_ips": {}})
    age_limit = float(cfg.get("blocklist_refresh_hours") or 24) * 3600
    have = os.path.exists(P(BLOCKLIST_PATH))
    if have and not force and (now() - meta.get("fetched_at", 0)) < age_limit:
        return "cached"

    url = cfg.get("blocklist_url") or BLOCKLIST_URL
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pornblock/" + VERSION})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log("blocklist refresh failed (%s); keeping cached copy" % exc)
        return "offline" if have else "missing"

    if len(data) < 50_000 or "0.0.0.0" not in data:
        log("blocklist download looked wrong (%d bytes); keeping cached copy" % len(data))
        return "suspect" if have else "missing"

    os.makedirs(P(STATE_DIR), exist_ok=True)
    atomic_write(P(BLOCKLIST_PATH), data, 0o644)
    meta["fetched_at"] = now()
    meta["domains"] = len(blocklist_domains())
    log("blocklist refreshed: %d domains" % meta["domains"])
    return "refreshed"


def refresh_safesearch_ips(cfg: dict, st: dict) -> dict:
    """Resolve the SafeSearch front ends; fall back to last-known / builtin."""
    meta = st.setdefault("blocklist", {})
    known = dict(SAFESEARCH_DEFAULTS)
    known["restrictmoderate.youtube.com"] = "216.239.38.119"
    cached = dict(meta.get("safesearch_ips") or {})
    out = {}
    for name, fallback in known.items():
        ip = None
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET)
            if infos:
                ip = infos[0][4][0]
        except (socket.gaierror, OSError):
            ip = None
        out[name] = ip or cached.get(name) or fallback
    meta["safesearch_ips"] = out
    return out


# ==========================================================================
# Enforcement layer 1 -- /etc/hosts
# ==========================================================================

def _safesearch_hosts_lines(cfg: dict, ips: dict) -> list:
    mode = (cfg.get("youtube_restrict") or "moderate").lower()
    yt_name = "restrict.youtube.com" if mode == "strict" else "restrictmoderate.youtube.com"
    g = ips.get("forcesafesearch.google.com", SAFESEARCH_DEFAULTS["forcesafesearch.google.com"])
    y = ips.get(yt_name, "216.239.38.119")
    b = ips.get("strict.bing.com", SAFESEARCH_DEFAULTS["strict.bing.com"])
    lines = ["# --- forced SafeSearch / YouTube Restricted (%s) ---" % mode]
    for tld in GOOGLE_TLDS:
        lines.append("%s google.%s www.google.%s" % (g, tld, tld))
    lines.append("%s %s" % (y, " ".join(YOUTUBE_HOSTS)))
    lines.append("%s %s" % (b, " ".join(BING_HOSTS)))
    lines.append("# --- end SafeSearch ---")
    return lines


def render_hosts_block(cfg: dict, st: dict) -> str:
    domains = blocklist_domains()
    meta = st.get("blocklist") or {}
    fetched = meta.get("fetched_at") or 0
    out = [HOSTS_BEGIN,
           "# source: %s" % (cfg.get("blocklist_url") or BLOCKLIST_URL),
           "# %d domains, list fetched %s" % (len(domains), stamp(fetched)),
           "# Removing this block will be detected within ~%ss and emailed to "
           "your approvers." % int(cfg.get("loop_seconds") or 45)]
    if cfg["enforce"].get("safesearch_hosts", True):
        out += _safesearch_hosts_lines(cfg, meta.get("safesearch_ips") or {})
    v6 = cfg["enforce"].get("hosts_block_ipv6", False)
    for d in sorted(domains):
        out.append("0.0.0.0 " + d)
        if v6:
            out.append(":: " + d)
    out.append(HOSTS_END)
    return "\n".join(out) + "\n"


def _split_hosts(text: str):
    """Return (before, managed_block_or_None, after)."""
    i = text.find(HOSTS_BEGIN)
    if i == -1:
        return text, None, ""
    j = text.find(HOSTS_END, i)
    if j == -1:
        return text[:i], text[i:], ""
    j += len(HOSTS_END)
    tail = text[j:]
    if tail.startswith("\n"):
        tail = tail[1:]
    return text[:i], text[i:j] + "\n", tail


def enforce_hosts(cfg: dict, st: dict, apply: bool) -> list:
    path = P(HOSTS_PATH)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            current = fh.read()
    except FileNotFoundError:
        if not apply:
            return []
        current = ""
    except OSError as exc:
        return ["hosts: unreadable (%s)" % exc]

    before, block, after = _split_hosts(current)
    if apply:
        desired_block = render_hosts_block(cfg, st)
        if not desired_block.count("0.0.0.0 "):
            return ["hosts: skipped, blocklist cache is empty"]
        if before and not before.endswith("\n"):
            before += "\n"
        desired = before + desired_block + after
        if current == desired:
            if not is_immutable(path):
                set_immutable(path, True)
                return ["hosts: re-applied immutable flag"]
            return []
        backup_once(HOSTS_PATH)
        set_immutable(path, False)
        atomic_write(path, desired, 0o644)
        set_immutable(path, True)
        n = desired_block.count("\n0.0.0.0 ") + desired_block.count("\n:: ")
        return ["hosts: wrote managed block (%d block entries)" % n]
    # lifting
    if block is None:
        return []
    desired = before + after
    set_immutable(path, False)
    atomic_write(path, desired, 0o644)
    return ["hosts: managed block removed (unlock window)"]


# ==========================================================================
# Enforcement layer 2 -- systemd-resolved (DNS-over-TLS to the filter)
# ==========================================================================

def resolved_dropin(cfg: dict) -> str:
    f = FILTERS[cfg["filter"]]
    servers = " ".join("%s#%s" % (ip, f["dot_name"])
                       for ip in f["ipv4"] + f["ipv6"])
    return (
        "# Managed by pornblock. Edits are reverted automatically and emailed\n"
        "# to your accountability partners.\n"
        "[Resolve]\n"
        "DNS=%s\n"
        "FallbackDNS=\n"
        "Domains=~.\n"
        "DNSOverTLS=yes\n"
        "DNSSEC=allow-downgrade\n"
        "DNSStubListener=yes\n"
        "Cache=yes\n" % servers)


def nm_dropin(cfg: dict) -> str:
    return (
        "# Managed by pornblock: stop NetworkManager pushing DHCP-supplied\n"
        "# resolvers into systemd-resolved, which would sidestep the filter.\n"
        "[main]\n"
        "dns=systemd-resolved\n"
        "\n"
        "[connection-pornblock-dns]\n"
        "match-device=*\n"
        "ipv4.ignore-auto-dns=true\n"
        "ipv6.ignore-auto-dns=true\n")


def _ensure_resolv_symlink() -> list:
    if SANDBOX:
        return []
    path = P(RESOLV_CONF)
    try:
        if os.path.islink(path) and os.readlink(path).endswith("stub-resolv.conf"):
            return []
    except OSError:
        pass
    if SANDBOX:
        return ["resolv.conf: would re-point at the resolved stub"]
    try:
        with contextlib.suppress(OSError):
            set_immutable(path, False)
        if os.path.exists(path) or os.path.islink(path):
            backup_once(RESOLV_CONF)
            os.unlink(path)
        os.symlink(RESOLVED_STUB, path)
        return ["resolv.conf: re-pointed at the systemd-resolved stub"]
    except OSError as exc:
        return ["resolv.conf: could not fix symlink (%s)" % exc]


def systemctl(*args) -> Result:
    if SANDBOX:
        return Result(0, "sandbox", "")
    return run(["systemctl"] + list(args), timeout=60)


def enforce_resolved(cfg: dict, st: dict, apply: bool) -> list:
    changes = []
    if apply:
        r = write_managed(RESOLVED_DROPIN, resolved_dropin(cfg), 0o644, True)
        if r != "unchanged":
            changes.append("systemd-resolved: drop-in %s" % r)
        if cfg["enforce"].get("networkmanager_dns", True):
            r2 = write_managed(NM_DROPIN, nm_dropin(cfg), 0o644, True)
            if r2 != "unchanged":
                changes.append("NetworkManager: dns drop-in %s" % r2)
                systemctl("reload-or-restart", "NetworkManager")
        changes += _ensure_resolv_symlink()
        if changes:
            systemctl("restart", "systemd-resolved")
    else:
        if remove_managed(RESOLVED_DROPIN):
            changes.append("systemd-resolved: drop-in removed (unlock window)")
        if remove_managed(NM_DROPIN):
            changes.append("NetworkManager: dns drop-in removed (unlock window)")
        if changes:
            systemctl("reload-or-restart", "NetworkManager")
            systemctl("restart", "systemd-resolved")
    return changes


# ==========================================================================
# Enforcement layer 3 -- nftables (our own table only)
# ==========================================================================

def nft_script(cfg: dict) -> str:
    f = FILTERS[cfg["filter"]]
    doh = cfg["enforce"].get("block_known_doh_ips", True)
    L = []
    L.append("#!/usr/sbin/nft -f")
    L.append("# Managed by pornblock. Only the 'pornblock' table is touched;")
    L.append("# firewalld and every other table are left alone.")
    L.append("table inet pornblock")
    L.append("delete table inet pornblock")
    L.append("")
    L.append("table inet pornblock {")
    L.append("\tset filter4 {")
    L.append("\t\ttype ipv4_addr")
    L.append("\t\telements = { %s }" % ", ".join(f["ipv4"]))
    L.append("\t}")
    L.append("\tset filter6 {")
    L.append("\t\ttype ipv6_addr")
    L.append("\t\telements = { %s }" % ", ".join(f["ipv6"]))
    L.append("\t}")
    if doh:
        L.append("\tset doh4 {")
        L.append("\t\ttype ipv4_addr")
        L.append("\t\telements = { %s }" % ", ".join(KNOWN_DOH_IPS4))
        L.append("\t}")
        L.append("\tset doh6 {")
        L.append("\t\ttype ipv6_addr")
        L.append("\t\telements = { %s }" % ", ".join(KNOWN_DOH_IPS6))
        L.append("\t}")
    L.append("\tchain output {")
    L.append("\t\ttype filter hook output priority -10; policy accept;")
    L.append("\t\toifname \"lo\" accept")
    L.append("\t\tip daddr 127.0.0.0/8 accept")
    L.append("\t\tip6 daddr ::1 accept")
    L.append("\t\tip daddr @filter4 udp dport { 53, 853 } accept")
    L.append("\t\tip daddr @filter4 tcp dport { 53, 853 } accept")
    L.append("\t\tip6 daddr @filter6 udp dport { 53, 853 } accept")
    L.append("\t\tip6 daddr @filter6 tcp dport { 53, 853 } accept")
    if doh:
        L.append("\t\tip daddr @doh4 tcp dport 443 reject with tcp reset")
        L.append("\t\tip6 daddr @doh6 tcp dport 443 reject with tcp reset")
        L.append("\t\tip daddr @doh4 udp dport 443 drop")
        L.append("\t\tip6 daddr @doh6 udp dport 443 drop")
    L.append("\t\tudp dport 53 drop")
    L.append("\t\ttcp dport 53 drop")
    L.append("\t\ttcp dport 853 drop")
    L.append("\t\tudp dport 853 drop")
    L.append("\t}")
    L.append("}")
    return "\n".join(L) + "\n"


def nft_expected_rules(cfg: dict) -> int:
    script = nft_script(cfg)
    inside = script.split("chain output {", 1)[1]
    body = inside.split("\n\t}", 1)[0]
    return len([ln for ln in body.splitlines()
                if ln.strip() and not ln.strip().startswith("type filter hook")])


def nft_table_rule_count() -> int | None:
    if SANDBOX:
        return None
    r = run(["nft", "-j", "list", "table", "inet", "pornblock"], timeout=30)
    if not r.ok:
        return None
    try:
        doc = json.loads(r.out)
    except ValueError:
        return None
    return sum(1 for item in doc.get("nftables", []) if "rule" in item)


def enforce_nftables(cfg: dict, st: dict, apply: bool) -> list:
    changes = []
    script = nft_script(cfg)
    if apply:
        r = write_managed(NFT_CONF_PATH, script, 0o644, True)
        if r != "unchanged":
            changes.append("nftables: ruleset file %s" % r)
        if SANDBOX:
            if r != "unchanged":
                changes.append("nftables: would load table inet pornblock")
            return changes
        have = nft_table_rule_count()
        want = nft_expected_rules(cfg)
        if have == want and r == "unchanged":
            return changes
        res = run(["nft", "-f", "-"], timeout=45, input_text=script)
        if res.ok:
            changes.append("nftables: (re)loaded table inet pornblock "
                           "(%s -> %d rules)" % (have, want))
        else:
            changes.append("nftables: load FAILED: %s" % res.err.strip()[:300])
            log("nft load failed: %s" % res.err.strip())
    else:
        if SANDBOX:
            return ["nftables: would delete table inet pornblock"]
        if nft_table_rule_count() is not None:
            res = run(["nft", "delete", "table", "inet", "pornblock"], timeout=30)
            if res.ok:
                changes.append("nftables: table deleted (unlock window)")
        remove_managed(NFT_CONF_PATH)
    return changes


# ==========================================================================
# Enforcement layer 4 -- browser policies
# ==========================================================================

def firefox_policy(cfg: dict) -> str:
    f = FILTERS[cfg["filter"]]
    enf = cfg["enforce"]
    pol = {
        "DNSOverHTTPS": {
            "Enabled": True,
            "ProviderURL": f["doh_url"],
            "Locked": True,
            "Fallback": False,
        },
        "BlockAboutConfig": True,
        "BlockAboutProfiles": True,
        "DisableProfileImport": True,
        "DisableSafeMode": True,
        "DisableSetDesktopBackground": False,
        "DisableTelemetry": False,
        "DisablePrivateBrowsing": bool(enf.get("disable_private_browsing", True)),
        "Preferences": {
            "network.trr.mode": {"Value": 3, "Status": "locked"},
            "network.trr.uri": {"Value": f["doh_url"], "Status": "locked"},
            "network.trr.custom_uri": {"Value": f["doh_url"], "Status": "locked"},
            "browser.privatebrowsing.autostart": {"Value": False, "Status": "locked"},
        },
    }
    if enf.get("block_extensions", False):
        pol["InstallAddonsPermission"] = {"Default": False, "Allow": []}
        if enf.get("block_extensions_strict", False):
            pol["ExtensionSettings"] = {
                "*": {
                    "installation_mode": "blocked",
                    "blocked_install_message":
                        "Add-on installs are managed by pornblock.",
                }
            }
    named = (cfg.get("blocked_extension_ids") or {}).get("firefox") or []
    if named:
        es = pol.setdefault("ExtensionSettings", {})
        for eid in named:
            es[eid] = {"installation_mode": "blocked",
                       "blocked_install_message":
                           "This add-on is blocked by pornblock."}
    return dump_json({"policies": pol})


def chromium_policy(cfg: dict) -> str:
    f = FILTERS[cfg["filter"]]
    enf = cfg["enforce"]
    yt = 2 if (cfg.get("youtube_restrict") or "moderate").lower() == "strict" else 1
    pol = {
        "DnsOverHttpsMode": "secure",
        "DnsOverHttpsTemplates": f["doh_url"],
        "BuiltInDnsClientEnabled": True,
        "ForceGoogleSafeSearch": True,
        "ForceYouTubeRestrict": yt,
        "SafeSitesFilterBehavior": 1,
        "IncognitoModeAvailability": 1 if enf.get("disable_private_browsing", True) else 0,
        "BrowserGuestModeEnabled": False,
        "URLBlocklist": [
            "chrome://flags",
            "chrome://net-internals",
            "chrome://net-export",
            "chrome://extensions-internals",
            "about:flags",
        ],
    }
    if enf.get("block_extensions", False):
        pol["ExtensionInstallBlocklist"] = ["*"]
        allow = list(cfg.get("chromium_extension_allowlist") or [])
        if allow:
            pol["ExtensionInstallAllowlist"] = allow
    else:
        named = (cfg.get("blocked_extension_ids") or {}).get("chromium") or []
        if named:
            pol["ExtensionInstallBlocklist"] = list(named)
    return dump_json(pol)


def enforce_browsers(cfg: dict, st: dict, apply: bool) -> list:
    changes = []
    targets = []
    if cfg["enforce"].get("firefox_policy", True):
        targets.append((FIREFOX_POLICY, firefox_policy(cfg), "Firefox"))
    if cfg["enforce"].get("chromium_policy", True):
        body = chromium_policy(cfg)
        targets.append((CHROMIUM_POLICY, body, "Chromium"))
        targets.append((CHROME_POLICY, body, "Chrome"))
    for path, body, label in targets:
        if apply:
            r = write_managed(path, body, 0o644, True)
            if r != "unchanged":
                changes.append("%s policy: %s" % (label, r))
        else:
            if remove_managed(path):
                changes.append("%s policy: removed (unlock window)" % label)
    return changes


# ==========================================================================
# Orchestration of all enforcement layers
# ==========================================================================

def enforce_all(cfg: dict, st: dict, apply: bool, quiet: bool = False) -> list:
    """Apply (or lift) every enabled layer.  Idempotent: returns [] when the
    machine already looks exactly the way it should."""
    changes = []
    enf = cfg["enforce"]
    try:
        if enf.get("hosts", True):
            changes += enforce_hosts(cfg, st, apply)
        if enf.get("resolved", True):
            changes += enforce_resolved(cfg, st, apply)
        if enf.get("nftables", True):
            changes += enforce_nftables(cfg, st, apply)
        if enf.get("firefox_policy", True) or enf.get("chromium_policy", True):
            changes += enforce_browsers(cfg, st, apply)
    except Exception as exc:                                  # never crash-loop
        log("enforcement error: %r" % exc)
        changes.append("ERROR during enforcement: %r" % exc)

    for ch in changes:
        log("enforce[%s] %s" % ("apply" if apply else "lift", ch))

    if apply and changes and st.get("enforced_once") and not quiet:
        body = ("Something changed the blocking configuration on %s and "
                "pornblock has just put it back.\n\n"
                "What was re-applied:\n%s\n\n"
                "If %s did not tell you they were doing maintenance, this is "
                "worth a conversation.\n"
                % (socket.gethostname(),
                   "\n".join("  - " + x for x in changes),
                   cfg.get("owner_name") or cfg.get("owner_email") or "they"))
        alert(cfg, st, "tamper_enforce", "Blocking was tampered with and restored", body)

    if apply:
        st["enforced_once"] = True
    return changes


# ==========================================================================
# Install record / config drift
# ==========================================================================

def reconcile_record(cfg: dict, st: dict) -> tuple:
    """
    Compare the live config against the immutable install record.

    Weakening changes (different approvers, lower threshold, shorter cool-off,
    longer unlock window) are reverted and emailed to BOTH the recorded and
    the newly-written addresses.  Strengthening changes are accepted and the
    record is re-synced.  While UNLOCKED everything is accepted -- you earned
    the right to reconfigure.
    """
    rec = load_record()
    if not rec:
        return cfg, []

    notes = []
    reverted = False
    new_appr = sorted(a.lower() for a in (cfg.get("approvers") or []))
    old_appr = sorted(a.lower() for a in (rec.get("approvers") or []))

    if st.get("mode") == "UNLOCKED":
        fresh = record_from_config(cfg)
        keys = [k for k in fresh if k != "recorded_at"]
        if {k: fresh[k] for k in keys} != {k: rec.get(k) for k in keys}:
            save_record(fresh)
            notes.append("install record re-synced during unlock window")
        return cfg, notes

    if new_appr != old_appr:
        cfg["approvers"] = list(rec["approvers"])
        reverted = True
        notes.append("approver list was edited (%s -> %s); reverted"
                     % (", ".join(old_appr) or "none", ", ".join(new_appr) or "none"))

    if int(cfg.get("approvals_required", 0)) < int(rec.get("approvals_required", 1)):
        notes.append("approval threshold lowered %s -> %s; reverted"
                     % (rec["approvals_required"], cfg["approvals_required"]))
        cfg["approvals_required"] = int(rec["approvals_required"])
        reverted = True
    elif int(cfg.get("approvals_required", 0)) > int(rec.get("approvals_required", 1)):
        rec["approvals_required"] = int(cfg["approvals_required"])
        notes.append("approval threshold raised to %s; accepted" % cfg["approvals_required"])
        save_record(rec)

    if float(cfg.get("cooloff_hours", 0)) < float(rec.get("cooloff_hours", 24)):
        notes.append("cool-off shortened %sh -> %sh; reverted"
                     % (rec["cooloff_hours"], cfg["cooloff_hours"]))
        cfg["cooloff_hours"] = float(rec["cooloff_hours"])
        reverted = True
    elif float(cfg.get("cooloff_hours", 0)) > float(rec.get("cooloff_hours", 24)):
        rec["cooloff_hours"] = float(cfg["cooloff_hours"])
        notes.append("cool-off lengthened to %sh; accepted" % cfg["cooloff_hours"])
        save_record(rec)

    if int(cfg.get("unlock_minutes", 0)) > int(rec.get("unlock_minutes", 60)):
        notes.append("unlock window lengthened %smin -> %smin; reverted"
                     % (rec["unlock_minutes"], cfg["unlock_minutes"]))
        cfg["unlock_minutes"] = int(rec["unlock_minutes"])
        reverted = True
    elif int(cfg.get("unlock_minutes", 0)) < int(rec.get("unlock_minutes", 60)):
        rec["unlock_minutes"] = int(cfg["unlock_minutes"])
        save_record(rec)

    if cfg.get("filter") not in FILTERS:
        notes.append("unknown filter %r; reverted to %s"
                     % (cfg.get("filter"), rec.get("filter")))
        cfg["filter"] = rec.get("filter", "cloudflare_family")
        reverted = True

    if reverted:
        save_config(cfg)
        recipients = list(dict.fromkeys(old_appr + new_appr +
                                        ([cfg["owner_email"]] if cfg.get("owner_email") else [])))
        body = ("pornblock on %s detected that its accountability settings had "
                "been edited by hand, and has reverted them.\n\n"
                "%s\n\n"
                "Recorded approvers (restored): %s\n"
                "Required approvals: %s\n"
                "Cool-off: %sh    Unlock window: %smin\n\n"
                "You are receiving this because you are either a recorded "
                "approver or an address that was just added to the config.\n"
                % (socket.gethostname(),
                   "\n".join("  - " + n for n in notes),
                   ", ".join(rec.get("approvers") or []),
                   rec.get("approvals_required"),
                   rec.get("cooloff_hours"), rec.get("unlock_minutes")))
        alert(cfg, st, "tamper_config", "Accountability settings were edited and reverted",
              body, to=recipients)
        for n in notes:
            history(st, "config drift: " + n)
    return cfg, notes


# ==========================================================================
# systemd units + self-protection of the binary
# ==========================================================================

def unit_service() -> str:
    return (
        "[Unit]\n"
        "Description=pornblock accountability content blocker\n"
        "Documentation=file:%s\n"
        "After=network-online.target systemd-resolved.service nftables.service\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s daemon\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "TimeoutStopSec=20\n"
        "KillMode=mixed\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n" % (ETC_DIR, BIN_PATH))


def unit_watchdog_service() -> str:
    return (
        "[Unit]\n"
        "Description=pornblock watchdog (re-enables the blocker if it is stopped)\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=%s watchdog\n" % BIN_PATH)


def unit_watchdog_timer() -> str:
    return (
        "[Unit]\n"
        "Description=pornblock watchdog timer\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=30s\n"
        "OnUnitActiveSec=60s\n"
        "AccuracySec=1s\n"
        "Persistent=true\n"
        "Unit=pornblock-watchdog.service\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n")


UNITS = [
    (UNIT_SERVICE, unit_service),
    (UNIT_WD_SERVICE, unit_watchdog_service),
    (UNIT_WD_TIMER, unit_watchdog_timer),
]


def write_units() -> list:
    changes = []
    for path, fn in UNITS:
        r = write_managed(path, fn(), 0o644, True)
        if r != "unchanged":
            changes.append("unit %s %s" % (os.path.basename(path), r))
    if changes:
        systemctl("daemon-reload")
    return changes


SELF_COPY = STATE_DIR + "/pornblock.py.installed"


def protect_binary(cfg: dict, st: dict) -> list:
    """If /usr/local/bin/pornblock is deleted or altered, put it back."""
    src = P(SELF_COPY)
    dst = P(BIN_PATH)
    if not os.path.exists(src):
        return []
    try:
        with open(src, "rb") as fh:
            want = fh.read()
    except OSError:
        return []
    cur = None
    if os.path.exists(dst):
        try:
            with open(dst, "rb") as fh:
                cur = fh.read()
        except OSError:
            cur = None
    if cur == want:
        if not is_immutable(dst):
            set_immutable(dst, True)
            return ["binary: immutable flag re-applied"]
        return []
    set_immutable(dst, False)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst), prefix=".pb-")
    with os.fdopen(fd, "wb") as fh:
        fh.write(want)
    os.chmod(tmp, 0o755)
    os.replace(tmp, dst)
    set_immutable(dst, True)
    return ["binary: %s restored from the protected copy"
            % BIN_PATH if cur is not None else "binary: %s reinstalled" % BIN_PATH]


def guard_units(cfg: dict, st: dict) -> list:
    """Daemon side of the mutual guard: keep the watchdog timer alive."""
    if SANDBOX or st.get("uninstalling"):
        return []
    fixed = []
    fixed += write_units()
    if systemctl("is-enabled", "pornblock-watchdog.timer").out.strip() == "masked":
        systemctl("unmask", "pornblock-watchdog.timer")
        fixed.append("watchdog timer was masked; unmasked")
    if systemctl("is-enabled", "pornblock-watchdog.timer").out.strip() != "enabled":
        systemctl("enable", "pornblock-watchdog.timer")
        fixed.append("watchdog timer was disabled; re-enabled")
    if systemctl("is-active", "pornblock-watchdog.timer").out.strip() != "active":
        systemctl("start", "pornblock-watchdog.timer")
        fixed.append("watchdog timer was not running; started")
    fixed += protect_binary(cfg, st)
    if fixed:
        body = ("pornblock's own watchdog had to be repaired on %s:\n\n%s\n\n"
                "The blocker is running again. Somebody had to be root to do "
                "this.\n" % (socket.gethostname(), "\n".join("  - " + f for f in fixed)))
        alert(cfg, st, "tamper_units", "Watchdog was disabled and has been restored", body)
        for f in fixed:
            history(st, "guard: " + f)
    return fixed


# ==========================================================================
# The unlock state machine
# ==========================================================================

def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def mailto_link(cfg: dict, token: str, verb: str = "APPROVE") -> str:
    payload = "%s %s" % (verb, token)
    return "mailto:%s?subject=%s&body=%s" % (cfg["email"]["address"],
                                             _q(payload), _q(payload))


def who(cfg: dict) -> str:
    return cfg.get("owner_name") or cfg.get("owner_email") or "your friend"


def request_email(cfg: dict, st: dict) -> tuple:
    req = st["request"]
    tok = req["token"]
    host = socket.gethostname()
    need = int(cfg["approvals_required"])
    got = len(req.get("approvals") or {})
    subject = "Unlock requested by %s - code %s" % (who(cfg), tok)
    text = (
        "%s has asked to switch off the porn blocker on %s.\n"
        "\n"
        "They set this up themselves and asked you to be the brake.\n"
        "\n"
        "  Cool-off ends : %s  (in %s)\n"
        "  Approvals      : %d of %d needed\n"
        "  Approvers      : %s\n"
        "\n"
        "NOTHING happens until BOTH the timer runs out AND %d of you approve.\n"
        "If you do nothing, the blocker stays on. Doing nothing is a valid,\n"
        "and often the kind, answer.\n"
        "\n"
        "TO APPROVE  - reply to this message with:   APPROVE %s\n"
        "              or open: %s\n"
        "\n"
        "TO REFUSE   - reply with:                   DENY %s\n"
        "              (a single DENY cancels the whole request)\n"
        "\n"
        "If it is granted, blocking lifts for %d minutes and then switches\n"
        "itself back on. Asking again restarts the %s-hour wait from zero.\n"
        "\n"
        "-- pornblock on %s\n"
        % (who(cfg), host, stamp(req["eligible_at"]),
           human_delta(req["eligible_at"] - now()), got, need,
           ", ".join(cfg["approvers"]), need, tok, mailto_link(cfg, tok), tok,
           int(cfg["unlock_minutes"]), cfg["cooloff_hours"], host))
    html = (
        "<div style='font-family:system-ui,sans-serif;font-size:15px;line-height:1.5'>"
        "<p><b>%s</b> has asked to switch off the porn blocker on <code>%s</code>.</p>"
        "<p>They set this up themselves and asked you to be the brake.</p>"
        "<table cellpadding='4'>"
        "<tr><td>Cool-off ends</td><td><b>%s</b> (in %s)</td></tr>"
        "<tr><td>Approvals</td><td><b>%d of %d</b></td></tr>"
        "<tr><td>Code</td><td><code>%s</code></td></tr>"
        "</table>"
        "<p style='margin:18px 0'>"
        "<a href='%s' style='background:#137333;color:#fff;padding:10px 20px;"
        "border-radius:6px;text-decoration:none;font-weight:600'>APPROVE</a>"
        "&nbsp;&nbsp;"
        "<a href='%s' style='background:#a50e0e;color:#fff;padding:10px 20px;"
        "border-radius:6px;text-decoration:none;font-weight:600'>DENY</a>"
        "</p>"
        "<p>Or just reply with <code>APPROVE %s</code> or <code>DENY %s</code>.</p>"
        "<p><b>Nothing happens until the timer runs out AND %d of you approve.</b> "
        "If you do nothing, the blocker stays on - that is a valid answer.</p>"
        "<p style='color:#666'>If granted, blocking lifts for %d minutes and then "
        "re-arms itself. Asking again restarts the %s-hour wait from zero.</p>"
        "</div>"
        % (who(cfg), host, stamp(req["eligible_at"]),
           human_delta(req["eligible_at"] - now()), got, need, tok,
           mailto_link(cfg, tok), mailto_link(cfg, tok, "DENY"), tok, tok,
           need, int(cfg["unlock_minutes"]), cfg["cooloff_hours"]))
    return subject, text, html


def classify_reply(subject: str, body: str, token: str):
    blob = (subject or "") + "\n" + (body or "")
    tok = re.escape(token)
    if re.search(r"\bDENY\s+%s\b" % tok, blob, re.I):
        return "deny"
    if re.search(r"\bAPPROVE\s+%s\b" % tok, blob, re.I):
        return "approve"
    # Forgiving path: a plain reply that keeps the code in the subject and
    # has the human typing the verb in the un-quoted part of the body.
    if token.lower() in (subject or "").lower():
        if re.search(r"\bDENY\b", body or "", re.I):
            return "deny"
        if re.search(r"\bAPPROVE\b", body or "", re.I):
            return "approve"
    return None


def poll_approvals(cfg: dict, st: dict, mailer: Mailer) -> list:
    req = st.get("request")
    if not req:
        return []
    events = []
    approvers = {a.strip().lower() for a in cfg.get("approvers") or []}
    for sender, subject, body, _uid in mailer.scan(st, req["requested_at"]):
        if sender not in approvers:
            continue
        verdict = classify_reply(subject, body, req["token"])
        if verdict == "deny":
            req.setdefault("denials", {})[sender] = now()
            events.append(("deny", sender))
        elif verdict == "approve" and sender not in (req.get("approvals") or {}):
            req.setdefault("approvals", {})[sender] = now()
            events.append(("approve", sender))
    return events


def to_locked(cfg: dict, st: dict, why_text: str) -> None:
    st["mode"] = "LOCKED"
    st["request"] = None
    st["unlock"] = None
    history(st, "-> LOCKED (%s)" % why_text)


def advance(cfg: dict, st: dict, mailer: Mailer) -> list:
    """Move the state machine forward.  Returns human-readable transitions."""
    moves = []
    mode = st.get("mode", "LOCKED")

    if mode == "PENDING":
        req = st.get("request") or {}
        ttl = float(cfg.get("request_ttl_hours") or 168) * 3600
        events = []
        poll_every = float(cfg.get("imap_poll_seconds") or 60)
        if now() - float(req.get("last_poll") or 0) >= poll_every:
            req["last_poll"] = now()
            events = poll_approvals(cfg, st, mailer)

        for kind, sender in events:
            if kind == "approve":
                history(st, "approval received from %s" % sender)
                got = len(req.get("approvals") or {})
                alert(cfg, st, "approval_%s" % sender,
                      "%s approved the unlock (%d/%s)"
                      % (sender, got, cfg["approvals_required"]),
                      "%s approved %s's unlock request (code %s).\n\n"
                      "That is %d of %s approvals. The cool-off %s.\n"
                      % (sender, who(cfg), req.get("token"), got,
                         cfg["approvals_required"],
                         ("ends " + stamp(req["eligible_at"]))
                         if now() < req["eligible_at"] else "has already ended"),
                      force=True)
            else:
                history(st, "DENIAL received from %s" % sender)
                alert(cfg, st, "denial",
                      "%s refused the unlock - request cancelled" % sender,
                      "%s replied DENY to %s's unlock request (code %s).\n\n"
                      "The request has been cancelled and the blocker stays on.\n"
                      % (sender, who(cfg), req.get("token")), force=True)
                to_locked(cfg, st, "denied by %s" % sender)
                return ["denied by %s - back to LOCKED" % sender]

        if now() - float(req.get("requested_at") or 0) > ttl:
            alert(cfg, st, "expired", "Unlock request expired",
                  "%s's unlock request (code %s) ran out of time without "
                  "enough approvals. The blocker stays on.\n"
                  % (who(cfg), req.get("token")), force=True)
            to_locked(cfg, st, "request expired")
            return ["request expired - back to LOCKED"]

        got = len(req.get("approvals") or {})
        need = int(cfg["approvals_required"])
        timer_done = now() >= float(req.get("eligible_at") or 0)
        if timer_done and got >= need:
            mins = int(cfg["unlock_minutes"])
            st["unlock"] = {"granted_at": now(), "expires_at": now() + mins * 60,
                            "token": req.get("token"),
                            "approved_by": sorted((req.get("approvals") or {}).keys())}
            st["mode"] = "UNLOCKED"
            st["request"] = None
            history(st, "-> UNLOCKED for %d min" % mins)
            alert(cfg, st, "granted", "Unlock GRANTED - %d minutes" % mins,
                  "The cool-off has elapsed and %d of %d approvals are in, so "
                  "blocking on %s is now OFF until %s (%d minutes).\n\n"
                  "Approved by: %s\n\n"
                  "It re-arms itself automatically. Requesting again starts a "
                  "fresh %s-hour wait.\n"
                  % (got, need, socket.gethostname(),
                     stamp(st["unlock"]["expires_at"]), mins,
                     ", ".join(st["unlock"]["approved_by"]), cfg["cooloff_hours"]),
                  force=True)
            moves.append("UNLOCKED for %d minutes" % mins)
        elif timer_done and not req.get("ready_notified"):
            req["ready_notified"] = True
            alert(cfg, st, "cooloff_done", "Cool-off finished - still needs %d approval(s)"
                  % (need - got),
                  "%s's cool-off timer has finished. The blocker will stay on "
                  "until %d more of you approve (code %s).\n\nApprove with: "
                  "APPROVE %s\n%s\n"
                  % (who(cfg), need - got, req.get("token"), req.get("token"),
                     mailto_link(cfg, req.get("token"))), force=True)
            moves.append("cool-off elapsed, waiting on approvals")

    elif mode == "UNLOCKED":
        unl = st.get("unlock") or {}
        if now() >= float(unl.get("expires_at") or 0):
            alert(cfg, st, "relocked", "Unlock window closed - blocking is back on",
                  "The %d-minute unlock window on %s has ended and every "
                  "blocking layer has been re-applied.\n\nNothing to do - this "
                  "is the system working.\n"
                  % (int(cfg["unlock_minutes"]), socket.gethostname()), force=True)
            to_locked(cfg, st, "unlock window expired")
            moves.append("unlock window expired - re-locked")

    return moves


# ==========================================================================
# Health report (for `status`)
# ==========================================================================

def health(cfg: dict, st: dict) -> list:
    rows = []

    def add(name, ok, detail):
        rows.append((name, ok, detail))

    enf = cfg["enforce"]
    if enf.get("hosts", True):
        try:
            with open(P(HOSTS_PATH), encoding="utf-8", errors="replace") as fh:
                txt = fh.read()
            n = txt.count("\n0.0.0.0 ")
            present = HOSTS_BEGIN in txt and HOSTS_END in txt
            add("/etc/hosts blocklist", present,
                "%d entries%s" % (n, ", immutable" if is_immutable(P(HOSTS_PATH))
                                  else ", NOT immutable"))
        except OSError as exc:
            add("/etc/hosts blocklist", False, str(exc))
    if enf.get("resolved", True):
        ok = os.path.exists(P(RESOLVED_DROPIN))
        detail = "drop-in present" if ok else "drop-in MISSING"
        if not SANDBOX:
            r = run(["resolvectl", "status"], timeout=20)
            if r.ok and "DNSOverTLS=yes" in r.out.replace(" ", ""):
                detail += ", DoT active"
            elif r.ok:
                m = re.search(r"Current DNS Server:\s*(\S+)", r.out)
                detail += ", current server %s" % (m.group(1) if m else "?")
        add("systemd-resolved DoT", ok, detail)
    if enf.get("nftables", True):
        cnt = nft_table_rule_count()
        add("nftables DNS lockdown", bool(cnt), "%s rules in table inet pornblock" % cnt)
    if enf.get("firefox_policy", True):
        add("Firefox policy", os.path.exists(P(FIREFOX_POLICY)),
            P(FIREFOX_POLICY))
    if enf.get("chromium_policy", True):
        okc = os.path.exists(P(CHROMIUM_POLICY)) and os.path.exists(P(CHROME_POLICY))
        add("Chromium/Chrome policy", okc, "managed policy files")
    if not SANDBOX:
        act = systemctl("is-active", "pornblock.service").out.strip()
        ena = systemctl("is-enabled", "pornblock.service").out.strip()
        add("daemon", act == "active", "%s / %s" % (act or "?", ena or "?"))
        tact = systemctl("is-active", "pornblock-watchdog.timer").out.strip()
        tena = systemctl("is-enabled", "pornblock-watchdog.timer").out.strip()
        add("watchdog timer", tact == "active", "%s / %s" % (tact or "?", tena or "?"))
    return rows


# ==========================================================================
# Commands
# ==========================================================================

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


def guess_provider(addr: str):
    dom = (addr.split("@")[-1] if "@" in addr else "").lower()
    return PROVIDERS.get(dom)


def validate_config(cfg: dict) -> list:
    errs = []
    if not valid_email(cfg.get("owner_email", "")):
        errs.append("owner_email is not a valid address")
    appr = [a for a in (cfg.get("approvers") or []) if a.strip()]
    if not appr:
        errs.append("you need at least one approver")
    for a in appr:
        if not valid_email(a):
            errs.append("approver %r is not a valid address" % a)
    n = int(cfg.get("approvals_required") or 0)
    if n < 1:
        errs.append("approvals_required must be at least 1")
    if n > len(appr):
        errs.append("approvals_required (%d) is higher than the number of "
                    "approvers (%d) - it could never unlock" % (n, len(appr)))
    if float(cfg.get("cooloff_hours") or 0) <= 0:
        errs.append("cooloff_hours must be > 0")
    if int(cfg.get("unlock_minutes") or 0) <= 0:
        errs.append("unlock_minutes must be > 0")
    if cfg.get("filter") not in FILTERS:
        errs.append("filter must be one of: %s" % ", ".join(FILTERS))
    e = cfg.get("email") or {}
    for k in ("address", "smtp_host", "imap_host"):
        if not e.get(k):
            errs.append("email.%s is required" % k)
    if e.get("address") and not valid_email(e["address"]):
        errs.append("email.address is not a valid address")
    return errs


def _ask(prompt, default=None, secret=False, cast=str):
    while True:
        suffix = " [%s]" % default if default not in (None, "") else ""
        try:
            raw = (getpass.getpass("%s%s: " % (prompt, suffix)) if secret
                   else input("%s%s: " % (prompt, suffix)))
        except EOFError:
            raw = ""
        raw = raw.strip()
        if not raw and default is not None:
            return default
        if not raw:
            print(red("  required"))
            continue
        try:
            return cast(raw)
        except (TypeError, ValueError):
            print(red("  could not read that, try again"))


def cmd_setup(args) -> int:
    require_root()
    existing = load_config() or {}
    cfg = deep_merge(DEFAULT_CONFIG, existing)

    if args.answers:
        with open(args.answers, encoding="utf-8") as fh:
            cfg = deep_merge(cfg, json.load(fh))
    else:
        print(bold("\n  pornblock setup\n  " + "-" * 60))
        print("  This asks for your details, your friends' emails, and a\n"
              "  dedicated mailbox the tool can send from and read replies in.\n"
              "  Use an app password, never your real one.\n")
        cfg["owner_name"] = _ask("Your name", cfg.get("owner_name") or "")
        cfg["owner_email"] = _ask("Your email", cfg.get("owner_email") or None)

        print(bold("\n  Approvers - the friends who can let you out"))
        cur = ", ".join(cfg.get("approvers") or [])
        raw = _ask("Approver emails (comma separated)", cur or None)
        cfg["approvers"] = [x.strip() for x in raw.split(",") if x.strip()]
        default_thr = min(2, len(cfg["approvers"])) or 1
        cfg["approvals_required"] = _ask(
            "How many of them must approve", default_thr, cast=int)

        print(bold("\n  Friction"))
        cfg["cooloff_hours"] = _ask("Cool-off before an unlock can be granted (hours)",
                                    cfg.get("cooloff_hours", 24.0), cast=float)
        cfg["unlock_minutes"] = _ask("How long blocking stays off once granted (minutes)",
                                     cfg.get("unlock_minutes", 60), cast=int)

        print(bold("\n  Filtering resolver"))
        keys = list(FILTERS)
        for i, k in enumerate(keys, 1):
            print("   %d) %s  (%s)" % (i, FILTERS[k]["label"], k))
        pick = _ask("Choose", 1 if cfg.get("filter") == keys[0] else 2, cast=int)
        cfg["filter"] = keys[max(1, min(len(keys), pick)) - 1]

        print(bold("\n  Dedicated mailbox"))
        cfg["email"]["address"] = _ask("Mailbox address (sends alerts, receives APPROVE)",
                                       cfg["email"].get("address") or None)
        g = guess_provider(cfg["email"]["address"])
        if g:
            print(dim("  recognised provider - defaults filled in"))
        sh, sp, ss, ih, ip_, isec = g or ("", 587, "starttls", "", 993, "ssl")
        cfg["email"]["smtp_host"] = _ask("SMTP host", cfg["email"].get("smtp_host") or sh or None)
        cfg["email"]["smtp_port"] = _ask("SMTP port", cfg["email"].get("smtp_port") or sp, cast=int)
        cfg["email"]["smtp_security"] = _ask("SMTP security (starttls/ssl/plain)",
                                             cfg["email"].get("smtp_security") or ss)
        cfg["email"]["smtp_user"] = _ask("SMTP username", cfg["email"].get("smtp_user")
                                         or cfg["email"]["address"])
        cfg["email"]["smtp_password"] = _ask("SMTP app password", secret=True)
        cfg["email"]["imap_host"] = _ask("IMAP host", cfg["email"].get("imap_host") or ih or None)
        cfg["email"]["imap_port"] = _ask("IMAP port", cfg["email"].get("imap_port") or ip_, cast=int)
        cfg["email"]["imap_security"] = _ask("IMAP security (ssl/starttls)",
                                             cfg["email"].get("imap_security") or isec)
        cfg["email"]["imap_user"] = _ask("IMAP username", cfg["email"].get("imap_user")
                                         or cfg["email"]["address"])
        same = _ask("IMAP password same as SMTP? (y/n)", "y").lower().startswith("y")
        cfg["email"]["imap_password"] = (cfg["email"]["smtp_password"] if same
                                         else _ask("IMAP app password", secret=True))

    errs = validate_config(cfg)
    if errs:
        print(red("\n  Configuration problems:"))
        for e in errs:
            print("   - " + e)
        return 1

    os.makedirs(P(ETC_DIR), exist_ok=True)
    os.chmod(P(ETC_DIR), 0o700)
    os.makedirs(P(STATE_DIR), exist_ok=True)
    os.chmod(P(STATE_DIR), 0o700)
    save_config(cfg)
    log("setup written by %s" % (os.environ.get("SUDO_USER") or "root"))

    print(green("\n  Saved %s (0600)" % P(CONFIG_PATH)))
    print("""
  %s
    approvers        : %s
    approvals needed : %d
    cool-off         : %s hours
    unlock window    : %s minutes
    resolver         : %s

  Next:
    1. %s test-email      <- prove email works BEFORE you rely on it
    2. %s install         <- write units, enable, lock it down
""" % (bold("Summary"), ", ".join(cfg["approvers"]), cfg["approvals_required"],
       cfg["cooloff_hours"], cfg["unlock_minutes"], FILTERS[cfg["filter"]]["label"],
       PROG, PROG))
    return 0


def cmd_test_email(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("No config. Run: %s setup" % PROG))
        return 1
    st = load_state()
    ok = True

    print(bold("\n  1. Sending alert mail via SMTP"))
    recipients = everyone(cfg) if not args.no_approvers else [cfg["owner_email"]]
    marker = secrets.token_hex(4).upper()
    text = (
        "This is a test from pornblock on %s.\n\n"
        "%s has asked you to be an accountability partner. From now on you "
        "will get an email when they ask to unlock the blocker, when anyone "
        "tampers with it, and when it re-locks.\n\n"
        "You do not need to do anything right now. When a real request "
        "arrives it will contain a code and an APPROVE link.\n\n"
        "Test marker: %s\n" % (socket.gethostname(), who(cfg), marker))
    try:
        Mailer(cfg).send_now(recipients, "[pornblock] test - you are an approver", text)
        print(green("     sent to: %s" % ", ".join(recipients)))
    except MailError as exc:
        print(red("     SMTP FAILED: %s" % exc))
        ok = False

    print(bold("\n  2. Logging in to IMAP"))
    try:
        print(green("     " + Mailer(cfg).probe()))
    except MailError as exc:
        print(red("     IMAP FAILED: %s" % exc))
        ok = False

    if ok and not args.no_roundtrip:
        print(bold("\n  3. Round trip: mailbox -> itself -> IMAP read back"))
        rt = "RT" + secrets.token_hex(3).upper()
        try:
            Mailer(cfg).send_now([cfg["email"]["address"]],
                                 "[pornblock] roundtrip %s" % rt,
                                 "APPROVE-STYLE ROUNDTRIP %s\n" % rt)
        except MailError as exc:
            print(red("     could not send round-trip mail: %s" % exc))
            return 1
        deadline = now() + args.wait
        found = False
        scratch = {"imap": {"uidvalidity": None, "seen_uids": []}}
        while now() < deadline and not found:
            time.sleep(6)
            for _s, subj, body, _u in Mailer(cfg).scan(scratch, now() - 600):
                if rt in (subj or "") or rt in (body or ""):
                    found = True
                    break
            left = int(deadline - now())
            print(dim("     waiting for delivery... %ds left" % max(0, left)))
        if found:
            print(green("     round trip OK - approvals sent to %s will be seen"
                        % cfg["email"]["address"]))
        else:
            print(yellow("     round-trip message did not arrive within %ds."
                         % args.wait))
            print(yellow("     Check the mailbox by hand; some providers delay "
                         "self-addressed mail."))
            ok = False

    save_state(st)
    print(green("\n  Email looks good.\n") if ok
          else red("\n  Email is NOT reliable yet - fix it before installing.\n"))
    return 0 if ok else 1


def cmd_request(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("No config. Run: %s setup" % PROG))
        return 1
    st = load_state()
    cfg, _ = reconcile_record(cfg, st)

    if st["mode"] == "UNLOCKED":
        print(yellow("Already unlocked until %s." % stamp(st["unlock"]["expires_at"])))
        return 0
    if st["mode"] == "PENDING":
        req = st["request"]
        print(yellow("A request is already open (code %s)." % req["token"]))
        print("Cool-off ends %s. Use '%s status' or '%s cancel'."
              % (stamp(req["eligible_at"]), PROG, PROG))
        return 0

    print(bold("\n  You are about to ask %d of your friends to let you turn "
               "off blocking." % int(cfg["approvals_required"])))
    print("  They will all get an email with your name on it, right now.")
    print("  Nothing unlocks for at least %s hours even if they all say yes.\n"
          % cfg["cooloff_hours"])
    if not args.yes:
        try:
            if input("  Type YES to send the request: ").strip() != "YES":
                print(green("\n  Nothing sent. Good call.\n"))
                return 0
        except EOFError:
            print(red("  no confirmation given"))
            return 1

    token = secrets.token_hex(4).upper()
    st["request"] = {
        "token": token,
        "requested_at": now(),
        "eligible_at": now() + float(cfg["cooloff_hours"]) * 3600.0,
        "approvals": {}, "denials": {}, "ready_notified": False, "last_poll": 0,
        "reason": args.reason or "",
    }
    st["mode"] = "PENDING"
    history(st, "unlock requested, code %s, eligible %s"
            % (token, stamp(st["request"]["eligible_at"])))
    subj, text, html = request_email(cfg, st)
    if args.reason:
        text = text.replace("\n\n  Cool-off", "\n\nTheir stated reason: %s\n\n  Cool-off"
                            % args.reason)
    sent = alert(cfg, st, "request", subj, text, html, force=True)
    save_state(st)

    print(green("\n  Request sent.") if sent
          else yellow("\n  Request recorded, but the email could not go out yet "
                      "(queued for retry)."))
    print("""
    code            : %s
    cool-off ends   : %s
    approvals needed: %d of %d

  Your friends can approve by replying   APPROVE %s
  You can back out at any time with      %s cancel
""" % (token, stamp(st["request"]["eligible_at"]), int(cfg["approvals_required"]),
       len(cfg["approvers"]), token, PROG))
    return 0


def cmd_cancel(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        return 1
    st = load_state()
    mode = st["mode"]
    if mode == "LOCKED":
        print(green("\n  Nothing to cancel - you are locked and that is a fine "
                    "place to be.\n"))
        return 0
    tok = (st.get("request") or {}).get("token") or (st.get("unlock") or {}).get("token")
    to_locked(cfg, st, "cancelled by owner")
    alert(cfg, st, "cancelled", "%s cancelled their unlock request" % who(cfg),
          "%s cancelled the unlock request (code %s) on %s and went straight "
          "back to LOCKED.\n\nThis is the good outcome. If you want to say "
          "something encouraging, now is the moment.\n"
          % (who(cfg), tok, socket.gethostname()), force=True)
    save_state(st)
    print(green("""
  Cancelled. Back to LOCKED.

  That was the hard part and you just did it. Your friends have been told
  you backed out on your own - which is a much better email for them to get
  than the other one.
"""))
    return 0


def cmd_status(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("Not configured. Run: sudo %s setup" % PROG))
        return 1
    st = load_state()
    cfg, notes = reconcile_record(cfg, st)
    mode = st["mode"]
    colour = {"LOCKED": green, "PENDING": yellow, "UNLOCKED": red}[mode]

    print("")
    print(bold("  pornblock %s" % VERSION) + dim("   host %s%s"
          % (socket.gethostname(), "   [SANDBOX %s]" % PREFIX if SANDBOX else "")))
    print("  " + "=" * 68)
    print("  mode               : %s" % colour(mode))
    if mode == "LOCKED":
        print("  " + dim("blocking is on; nothing pending"))
    print("  approvers          : %s" % ", ".join(cfg["approvers"]))
    print("  approvals required : %d of %d" % (int(cfg["approvals_required"]),
                                               len(cfg["approvers"])))
    print("  cool-off           : %s hours" % cfg["cooloff_hours"])
    print("  unlock window      : %s minutes" % cfg["unlock_minutes"])
    print("  resolver           : %s" % FILTERS[cfg["filter"]]["label"])

    if mode == "PENDING":
        req = st["request"]
        got = req.get("approvals") or {}
        need = int(cfg["approvals_required"])
        left = float(req["eligible_at"]) - now()
        print("  " + "-" * 68)
        print("  request code       : %s" % bold(req["token"]))
        print("  requested          : %s" % stamp(req["requested_at"]))
        print("  cool-off ends      : %s" % stamp(req["eligible_at"]))
        print("  time still to wait : %s" % (green("elapsed - timer is done")
                                             if left <= 0 else yellow(human_delta(left))))
        print("  approvals received : %s" % ("%d of %d" % (len(got), need)))
        for a in cfg["approvers"]:
            key = a.strip().lower()
            mark = green("  approved  ") if key in got else dim("  waiting   ")
            when = stamp(got[key]) if key in got else ""
            print("      %s %-34s %s" % (mark, a, dim(when)))
        blockers = []
        if left > 0:
            blockers.append("the %s timer" % human_delta(left))
        if len(got) < need:
            blockers.append("%d more approval(s)" % (need - len(got)))
        print("  still waiting on   : %s" % (yellow(" and ".join(blockers))
                                             if blockers else green("nothing - unlocking")))
    elif mode == "UNLOCKED":
        unl = st["unlock"]
        print("  " + "-" * 68)
        print("  " + red("BLOCKING IS OFF"))
        print("  granted            : %s" % stamp(unl["granted_at"]))
        print("  re-locks at        : %s" % stamp(unl["expires_at"]))
        print("  window remaining   : %s" % red(human_delta(unl["expires_at"] - now())))
        print("  approved by        : %s" % ", ".join(unl.get("approved_by") or []))

    print("  " + "-" * 68)
    print("  enforcement")
    want_on = mode != "UNLOCKED"
    for name, ok, detail in health(cfg, st):
        if not want_on and name not in ("daemon", "watchdog timer"):
            flag = dim("[off] ")
        else:
            flag = green("[ ok ]") if ok else red("[FAIL]")
        print("      %s %-26s %s" % (flag, name, dim(detail)))
    bl = st.get("blocklist") or {}
    print("  blocklist          : %s domains, refreshed %s"
          % (bl.get("domains", 0), stamp(bl.get("fetched_at"))))
    if st.get("outbox"):
        print("  " + yellow("queued emails      : %d waiting to send" % len(st["outbox"])))
    for n in notes:
        print("  " + red("drift: " + n))
    if st.get("history"):
        print("  " + "-" * 68)
        print("  recent")
        for h in st["history"][-5:]:
            print("      %s  %s" % (dim(stamp(h["at"])), h["event"]))
    print("")
    save_state(st)
    return 0


def cmd_install(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("No config. Run: sudo %s setup" % PROG))
        return 1
    errs = validate_config(cfg)
    if errs:
        print(red("Config is not usable:"))
        for e in errs:
            print("  - " + e)
        return 1

    for d, mode in ((ETC_DIR, 0o700), (STATE_DIR, 0o700), (BACKUP_DIR, 0o700)):
        os.makedirs(P(d), exist_ok=True)
        os.chmod(P(d), mode)

    st = load_state()

    # A reinstall must not be a way to quietly reset the contract.
    rec = load_record()
    if rec and st.get("mode") != "UNLOCKED":
        cfg, notes = reconcile_record(cfg, st)
        for n in notes:
            print(yellow("  install record wins: " + n))
    save_config(cfg)

    src = os.path.abspath(__file__)
    with open(src, "r", encoding="utf-8") as fh:
        source = fh.read()
    write_managed(SELF_COPY, source, 0o600, True, backup=False)
    write_managed(BIN_PATH, source, 0o755, True, backup=False)
    print(green("  installed %s" % P(BIN_PATH)))

    for ch in write_units():
        print(green("  " + ch))
    systemctl("daemon-reload")

    save_record(record_from_config(cfg))
    print(green("  install record written and made immutable"))

    print("  fetching blocklist...")
    res = refresh_blocklist(cfg, st, force=args.refresh)
    refresh_safesearch_ips(cfg, st)
    print("  blocklist: %s (%d domains)" % (res, len(blocklist_domains())))

    apply = st.get("mode") != "UNLOCKED"
    for ch in enforce_all(cfg, st, apply, quiet=True):
        print("  " + ch)

    systemctl("enable", "--now", "pornblock-watchdog.timer")
    systemctl("enable", "--now", "pornblock.service")
    save_state(st)

    print(green("\n  Installed and enabled.\n"))
    print("  Check it with:   sudo %s status" % PROG)
    print("  Ask to unlock:   sudo %s request-unlock" % PROG)
    print(dim("\n  Restart your browser once so the new policies load.\n"))
    return 0


def cmd_uninstall(args) -> int:
    require_root()
    cfg = load_config()
    st = load_state()
    unl = st.get("unlock") or {}
    granted = (st.get("mode") == "UNLOCKED" and now() < float(unl.get("expires_at") or 0))

    if not granted:
        print(red("""
  REFUSED.

  Uninstall is only possible during a granted unlock window. That is the
  whole point: you agreed to let your friends hold this door.

  Do it the honest way:
      sudo %s request-unlock
  wait out the cool-off, get your approvals, then run uninstall inside the
  unlock window.
""" % PROG))
        if cfg:
            alert(cfg, st, "uninstall_refused",
                  "%s tried to uninstall the blocker" % who(cfg),
                  "Someone ran '%s uninstall' on %s while it was %s.\n\n"
                  "It was refused. No unlock had been granted.\n"
                  % (PROG, socket.gethostname(), st.get("mode")))
            save_state(st)
        return 1

    if not args.yes:
        try:
            if input("  Type REMOVE to uninstall pornblock: ").strip() != "REMOVE":
                print(green("  Aborted. Still protected."))
                return 0
        except EOFError:
            return 1

    if cfg:
        alert(cfg, st, "uninstalled", "%s uninstalled the blocker" % who(cfg),
              "%s removed pornblock from %s during an approved unlock window.\n\n"
              "Everything it was enforcing is now off. If that was not the plan, "
              "this is the moment to check in with them.\n"
              % (who(cfg), socket.gethostname()), force=True)

    st["uninstalling"] = True
    save_state(st)

    if cfg:
        enforce_all(cfg, st, apply=False, quiet=True)

    systemctl("disable", "--now", "pornblock-watchdog.timer")
    systemctl("disable", "--now", "pornblock.service")
    for path, _fn in UNITS:
        remove_managed(path)
    systemctl("daemon-reload")

    for path in (RESOLVED_DROPIN, NM_DROPIN, FIREFOX_POLICY, CHROMIUM_POLICY,
                 CHROME_POLICY, NFT_CONF_PATH, RECORD_PATH, CONFIG_PATH,
                 SELF_COPY, BIN_PATH):
        remove_managed(path)

    bdir = P(BACKUP_DIR)
    if os.path.isdir(bdir):
        for name in os.listdir(bdir):
            if not name.endswith(".orig"):
                continue
            target = "/" + name[:-len(".orig")].replace("_", "/")
            if target in (HOSTS_PATH, RESOLV_CONF):
                continue
            with contextlib.suppress(OSError):
                set_immutable(P(target), False)
                shutil.copy2(os.path.join(bdir, name), P(target))
                print("  restored %s from backup" % target)

    set_immutable(P(HOSTS_PATH), False)
    for d in (STATE_DIR, ETC_DIR):
        with contextlib.suppress(OSError):
            shutil.rmtree(P(d))
    print(green("\n  Uninstalled. Your approvers were emailed.\n"))
    return 0


def tick(cfg_override=None) -> dict:
    cfg = cfg_override or load_config()
    if not cfg:
        log("daemon tick: no config at %s" % P(CONFIG_PATH))
        return {}
    st = load_state()
    cfg, notes = reconcile_record(cfg, st)
    mailer = Mailer(cfg)
    mailer.flush_outbox(st)

    bl = refresh_blocklist(cfg, st)
    if bl == "refreshed" or not (st.get("blocklist") or {}).get("safesearch_ips"):
        refresh_safesearch_ips(cfg, st)

    moves = advance(cfg, st, mailer)
    apply = st.get("mode") != "UNLOCKED"
    quiet = bool(moves) or bool(notes) or bl == "refreshed" or not st.get("enforced_once")
    changes = enforce_all(cfg, st, apply, quiet=quiet)
    guard_units(cfg, st)
    mailer.flush_outbox(st)
    save_state(st)
    return {"moves": moves, "changes": changes, "blocklist": bl, "mode": st["mode"]}


def cmd_daemon(args) -> int:
    require_root()
    log("daemon starting v%s%s" % (VERSION, " [SANDBOX %s]" % PREFIX if SANDBOX else ""),
        echo=True)
    while True:
        started = now()
        try:
            out = tick()
            if args.once and out:
                for m in out.get("moves") or []:
                    print("  transition: " + m)
                for ch in out.get("changes") or []:
                    print("  " + ch)
                print("  mode=%s blocklist=%s" % (out.get("mode"), out.get("blocklist")))
        except Exception as exc:                              # never crash-loop
            log("daemon tick failed: %r" % exc)
        if args.once:
            return 0
        cfg = load_config() or DEFAULT_CONFIG
        nap = max(5.0, float(cfg.get("loop_seconds") or 45) - (now() - started))
        time.sleep(nap)


def cmd_watchdog(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        return 0
    st = load_state()
    if st.get("uninstalling"):
        return 0
    fixed = []
    if not SANDBOX:
        for path, fn in UNITS:
            if not os.path.exists(P(path)):
                write_managed(path, fn(), 0o644, True)
                fixed.append("unit file %s was deleted; rewritten" % os.path.basename(path))
        if fixed:
            systemctl("daemon-reload")
        state_en = systemctl("is-enabled", "pornblock.service").out.strip()
        if state_en == "masked":
            systemctl("unmask", "pornblock.service")
            fixed.append("service was masked; unmasked")
            state_en = ""
        if state_en != "enabled":
            systemctl("enable", "pornblock.service")
            fixed.append("service was disabled; re-enabled")
        if systemctl("is-active", "pornblock.service").out.strip() != "active":
            systemctl("restart", "pornblock.service")
            fixed.append("service was not running; restarted")
        fixed += protect_binary(cfg, st)

    if fixed:
        for f in fixed:
            history(st, "watchdog: " + f)
        body = ("The pornblock watchdog on %s found the blocker switched off "
                "and turned it back on.\n\n%s\n\n"
                "Only root can do this, so it was almost certainly %s. Worth "
                "asking about.\n"
                % (socket.gethostname(), "\n".join("  - " + f for f in fixed), who(cfg)))
        alert(cfg, st, "watchdog", "Blocker was stopped - watchdog restarted it", body)
        save_state(st)
        print("\n".join(fixed))
    return 0


def cmd_enforce(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        return 1
    st = load_state()
    cfg, _ = reconcile_record(cfg, st)
    if args.refresh:
        print("blocklist: %s" % refresh_blocklist(cfg, st, force=True))
        refresh_safesearch_ips(cfg, st)
    apply = st.get("mode") != "UNLOCKED"
    changes = enforce_all(cfg, st, apply, quiet=args.quiet)
    save_state(st)
    print("\n".join("  " + c for c in changes) if changes
          else green("  already exactly as it should be (no changes)"))
    return 0


def cmd_simulate_approval(args) -> int:
    """Sandbox-only: pretend an approver replied. Never available for real."""
    if not SANDBOX:
        print(red("simulate-approval only works inside a PORNBLOCK_PREFIX "
                  "sandbox. Real approvals must arrive by email."))
        return 1
    cfg = load_config()
    st = load_state()
    if st.get("mode") != "PENDING":
        print(red("no pending request"))
        return 1
    who_ = args.approver.strip().lower()
    if who_ not in {a.lower() for a in cfg["approvers"]}:
        print(red("%s is not an approver" % who_))
        return 1
    if args.deny:
        st["request"].setdefault("denials", {})[who_] = now()
        to_locked(cfg, st, "denied by %s (simulated)" % who_)
    else:
        st["request"].setdefault("approvals", {})[who_] = now()
        history(st, "simulated approval from %s" % who_)
    save_state(st)
    print(green("  recorded simulated %s from %s"
                % ("denial" if args.deny else "approval", who_)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Accountability-gated content blocker. "
                    "Turning it off needs a %s-hour wait AND your friends."
                    % int(DEFAULT_CONFIG["cooloff_hours"]),
        epilog="Set PORNBLOCK_PREFIX=/some/dir to run everything in a harmless "
               "sandbox (no chattr, no systemctl, no system files touched).")
    p.add_argument("--version", action="version", version="%s %s" % (PROG, VERSION))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("setup", help="interactive configuration wizard")
    s.add_argument("--answers", help="JSON file of answers (non-interactive)")
    s.set_defaults(fn=cmd_setup)

    s = sub.add_parser("install", help="install units, enable, lock everything down")
    s.add_argument("--refresh", action="store_true", help="force a blocklist download")
    s.set_defaults(fn=cmd_install)

    s = sub.add_parser("uninstall", help="remove everything (only during an unlock)")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(fn=cmd_uninstall)

    s = sub.add_parser("daemon", help="run the enforcement loop")
    s.add_argument("--once", action="store_true", help="single pass, then exit")
    s.set_defaults(fn=cmd_daemon)

    s = sub.add_parser("watchdog", help="re-enable the service if it was stopped")
    s.set_defaults(fn=cmd_watchdog)

    s = sub.add_parser("status", help="show mode, approvals, timers, health")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("request-unlock", help="start the cool-off and email your friends")
    s.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    s.add_argument("--reason", default="", help="tell your approvers why")
    s.set_defaults(fn=cmd_request)

    s = sub.add_parser("cancel", help="withdraw a request / end an unlock early")
    s.set_defaults(fn=cmd_cancel)

    s = sub.add_parser("test-email", help="prove SMTP and IMAP work")
    s.add_argument("--no-approvers", action="store_true",
                   help="only mail yourself, do not bother your friends")
    s.add_argument("--no-roundtrip", action="store_true")
    s.add_argument("--wait", type=int, default=90, help="seconds to wait for round trip")
    s.set_defaults(fn=cmd_test_email)

    s = sub.add_parser("enforce", help="run one enforcement pass now")
    s.add_argument("--refresh", action="store_true")
    s.add_argument("--quiet", action="store_true", help="do not send tamper alerts")
    s.set_defaults(fn=cmd_enforce)

    s = sub.add_parser("simulate-approval", help="sandbox only: fake an approval")
    s.add_argument("approver")
    s.add_argument("--deny", action="store_true")
    s.set_defaults(fn=cmd_simulate_approval)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args) or 0
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
