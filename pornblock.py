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
import base64
import binascii
import contextlib
import datetime as dt
import email
import email.header
import email.message
import email.utils
import getpass
import hashlib
import hmac
import imaplib
import io
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
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

VERSION = "1.2.1"
HOMEPAGE = "https://github.com/EasternProdigy/christwatch"
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
SECRETS_PATH = ETC_DIR + "/secrets.json"
NFT_CONF_PATH = ETC_DIR + "/nftables.conf"

STATE_DIR = "/var/lib/pornblock"
STATE_PATH = STATE_DIR + "/state.json"
BLOCKLIST_PATH = STATE_DIR + "/blocklist-porn.hosts"
# Second copy of the contract. Deleting the record in /etc would otherwise
# quietly remove the passphrase gate along with it.
RECORD_BACKUP = STATE_DIR + "/install-record.json.bak"
BACKUP_DIR = STATE_DIR + "/backups"
ACTIVITY_DIR = STATE_DIR + "/activity"

LOG_PATH = "/var/log/pornblock.log"
BIN_PATH = "/usr/local/bin/pornblock"
GUI_BIN_PATH = "/usr/local/bin/pornblock-gui"

# Public, secret-free status snapshot so the desktop app can show live
# state without asking for a password every two seconds.
RUN_DIR = "/run/pornblock"
PUBLIC_STATUS = RUN_DIR + "/status.json"
# Where this copy came from, so the wizard can offer it as the update
# source. World-readable; the GUI runs as you, not as root.
SOURCE_HINT = RUN_DIR + "/source-hint.json"

DESKTOP_PATH = "/usr/share/applications/christwatch.desktop"
ICON_PATH = "/usr/share/icons/hicolor/scalable/apps/christwatch.svg"

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
    "app_name": "ChristWatch",
    "owner_name": "",
    "owner_email": "",
    "approvers": [],
    # how your friends hear about it and how they answer:
    #   "email"   - SMTP out, IMAP in, approvers are addresses
    #   "discord" - a bot posts in one channel and reads the replies there,
    #               approvers are Discord user ids
    "transport": "email",
    # identifier -> the name to show, so status is not a wall of numbers
    "approver_names": {},
    "discord": {
        "channel_id": "",
        "bot_token": "",          # kept in secrets.json, blanked out here
        "ping_on_alert": True,
        "poll_seconds": 45,
    },
    "approvals_required": 2,
    "cooloff_hours": 24.0,
    "unlock_minutes": 60,
    "request_ttl_hours": 168.0,
    # A passphrase your friend sets and keeps. Third gate on top of the
    # timer and the approvals.
    "require_passphrase": True,
    # If the friend who holds it is unreachable, UNANIMOUS approval from
    # every approver substitutes for it. Without this a lost passphrase
    # means the honest unlock path is closed for good.
    "passphrase_recovery": True,
    "filter": "cloudflare_family",
    "youtube_restrict": "moderate",   # moderate | strict
    "loop_seconds": 45,
    "imap_poll_seconds": 60,
    # Pulling code from a repo and running it as root is, honestly, a way
    # round all of this if you control the repo. The source is pinned in the
    # install record, every applied update emails your approvers, and a
    # candidate that fails its own self-test is refused.
    "updates": {
        "enabled": True,
        "repo": "",
        "branch": "main",
        # Cheap: this is a git ls-remote, not a clone. Nothing is downloaded
        # until the branch head actually moves.
        "check_minutes": 15,
        "auto_apply": True,
        "require_unlock": False,
    },
    # What gets recorded once the blocker is active. The daily digest goes
    # to every approver, so "dns_log" means they see all of your browsing,
    # not only the blocked parts. That is the trade you chose.
    "tracking": {
        "enabled": True,
        "screen_time": True,
        "apps": True,
        "dns_log": True,
        "keep_days": 90,
        "digest_enabled": True,
        "digest_hour": 20,
        "top_n": 15,
    },
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
    "passphrase": {"fails": 0, "locked_until": 0},
    "request": None,
    "unlock": None,
    "blocklist": {"fetched_at": 0, "domains": 0, "safesearch_ips": {}},
    "imap": {"uidvalidity": None, "seen_uids": []},
    "outbox": [],
    "update": {"last_check": 0, "installed_sha": "", "available": None,
               "last_applied": 0, "last_error": "", "last_remote_sha": "",
               "rolled_back": ""},
    "activity": {"journal_cursor": "", "last_sample": 0, "last_digest_day": ""},
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


def run(cmd, timeout: int = 90, input_text: str | None = None,
        env=None, cwd=None) -> Result:
    """Run a command, never raise.  Returns Result."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=input_text, env=env, cwd=cwd)
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


def short_stamp(epoch: float | None) -> str:
    """Day and time, for messages people read on a phone."""
    if not epoch:
        return "-"
    return dt.datetime.fromtimestamp(epoch).astimezone().strftime("%a %H:%M")


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


DEFAULT_SECRETS = {
    "smtp_password": "",
    "imap_password": "",
    "discord_bot_token": "",
    # {"algo","iter","salt","hash","set_at"} - never the passphrase itself
    "partner_passphrase": None,
}


def load_secrets() -> dict:
    sec = deep_merge(DEFAULT_SECRETS, load_json(SECRETS_PATH, {}) or {})
    # migrate credentials that older configs kept inline
    raw = load_json(CONFIG_PATH, None) or {}
    inline = (raw.get("email") or {})
    moved = False
    for k in ("smtp_password", "imap_password"):
        if not sec.get(k) and inline.get(k):
            sec[k] = inline[k]
            moved = True
    tok = (raw.get("discord") or {}).get("bot_token")
    if not sec.get("discord_bot_token") and tok:
        sec["discord_bot_token"] = tok
        moved = True
    if moved:
        save_secrets(sec)
        log("migrated mail credentials out of config.json into secrets.json")
    return sec


def save_secrets(sec: dict) -> None:
    os.makedirs(P(ETC_DIR), exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(P(ETC_DIR), 0o700)
    write_managed(SECRETS_PATH, dump_json(sec), mode=0o600,
                  immutable=True, backup=False)


def hash_passphrase(phrase: str, iters: int = 600_000) -> dict:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", phrase.encode("utf-8"), salt, iters)
    return {"algo": "pbkdf2_sha256", "iter": iters, "salt": salt.hex(),
            "hash": dk.hex(), "set_at": now()}


def verify_passphrase(rec: dict | None, phrase: str) -> bool:
    if not rec or not phrase:
        return False
    try:
        dk = hashlib.pbkdf2_hmac("sha256", phrase.encode("utf-8"),
                                 bytes.fromhex(rec["salt"]), int(rec["iter"]))
    except (KeyError, ValueError):
        return False
    return hmac.compare_digest(dk.hex(), rec.get("hash", ""))


def load_config(with_secrets: bool = True) -> dict:
    raw = load_json(CONFIG_PATH, None)
    if raw is None:
        return None
    cfg = deep_merge(DEFAULT_CONFIG, raw)
    if with_secrets:
        sec = load_secrets()
        cfg["email"]["smtp_password"] = sec.get("smtp_password") or ""
        cfg["email"]["imap_password"] = sec.get("imap_password") or ""
        cfg["discord"]["bot_token"] = sec.get("discord_bot_token") or ""
        cfg["_secrets"] = sec
    return cfg


def save_config(cfg: dict) -> None:
    """Write config.json with every secret stripped out."""
    out = {k: v for k, v in cfg.items() if not k.startswith("_")}
    out = json.loads(json.dumps(out))
    out.setdefault("email", {})["smtp_password"] = ""
    out["email"]["imap_password"] = ""
    out.setdefault("discord", {})["bot_token"] = ""
    write_managed(CONFIG_PATH, dump_json(out), mode=0o600,
                  immutable=False, backup=False)


def load_record() -> dict | None:
    return load_json(RECORD_PATH, None)


def save_record(rec: dict) -> None:
    body = dump_json(rec)
    write_managed(RECORD_PATH, body, mode=0o600, immutable=True, backup=False)
    os.makedirs(P(STATE_DIR), exist_ok=True)
    write_managed(RECORD_BACKUP, body, mode=0o600, immutable=True, backup=False)


def record_from_config(cfg: dict) -> dict:
    return {
        "owner_email": cfg["owner_email"],
        "approvers": sorted(a.lower() for a in cfg["approvers"]),
        "approvals_required": int(cfg["approvals_required"]),
        "cooloff_hours": float(cfg["cooloff_hours"]),
        "unlock_minutes": int(cfg["unlock_minutes"]),
        "filter": cfg["filter"],
        "transport": (cfg.get("transport") or "email").lower(),
        "discord_channel": str((cfg.get("discord") or {}).get("channel_id") or ""),
        "update_repo": (cfg.get("updates") or {}).get("repo", ""),
        "update_branch": (cfg.get("updates") or {}).get("branch", "main"),
        "update_require_unlock": bool((cfg.get("updates") or {}
                                       ).get("require_unlock", False)),
        "require_passphrase": bool(cfg.get("require_passphrase", True)),
        "passphrase_recovery": bool(cfg.get("passphrase_recovery", True)),
        "passphrase_set": bool((cfg.get("_secrets") or load_secrets()
                                ).get("partner_passphrase")),
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
    NAME = "email"

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

    def smtp_probe(self) -> str:
        """Log in to SMTP and hang up. Sends nothing. Raises MailError."""
        if not self.e.get("smtp_host"):
            raise MailError("SMTP not configured")
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
                if self.e.get("smtp_password"):
                    srv.login(self.e.get("smtp_user") or self.e["address"],
                              self.e["smtp_password"])
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            raise MailError("%s: %s" % (type(exc).__name__, exc)) from exc
        return "signed in to %s:%d" % (host, port)

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
                    "transport": self.NAME,
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
            if (item.get("transport") or "email") != self.NAME:
                log("dropping a queued %s message: this machine now uses %s"
                    % (item.get("transport") or "email", self.NAME))
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
# Discord: one channel, in front of everybody
# --------------------------------------------------------------------------

DISCORD_API = "https://discord.com/api/v10"
# said whenever the channel simply has nothing in it to judge by yet
INCONCLUSIVE = "not proven yet"
DISCORD_EPOCH_MS = 1420070400000
DISCORD_LIMIT = 1900          # real limit is 2000; leave room for the header


def snowflake_at(epoch_seconds: float) -> int:
    """A Discord id encodes its own timestamp, so "everything posted after
    the request went out" needs no bookkeeping on our side."""
    return max(0, int(epoch_seconds * 1000) - DISCORD_EPOCH_MS) << 22


# View Channel, Send Messages, Read Message History, Add Reactions,
# and nothing else
DISCORD_PERMS = (1 << 10) | (1 << 11) | (1 << 16) | (1 << 6)
TICK, CROSS = "\u2705", "\u274c"


def app_id_from_token(token: str) -> str:
    """
    A bot token starts with its own application id, base64'd.

    Which means the app can build the invite link and link straight to the
    right settings page, instead of asking anyone to hunt for an id.
    """
    head = (token or "").strip().split(".")[0]
    if not head:
        return ""
    try:
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
    except (ValueError, binascii.Error):
        return ""
    text = raw.decode("ascii", "ignore").strip()
    return text if text.isdigit() and len(text) >= 15 else ""


def invite_url(token_or_id: str) -> str:
    app = (token_or_id if str(token_or_id).isdigit()
           else app_id_from_token(token_or_id))
    if not app:
        return ""
    return ("https://discord.com/oauth2/authorize?client_id=%s"
            "&scope=bot&permissions=%d" % (app, DISCORD_PERMS))


def bot_settings_url(token_or_id: str) -> str:
    app = (token_or_id if str(token_or_id).isdigit()
           else app_id_from_token(token_or_id))
    return ("https://discord.com/developers/applications/%s/bot" % app
            if app else "https://discord.com/developers/applications")


def _discord_error(code: int, raw: str) -> str:
    detail = ""
    with contextlib.suppress(ValueError):
        body = json.loads(raw or "{}")
        detail = body.get("message") or ""
    if code == 401:
        return ("the bot token was rejected. Copy it again from the Bot page "
                "of your application - it is not the application id or the "
                "client secret. %s" % detail)
    if code == 403:
        return ("the bot is not allowed to do that in this channel. Give it "
                "View Channel, Send Messages and Read Message History. %s" % detail)
    if code == 404:
        return ("no channel with that id, or the bot is not in that server. "
                "%s" % detail)
    if code == 429:
        return "Discord is rate-limiting us. %s" % detail
    return "HTTP %d %s" % (code, detail or raw[:200])


def _chunk_text(text: str, limit: int = DISCORD_LIMIT) -> list:
    """Split on line breaks so a message never lands mid-sentence."""
    out, cur = [], ""
    for line in (text or "").splitlines(True):
        while len(line) > limit:
            if cur:
                out.append(cur)
                cur = ""
            out.append(line[:limit])
            line = line[limit:]
        if len(cur) + len(line) > limit:
            out.append(cur)
            cur = ""
        cur += line
    if cur.strip() or not out:
        out.append(cur)
    return [c for c in out if c.strip()]


class DiscordCourier:
    """
    The same four methods as Mailer, over a Discord bot token.

    Everything goes to one channel that all the approvers can see, and their
    answers are read back out of the same channel. There is deliberately no
    private path: approving an unlock happens in front of the group, which is
    most of what makes this work at all.
    """

    NAME = "discord"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.d = cfg.get("discord") or {}

    # -- plumbing ---------------------------------------------------------

    def _token(self) -> str:
        tok = (self.d.get("bot_token") or "").strip()
        if not tok:
            raise MailError("no bot token configured")
        return tok

    def _channel(self) -> str:
        cid = str(self.d.get("channel_id") or "").strip()
        if not cid.isdigit():
            raise MailError("no channel id configured")
        return cid

    def _call(self, method: str, path: str, body=None, timeout: int = 25,
              retries: int = 1):
        data = dump_json(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(DISCORD_API + path, data=data, method=method)
        req.add_header("Authorization", "Bot " + self._token())
        req.add_header("User-Agent", "DiscordBot (%s, %s)" % (HOMEPAGE, VERSION))
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            if exc.code == 429 and retries > 0:
                wait = 1.0
                with contextlib.suppress(ValueError, TypeError):
                    wait = min(5.0, float(json.loads(raw).get("retry_after") or 1))
                time.sleep(wait)
                return self._call(method, path, body, timeout, retries - 1)
            raise MailError(_discord_error(exc.code, raw)) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise MailError("%s: %s" % (type(exc).__name__, exc)) from exc

    # -- outgoing ---------------------------------------------------------

    def post(self, text: str, ping_ids=()) -> str:
        """Post, and hand back the id of the last message written."""
        cid = self._channel()
        ids = [str(i) for i in ping_ids if str(i).isdigit()]
        chunks = _chunk_text(text)
        last = ""
        for i, chunk in enumerate(chunks):
            content = chunk
            if i == 0 and ids and self.d.get("ping_on_alert", True):
                content = " ".join("<@%s>" % i_ for i_ in ids) + "\n" + chunk
            res = self._call("POST", "/channels/%s/messages" % cid,
                             {"content": content,
                              "allowed_mentions": {"parse": [], "users": ids[:50]}})
            last = str((res or {}).get("id") or last)
        return last

    # -- one tap instead of typing ----------------------------------------

    def add_buttons(self, message_id: str) -> None:
        """Put a tick and a cross under a message, to be pressed."""
        for emoji in (TICK, CROSS):
            self._call("PUT", "/channels/%s/messages/%s/reactions/%s/@me"
                       % (self._channel(), message_id,
                          urllib.parse.quote(emoji, safe="")))

    def who_pressed(self, message_id: str, emoji: str) -> set:
        """User ids who put that reaction on the message. Bots excluded."""
        out = set()
        users = self._call(
            "GET", "/channels/%s/messages/%s/reactions/%s?limit=100"
            % (self._channel(), message_id, urllib.parse.quote(emoji, safe="")))
        for u in users or []:
            if not u.get("bot"):
                out.add(str(u.get("id") or ""))
        return {u for u in out if u}

    def send_now(self, to_list, subject, text, html=None) -> None:
        """Post synchronously. html is ignored - Discord has no use for it."""
        head = ("**%s**" % subject.strip()) if subject else ""
        body = "\n".join(x for x in (head, (text or "").strip()) if x)
        self.post(body, ping_ids=to_list or [])
        log("discord post :: %s" % subject)

    def send(self, st: dict, to_list, subject, text, html=None,
             queue_on_fail: bool = True) -> bool:
        try:
            self.send_now(to_list, subject, text, html)
            return True
        except MailError as exc:
            log("discord post FAILED (%s) :: %s" % (exc, subject))
            if queue_on_fail and st is not None:
                st.setdefault("outbox", []).append({
                    "transport": self.NAME, "to": list(to_list or []),
                    "subject": subject, "text": text, "html": None,
                    "queued_at": now(), "attempts": 0, "last_error": str(exc),
                })
                st["outbox"] = st["outbox"][-100:]
            return False

    def flush_outbox(self, st: dict) -> None:
        box = st.get("outbox") or []
        if not box:
            return
        st["outbox"] = []
        keep = []
        for item in box:
            if item.get("attempts", 0) >= 20:
                log("dropping an undeliverable queued post :: %s"
                    % item.get("subject"))
                continue
            if (item.get("transport") or "email") != self.NAME:
                log("dropping a queued %s message: this machine now uses %s"
                    % (item.get("transport") or "email", self.NAME))
                continue
            try:
                self.send_now(item["to"], item["subject"], item["text"])
            except MailError as exc:
                item["attempts"] = item.get("attempts", 0) + 1
                item["last_error"] = str(exc)
                keep.append(item)
        st["outbox"] = keep

    # -- incoming ---------------------------------------------------------

    def scan(self, st: dict, since_epoch: float) -> list:
        """
        (author id, "", message text, message id) for everything humans have
        said in the channel since `since_epoch`.

        Never raises. A Discord outage, a revoked token or a channel someone
        deleted must leave the machine locked and enforcing, not wedge the
        daemon - the blocker staying on is always the safe failure.
        """
        try:
            return self._scan(st, since_epoch)
        except MailError as exc:
            log("discord read failed: %s" % exc)
            return []

    def _scan(self, st: dict, since_epoch: float) -> list:
        cid = self._channel()
        after = snowflake_at(since_epoch)
        out, blank = [], 0
        self.last_blank = 0
        for _page in range(10):
            msgs = self._call(
                "GET", "/channels/%s/messages?limit=100&after=%d" % (cid, after))
            if not isinstance(msgs, list) or not msgs:
                break
            msgs.sort(key=lambda m: int(m.get("id") or 0))
            for m in msgs:
                with contextlib.suppress(TypeError, ValueError):
                    after = max(after, int(m.get("id") or 0))
                author = m.get("author") or {}
                if author.get("bot"):
                    continue
                body = m.get("content") or ""
                if not body:
                    blank += 1
                    continue
                out.append((str(author.get("id") or ""), "", body,
                            str(m.get("id") or "")))
            if len(msgs) < 100:
                break
        self.last_blank = blank
        if blank and not out:
            log("discord: message text came back empty - switch on the "
                "Message Content intent for the bot")
        return out

    def probe(self) -> str:
        me = self._call("GET", "/users/@me")
        ch = self._call("GET", "/channels/%s" % self._channel())
        name = ch.get("name") or self._channel()
        return "signed in as %s, can see #%s" % (me.get("username") or "?", name)

    def content_intent(self) -> bool:
        """Whether the bot may read what other people type. Without it the
        text of every message that does not mention the bot arrives empty."""
        app = self._call("GET", "/applications/@me")
        flags = int(app.get("flags") or 0)
        return bool(flags & ((1 << 18) | (1 << 19)))

    def content_evidence(self) -> tuple:
        """
        (messages by people, how many were blank, why we could not look).

        The flag on the application is what the portal *says*. This is what
        actually arrives, which is the thing that matters: if a person's words
        come through, the intent is on whatever any flag claims. And if the
        read itself fails, that is a third answer, not a silent zero.
        """
        try:
            msgs = self._call("GET", "/channels/%s/messages?limit=50"
                              % self._channel())
        except MailError as exc:
            return 0, 0, str(exc)
        seen = blank = 0
        for m in msgs or []:
            if (m.get("author") or {}).get("bot"):
                continue
            seen += 1
            if not (m.get("content") or "").strip():
                blank += 1
        return seen, blank, None


def courier(cfg: dict):
    """The way this machine talks to its approvers."""
    if (cfg.get("transport") or "email").lower() == "discord":
        return DiscordCourier(cfg)
    return Mailer(cfg)


def is_discord(cfg: dict) -> bool:
    return (cfg.get("transport") or "email").lower() == "discord"


def display_name(cfg: dict, ident: str) -> str:
    """Approvers are addresses on email and 18-digit ids on Discord; nobody
    should have to read the latter."""
    ident = str(ident or "").strip()
    name = (cfg.get("approver_names") or {}).get(ident)
    if name:
        return name
    if is_discord(cfg) and ident.isdigit():
        return "<@%s>" % ident
    return ident


def people_list(cfg: dict) -> str:
    return ", ".join(display_name(cfg, a) for a in (cfg.get("approvers") or []))


# --------------------------------------------------------------------------
# Alerting helpers
# --------------------------------------------------------------------------

def everyone(cfg: dict) -> list:
    people = list(cfg.get("approvers") or [])
    if cfg.get("owner_email") and not is_discord(cfg):
        people.append(cfg["owner_email"])
    return list(dict.fromkeys(a.strip() for a in people if a.strip()))


def alert(cfg: dict, st: dict, key: str, subject: str, text: str,
          html: str | None = None, to=None, force: bool = False,
          ping: bool = True) -> bool:
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
    app = cfg.get("app_name") or PROG
    prefix = "[%s DEMO] " % app if SANDBOX else "[%s] " % app
    if is_discord(cfg) and not ping:
        recipients = []          # still posted, just nobody's phone buzzes
    return courier(cfg).send(st, recipients, prefix + subject, text, html)


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


def _links() -> list:
    r = run(["ip", "-o", "link", "show"], timeout=15)
    names = []
    for line in r.out.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@")[0].strip()
        if name and name != "lo":
            names.append(name)
    return names


def _links_with_foreign_dns(cfg: dict) -> list:
    """Links whose per-link resolvers are not our filter."""
    f = FILTERS[cfg["filter"]]
    allowed = {ip.lower() for ip in f["ipv4"] + f["ipv6"]}
    r = run(["resolvectl", "dns"], timeout=20)
    if not r.ok:
        return []
    bad = []
    for line in r.out.splitlines():
        m = re.match(r"\s*Link\s+\d+\s+\(([^)]+)\):(.*)$", line)
        if not m:
            continue
        iface, servers = m.group(1).strip(), m.group(2).split()
        if iface == "lo":
            continue
        for srv in servers:
            if srv.split("%")[0].lower() not in allowed:
                bad.append(iface)
                break
    return bad


def enforce_link_dns(cfg: dict, apply: bool) -> list:
    if SANDBOX:
        return []
    changes = []
    f = FILTERS[cfg["filter"]]
    if apply:
        bad = _links_with_foreign_dns(cfg)
        for iface in bad:
            run(["resolvectl", "dns", iface] + f["ipv4"] + f["ipv6"], timeout=20)
            run(["resolvectl", "domain", iface, "~."], timeout=20)
            changes.append("link %s was using another resolver; pinned to the "
                           "filter" % iface)
    else:
        for iface in _links():
            run(["resolvectl", "revert", iface], timeout=20)
        if _links():
            changes.append("per-link DNS reverted to DHCP (unlock window)")
    return changes


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
        # after any restart the links need re-pinning, so this comes last
        changes += enforce_link_dns(cfg, True)
    else:
        if remove_managed(RESOLVED_DROPIN):
            changes.append("systemd-resolved: drop-in removed (unlock window)")
        if remove_managed(NM_DROPIN):
            changes.append("NetworkManager: dns drop-in removed (unlock window)")
        changes += enforce_link_dns(cfg, False)
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
    L.append("\t\tudp dport 53 counter drop")
    L.append("\t\ttcp dport 53 counter drop")
    L.append("\t\ttcp dport 853 counter drop")
    L.append("\t\tudp dport 853 counter drop")
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
        changes += enforce_dns_logging(cfg, apply)
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
        spare = load_json(RECORD_BACKUP, None)
        if not spare:
            return cfg, []
        # The record was deleted. Put it back and make some noise.
        save_record(spare)
        rec = spare
        log("install record was missing; restored from the spare copy")
        alert(cfg, st, "tamper_record",
              "The install record was deleted and has been restored",
              "Someone deleted %s on %s - the file that pins the approver "
              "list, the quorum, the cool-off and the passphrase requirement.\n\n"
              "It has been restored from the spare copy. Deleting it is how "
              "you would remove those gates, so it is worth asking about.\n"
              % (RECORD_PATH, socket.gethostname()), force=True)
        history(st, "install record deleted and restored from spare")

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

    if bool(rec.get("require_passphrase", False)) and \
            not bool(cfg.get("require_passphrase", True)):
        notes.append("partner passphrase requirement was switched off; reverted")
        cfg["require_passphrase"] = True
        reverted = True
    if not bool(rec.get("passphrase_recovery", True)) and \
            bool(cfg.get("passphrase_recovery", True)):
        notes.append("passphrase recovery-by-unanimity was switched on; reverted")
        cfg["passphrase_recovery"] = False
        reverted = True
    if rec.get("passphrase_set") and not (cfg.get("_secrets") or
                                          load_secrets()).get("partner_passphrase"):
        notes.append("the stored partner passphrase was DELETED - it cannot be "
                     "restored, so this unlock path now needs unanimous approval")
        alert(cfg, st, "tamper_passphrase",
              "The partner passphrase was deleted",
              "Someone removed the stored partner passphrase on %s.\n\n"
              "It cannot be recovered. Until a new one is set during an unlock "
              "window, the only way out is unanimous approval from all of you.\n"
              % socket.gethostname())

    rec_tr = (rec.get("transport") or "email").lower()
    cfg_tr = (cfg.get("transport") or "email").lower()
    if rec.get("transport") and rec_tr != cfg_tr:
        notes.append("the way your friends are contacted was changed (%s -> %s); "
                     "reverted" % (rec_tr, cfg_tr))
        cfg["transport"] = rec_tr
        reverted = True
        cfg_tr = rec_tr

    rec_ch = str(rec.get("discord_channel") or "")
    cfg_ch = str((cfg.get("discord") or {}).get("channel_id") or "")
    if rec_ch and cfg_ch != rec_ch:
        # a channel your friends are not in is the same as no alerts at all
        notes.append("the Discord channel was changed (%s -> %s); reverted"
                     % (rec_ch, cfg_ch or "none"))
        cfg.setdefault("discord", {})["channel_id"] = rec_ch
        reverted = True
    elif not rec_ch and cfg_ch and cfg_tr == "discord":
        rec["discord_channel"] = cfg_ch
        save_record(rec)
        notes.append("Discord channel recorded as %s" % cfg_ch)

    up = cfg.setdefault("updates", {})
    rec_repo = rec.get("update_repo") or ""
    cfg_repo = (up.get("repo") or "").strip()
    if rec_repo != cfg_repo:
        if not rec_repo:
            # Adopting a source for the first time. Allowed - otherwise
            # anyone who set up without one could never enable updates - but
            # it hands a repository the power to run code as root here, so
            # it is recorded and everybody hears about it.
            rec["update_repo"] = cfg_repo
            rec["update_branch"] = (up.get("branch") or "main")
            save_record(rec)
            notes.append("update source set to %s; accepted and pinned" % cfg_repo)
            alert(cfg, st, "update_source_added",
                  "An update source was added",
                  "%s pointed the blocker on %s at a code repository:\n\n"
                  "  %s (%s)\n\n"
                  "From now on it can pull new versions from there and run "
                  "them as root. Candidates must pass the project's own "
                  "self-test first, and you will be emailed on every update "
                  "that is applied - but whoever controls that repository has "
                  "a lot of power over this machine. If it is %s's own repo, "
                  "that is worth knowing about.\n"
                  % (who(cfg), socket.gethostname(), cfg_repo,
                     rec["update_branch"], who(cfg)), force=True)
        elif not cfg_repo:
            rec["update_repo"] = ""
            save_record(rec)
            notes.append("update source removed; accepted")
        else:
            notes.append("update source was repointed (%s -> %s); reverted"
                         % (rec_repo, cfg_repo))
            up["repo"] = rec_repo
            reverted = True
    if rec.get("update_branch") and cfg_repo and rec_repo and \
            up.get("branch") != rec.get("update_branch"):
        notes.append("update branch was changed (%s -> %s); reverted"
                     % (rec.get("update_branch"), up.get("branch")))
        up["branch"] = rec.get("update_branch")
        reverted = True
    if bool(rec.get("update_require_unlock", False)) and \
            not bool(up.get("require_unlock", False)):
        notes.append("updates-need-an-unlock was switched off; reverted")
        up["require_unlock"] = True
        reverted = True

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

def desktop_entry(cfg: dict) -> str:
    name = cfg.get("app_name") or "ChristWatch"
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Version=1.0\n"
        "Name=%s\n"
        "GenericName=Accountability blocker\n"
        "Comment=Content blocking with a cool-off and friends who have to agree\n"
        "Exec=%s\n"
        "Icon=christwatch\n"
        "Terminal=false\n"
        "Categories=Utility;Security;\n"
        "Keywords=accountability;blocker;filter;porn;\n"
        "StartupNotify=true\n"
        "StartupWMClass=christwatch\n" % (name, GUI_BIN_PATH))


def icon_svg() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" '
        'width="128" height="128">\n'
        '  <defs>\n'
        '    <linearGradient id="body" x1="0" y1="0" x2="0" y2="1">\n'
        '      <stop offset="0" stop-color="#6ea8fe"/>\n'
        '      <stop offset="1" stop-color="#2f52c9"/>\n'
        '    </linearGradient>\n'
        '    <linearGradient id="sheen" x1="0" y1="0" x2="1" y2="1">\n'
        '      <stop offset="0" stop-color="#ffffff" stop-opacity=".28"/>\n'
        '      <stop offset="0.6" stop-color="#ffffff" stop-opacity="0"/>\n'
        '    </linearGradient>\n'
        '  </defs>\n'
        '  <path d="M64 7 L115 25 V65 c0 30-22 51-51 57 C35 116 13 95 13 65 '
        'V25 Z" fill="url(#body)"/>\n'
        '  <path d="M64 7 L115 25 V65 c0 30-22 51-51 57 C35 116 13 95 13 65 '
        'V25 Z" fill="url(#sheen)"/>\n'
        '  <path d="M64 15 L107 30 V65 c0 26-19 44-43 50 C40 109 21 91 21 65 '
        'V30 Z" fill="none" stroke="#ffffff" stroke-opacity=".35" '
        'stroke-width="2"/>\n'
        # the eight-pointed Orthodox cross: titulus, the main bar, and the
        # slanted footrest, raised on the side of the thief who repented
        '  <path fill="#ffffff" fill-opacity=".95" d="'
        'M59 24 H69 V107 H59 Z '
        'M46 34 H82 V42 H46 Z '
        'M34 56 H94 V66 H34 Z '
        'M42 80 L86 93 V101 L42 88 Z"/>\n'
        '</svg>\n')


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
GUI_SELF_COPY = STATE_DIR + "/pornblock_gui.py.installed"
# The version we are replacing, kept so a bad push can be undone.
PREV_COPY = STATE_DIR + "/pornblock.py.previous"


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
    """A one-click reply link. Empty on Discord, where you just type it."""
    if is_discord(cfg):
        return ""
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
    if is_discord(cfg):
        text = (
            "%s wants the blocker on %s switched off.\n"
            "Tap %s to allow it, %s to refuse. %d of %d needed, and it cannot "
            "happen before %s (%s from now).\n"
            "Doing nothing keeps it on. You can untap any time before it is "
            "granted. Code `%s`."
            % (who(cfg), host, TICK, CROSS, need, len(cfg.get("approvers") or []),
               short_stamp(req["eligible_at"]),
               human_delta(req["eligible_at"] - now()), tok))
        return subject, text, None
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
           people_list(cfg), need, tok, mailto_link(cfg, tok), tok,
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


def passphrase_is_inert(cfg: dict) -> bool:
    """
    True when the recovery rule makes the passphrase gate meaningless.

    If unanimous approval can stand in for the passphrase, and your quorum is
    already everybody, then the moment enough friends approve the passphrase
    is satisfied too. Two friends with "both must agree" lands exactly here.
    The way out is a third approver, or turning the recovery rule off.
    """
    if not cfg.get("passphrase_recovery", True):
        return False
    if not cfg.get("require_passphrase", True):
        return False
    people = len(cfg.get("approvers") or [])
    return bool(people) and int(cfg.get("approvals_required") or 1) >= people


def passphrase_gate(cfg: dict, st: dict, req: dict) -> tuple:
    """
    Returns (required, satisfied) for the partner passphrase.

    Note what happens if the stored hash is deleted: the install record still
    says a passphrase exists, so the gate stays shut and cannot be satisfied
    by typing anything. That is deliberate - deleting the hash must not be a
    way to remove a gate. Unanimous approval is then the way out.
    """
    rec = load_record() or {}
    sec = cfg.get("_secrets") or load_secrets()
    ever_set = bool(sec.get("partner_passphrase")) or bool(rec.get("passphrase_set"))
    if not (bool(cfg.get("require_passphrase", True)) and ever_set):
        return False, True
    if req.get("passphrase_ok"):
        return True, True
    if cfg.get("passphrase_recovery", True):
        wanted = {a.strip().lower() for a in (cfg.get("approvers") or [])}
        have = {k.strip().lower() for k in (req.get("approvals") or {})}
        if wanted and wanted <= have:
            return True, True          # unanimity stands in for the passphrase
    return True, False


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


def ensure_request_posted(cfg: dict, st: dict) -> bool:
    """
    Put the request in the channel with a tick and a cross under it.

    Safe to call on every tick: it does nothing once the message is up, and
    it tries again by itself if Discord was unreachable when the request was
    made, so a flaky moment does not cost anyone their request.
    """
    req = st.get("request") or {}
    if not req:
        return True
    if req.get("message_id"):
        return True
    dc = DiscordCourier(cfg)
    subject, text, _html = request_email(cfg, st)
    head = "**Unlock request%s**" % (" (demo)" if SANDBOX else "")
    try:
        mid = dc.post(head + "\n" + text, ping_ids=everyone(cfg))
        if not mid:
            return False
        req["message_id"] = mid
        with contextlib.suppress(MailError):
            dc.add_buttons(mid)
        log("discord: request %s posted as message %s" % (req.get("token"), mid))
        return True
    except MailError as exc:
        log("discord: could not post the request (%s)" % exc)
        return False


def poll_reactions(cfg: dict, st: dict, post, req: dict) -> list:
    """
    Read the tick and the cross. One tap, no typing, and no dependence on the
    Message Content intent - a reaction carries a user id and nothing else,
    which is all an approval needs.
    """
    mid = req.get("message_id")
    if not mid or not hasattr(post, "who_pressed"):
        return []
    approvers = {a.strip().lower() for a in cfg.get("approvers") or []}
    try:
        ticked = post.who_pressed(mid, TICK) & approvers
        crossed = post.who_pressed(mid, CROSS) & approvers
    except Exception as exc:                  # never wedge the tick
        log("could not read the buttons: %r" % exc)
        return []

    for uid in sorted(crossed):
        if uid not in (req.get("denials") or {}):
            req.setdefault("denials", {})[uid] = now()
            return [("deny", uid)]

    events = []
    tapped = req.setdefault("tapped", {})
    got = req.setdefault("approvals", {})
    for uid in sorted(ticked):
        if uid not in got:
            got[uid] = now()
            tapped[uid] = True
            events.append(("approve", uid))
    # taking the tick back takes the approval back, which is the whole
    # difference between a tap and something you cannot undo
    for uid in [u for u in tapped if u not in ticked]:
        tapped.pop(uid, None)
        got.pop(uid, None)
        events.append(("unapprove", uid))
    return events


def poll_approvals(cfg: dict, st: dict, post) -> list:
    req = st.get("request")
    if not req:
        return []
    events = []
    approvers = {a.strip().lower() for a in cfg.get("approvers") or []}
    try:
        incoming = post.scan(st, req["requested_at"])
    except Exception as exc:              # a dead channel is not a crash
        log("could not read approvals: %r" % exc)
        return []
    if getattr(post, "last_blank", 0) and not incoming:
        # people are talking and the bot is deaf. A message that mentions the
        # bot always carries its text, intent or no intent, so there is a way
        # through even before anyone fixes the switch.
        alert(cfg, st, "blind_bot",
              "I cannot read what you are typing",
              "Someone has posted here, but the text arrives blank, which "
              "means my Message Content permission is off.\n\n"
              "Two ways past it:\n"
              "  - mention me in the message: APPROVE %s @me - a message that "
              "mentions me always comes through\n"
              "  - or %s turns on MESSAGE CONTENT INTENT for this bot at "
              "discord.com/developers (Bot, then Save Changes)\n"
              % (req.get("token"), who(cfg)))
    for sender, subject, body, _uid in incoming:
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


def advance(cfg: dict, st: dict, post) -> list:
    """Move the state machine forward.  Returns human-readable transitions."""
    moves = []
    mode = st.get("mode", "LOCKED")

    if mode == "PENDING":
        req = st.get("request") or {}
        ttl = float(cfg.get("request_ttl_hours") or 168) * 3600
        events = []
        poll_every = float(cfg.get("imap_poll_seconds") or 60)
        if is_discord(cfg):
            ensure_request_posted(cfg, st)
        if now() - float(req.get("last_poll") or 0) >= poll_every:
            req["last_poll"] = now()
            events = poll_approvals(cfg, st, post)
            if is_discord(cfg):
                events += poll_reactions(cfg, st, post, req)

        for kind, sender in events:
            if kind == "approve":
                sender_name = display_name(cfg, sender)
                history(st, "approval received from %s" % sender_name)
                got = len(req.get("approvals") or {})
                alert(cfg, st, "approval_%s" % sender,
                      "%s approved the unlock (%d/%s)"
                      % (sender_name, got, cfg["approvals_required"]),
                      "%s approved %s's unlock request (code %s).\n\n"
                      "That is %d of %s approvals. The cool-off %s.\n"
                      % (sender_name, who(cfg), req.get("token"), got,
                         cfg["approvals_required"],
                         ("ends " + stamp(req["eligible_at"]))
                         if now() < req["eligible_at"] else "has already ended"),
                      force=True)
            elif kind == "unapprove":
                sender_name = display_name(cfg, sender)
                history(st, "%s took their approval back" % sender_name)
                alert(cfg, st, "unapprove_%s" % sender,
                      "%s took their approval back" % sender_name,
                      "%s removed the tick from %s's unlock request "
                      "(code %s).\n\nThat is %d of %s approvals now.\n"
                      % (sender_name, who(cfg), req.get("token"),
                         len(req.get("approvals") or {}),
                         cfg["approvals_required"]), force=True)
            else:
                sender_name = display_name(cfg, sender)
                history(st, "DENIAL received from %s" % sender_name)
                alert(cfg, st, "denial",
                      "%s refused the unlock - request cancelled" % sender_name,
                      "%s replied DENY to %s's unlock request (code %s).\n\n"
                      "The request has been cancelled and the blocker stays on.\n"
                      % (sender_name, who(cfg), req.get("token")), force=True)
                to_locked(cfg, st, "denied by %s" % sender_name)
                return ["denied by %s - back to LOCKED" % sender_name]

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
        pass_req, pass_ok = passphrase_gate(cfg, st, req)
        if timer_done and got >= need and pass_ok:
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
                     ", ".join(display_name(cfg, a)
                               for a in st["unlock"]["approved_by"]),
                     cfg["cooloff_hours"]),
                  force=True)
            moves.append("UNLOCKED for %d minutes" % mins)
        elif timer_done and not req.get("ready_notified"):
            req["ready_notified"] = True
            outstanding = []
            if got < need:
                outstanding.append("%d more approval(s)" % (need - got))
            if pass_req and not pass_ok:
                outstanding.append("the partner passphrase")
            alert(cfg, st, "cooloff_done",
                  "Cool-off finished - still waiting on %s" % " and ".join(outstanding),
                  "%s's cool-off timer has finished. The blocker stays on until "
                  "%s (code %s).\n\nApprove with: APPROVE %s\n%s\n"
                  % (who(cfg), " and ".join(outstanding), req.get("token"),
                     req.get("token"), mailto_link(cfg, req.get("token"))), force=True)
            moves.append("cool-off elapsed, waiting on " + " and ".join(outstanding))

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
# Activity tracking
# ==========================================================================

# Long-running desktop plumbing lives in app.slice too. Counting it would
# bury the things you actually used under a pile of always-on daemons.
_BACKGROUND_APPS = re.compile(
    r"^(xdg-|geoclue|at-spi|gvfs|pipewire|wireplumber|dconf|gcr|kaccess|"
    r"polkit|obex|tracker|evolution|goa-|gsd-|kde-systemd|plasma-|kwin|"
    r"ksmserver|kactivitymanagerd|baloo|kglobalaccel|kscreen|powerdevil|"
    r"org\.kde\.kded|org\.freedesktop\.)", re.I)

_BL_CACHE = {"mtime": 0, "set": frozenset()}


def blocklist_set() -> frozenset:
    """Cached set of blocked domains, reloaded when the file changes."""
    path = P(BLOCKLIST_PATH)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return frozenset()
    if mtime != _BL_CACHE["mtime"]:
        _BL_CACHE["set"] = frozenset(blocklist_domains())
        _BL_CACHE["mtime"] = mtime
    return _BL_CACHE["set"]


def is_blocked_domain(domain: str) -> bool:
    bl = blocklist_set()
    if not bl:
        return False
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in bl:
            return True
    return False


def today_str() -> str:
    return dt.date.today().isoformat()


def activity_path(day: str) -> str:
    return "%s/%s.json" % (ACTIVITY_DIR, day)


def load_day(day: str) -> dict:
    return load_json(activity_path(day), {
        "day": day, "screen_seconds": 0, "apps": {}, "domains": {},
        "blocked": {}, "bypass": {}, "updated_at": 0})


def save_day(day: str, doc: dict) -> None:
    doc["updated_at"] = now()
    real = P(activity_path(day))
    os.makedirs(os.path.dirname(real), exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(os.path.dirname(real), 0o700)
    atomic_write(real, dump_json(doc), 0o600)


def graphical_session() -> tuple:
    """(session id, uid) of the active graphical session, or ("", 0)."""
    r = run(["loginctl", "list-sessions", "--no-legend"], timeout=20)
    if not r.ok:
        return "", 0
    for line in r.out.splitlines():
        parts = line.split()
        if not parts:
            continue
        sid = parts[0]
        d = run(["loginctl", "show-session", sid, "-p", "Type", "-p", "Active",
                 "-p", "User", "-p", "IdleHint"], timeout=20)
        props = dict(x.split("=", 1) for x in d.out.splitlines() if "=" in x)
        if props.get("Type") in ("wayland", "x11") and props.get("Active") == "yes":
            try:
                return sid, int(props.get("User") or 0)
            except ValueError:
                return sid, 0
    return "", 0


def session_is_busy(sid: str) -> bool:
    if not sid:
        return False
    d = run(["loginctl", "show-session", sid, "-p", "IdleHint", "-p", "Active",
             "-p", "LockedHint"], timeout=20)
    props = dict(x.split("=", 1) for x in d.out.splitlines() if "=" in x)
    return (props.get("Active") == "yes" and props.get("IdleHint") == "no"
            and props.get("LockedHint") != "yes")


def app_name_from_cgroup(entry: str) -> str:
    n = entry
    for suf in (".scope", ".service"):
        if n.endswith(suf):
            n = n[:-len(suf)]
    if not n.startswith("app-"):
        return ""
    n = n[4:].split("@", 1)[0]
    n = re.sub(r"-\d{3,}$", "", n)
    if n.startswith("flatpak-"):
        n = n[len("flatpak-"):]
    return n.replace("\\x2d", "-").strip("-")


def running_apps(uid: int) -> list:
    base = ("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/app.slice"
            % (uid, uid))
    try:
        entries = os.listdir(base)
    except OSError:
        return []
    out = []
    for e in entries:
        if "@autostart.service" in e:
            continue
        name = app_name_from_cgroup(e)
        if name and not _BACKGROUND_APPS.match(name):
            out.append(name)
    return sorted(set(out))


_DNS_LOOKUP = re.compile(r"Looking up RR for (\S+) IN (?:A|AAAA|HTTPS|SVCB)\b")
_SKIP_DOMAIN = re.compile(
    r"(\.in-addr\.arpa$|\.ip6\.arpa$|\.local$|^_|\.arpa$|^localhost$)", re.I)


def harvest_dns(cfg: dict, st: dict, doc: dict) -> int:
    """Pull new resolved debug lines and count the domains looked up."""
    act = st.setdefault("activity", {})
    args = ["journalctl", "-u", "systemd-resolved", "-o", "cat", "--no-pager",
            "-q", "--show-cursor"]
    cursor = act.get("journal_cursor") or ""
    args += (["--after-cursor", cursor] if cursor else ["-n", "500"])
    r = run(args, timeout=90)
    if not r.ok:
        return 0
    seen = 0
    for line in r.out.splitlines():
        if line.startswith("-- cursor:"):
            act["journal_cursor"] = line.split(":", 1)[1].strip()
            continue
        m = _DNS_LOOKUP.search(line)
        if not m:
            continue
        domain = m.group(1).rstrip(".").lower()
        if not domain or _SKIP_DOMAIN.search(domain):
            continue
        doc["domains"][domain] = doc["domains"].get(domain, 0) + 1
        seen += 1
        if is_blocked_domain(domain):
            doc["blocked"][domain] = doc["blocked"].get(domain, 0) + 1
    return seen


def enforce_dns_logging(cfg: dict, apply: bool) -> list:
    """resolved only logs queries at debug level, and the setting is runtime
    only - so it has to be re-asserted like everything else here."""
    if SANDBOX:
        return []
    trk = cfg.get("tracking") or {}
    want = "debug" if (apply and trk.get("enabled", True)
                       and trk.get("dns_log", True)) else "info"
    r = run(["resolvectl", "log-level"], timeout=20)
    if r.ok and r.out.strip() == want:
        return []
    res = run(["resolvectl", "log-level", want], timeout=20)
    if not res.ok:
        return []
    return ["systemd-resolved logging set to %s (domain tracking)" % want]


def read_nft_counters() -> dict:
    if SANDBOX:
        return {}
    r = run(["nft", "-j", "list", "table", "inet", "pornblock"], timeout=30)
    if not r.ok:
        return {}
    try:
        doc = json.loads(r.out)
    except ValueError:
        return {}
    total = 0
    for item in doc.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        verdict = json.dumps(rule.get("expr", []))
        if '"drop"' not in verdict and '"reject"' not in verdict:
            continue
        for expr in rule.get("expr", []):
            c = expr.get("counter")
            if isinstance(c, dict):
                total += int(c.get("packets") or 0)
    return {"dns_bypass_packets": total}


def sample_activity(cfg: dict, st: dict) -> None:
    """One sampling pass. Cheap, and never fatal."""
    trk = cfg.get("tracking") or {}
    if not trk.get("enabled", True):
        return
    act = st.setdefault("activity", {})
    last = float(act.get("last_sample") or 0)
    elapsed = min(300.0, max(0.0, now() - last)) if last else 0.0
    act["last_sample"] = now()

    day = today_str()
    doc = load_day(day)
    sid, uid = graphical_session()
    busy = session_is_busy(sid)

    if elapsed and busy and trk.get("screen_time", True):
        doc["screen_seconds"] = int(doc.get("screen_seconds", 0) + elapsed)
    if elapsed and busy and trk.get("apps", True) and uid:
        for app in running_apps(uid):
            doc["apps"][app] = int(doc["apps"].get(app, 0) + elapsed)
    if trk.get("dns_log", True):
        harvest_dns(cfg, st, doc)
    counters = read_nft_counters()
    if counters:
        doc["bypass"] = counters
    save_day(day, doc)
    prune_activity(cfg)


def prune_activity(cfg: dict) -> None:
    keep = int((cfg.get("tracking") or {}).get("keep_days") or 90)
    cutoff = dt.date.today() - dt.timedelta(days=keep)
    try:
        names = os.listdir(P(ACTIVITY_DIR))
    except OSError:
        return
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            d = dt.date.fromisoformat(name[:-5])
        except ValueError:
            continue
        if d < cutoff:
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(P(ACTIVITY_DIR), name))


def summarise_day(cfg: dict, day: str) -> dict:
    doc = load_day(day)
    top = int((cfg.get("tracking") or {}).get("top_n") or 15)
    apps = sorted(doc.get("apps", {}).items(), key=lambda kv: -kv[1])[:top]
    domains = sorted(doc.get("domains", {}).items(), key=lambda kv: -kv[1])[:top]
    blocked = sorted(doc.get("blocked", {}).items(), key=lambda kv: -kv[1])[:top]
    return {
        "day": day,
        "screen_seconds": int(doc.get("screen_seconds", 0)),
        "apps": apps,
        "domains": domains,
        "blocked": blocked,
        "unique_domains": len(doc.get("domains", {})),
        "blocked_hits": sum(doc.get("blocked", {}).values()),
        "blocked_unique": len(doc.get("blocked", {})),
        "bypass": doc.get("bypass", {}),
    }


def digest_body(cfg: dict, day: str) -> tuple:
    d = summarise_day(cfg, day)
    trk = cfg.get("tracking") or {}
    lines = [
        "Daily report for %s on %s" % (who(cfg), socket.gethostname()),
        "=" * 58,
        "",
        "  Screen time      : %s" % human_delta(d["screen_seconds"]),
        "  Sites looked up  : %d unique domains" % d["unique_domains"],
        "  Blocked attempts : %d hits across %d blocked domains"
        % (d["blocked_hits"], d["blocked_unique"]),
    ]
    byp = (d.get("bypass") or {}).get("dns_bypass_packets")
    if byp:
        lines.append("  DNS bypass       : %d packets dropped trying to reach "
                     "another resolver" % byp)
    lines.append("")
    if d["blocked"]:
        lines += ["  Blocked domains that were requested:"]
        lines += ["    %-45s %d" % (n, c) for n, c in d["blocked"]]
        lines += ["",
                  "  A request does not mean a page was seen - these were "
                  "stopped. But",
                  "  something asked for them.", ""]
    else:
        lines += ["  Nothing on the blocklist was requested today.", ""]
    if d["apps"]:
        lines += ["  Applications open while you were at the machine:"]
        lines += ["    %-45s %s" % (n, human_delta(sec)) for n, sec in d["apps"]]
        lines += [""]
    if trk.get("dns_log", True) and d["domains"]:
        lines += ["  Most looked-up domains (all browsing, not just blocked):"]
        lines += ["    %-45s %d" % (n, c) for n, c in d["domains"]]
        lines += [""]
    lines += [
        "-" * 58,
        "You are getting this because %s asked you to hold them to it."
        % who(cfg),
        "App time is time the application was open while the screen was in",
        "use - not time spent looking at it.",
    ]
    return ("Daily report for %s - %s" % (who(cfg), day), "\n".join(lines) + "\n")


def maybe_digest(cfg: dict, st: dict, post) -> None:
    trk = cfg.get("tracking") or {}
    if not (trk.get("enabled", True) and trk.get("digest_enabled", True)):
        return
    act = st.setdefault("activity", {})
    day = today_str()
    if act.get("last_digest_day") == day:
        return
    if dt.datetime.now().hour < int(trk.get("digest_hour") or 20):
        return
    act["last_digest_day"] = day
    subject, text = digest_body(cfg, day)
    alert(cfg, st, "digest", subject, text, force=True, ping=False)
    history(st, "daily report sent for %s" % day)


def cmd_activity(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("No config. Run: sudo %s setup" % PROG))
        return 1
    day = args.day or today_str()
    if args.json:
        print(dump_json(summarise_day(cfg, day)))
        return 0
    if args.send:
        st = load_state()
        subject, text = digest_body(cfg, day)
        ok = alert(cfg, st, "digest_manual", subject, text,
                   force=True, ping=False)
        save_state(st)
        print(green("  report sent") if ok else yellow("  queued for retry"))
        return 0
    d = summarise_day(cfg, day)
    print("")
    print(bold("  Activity for %s" % day))
    print("  " + "=" * 64)
    print("  screen time      : %s" % human_delta(d["screen_seconds"]))
    print("  domains looked up: %d unique" % d["unique_domains"])
    print("  blocked attempts : %s"
          % (red("%d hits / %d domains" % (d["blocked_hits"], d["blocked_unique"]))
             if d["blocked_hits"] else green("none")))
    byp = (d.get("bypass") or {}).get("dns_bypass_packets")
    if byp:
        print("  dns bypass drops : %d packets" % byp)
    if d["blocked"]:
        print("  " + "-" * 64)
        print("  blocked domains requested")
        for n, c in d["blocked"]:
            print("      %-46s %d" % (n, c))
    if d["apps"]:
        print("  " + "-" * 64)
        print("  applications open while you were at the machine")
        for n, sec in d["apps"]:
            print("      %-46s %s" % (n, human_delta(sec)))
    if args.domains and d["domains"]:
        print("  " + "-" * 64)
        print("  most looked-up domains")
        for n, c in d["domains"]:
            print("      %-46s %d" % (n, c))
    elif d["domains"]:
        print("  " + dim("  (--domains to list what was looked up)"))
    print("")
    return 0


# ==========================================================================
# Public status snapshot -- what the desktop app reads
# ==========================================================================

def public_status_doc(cfg: dict, st: dict) -> dict:
    rec = load_record() or {}
    sec = cfg.get("_secrets") or {}
    req = st.get("request") or {}
    mode = st.get("mode", "LOCKED")
    if mode == "PENDING":
        pass_req, pass_ok = passphrase_gate(cfg, st, req)
    else:
        pass_req = bool(cfg.get("require_passphrase", True)) and bool(
            sec.get("partner_passphrase") or rec.get("passphrase_set"))
        pass_ok = False
    doc = {
        "schema": 1,
        "version": VERSION,
        "app_name": cfg.get("app_name") or PROG,
        "generated_at": now(),
        "hostname": socket.gethostname(),
        "configured": True,
        "installed": os.path.exists(P(BIN_PATH)),
        "mode": mode,
        "owner_name": cfg.get("owner_name") or "",
        "owner_email": cfg.get("owner_email") or "",
        "approvers": list(cfg.get("approvers") or []),
        "approver_names": {str(k): str(v) for k, v in
                           (cfg.get("approver_names") or {}).items()},
        "transport": (cfg.get("transport") or "email").lower(),
        "channel_id": str((cfg.get("discord") or {}).get("channel_id") or ""),
        "approvals_required": int(cfg.get("approvals_required") or 1),
        "cooloff_hours": float(cfg.get("cooloff_hours") or 24),
        "unlock_minutes": int(cfg.get("unlock_minutes") or 60),
        "filter": cfg.get("filter"),
        "filter_label": FILTERS.get(cfg.get("filter"), {}).get("label", "?"),
        "passphrase_required": pass_req,
        "passphrase_satisfied": pass_ok,
        "passphrase_set": bool(sec.get("partner_passphrase") or rec.get("passphrase_set")),
        "passphrase_locked_until": float((st.get("passphrase") or {}).get("locked_until") or 0),
        "passphrase_fails": int((st.get("passphrase") or {}).get("fails") or 0),
        "recovery_enabled": bool(cfg.get("passphrase_recovery", True)),
        "passphrase_inert": passphrase_is_inert(cfg),
        "queued_emails": len(st.get("outbox") or []),
        "armed": bool(os.path.exists(P(UNIT_SERVICE)) and
                      (SANDBOX or systemctl("is-enabled", "pornblock.service")
                       .out.strip() == "enabled")),
        "tracking": _public_activity(cfg),
        "update": {
            "enabled": bool((cfg.get("updates") or {}).get("enabled", True)),
            "repo": (cfg.get("updates") or {}).get("repo", ""),
            "branch": (cfg.get("updates") or {}).get("branch", "main"),
            "auto_apply": bool((cfg.get("updates") or {}).get("auto_apply", True)),
            "interval_minutes": int(update_interval_seconds(cfg) // 60),
            "rolled_back": (st.get("update") or {}).get("rolled_back", ""),
            "installed_sha": (st.get("update") or {}).get("installed_sha", ""),
            "last_check": (st.get("update") or {}).get("last_check", 0),
            "last_applied": (st.get("update") or {}).get("last_applied", 0),
            "last_error": (st.get("update") or {}).get("last_error", ""),
            "available": {k: v for k, v in
                          ((st.get("update") or {}).get("available") or {}).items()
                          if k != "path"} or None,
        },
        "blocklist": {"domains": (st.get("blocklist") or {}).get("domains", 0),
                      "fetched_at": (st.get("blocklist") or {}).get("fetched_at", 0)},
        "history": [dict(h) for h in (st.get("history") or [])[-25:]],
        "request": None,
        "unlock": None,
        "health": [],
    }
    if mode == "PENDING" and req:
        doc["request"] = {
            "token": req.get("token"),
            "requested_at": req.get("requested_at"),
            "eligible_at": req.get("eligible_at"),
            "reason": req.get("reason") or "",
            "approvals": dict(req.get("approvals") or {}),
            "denials": dict(req.get("denials") or {}),
        }
    if mode == "UNLOCKED":
        doc["unlock"] = dict(st.get("unlock") or {})
    try:
        doc["health"] = [{"name": n, "ok": bool(o), "detail": d}
                         for n, o, d in health(cfg, st)]
    except Exception as exc:
        log("health probe failed: %r" % exc)
    return doc


def _public_activity(cfg: dict) -> dict:
    """Aggregates for the app. The full list of what you looked up stays
    root-only; seeing that costs an authentication prompt."""
    trk = cfg.get("tracking") or {}
    if not trk.get("enabled", True):
        return {"enabled": False}
    try:
        d = summarise_day(cfg, today_str())
    except Exception:
        return {"enabled": True, "error": True}
    return {
        "enabled": True,
        "day": d["day"],
        "screen_seconds": d["screen_seconds"],
        "apps": d["apps"][:8],
        "unique_domains": d["unique_domains"],
        "blocked_hits": d["blocked_hits"],
        "blocked_unique": d["blocked_unique"],
        "blocked": d["blocked"][:8],
        "bypass": d.get("bypass", {}),
        "digest_hour": int(trk.get("digest_hour") or 20),
        "dns_log": bool(trk.get("dns_log", True)),
    }


def write_public_status(cfg: dict, st: dict) -> None:
    """World-readable so the GUI never needs a password just to look."""
    try:
        doc = public_status_doc(cfg, st)
        os.makedirs(P(RUN_DIR), exist_ok=True)
        os.chmod(P(RUN_DIR), 0o755)
        atomic_write(P(PUBLIC_STATUS), dump_json(doc), 0o644)
    except OSError as exc:
        log("could not write public status: %s" % exc)


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
            m = re.search(r"Current DNS Server:\s*(\S+)", r.out or "")
            cur = m.group(1) if m else "?"
            allowed = set(FILTERS[cfg["filter"]]["ipv4"] +
                          FILTERS[cfg["filter"]]["ipv6"])
            detail += ", now using %s" % cur
            stray = _links_with_foreign_dns(cfg)
            if stray:
                ok = False
                detail += ", STRAY on " + ",".join(stray)
            elif cur not in allowed and cur != "?":
                ok = False
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
    discord = is_discord(cfg)
    if not discord and not valid_email(cfg.get("owner_email", "")):
        errs.append("owner_email is not a valid address")
    appr = [a for a in (cfg.get("approvers") or []) if a.strip()]
    if not appr:
        errs.append("you need at least one approver")
    for a in appr:
        if discord:
            if not str(a).isdigit() or len(str(a)) < 15:
                errs.append("approver %r is not a Discord user id - turn on "
                            "Developer Mode, right-click the person and use "
                            "Copy User ID" % a)
        elif not valid_email(a):
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
    if discord:
        d = cfg.get("discord") or {}
        if not str(d.get("channel_id") or "").isdigit():
            errs.append("discord.channel_id is required - right-click the "
                        "channel and use Copy Channel ID")
        if not (d.get("bot_token") or "").strip():
            errs.append("no Discord bot token stored - your friend needs to "
                        "paste it")
        return errs
    e = cfg.get("email") or {}
    for k in ("address", "smtp_host", "imap_host"):
        if not e.get(k):
            errs.append("email.%s is required" % k)
    if not e.get("smtp_password"):
        errs.append("no SMTP password stored - your friend needs to enter it")
    if not e.get("imap_password"):
        errs.append("no IMAP password stored - your friend needs to enter it")
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
        raw = (sys.stdin.read() if args.answers == "-"
               else open(args.answers, encoding="utf-8").read())
        try:
            cfg = deep_merge(cfg, json.loads(raw))
        except ValueError as exc:
            print(red("  answers are not valid JSON: %s" % exc))
            return 1
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

        print(bold("\n  Updates (optional)"))
        print("  A git URL to pull new versions from. Whoever controls it")
        print("  controls what runs as root here - a friend's fork is safer")
        print("  than your own. Leave blank to switch updates off.")
        cfg["updates"]["repo"] = _ask("Update repo URL",
                                      cfg["updates"].get("repo") or "")
        if cfg["updates"]["repo"]:
            cfg["updates"]["branch"] = _ask("Branch",
                                            cfg["updates"].get("branch") or "main")
        else:
            cfg["updates"]["enabled"] = False

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
        print(bold("\n  >>> HAND THE KEYBOARD TO YOUR FRIEND NOW <<<"))
        print("  They type the mailbox app password. You should not know it -")
        print("  if you do, you can log into the mailbox and approve yourself.")
        cfg["email"]["smtp_password"] = _ask("Mailbox app password (friend types this)",
                                             secret=True)
        cfg["email"]["imap_host"] = _ask("IMAP host", cfg["email"].get("imap_host") or ih or None)
        cfg["email"]["imap_port"] = _ask("IMAP port", cfg["email"].get("imap_port") or ip_, cast=int)
        cfg["email"]["imap_security"] = _ask("IMAP security (ssl/starttls)",
                                             cfg["email"].get("imap_security") or isec)
        cfg["email"]["imap_user"] = _ask("IMAP username", cfg["email"].get("imap_user")
                                         or cfg["email"]["address"])
        same = _ask("IMAP password same as SMTP? (y/n)", "y").lower().startswith("y")
        cfg["email"]["imap_password"] = (cfg["email"]["smtp_password"] if same
                                         else _ask("IMAP app password", secret=True))

        print(bold("\n  Partner passphrase (still your friend typing)"))
        print("  A third gate: even after the timer and the approvals, an")
        print("  unlock needs this typed in. Only they should know it.")
        while True:
            one = _ask("Partner passphrase", secret=True)
            two = _ask("Type it again", secret=True)
            if one != two:
                print(red("  they did not match"))
                continue
            if len(one) < 8:
                print(red("  use at least 8 characters"))
                continue
            cfg["partner_passphrase"] = one
            break

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

    # Secrets never go into config.json.
    sec = load_secrets()
    if cfg["email"].get("smtp_password"):
        sec["smtp_password"] = cfg["email"]["smtp_password"]
    if cfg["email"].get("imap_password"):
        sec["imap_password"] = cfg["email"]["imap_password"]
    if (cfg.get("discord") or {}).get("bot_token"):
        sec["discord_bot_token"] = cfg["discord"]["bot_token"]
    phrase = cfg.pop("partner_passphrase", None)
    if phrase:
        if len(phrase) < 8:
            print(red("  partner passphrase must be at least 8 characters"))
            return 1
        sec["partner_passphrase"] = hash_passphrase(phrase)
        del phrase
    save_secrets(sec)
    cfg["_secrets"] = sec
    save_config(cfg)
    log("setup written by %s" % (os.environ.get("SUDO_USER") or "root"))

    write_public_status(cfg, load_state())
    print(green("\n  Saved %s (0600)" % P(CONFIG_PATH)))
    print(green("  Secrets in %s (0600, immutable)" % P(SECRETS_PATH)))
    print("""
  %s
    approvers        : %s
    approvals needed : %d
    cool-off         : %s hours
    unlock window    : %s minutes
    resolver         : %s
    partner passcode : %s

  Next:
    1. %s test-email      <- prove %s works BEFORE you rely on it
    2. %s install         <- write units, enable, lock it down
""" % (bold("Summary"), people_list(cfg), cfg["approvals_required"],
       cfg["cooloff_hours"], cfg["unlock_minutes"], FILTERS[cfg["filter"]]["label"],
       "set by your friend" if sec.get("partner_passphrase") else "NOT SET",
       PROG, "the channel" if is_discord(cfg) else "email", PROG))

    if getattr(args, "install", False):
        print(bold("  continuing straight into install...\n"))
        return cmd_install(argparse.Namespace(refresh=False))
    return 0


def friendly_mail_error(text: str) -> str:
    """Turn a python exception string into something worth reading."""
    t = (text or "").lower()
    if "gaierror" in t or "name or service not known" in t:
        return ("no server by that name - check the host spelling. " + text)
    if "authenticationfailed" in t or "smtpauthenticationerror" in t \
            or "invalid credentials" in t or "authentication failed" in t:
        return ("the server refused that address and password. It has to be "
                "an app password made for this mailbox, not the account's "
                "normal one, and two-factor sign-in usually has to be on "
                "first. " + text)
    if "timeout" in t or "timed out" in t:
        return ("no answer from the server - wrong port, or something is "
                "blocking the connection. " + text)
    if "connectionrefused" in t or "connection refused" in t:
        return "the server refused the connection on that port. " + text
    if "sslerror" in t or "wrong_version_number" in t:
        return ("the secure connection failed - the security setting is "
                "probably wrong for that port. " + text)
    return text


def _discord_from_answers(args):
    """Shared by the two unprivileged Discord commands."""
    raw = sys.stdin.read() if args.answers == "-" else \
        open(args.answers, encoding="utf-8").read()
    ans = json.loads(raw)
    d = dict(DEFAULT_CONFIG["discord"])
    d.update(ans.get("discord") or ans or {})
    return ans, DiscordCourier({"discord": d})


def cmd_check_discord(args) -> int:
    """
    Try a bot token and channel. Needs no root, writes nothing, posts nothing.

    Checks the three things that actually go wrong: a token that is really the
    application id, a channel the bot was never invited to, and the Message
    Content switch nobody remembers to turn on.
    """
    try:
        _ans, dc = _discord_from_answers(args)
    except (OSError, ValueError) as exc:
        print("could not read the answers: %s" % exc)
        return 2
    ok = True
    try:
        print("Bot and channel: ok, %s" % dc.probe())
    except MailError as exc:
        print("Bot and channel failed: %s" % exc)
        return 1
    seen, blank, why = dc.content_evidence()
    if why:
        print("Reading the channel failed: %s" % why)
        print("  The bot needs Read Message History there. Use step 3 to add "
              "it again, or give its role that permission on the channel.")
        return 1
    if seen and blank < seen:
        print("Reading replies: ok, the bot really can read what people type")
    elif seen and blank == seen:
        print("Reading replies: NO - %d message(s) from people in that channel "
              "and every one arrived blank, which is exactly what a missing "
              "Message Content intent looks like. Open your application on "
              "discord.com/developers, go to Bot, switch on MESSAGE CONTENT "
              "INTENT, and press SAVE CHANGES at the bottom of that page.\n"
              "  Until then approvals still work if the person mentions the "
              "bot in the message - a message that mentions it always comes "
              "through." % seen)
        ok = False
    else:
        print("Reading replies: %s. Nobody has typed in that channel yet, so "
              "there is nothing to read back. Say anything there and press "
              "this again, or just carry on - the next step asks your friends "
              "to check in, and that proves it for real." % INCONCLUSIVE)
    return 0 if ok else 1


def cmd_discord_channels(args) -> int:
    """
    List the text channels the bot can see, so nobody has to turn on Developer
    Mode and copy an id. Unprivileged, reads only.
    """
    try:
        _ans, dc = _discord_from_answers(args)
    except (OSError, ValueError) as exc:
        print(dump_json({"error": "could not read the answers: %s" % exc}))
        return 2
    try:
        guilds = dc._call("GET", "/users/@me/guilds")
    except MailError as exc:
        print(dump_json({"error": str(exc),
                         "invite": invite_url(dc.d.get("bot_token") or "")}))
        return 1
    if not guilds:
        print(dump_json({
            "error": "this bot is not in any server yet",
            "invite": invite_url(dc.d.get("bot_token") or ""),
            "channels": []}))
        return 1
    out = []
    for g in guilds[:20]:
        try:
            chans = dc._call("GET", "/guilds/%s/channels" % g.get("id"))
        except MailError:
            continue
        for c in chans or []:
            if c.get("type") in (0, 5):           # text and announcement
                out.append({"id": str(c.get("id")), "name": c.get("name") or "",
                            "server": g.get("name") or "",
                            "position": int(c.get("position") or 0)})
    out.sort(key=lambda c: (c["server"], c["position"], c["name"]))
    print(dump_json({"channels": out}))
    return 0 if out else 1


def cmd_discord_people(args) -> int:
    """
    The people who have spoken in the channel lately.

    Who wrote a message is never hidden the way the message text can be, so
    this needs no privileged intent - and unlike the server member list, it
    needs no Server Members intent either.
    """
    try:
        _ans, dc = _discord_from_answers(args)
    except (OSError, ValueError) as exc:
        print(dump_json({"error": "could not read the answers: %s" % exc}))
        return 2
    try:
        msgs = dc._call("GET", "/channels/%s/messages?limit=100"
                        % dc._channel())
    except MailError as exc:
        print(dump_json({"error": str(exc), "people": []}))
        return 1
    people, order = {}, []
    for m in msgs or []:
        a = m.get("author") or {}
        uid = str(a.get("id") or "")
        if not uid or a.get("bot") or uid in people:
            continue
        people[uid] = {"id": uid,
                       "name": a.get("global_name") or a.get("username") or uid}
        order.append(uid)
    print(dump_json({"people": [people[u] for u in order]}))
    return 0 if people else 1


def cmd_discord_checkin(args) -> int:
    """
    Find out which Discord accounts your approvers are.

    Nobody has to copy an id, and - this is the part that was broken - nobody
    has to type anything the bot might not be allowed to read. A tap on the
    tick is enough, because a reaction carries a user id and no text at all.

    --post-only puts the question up and returns straight away. --collect
    reads who has answered so far. Between the two there is no deadline: the
    app keeps asking while you get on with something else.
    """
    try:
        _ans, dc = _discord_from_answers(args)
    except (OSError, ValueError) as exc:
        print(dump_json({"error": "could not read the answers: %s" % exc}))
        return 2

    word = (args.word or "").strip().upper() or secrets.token_hex(2).upper()
    started = float(args.since or 0) or now()

    def collect(since, message_id, dm_channels):
        """(who answered, why we could not look)"""
        found = {}
        if message_id:
            with contextlib.suppress(MailError):
                for uid in dc.who_pressed(message_id, TICK):
                    found.setdefault(uid, {"id": uid, "name": ""})
        for cid in dm_channels:
            with contextlib.suppress(MailError):
                msgs = dc._call("GET", "/channels/%s/messages?limit=20&after=%d"
                                % (cid, snowflake_at(since - 5)))
                for m in msgs or []:
                    a = m.get("author") or {}
                    if not a.get("bot"):
                        uid = str(a.get("id") or "")
                        found.setdefault(uid, {"id": uid, "name": ""})
        if not dm_channels:
            try:
                msgs = dc._call("GET", "/channels/%s/messages?limit=100&after=%d"
                                % (dc._channel(), snowflake_at(since - 5)))
            except MailError as exc:
                return found, str(exc)
            for m in msgs or []:
                a = m.get("author") or {}
                if a.get("bot"):
                    continue
                uid = str(a.get("id") or "")
                body = m.get("content") or ""
                # the word if we can read it, and otherwise the plain fact
                # that they said something right after being asked
                if not body or re.search(r"\b%s\b" % re.escape(word), body, re.I):
                    found.setdefault(uid, {"id": uid, "name": ""})
        return found, None

    def name_them(found):
        for uid in list(found):
            with contextlib.suppress(MailError, KeyError, TypeError):
                u = dc._call("GET", "/users/%s" % uid)
                found[uid]["name"] = (u.get("global_name") or u.get("username")
                                      or uid)
        return found

    # -- just read who has answered so far ---------------------------------
    if args.collect:
        dms = [c for c in (args.dm_channels or "").split(",") if c.strip()]
        found, why = collect(started, args.message_id, dms)
        if why and not found:
            print(dump_json({"error": why, "members": []}))
            return 1
        print(dump_json({"word": word, "members": list(name_them(found).values())}))
        return 0 if found else 1

    # -- put the question up -----------------------------------------------
    invite = ("**%s is setting up a porn blocker**\n"
              "They have asked you to be one of the people who can let them "
              "out of it. Tap %s if you are in."
              % (_ans.get("owner_name") or "Someone", TICK))
    dms, failed, message_id = {}, {}, ""
    targets = [t.strip() for t in (args.dm or "").split(",") if t.strip().isdigit()]
    if targets:
        for uid in targets:
            try:
                ch = dc._call("POST", "/users/@me/channels", {"recipient_id": uid})
                cid = str((ch or {}).get("id") or "")
                dc._call("POST", "/channels/%s/messages" % cid, {"content": invite})
                dms[uid] = cid
            except MailError as exc:
                failed[uid] = ("cannot send them a direct message - they "
                               "probably have messages from server members "
                               "switched off. %s" % exc)
        if not dms:
            print(dump_json({"error": "could not reach any of them privately",
                             "failed": failed, "members": []}))
            return 1
    else:
        try:
            message_id = dc.post(invite)
            if message_id:
                with contextlib.suppress(MailError):
                    dc._call("PUT", "/channels/%s/messages/%s/reactions/%s/@me"
                             % (dc._channel(), message_id,
                                urllib.parse.quote(TICK, safe="")))
        except MailError as exc:
            print(dump_json({"error": str(exc)}))
            return 1

    if args.post_only:
        print(dump_json({"word": word, "posted_at": started,
                         "message_id": message_id,
                         "dm_channels": ",".join(dms.values()),
                         "failed": failed, "private": bool(dms), "members": []}))
        return 0

    # -- or hang around and watch, for anyone driving this from a terminal --
    found, deadline = {}, started + max(10, int(args.wait or 120))
    while now() < deadline and len(found) < int(args.expect or 99):
        time.sleep(3)
        found, _why = collect(started, message_id, list(dms.values()))
    print(dump_json({"word": word, "members": list(name_them(found).values()),
                     "failed": failed, "private": bool(dms)}))
    return 0 if found else 1


def cmd_check_mailbox(args) -> int:
    """
    Try a set of mailbox credentials and say whether they work.

    Deliberately unprivileged and stateless: it reads the same JSON the setup
    wizard would install, logs in to SMTP and IMAP, sends nothing and writes
    nothing. The wizard calls it while the friend who knows the app password
    is still sitting there.
    """
    try:
        raw = sys.stdin.read() if args.answers == "-" else \
            open(args.answers, encoding="utf-8").read()
        ans = json.loads(raw)
    except (OSError, ValueError) as exc:
        print("could not read the answers: %s" % exc)
        return 2
    e = dict(DEFAULT_CONFIG["email"])
    e.update(ans.get("email") or ans or {})
    if not e.get("address"):
        print("no mailbox address given")
        return 2
    m = Mailer({"email": e})
    ok = True
    try:
        print("Sending (SMTP): ok, %s" % m.smtp_probe())
    except MailError as exc:
        print("Sending (SMTP) failed: %s" % friendly_mail_error(str(exc)))
        ok = False
    try:
        print("Reading replies (IMAP): ok, %s" % m.probe())
    except MailError as exc:
        print("Reading replies (IMAP) failed: %s" % friendly_mail_error(str(exc)))
        ok = False
    return 0 if ok else 1


def cmd_test_email(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("No config. Run: %s setup" % PROG))
        return 1
    st = load_state()
    ok = True

    if is_discord(cfg):
        dc = DiscordCourier(cfg)
        marker = secrets.token_hex(4).upper()
        print(bold("\n  1. Posting in the channel"))
        try:
            dc.send_now(everyone(cfg) if not args.no_approvers else [],
                        "test - you are an approver",
                        "%s set up ChristWatch on %s and named you as someone "
                        "who can let them out of it.\n\n"
                        "From now on this channel gets a message when they ask "
                        "to unlock, when anyone tampers with it, and every "
                        "evening with what happened on the machine.\n\n"
                        "Nothing to do right now. A real request will carry a "
                        "code and you answer with APPROVE <code> right here.\n\n"
                        "Test marker: %s"
                        % (who(cfg), socket.gethostname(), marker))
            print(green("     posted"))
        except MailError as exc:
            print(red("     POSTING FAILED: %s" % exc))
            ok = False
        print(bold("\n  2. Reading the channel back"))
        try:
            print(green("     " + dc.probe()))
        except MailError as exc:
            print(red("     FAILED: %s" % exc))
            ok = False
        seen, blank, why = dc.content_evidence()
        if why:
            print(red("     could not read the channel: %s" % why))
            ok = False
        elif seen and blank < seen:
            print(green("     the bot really can read what people type"))
        elif seen and blank == seen:
            print(red("     every message from a person arrives blank - "
                      "MESSAGE CONTENT INTENT is off. Switch it on under your "
                      "application, Bot, and press SAVE CHANGES."))
            ok = False
        else:
            print(yellow("     nobody has typed there yet, so there is "
                         "nothing to read back"))
        save_state(st)
        print(green("\n  Discord looks good.\n") if ok
              else red("\n  Discord is NOT working yet - fix it before installing.\n"))
        return 0 if ok else 1

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
        "passphrase_ok": False,
        "reason": args.reason or "",
    }
    st["mode"] = "PENDING"
    history(st, "unlock requested, code %s, eligible %s"
            % (token, stamp(st["request"]["eligible_at"])))
    subj, text, html = request_email(cfg, st)
    if args.reason:
        text = text.replace("\n\n  Cool-off", "\n\nTheir stated reason: %s\n\n  Cool-off"
                            % args.reason)
    if is_discord(cfg):
        sent = ensure_request_posted(cfg, st)
    else:
        sent = alert(cfg, st, "request", subj, text, html, force=True)
    write_public_status(cfg, st)
    save_state(st)

    print(green("\n  Request sent.") if sent
          else yellow("\n  Request recorded, but the email could not go out yet "
                      "(queued for retry)."))
    print("""
    code            : %s
    cool-off ends   : %s
    approvals needed: %d of %d

  Your friends approve by %-17s %s
  You can back out at any time with      %s cancel
""" % (token, stamp(st["request"]["eligible_at"]), int(cfg["approvals_required"]),
       len(cfg["approvers"]),
       "tapping the tick under" if is_discord(cfg) else "replying",
       "the message in the channel" if is_discord(cfg) else "APPROVE " + token,
       PROG))
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
    write_public_status(cfg, st)
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
        if getattr(args, "json", False):
            print(dump_json({"schema": 1, "configured": False}))
            return 0
        print(red("Not configured. Run: sudo %s setup" % PROG))
        return 1
    st = load_state()
    cfg, notes = reconcile_record(cfg, st)
    if getattr(args, "json", False):
        doc = public_status_doc(cfg, st)
        write_public_status(cfg, st)
        save_state(st)
        print(dump_json(doc))
        return 0
    mode = st["mode"]
    colour = {"LOCKED": green, "PENDING": yellow, "UNLOCKED": red}[mode]

    print("")
    print(bold("  pornblock %s" % VERSION) + dim("   host %s%s"
          % (socket.gethostname(), "   [SANDBOX %s]" % PREFIX if SANDBOX else "")))
    print("  " + "=" * 68)
    print("  mode               : %s" % colour(mode))
    if mode == "LOCKED":
        print("  " + dim("blocking is on; nothing pending"))
    print("  contact            : %s" % (
        ("Discord channel %s" % ((cfg.get("discord") or {}).get("channel_id")
                                 or "?")) if is_discord(cfg)
        else "email via %s" % (cfg["email"].get("address") or "?")))
    print("  approvers          : %s" % people_list(cfg))
    print("  approvals required : %d of %d" % (int(cfg["approvals_required"]),
                                               len(cfg["approvers"])))
    print("  cool-off           : %s hours" % cfg["cooloff_hours"])
    print("  unlock window      : %s minutes" % cfg["unlock_minutes"])
    print("  resolver           : %s" % FILTERS[cfg["filter"]]["label"])
    if passphrase_is_inert(cfg):
        print("  " + yellow("note") + "               : every quorum here is unanimous, so the")
        print("  " + dim("                     passphrase gate is satisfied automatically."))
        print("  " + dim("                     Add an approver, or turn the recovery rule off."))

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
            print("      %s %-34s %s" % (mark, display_name(cfg, a), dim(when)))
        pass_req, pass_ok = passphrase_gate(cfg, st, req)
        if pass_req:
            print("  partner passphrase : %s"
                  % (green("entered") if pass_ok else yellow("not entered yet")))
            if pass_ok and not req.get("passphrase_ok"):
                print("  " + dim("    (satisfied by unanimous approval)"))
        blockers = []
        if left > 0:
            blockers.append("the %s timer" % human_delta(left))
        if len(got) < need:
            blockers.append("%d more approval(s)" % (need - len(got)))
        if pass_req and not pass_ok:
            blockers.append("the partner passphrase")
        print("  still waiting on   : %s" % (yellow(" and ".join(blockers))
                                             if blockers else green("nothing - unlocking")))
    elif mode == "UNLOCKED":
        unl = st["unlock"]
        print("  " + "-" * 68)
        print("  " + red("BLOCKING IS OFF"))
        print("  granted            : %s" % stamp(unl["granted_at"]))
        print("  re-locks at        : %s" % stamp(unl["expires_at"]))
        print("  window remaining   : %s" % red(human_delta(unl["expires_at"] - now())))
        print("  approved by        : %s"
              % ", ".join(display_name(cfg, a)
                          for a in unl.get("approved_by") or []))

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
    write_public_status(cfg, st)
    save_state(st)
    return 0


def _vtuple(v: str) -> tuple:
    nums = tuple(int(x) for x in re.findall(r"\d+", v or "")[:4])
    return nums or (0,)


def installed_version() -> str:
    try:
        with open(P(BIN_PATH), encoding="utf-8", errors="replace") as fh:
            m = re.search(r'^VERSION\s*=\s*"([^"]+)"', fh.read(), re.M)
        return m.group(1) if m else ""
    except OSError:
        return ""


def install_program_files(cfg: dict, immutable: bool) -> list:
    """
    Put the program, the desktop app, its launcher and its icon in place.

    Shared by `install-app` (just the files, nothing armed, nothing locked)
    and `install` (same files, plus chattr +i once there is something worth
    protecting).
    """
    msgs = []
    src = os.path.abspath(__file__)
    with open(src, encoding="utf-8") as fh:
        core = fh.read()

    # A package upgrade must not walk back over a newer in-app update.
    have = installed_version()
    if have and _vtuple(have) > _vtuple(VERSION):
        msgs.append("kept the installed %s; this copy is only %s" % (have, VERSION))
        with open(P(BIN_PATH), encoding="utf-8", errors="replace") as fh:
            core = fh.read()

    write_managed(SELF_COPY, core, 0o600, immutable, backup=False)
    write_managed(BIN_PATH, core, 0o755, immutable, backup=False)
    msgs.append("installed %s" % P(BIN_PATH))

    gui_src = None
    cand = os.path.join(os.path.dirname(src), "pornblock_gui.py")
    for path in (cand, P(GUI_SELF_COPY)):
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                gui_src = fh.read()
            break
    if gui_src:
        write_managed(GUI_SELF_COPY, gui_src, 0o600, immutable, backup=False)
        write_managed(GUI_BIN_PATH, gui_src, 0o755, immutable, backup=False)
        write_managed(DESKTOP_PATH, desktop_entry(cfg), 0o644, immutable, backup=False)
        write_managed(ICON_PATH, icon_svg(), 0o644, immutable, backup=False)
        msgs.append("desktop app '%s' installed" % (cfg.get("app_name") or PROG))
        if not SANDBOX:
            run(["update-desktop-database", os.path.dirname(DESKTOP_PATH)], timeout=60)
            run(["gtk-update-icon-cache", "-f", "-t", "/usr/share/icons/hicolor"],
                timeout=60)
    else:
        msgs.append("pornblock_gui.py not found - desktop app not installed")
    return msgs


def detect_origin(src_dir: str) -> dict:
    """If this copy is a git checkout, note its remote so the wizard can
    offer it as the update source."""
    r = run(["git", "-C", src_dir, "remote", "get-url", "origin"], timeout=20)
    if not r.ok or not r.out.strip():
        return {}
    url = r.out.strip()
    b = run(["git", "-C", src_dir, "rev-parse", "--abbrev-ref", "HEAD"], timeout=20)
    branch = b.out.strip() if b.ok else ""
    if branch in ("", "HEAD"):
        branch = "main"
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url.split(":", 1)[1]
    return {"repo": url.removesuffix(".git"), "branch": branch}


def write_source_hint(hint: dict) -> None:
    if not hint:
        return
    try:
        os.makedirs(P(RUN_DIR), exist_ok=True)
        os.chmod(P(RUN_DIR), 0o755)
        atomic_write(P(SOURCE_HINT), dump_json(hint), 0o644)
    except OSError as exc:
        log("could not write the source hint: %s" % exc)


def cmd_install_app(args) -> int:
    """
    Stage one: put the app on the machine. Nothing is blocked, nothing is
    made immutable, no config is needed. Arming happens in the wizard.
    """
    require_root()
    for d, mode in ((ETC_DIR, 0o700), (STATE_DIR, 0o700), (BACKUP_DIR, 0o700)):
        os.makedirs(P(d), exist_ok=True)
        os.chmod(P(d), mode)
    cfg = load_config() or json.loads(json.dumps(DEFAULT_CONFIG))
    for m in install_program_files(cfg, immutable=False):
        print(green("  " + m))
    hint = detect_origin(os.path.dirname(os.path.abspath(__file__)))
    if hint:
        write_source_hint(hint)
        print(green("  update source offered to the wizard: %s (%s)"
                    % (hint["repo"], hint["branch"])))
    if not SANDBOX:
        probe = run([sys.executable, "-c", "import gi;"
                     "gi.require_version('Gtk','4.0');"
                     "gi.require_version('Adw','1');"
                     "from gi.repository import Gtk, Adw"], timeout=30)
        if not probe.ok:
            print(yellow("\n  The desktop app needs GTK4 + libadwaita:"))
            print(yellow("      sudo dnf install python3-gobject gtk4 libadwaita"))
    print(green("\n  Installed. Nothing is blocked yet.\n"))
    print("  Open '%s' from your app menu to set it up," % (cfg.get("app_name") or PROG))
    print("  or run:  sudo %s setup\n" % PROG)
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

    for m in install_program_files(cfg, immutable=True):
        print(green("  " + m))

    for ch in write_units():
        print(green("  " + ch))
    systemctl("daemon-reload")

    save_record(record_from_config(cfg))
    print(green("  install record written and made immutable"))
    src = os.path.abspath(__file__)
    sha = current_source_sha()
    if sha:
        st.setdefault("update", {})["installed_sha"] = sha
        print("  installed from commit %s" % sha[:12])

    print("  fetching blocklist...")
    res = refresh_blocklist(cfg, st, force=args.refresh)
    refresh_safesearch_ips(cfg, st)
    print("  blocklist: %s (%d domains)" % (res, len(blocklist_domains())))

    apply = st.get("mode") != "UNLOCKED"
    for ch in enforce_all(cfg, st, apply, quiet=True):
        print("  " + ch)

    systemctl("enable", "--now", "pornblock-watchdog.timer")
    systemctl("enable", "--now", "pornblock.service")
    write_public_status(cfg, st)
    save_state(st)

    print(green("\n  Installed and enabled.\n"))
    print("  Check it with:   sudo %s status" % PROG)
    print("  Or open '%s' from your app menu."
          % (cfg.get("app_name") or PROG))
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
                 SECRETS_PATH, SELF_COPY, GUI_SELF_COPY, BIN_PATH,
                 GUI_BIN_PATH, DESKTOP_PATH, ICON_PATH, PUBLIC_STATUS):
        remove_managed(path)
    if not SANDBOX:
        run(["update-desktop-database", os.path.dirname(DESKTOP_PATH)], timeout=60)
        run(["gtk-update-icon-cache", "-f", "-t", "/usr/share/icons/hicolor"],
            timeout=60)

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
    post = courier(cfg)
    post.flush_outbox(st)

    bl = refresh_blocklist(cfg, st)
    if bl == "refreshed" or not (st.get("blocklist") or {}).get("safesearch_ips"):
        refresh_safesearch_ips(cfg, st)

    moves = advance(cfg, st, post)
    apply = st.get("mode") != "UNLOCKED"
    quiet = bool(moves) or bool(notes) or bl == "refreshed" or not st.get("enforced_once")
    changes = enforce_all(cfg, st, apply, quiet=quiet)
    guard_units(cfg, st)
    try:
        sample_activity(cfg, st)
        maybe_digest(cfg, st, post)
    except Exception as exc:                      # tracking must never wedge it
        log("activity sampling failed: %r" % exc)
    post.flush_outbox(st)
    write_public_status(cfg, st)
    save_state(st)
    maybe_update(cfg, st)
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
    write_public_status(cfg, st)
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


# ==========================================================================
# Updating from git
# ==========================================================================

def _github_tarball_url(repo: str, branch: str):
    m = re.match(r"https?://github\.com/([^/\s]+)/([^/\s.]+)", (repo or "").strip())
    if not m:
        return None
    return "https://codeload.github.com/%s/%s/tar.gz/refs/heads/%s" % (
        m.group(1), m.group(2), branch)


def remote_head_sha(cfg: dict) -> str:
    """The branch head, without downloading anything. Empty when unknown."""
    up = cfg.get("updates") or {}
    repo = (up.get("repo") or "").strip()
    branch = (up.get("branch") or "main").strip()
    if not repo or not shutil.which("git"):
        return ""
    r = run(["git", "ls-remote", "--heads", repo, branch], timeout=60)
    if not r.ok or not r.out.strip():
        return ""
    return r.out.split()[0].strip()


def update_interval_seconds(cfg: dict) -> float:
    up = cfg.get("updates") or {}
    if up.get("check_minutes") is not None:
        return max(60.0, float(up["check_minutes"]) * 60.0)
    return max(60.0, float(up.get("check_hours") or 24) * 3600.0)


def fetch_source(cfg: dict, dest: str) -> tuple:
    """Download the pinned repo into `dest`. Returns (ok, sha, subject, err)."""
    up = cfg.get("updates") or {}
    repo = (up.get("repo") or "").strip()
    branch = (up.get("branch") or "main").strip()
    if not repo:
        return False, "", "", "no update repo is configured"

    err = ""
    if shutil.which("git"):
        r = run(["git", "clone", "--quiet", "--depth", "1", "--branch", branch,
                 repo, dest], timeout=240)
        if r.ok:
            sha = run(["git", "-C", dest, "rev-parse", "HEAD"], timeout=30).out.strip()
            subj = run(["git", "-C", dest, "log", "-1", "--pretty=%s"],
                       timeout=30).out.strip()
            return True, sha, subj, ""
        err = "git clone failed: " + (r.err.strip()[:200] or "unknown")
        shutil.rmtree(dest, ignore_errors=True)
    else:
        err = "git is not installed"

    url = _github_tarball_url(repo, branch)
    if not url:
        return False, "", "", err
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pornblock/" + VERSION})
        with urllib.request.urlopen(req, timeout=180) as resp:
            blob = resp.read()
        raw = dest + ".raw"
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            first = next((m.name for m in tf.getmembers() if m.name), "")
            root = first.split("/")[0]
            tf.extractall(raw, filter="data")
        shutil.move(os.path.join(raw, root), dest)
        shutil.rmtree(raw, ignore_errors=True)
        return True, "tarball@" + branch, "", ""
    except Exception as exc:                       # noqa: BLE001 - never fatal
        return False, "", "", "%s; tarball fetch failed: %s" % (err, exc)


def verify_source(dest: str) -> tuple:
    """
    Decide whether a downloaded candidate is safe to run as root.
    Returns (ok, version, error).  A candidate that cannot compile, or that
    fails its own self-test, is refused.
    """
    main = os.path.join(dest, "pornblock.py")
    if not os.path.exists(main):
        return False, "", "the download contains no pornblock.py"
    r = run([sys.executable, "-m", "py_compile", main], timeout=120)
    if not r.ok:
        return False, "", "the new pornblock.py does not compile"
    try:
        with open(main, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
    except OSError as exc:
        return False, "", str(exc)
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', body, re.M)
    if not m:
        return False, "", "the new pornblock.py declares no VERSION"
    newver = m.group(1)

    selftest = os.path.join(dest, "selftest.py")
    if os.path.exists(selftest):
        box = tempfile.mkdtemp(prefix="pb-update-check-")
        env = dict(os.environ, PORNBLOCK_PREFIX=box)
        env.pop("PYTHONPATH", None)
        r = run([sys.executable, selftest], timeout=420, env=env, cwd=dest)
        shutil.rmtree(box, ignore_errors=True)
        if not r.ok:
            tail = (r.out or r.err or "").strip().splitlines()[-6:]
            return False, newver, ("the new version fails its own self-test, so "
                                   "it will not be installed:\n  "
                                   + "\n  ".join(tail))
    return True, newver, ""


def current_source_sha() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    r = run(["git", "-C", here, "rev-parse", "HEAD"], timeout=20)
    return r.out.strip() if r.ok else ""


def apply_update(cfg: dict, st: dict, dest: str, sha: str, subject: str,
                 newver: str) -> list:
    done = []
    with open(os.path.join(dest, "pornblock.py"), encoding="utf-8") as fh:
        core = fh.read()

    # Keep what we are replacing, and keep the current lock state.
    imm = is_immutable(P(BIN_PATH)) if os.path.exists(P(BIN_PATH)) else True
    previous = None
    if os.path.exists(P(BIN_PATH)):
        with open(P(BIN_PATH), encoding="utf-8", errors="replace") as fh:
            previous = fh.read()
        write_managed(PREV_COPY, previous, 0o600, imm, backup=False)

    write_managed(SELF_COPY, core, 0o600, imm, backup=False)
    write_managed(BIN_PATH, core, 0o755, imm, backup=False)

    # The self-test proved the code is sane in a sandbox. This proves it can
    # actually run on THIS machine before we hand the daemon over to it.
    if previous is not None:
        broken = ""
        for probe in (["--version"], ["status", "--json"]):
            r = run([P(BIN_PATH)] + probe, timeout=180)
            if not r.ok:
                broken = "%s exited %d: %s" % (" ".join(probe), r.rc,
                                               (r.err or r.out).strip()[:200])
                break
        if broken:
            write_managed(SELF_COPY, previous, 0o600, imm, backup=False)
            write_managed(BIN_PATH, previous, 0o755, imm, backup=False)
            st.setdefault("update", {})["rolled_back"] = "%s (%s)" % (newver, broken)
            st["update"]["last_error"] = "rolled back %s: %s" % (newver, broken)
            history(st, "rolled back %s - it would not run: %s" % (newver, broken))
            alert(cfg, st, "update_rolled_back",
                  "An update was rolled back",
                  "%s pulled version %s onto %s. It passed the self-test but "
                  "would not run here:\n\n  %s\n\nThe previous version has "
                  "been put back and blocking is unaffected.\n"
                  % (cfg.get("app_name") or PROG, newver, socket.gethostname(),
                     broken), force=True)
            save_state(st)
            return ["rolled back %s - it would not run here" % newver]
    done.append("core updated to %s" % newver)

    gui_path = os.path.join(dest, "pornblock_gui.py")
    if os.path.exists(gui_path):
        with open(gui_path, encoding="utf-8") as fh:
            gui = fh.read()
        write_managed(GUI_SELF_COPY, gui, 0o600, True, backup=False)
        write_managed(GUI_BIN_PATH, gui, 0o755, True, backup=False)
        write_managed(DESKTOP_PATH, desktop_entry(cfg), 0o644, True, backup=False)
        write_managed(ICON_PATH, icon_svg(), 0o644, True, backup=False)
        done.append("desktop app updated")

    for ch in write_units():
        done.append(ch)
    systemctl("daemon-reload")

    upd = st.setdefault("update", {})
    upd["installed_sha"] = sha
    upd["last_applied"] = now()
    upd["available"] = None
    upd["last_error"] = ""
    history(st, "updated to %s (%s)" % (newver, sha[:12] or "?"))

    alert(cfg, st, "updated", "%s was updated to %s" % (cfg.get("app_name") or PROG, newver),
          "%s on %s just installed an update pulled from:\n\n"
          "  %s (%s)\n  commit %s\n  %s\n\n"
          "The new code passed its own self-test before being installed, but "
          "understand what this means: whoever controls that repository "
          "controls what runs as root on this machine. If that is %s and this "
          "update was not something you expected, ask about it.\n"
          % (cfg.get("app_name") or PROG, socket.gethostname(),
             (cfg.get("updates") or {}).get("repo"),
             (cfg.get("updates") or {}).get("branch"),
             sha[:12] or "?", subject or "(no commit subject)", who(cfg)),
          force=True)
    save_state(st)
    return done


def check_for_update(cfg: dict, st: dict, quiet: bool = True) -> dict:
    """Fetch and evaluate, without installing. Returns the availability dict."""
    upd = st.setdefault("update", {})
    upd["last_check"] = now()
    dest = tempfile.mkdtemp(prefix="pb-update-") + "/src"
    try:
        ok, sha, subject, err = fetch_source(cfg, dest)
        if not ok:
            upd["last_error"] = err
            if not quiet:
                print(red("  " + err))
            return None
        try:
            with open(os.path.join(dest, "pornblock.py"), encoding="utf-8") as fh:
                candidate = fh.read()
        except OSError as exc:
            upd["last_error"] = str(exc)
            return None
        current = ""
        for path in (P(SELF_COPY), os.path.abspath(__file__)):
            if os.path.exists(path):
                with open(path, encoding="utf-8", errors="replace") as fh:
                    current = fh.read()
                break
        if candidate == current:
            upd["available"] = None
            upd["last_error"] = ""
            if not quiet:
                print(green("  already up to date"))
            return None
        good, newver, verr = verify_source(dest)
        if not good:
            upd["available"] = None
            upd["last_error"] = verr
            if not quiet:
                print(red("  " + verr))
            log("update candidate rejected: %s" % verr.replace("\n", " "))
            return None
        upd["available"] = {"version": newver, "sha": sha, "subject": subject,
                            "checked_at": now(), "path": dest}
        upd["last_error"] = ""
        if not quiet:
            print(green("  update available: %s (%s) %s"
                        % (newver, sha[:12] or "?", subject)))
        return upd["available"]
    finally:
        pass


def maybe_update(cfg: dict, st: dict) -> None:
    """Daily availability check from the daemon; applies only if asked to."""
    up = cfg.get("updates") or {}
    if not up.get("enabled", True) or not (up.get("repo") or "").strip():
        return
    if st.get("mode") == "PENDING":
        return
    every = update_interval_seconds(cfg)
    upd = st.setdefault("update", {})
    last = float(upd.get("last_check") or 0)
    if now() - last < every:
        return
    head = remote_head_sha(cfg)
    if head and head == (upd.get("last_remote_sha") or "") \
            and not upd.get("available"):
        upd["last_check"] = now()          # nothing has moved; no download
        save_state(st)
        return
    try:
        avail = check_for_update(cfg, st)
        if head:
            st.setdefault("update", {})["last_remote_sha"] = head
    except Exception as exc:                       # never take the loop down
        log("update check blew up: %r" % exc)
        st.setdefault("update", {})["last_error"] = repr(exc)
        avail = None
    save_state(st)
    if not avail or not up.get("auto_apply"):
        if avail:
            log("update %s is available; waiting to be applied by hand"
                % avail.get("version"))
        return
    unl = st.get("unlock") or {}
    if up.get("require_unlock") and not (st.get("mode") == "UNLOCKED" and
                                         now() < float(unl.get("expires_at") or 0)):
        return
    try:
        apply_update(cfg, st, avail["path"], avail["sha"],
                     avail.get("subject", ""), avail["version"])
        write_public_status(cfg, st)
        save_state(st)
        systemctl("restart", "pornblock.service")   # replaces this process
    except Exception as exc:
        log("applying the update failed: %r" % exc)


def cmd_update_source(args) -> int:
    """Point the updater at a repo (or switch it off) without editing JSON."""
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("No config. Run: sudo %s setup" % PROG))
        return 1
    st = load_state()
    up = cfg.setdefault("updates", {})
    if args.off:
        up["repo"] = ""
        up["enabled"] = False
    else:
        url = (args.url or "").strip()
        if not re.match(r"(https?://|git@|/|file://)", url):
            print(red("  that does not look like a git URL"))
            return 1
        up["repo"] = url
        up["branch"] = args.branch
        up["enabled"] = True
    wanted = str(up.get("repo") or "")      # copy: reconcile mutates in place
    save_config(cfg)
    cfg, notes = reconcile_record(cfg, st)
    save_config(cfg)
    save_state(st)
    write_public_status(cfg, st)
    for n in notes:
        print(("  " + n) if "accepted" in n else red("  " + n))
    live = str((cfg.get("updates") or {}).get("repo") or "")
    if live == wanted:
        print(green("\n  Update source is now: %s (%s)\n"
                    % (live or "(none)", cfg["updates"].get("branch") or "main")))
        return 0
    print(red("""
  Refused. It is still %s.

  The source is pinned in the immutable install record. Repointing it would
  let you feed this machine any code you liked, so it only changes during a
  granted unlock window.
""" % (live or "(none)")))
    return 1


def cmd_update(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("No config. Run: sudo %s setup" % PROG))
        return 1
    st = load_state()
    cfg, _ = reconcile_record(cfg, st)
    up = cfg.get("updates") or {}

    if not up.get("enabled", True):
        print(yellow("  Updates are switched off in the config."))
        return 1
    if not (up.get("repo") or "").strip():
        print(yellow("""
  No update repo is configured.

  Put your GitHub URL in /etc/pornblock/config.json:

      "updates": { "enabled": true, "repo": "https://github.com/you/porn-block",
                   "branch": "main" }

  then run install once so it is pinned into the install record.
"""))
        return 1

    unl = st.get("unlock") or {}
    unlocked = (st.get("mode") == "UNLOCKED"
                and now() < float(unl.get("expires_at") or 0))
    if st.get("mode") == "PENDING" and not args.check:
        print(red("  Not while an unlock request is open - you do not get to "
                  "update your way out mid-request."))
        return 1
    if up.get("require_unlock", False) and not unlocked and not args.check:
        print(red("  This install requires an unlock window before an update "
                  "can be applied."))
        return 1

    print("  checking %s (%s)..." % (up.get("repo"), up.get("branch")))
    avail = check_for_update(cfg, st, quiet=False)
    if not avail:
        save_state(st)
        write_public_status(cfg, st)
        return 0 if not (st.get("update") or {}).get("last_error") else 1
    if args.check:
        save_state(st)
        write_public_status(cfg, st)
        print("  run '%s update' to install it" % PROG)
        return 0

    print("  self-test passed; installing...")
    for line in apply_update(cfg, st, avail["path"], avail["sha"],
                             avail.get("subject", ""), avail["version"]):
        print(green("  " + line))
    write_public_status(cfg, st)
    save_state(st)
    systemctl("restart", "pornblock.service")
    print(green("\n  Updated to %s. Your approvers were emailed.\n"
                % avail["version"]))
    return 0


def _read_phrase(args, prompt: str, confirm: bool = False):
    """Read a passphrase from stdin (GUI) or a TTY (terminal)."""
    if getattr(args, "stdin", False):
        data = sys.stdin.read()
        return data.split("\n", 1)[0]
    try:
        one = getpass.getpass(prompt + ": ")
    except EOFError:
        return None
    if confirm:
        try:
            two = getpass.getpass("Type it again: ")
        except EOFError:
            return None
        if one != two:
            print(red("  they did not match"))
            return None
    return one


def cmd_passphrase(args) -> int:
    require_root()
    cfg = load_config()
    if not cfg:
        print(red("No config. Run: sudo %s setup" % PROG))
        return 1
    st = load_state()
    sec = cfg["_secrets"]
    rec = load_record() or {}

    if args.set:
        already = bool(sec.get("partner_passphrase") or rec.get("passphrase_set"))
        unl = st.get("unlock") or {}
        unlocked = (st.get("mode") == "UNLOCKED"
                    and now() < float(unl.get("expires_at") or 0))
        if already and not unlocked:
            print(red("""
  REFUSED.

  A partner passphrase is already set. Changing it is only possible during a
  granted unlock window - otherwise you could just overwrite your friend's
  secret whenever you felt like it.
"""))
            alert(cfg, st, "passphrase_change_refused",
                  "Someone tried to change the partner passphrase",
                  "A change to the partner passphrase was attempted on %s while "
                  "the blocker was %s. It was refused.\n"
                  % (socket.gethostname(), st.get("mode")))
            save_state(st)
            return 1
        phrase = _read_phrase(args, "New partner passphrase", confirm=not args.stdin)
        if not phrase:
            print(red("  nothing set"))
            return 1
        if len(phrase) < 8:
            print(red("  use at least 8 characters"))
            return 1
        sec["partner_passphrase"] = hash_passphrase(phrase)
        save_secrets(sec)
        if rec:
            rec["passphrase_set"] = True
            rec["require_passphrase"] = bool(cfg.get("require_passphrase", True))
            save_record(rec)
        history(st, "partner passphrase set")
        alert(cfg, st, "passphrase_set", "A partner passphrase was set",
              "A partner passphrase was set on %s. From now on an unlock needs "
              "the cool-off, %s approval(s) AND this passphrase typed in.\n\n"
              "Whoever set it should be the only one who knows it.%s\n"
              % (socket.gethostname(), cfg.get("approvals_required"),
                 ("\n\nIf it is ever lost, unanimous approval from all %d of you "
                  "unlocks without it." % len(cfg.get("approvers") or []))
                 if cfg.get("passphrase_recovery", True) else ""), force=True)
        cfg["_secrets"] = sec
        write_public_status(cfg, st)
        save_state(st)
        print(green("\n  Partner passphrase stored (hashed, never in plain text).\n"))
        return 0

    # --- verifying against an open request -------------------------------
    if st.get("mode") != "PENDING":
        print(yellow("  No open unlock request, so there is nothing to unlock "
                     "with a passphrase. Current mode: %s" % st.get("mode")))
        return 1
    pp = st.setdefault("passphrase", {"fails": 0, "locked_until": 0})
    if now() < float(pp.get("locked_until") or 0):
        print(red("  Too many wrong attempts. Try again in %s."
                  % human_delta(float(pp["locked_until"]) - now())))
        return 1
    req = st["request"]
    if req.get("passphrase_ok"):
        print(green("  Already entered for this request."))
        return 0
    if not sec.get("partner_passphrase"):
        print(red("""
  The stored passphrase is gone, so nothing you type can match it.

  This cannot be repaired from here - that is the point. The remaining route
  is unanimous approval from every approver.
"""))
        return 1

    phrase = _read_phrase(args, "Partner passphrase")
    if verify_passphrase(sec.get("partner_passphrase"), phrase or ""):
        req["passphrase_ok"] = True
        pp["fails"] = 0
        history(st, "partner passphrase accepted for %s" % req.get("token"))
        alert(cfg, st, "passphrase_ok", "The partner passphrase was entered",
              "The partner passphrase for request %s on %s has been entered.\n\n"
              "If you did not give it to %s, say so now.\n"
              % (req.get("token"), socket.gethostname(), who(cfg)), force=True)
        print(green("\n  Accepted. The passphrase gate is now satisfied.\n"))
        rc = 0
    else:
        pp["fails"] = int(pp.get("fails") or 0) + 1
        history(st, "WRONG partner passphrase (attempt %d)" % pp["fails"])
        if pp["fails"] >= 5:
            pp["locked_until"] = now() + 900
            pp["fails"] = 0
            alert(cfg, st, "passphrase_lockout",
                  "Five wrong partner-passphrase attempts",
                  "There have been five wrong partner-passphrase attempts on "
                  "%s. Entry is locked for 15 minutes.\n\nIf %s is guessing at "
                  "it, that is worth knowing.\n"
                  % (socket.gethostname(), who(cfg)), force=True)
            print(red("\n  Wrong. Locked out for 15 minutes; your approvers "
                      "have been told.\n"))
        else:
            alert(cfg, st, "passphrase_fail",
                  "Wrong partner passphrase entered",
                  "A wrong partner passphrase was entered on %s (attempt %d of "
                  "5 before lockout).\n" % (socket.gethostname(), pp["fails"]))
            print(red("\n  Wrong passphrase. Attempt %d of 5.\n" % pp["fails"]))
        rc = 1
    write_public_status(cfg, st)
    save_state(st)
    return rc


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
    s.add_argument("--answers",
                   help="JSON file of answers, or '-' for stdin (non-interactive)")
    s.add_argument("--install", action="store_true",
                   help="run install straight afterwards (one auth prompt)")
    s.set_defaults(fn=cmd_setup)

    s = sub.add_parser("install-app",
                       help="stage one: put the app on the machine, block nothing")
    s.set_defaults(fn=cmd_install_app)

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
    s.add_argument("--json", action="store_true",
                   help="print the machine-readable snapshot instead")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("passphrase",
                       help="enter the partner passphrase, or --set a new one")
    s.add_argument("--set", action="store_true",
                   help="set it (only when none exists, or during an unlock)")
    s.add_argument("--stdin", action="store_true",
                   help="read the passphrase from stdin instead of prompting")
    s.set_defaults(fn=cmd_passphrase)

    s = sub.add_parser("request-unlock", help="start the cool-off and email your friends")
    s.add_argument("--yes", action="store_true", help="skip the typed confirmation")
    s.add_argument("--reason", default="", help="tell your approvers why")
    s.set_defaults(fn=cmd_request)

    s = sub.add_parser("cancel", help="withdraw a request / end an unlock early")
    s.set_defaults(fn=cmd_cancel)

    s = sub.add_parser("check-discord",
                       help="try a bot token and channel (no root, posts nothing)")
    s.add_argument("--answers", default="-",
                   help="JSON file with a discord block, or - for stdin")
    s.set_defaults(fn=cmd_check_discord)

    s = sub.add_parser("discord-channels",
                       help="list the channels the bot can see")
    s.add_argument("--answers", default="-")
    s.set_defaults(fn=cmd_discord_channels)

    s = sub.add_parser("discord-checkin",
                       help="ask the channel who the approvers are")
    s.add_argument("--answers", default="-")
    s.add_argument("--word", default="", help="the word to watch for")
    s.add_argument("--wait", type=int, default=120, help="seconds to listen")
    s.add_argument("--expect", type=int, default=99,
                   help="stop early once this many people have checked in")
    s.add_argument("--dm", default="",
                   help="comma separated user ids to ask privately instead of "
                        "asking in the channel")
    s.add_argument("--post-only", action="store_true",
                   help="ask, then return at once - collect the answers later")
    s.add_argument("--collect", action="store_true",
                   help="read who has answered so far and return at once")
    s.add_argument("--message-id", default="", help="with --collect")
    s.add_argument("--dm-channels", default="", help="with --collect")
    s.add_argument("--since", default="", help="with --collect: epoch seconds")
    s.set_defaults(fn=cmd_discord_checkin)

    s = sub.add_parser("discord-people",
                       help="who has spoken in the channel lately")
    s.add_argument("--answers", default="-")
    s.set_defaults(fn=cmd_discord_people)

    s = sub.add_parser("check-mailbox",
                       help="try mailbox credentials (no root, writes nothing)")
    s.add_argument("--answers", default="-",
                   help="JSON file with an email block, or - for stdin")
    s.set_defaults(fn=cmd_check_mailbox)

    s = sub.add_parser("test-email",
                       help="prove the alert path works end to end")
    s.add_argument("--no-approvers", action="store_true",
                   help="only mail yourself, do not bother your friends")
    s.add_argument("--no-roundtrip", action="store_true")
    s.add_argument("--wait", type=int, default=90, help="seconds to wait for round trip")
    s.set_defaults(fn=cmd_test_email)

    s = sub.add_parser("activity", help="what has happened on this machine today")
    s.add_argument("--day", help="YYYY-MM-DD (default today)")
    s.add_argument("--domains", action="store_true", help="list looked-up domains")
    s.add_argument("--json", action="store_true")
    s.add_argument("--send", action="store_true", help="email the report now")
    s.set_defaults(fn=cmd_activity)

    s = sub.add_parser("update-source",
                       help="set (once) or clear where updates come from")
    s.add_argument("url", nargs="?", default="")
    s.add_argument("--branch", default="main")
    s.add_argument("--off", action="store_true", help="switch updates off")
    s.set_defaults(fn=cmd_update_source)

    s = sub.add_parser("update", help="pull a newer version from the pinned repo")
    s.add_argument("--check", action="store_true",
                   help="only report whether one is available")
    s.set_defaults(fn=cmd_update)

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
