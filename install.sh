#!/usr/bin/env bash
# ChristWatch installer.
#
# Stage one only: it puts the app on the machine and opens it. Nothing is
# blocked until you go through the wizard, and the wizard is where a friend
# types the secrets.
#
#   ./install.sh                 from a checkout or an unpacked download
#   CHRISTWATCH_REPO=... ./install.sh    fetches the repo first
#
set -euo pipefail

REPO_URL="${CHRISTWATCH_REPO:-}"
BRANCH="${CHRISTWATCH_BRANCH:-main}"
ASSUME_YES="${CHRISTWATCH_YES:-0}"
LAUNCH=1

for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --no-launch) LAUNCH=0 ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32;1m'; Y=$'\033[33;1m'; R=$'\033[31;1m'; N=$'\033[0m'
else
  B=""; G=""; Y=""; R=""; N=""
fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '    %s%s%s\n' "$G" "$*" "$N"; }
warn() { printf '    %s%s%s\n' "$Y" "$*" "$N"; }
die()  { printf '\n%sX %s%s\n\n' "$R" "$*" "$N" >&2; exit 1; }

ask() {   # ask "question" -> 0 for yes
  [ "$ASSUME_YES" = "1" ] && return 0
  [ -t 0 ] || return 1
  local reply
  read -r -p "    $1 [Y/n] " reply
  case "${reply:-y}" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

cat <<'BANNER'

   ____ _          _    _ __        __    _       _
  / ___| |__  _ __(_)__| |\ \      / /_ _| |_ ___| |__
 | |   | '_ \| '__| / _` | \ \ /\ / / _` | __/ __| '_ \
 | |___| | | | |  | | (_| |  \ V  V / (_| | || (__| | | |
  \____|_| |_|_|  |_|\__,_|   \_/\_/ \__,_|\__\___|_| |_|

  Content blocking you cannot quietly switch off.

BANNER

# ---------------------------------------------------------------- source
step "Finding the program"
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
if [ -f "$HERE/pornblock.py" ]; then
  SRC="$HERE"
  ok "using $SRC"
elif [ -n "$REPO_URL" ]; then
  command -v git >/dev/null 2>&1 || die "git is needed to fetch $REPO_URL"
  SRC="$(mktemp -d)/christwatch"
  git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC" \
    || die "could not clone $REPO_URL ($BRANCH)"
  ok "fetched $REPO_URL ($BRANCH)"
else
  die "pornblock.py is not next to this script. Run it from the unpacked
     download, or set CHRISTWATCH_REPO=https://github.com/EasternProdigy/christwatch"
fi

# ---------------------------------------------------------- dependencies
step "Checking what is already here"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
ok "python3 $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"

need_gui=0
python3 - <<'PY' >/dev/null 2>&1 || need_gui=1
import gi
gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw
PY
if [ "$need_gui" = "0" ]; then
  ok "GTK4 + libadwaita bindings"
else
  warn "the desktop app needs GTK4 + libadwaita python bindings"
fi

missing_tools=""
for t in nft chattr systemctl resolvectl; do
  command -v "$t" >/dev/null 2>&1 || missing_tools="$missing_tools $t"
done
[ -z "$missing_tools" ] && ok "nftables, e2fsprogs, systemd tools" \
                        || warn "missing tools:$missing_tools"

if [ "$need_gui" = "1" ] || [ -n "$missing_tools" ]; then
  PKGS=""; PM=""
  if command -v dnf >/dev/null 2>&1; then
    PM="sudo dnf install -y"
    PKGS="python3-gobject gtk4 libadwaita adwaita-icon-theme nftables e2fsprogs systemd-resolved polkit"
  elif command -v apt-get >/dev/null 2>&1; then
    PM="sudo apt-get install -y"
    PKGS="python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 adwaita-icon-theme nftables e2fsprogs systemd-resolved policykit-1"
  elif command -v pacman >/dev/null 2>&1; then
    PM="sudo pacman -S --needed --noconfirm"
    PKGS="python-gobject gtk4 libadwaita adwaita-icon-theme nftables e2fsprogs polkit"
  elif command -v zypper >/dev/null 2>&1; then
    PM="sudo zypper install -y"
    PKGS="python3-gobject typelib-1_0-Gtk-4_0 typelib-1_0-Adw-1 adwaita-icon-theme nftables e2fsprogs polkit"
  fi
  if [ -n "$PM" ]; then
    step "Installing what is missing"
    say "    $PM $PKGS"
    if ask "Install these now?"; then
      # shellcheck disable=SC2086
      $PM $PKGS || warn "package install reported a problem; carrying on"
    else
      warn "skipped - the desktop app may not start"
    fi
  else
    warn "unknown package manager; install GTK4 + libadwaita python bindings yourself"
  fi
fi

# -------------------------------------------------------------- install
step "Installing ChristWatch"
if [ "$(id -u)" = "0" ]; then
  RUN=""
elif command -v sudo >/dev/null 2>&1 && { [ -t 0 ] || sudo -n true 2>/dev/null; }; then
  RUN="sudo"
elif command -v pkexec >/dev/null 2>&1; then
  RUN="pkexec"
else
  die "need root: re-run with sudo"
fi
$RUN python3 "$SRC/pornblock.py" install-app || die "install failed"

# --------------------------------------------------------------- finish
step "Done"
say ""
say "  Nothing is blocked yet. ${B}Open ChristWatch from your app menu${N} and"
say "  go through the wizard - there is a step near the end where you hand"
say "  the keyboard to a friend."
say ""
say "  From a terminal instead:   sudo pornblock setup"
say "  Check on it any time:      sudo pornblock status"
say ""

if [ "$LAUNCH" = "1" ] && [ "$need_gui" = "0" ] && [ -x /usr/local/bin/pornblock-gui ]; then
  if ask "Open ChristWatch now?"; then
    setsid /usr/local/bin/pornblock-gui >/dev/null 2>&1 &
    ok "launched"
  fi
fi
