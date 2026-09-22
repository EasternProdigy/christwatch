# ChristWatch (`pornblock`)

A self-hosted, accountability-gated porn blocker for Fedora/systemd Linux,
with a desktop app.

Blocking is the easy half. Making *unblocking* hard is the product. To turn it
off you need **three things at once**: a 24-hour cool-off, your friends'
approval by email, and a passphrase only they know.

```
LOCKED  --ask to unlock-->  PENDING  --24h timer            --.
                                     + N approvals by email  >--> UNLOCKED
                                     + partner passphrase   --'      |
   ^                            |                                    |
   +------- cancel / any DENY --+---------- 60 min, then auto --------+
```

* **`pornblock`** - the CLI and the root daemon that does the work.
* **ChristWatch** - the GTK desktop app in your app grid. Same thing, friendlier.

---

## Read this first: what this actually is

You are root on this machine. **Nothing here is unremovable and this file is
not going to pretend otherwise.** Anyone with root and fifteen focused minutes
can take it apart.

What it *is*:

* **Friction.** A daemon re-applies four blocking layers every ~45 seconds and
  re-sets `chattr +i` on everything it manages. Undoing it by hand means
  fighting a loop that undoes your undo.
* **Delay.** Even with unanimous approval, nothing unlocks for 24 hours. The
  urge that made you click "Ask to unlock" will not be the same urge a day
  later. That is the mechanism.
* **Witnesses.** Every request, approval, denial, grant, re-lock, wrong
  passphrase, tamper event and uninstall attempt emails all of your approvers.
  The cost of bypassing isn't technical, it's having to explain yourself.
* **One thing you genuinely cannot do alone.** The partner passphrase is
  stored only as a PBKDF2 hash. You can delete it, but deleting it does not
  open the gate - it welds it shut (see below). Short of brute force, you
  cannot recover it without your friend.

Optimise for *"I'd be embarrassed to bypass this"*, not for *"I can't."*

---

## What it enforces

| Layer | What it does | File it owns |
|---|---|---|
| 1. hosts | StevenBlack porn-only list (~77k domains) plus forced SafeSearch / YouTube Restricted pinning, injected between markers | `/etc/hosts` |
| 2. DNS | Forces systemd-resolved to DNS-over-TLS to a filtering resolver, and stops NetworkManager pushing DHCP resolvers over the top | `/etc/systemd/resolved.conf.d/90-pornblock.conf`, `/etc/NetworkManager/conf.d/90-pornblock-dns.conf` |
| 3. firewall | Own nftables table dropping outbound 53/853 to anything except the filter, plus rejecting 443 to well-known public DoH endpoints | `table inet pornblock` |
| 4. browsers | Forces DoH to the filter, SafeSearch, YouTube Restricted, no private/incognito, blocks `about:config` and `chrome://flags` | `/etc/firefox/policies/policies.json`, `/etc/chromium/policies/managed/pornblock.json`, `/etc/opt/chrome/policies/managed/pornblock.json` |

Layer 3 deliberately touches **only** the `pornblock` table. firewalld and
everything else in your ruleset are left alone.

---

## Install

Needs `python3-gobject gtk4 libadwaita` for the desktop app (already present
on a stock Fedora Workstation). The CLI itself is pure standard library.

**Get a friend to sit with you for the last two minutes of this.**

```bash
git clone <this repo> && cd porn-block
./pornblock_gui.py          # the wizard walks the whole thing
```

or entirely from the terminal:

```bash
sudo ./pornblock.py setup        # interactive wizard
sudo ./pornblock.py test-email   # prove SMTP+IMAP work BEFORE you rely on them
sudo ./pornblock.py install      # units, desktop app, lock down
sudo pornblock status
```

Setup asks for a **dedicated mailbox** (Gmail/Fastmail/whatever) with an **app
password**. Common providers are auto-detected.

### The step where you look away

Near the end, setup says **hand the keyboard to your friend**. They type two
things:

1. **The mailbox app password.** If *you* know it, you can log into the
   approval mailbox and send `APPROVE` to yourself. Them typing it is what
   makes the email gate mean anything.
2. **The partner passphrase.** Stored as a salted PBKDF2-SHA256 hash
   (600k iterations). Even after the timer expires and your friends approve,
   an unlock needs this typed in.

### Files it creates

```
/etc/pornblock/config.json          0600, no secrets in it
/etc/pornblock/secrets.json         0600 + immutable, mailbox password + passphrase hash
/etc/pornblock/install-record.json  0600 + immutable, the contract with your friends
/etc/pornblock/nftables.conf        the generated ruleset
/var/lib/pornblock/state.json       0600, the state machine
/var/lib/pornblock/install-record.json.bak   spare copy of the contract
/var/lib/pornblock/blocklist-porn.hosts      cached list, refreshed daily
/var/lib/pornblock/backups/         originals of anything it took over
/run/pornblock/status.json          0644, secret-free snapshot the GUI reads
/var/log/pornblock.log              rotates at 5 MB, keeps 3
/usr/local/bin/pornblock            immutable copy of the program
/usr/local/bin/pornblock-gui        the desktop app
/usr/share/applications/christwatch.desktop
/usr/share/icons/hicolor/scalable/apps/christwatch.svg
/etc/systemd/system/pornblock.service            Restart=always
/etc/systemd/system/pornblock-watchdog.{service,timer}   every 60s
```

---

## Daily use

Open **ChristWatch** from your app grid, or:

```bash
sudo pornblock status           # mode, approvals, hours left, window left, health
sudo pornblock request-unlock   # starts the 24h clock, emails everyone
sudo pornblock passphrase       # enter the partner passphrase
sudo pornblock cancel           # always allowed, always the right answer
sudo pornblock test-email       # re-verify the mail path
sudo pornblock enforce          # force one enforcement pass now
```

### How the desktop app is wired

The app runs as **you**, not as root, and it never reads anything privileged.
The daemon publishes a secret-free snapshot to `/run/pornblock/status.json`
and the app just reads that, so looking at your status never asks for a
password. Anything that *changes* something is handed to
`pkexec pornblock ...`, so you get your desktop's own authentication dialog.
Secrets typed into the wizard are piped to the privileged helper over stdin
and never touch disk in the GUI process.

### The unlock flow, step by step

1. You click **Ask to unlock** (or run `request-unlock`). A random code like
   `A7F31C08` is generated, and **every approver gets an email immediately**
   with an APPROVE button, a DENY button, and your name on it.
2. The 24-hour cool-off starts. Approvals can arrive at any time during it -
   pre-approving does not shorten the clock.
3. Friends approve by clicking the `mailto:` APPROVE link (their mail client
   opens pre-filled with `APPROVE A7F31C08`, they hit send) or by replying
   `APPROVE A7F31C08`. The daemon polls IMAP every 60s.
4. Someone tells you the **partner passphrase** and you type it in. Five wrong
   attempts locks entry for 15 minutes and emails everyone.
5. When **the timer has elapsed AND the quorum is met AND the passphrase is
   in**, mode goes to `UNLOCKED`, every layer lifts, and everyone is emailed.
6. After the window (default 60 min) it re-locks itself and emails again.
7. Requesting again starts a **fresh** 24 hours.

Any single approver replying `DENY <code>` cancels the whole request. Nobody
replying at all means it stays locked - silence is a valid answer. An
unanswered request expires after 7 days.

> **Browser restart:** browser policies are read at launch. Restart Firefox
> after an unlock is granted, and again after it re-locks.

### If the passphrase is lost

Default on: **unanimous approval substitutes for it.** With three approvers
and a quorum of two, the normal path is 2 approvals + timer + passphrase; the
recovery path is all 3 approvals + timer, no passphrase. Turn it off with
`passphrase_recovery: false` and understand that a friend who moves away and
forgets then leaves this machine locked for good.

**Deleting the stored hash does not remove the gate.** The install record
remembers that a passphrase exists, so the gate stays shut and nothing you
type can satisfy it - unanimity becomes the only route. That is deliberate.

---

## Tuning

Edit `/etc/pornblock/config.json`, then `sudo systemctl restart pornblock`.

| Key | Default | Meaning |
|---|---|---|
| `cooloff_hours` | `24` | Wait between the request and the earliest possible grant |
| `unlock_minutes` | `60` | How long blocking stays off once granted |
| `approvers` | - | List of friends' addresses. All of them get every alert |
| `approvals_required` | `2` | How many of them must say APPROVE |
| `require_passphrase` | `true` | Whether the partner passphrase is a gate |
| `passphrase_recovery` | `true` | Unanimous approval can stand in for it |
| `request_ttl_hours` | `168` | An unapproved request expires after this |
| `filter` | `cloudflare_family` | or `cleanbrowsing_adult` |
| `youtube_restrict` | `moderate` | or `strict` |
| `loop_seconds` | `45` | How often everything is re-applied |
| `blocklist_refresh_hours` | `24` | How often the list is re-downloaded |
| `app_name` | `ChristWatch` | Name on the desktop icon |
| `enforce.*` | all on | Turn individual layers off |
| `enforce.block_extensions` | `false` | Blanket block on browser extension installs |
| `blocked_extension_ids` | empty | Specific add-on IDs to block, per browser |

### The catch: the config is not fully yours any more

`install-record.json` is immutable and holds the approvers, the quorum, the
cool-off, the window and the passphrase policy. On every pass the daemon
compares the live config against it:

* **Weakening** a setting (different approvers, lower quorum, shorter
  cool-off, longer window, passphrase requirement switched off) is
  **reverted**, and an email goes to *both* the recorded approvers *and* any
  address you just added.
* **Strengthening** a setting is accepted and the record is updated.
* While `UNLOCKED`, anything goes and the record re-syncs. That is the
  sanctioned way to change your approvers: earn an unlock first.
* Reinstalling does **not** reset the record. Deleting the record restores it
  from the spare copy in `/var/lib/pornblock/` and emails everyone.

### Turning it off for good

```bash
sudo pornblock uninstall
```

This **refuses** unless you are inside a granted unlock window. Get the 24
hours, the approvals and the passphrase, then uninstall during the 60 minutes.
It emails your approvers on the way out, and on every refused attempt.

---

## Honest limitations

Roughly in order of how likely you are to actually use them.

**You are root.**  `systemctl stop pornblock && systemctl stop
pornblock-watchdog.timer && chattr -i /etc/hosts && ...` works. The watchdog
fires every 60s and puts it back, and mails your approvers that it had to -
but a root user who keeps going, wins. This is friction and social cost, not
security.

**You can read the mailbox password.**  Your friend types it, but it is stored
in `/etc/pornblock/secrets.json`, which root can read. Splitting it into its
own immutable 0600 file keeps it out of casual sight and out of the GUI and
the status snapshot - it does not hide it from a determined you. The
passphrase is different: only a hash is kept, so that one really does need
your friend.

**DNS-over-HTTPS from non-browser apps.**  The big technical one. DoH is HTTPS
on port 443 and is indistinguishable from normal web traffic. Browsers are
pinned to the filter by policy, and the firewall rejects 443 to a list of
well-known public resolvers - but any app that hardcodes an obscure DoH
endpoint, or any DoH server not on that list, gets through. Closing this
properly needs allowlist-style egress filtering, which would break ordinary
use of the machine.

**VPNs, Tor, proxies.**  Anything that tunnels traffic sidesteps every layer
here. A system VPN, a browser proxy extension, Tor Browser (which ships its
own DNS and its own policy-immune profile), or an SSH `-D` SOCKS proxy all
bypass this completely. This is the single largest hole after "you are root".

**Browser extensions are not restricted** by default, by choice. Browsers
cannot filter extensions by topic, so there is no "block porn extensions"
setting that exists anywhere to turn on. In practice you do not need one: a
content extension still has to fetch over the network and gets starved by
layers 1-3. A *proxy or VPN* extension does not. If you want specific ones
gone, put their IDs in `blocked_extension_ids`, or set
`enforce.block_extensions: true` for a blanket install block (which on
Chromium also disables extensions you already have).

**Anything that isn't this machine.**  Your phone, a second laptop, a guest
account, a live USB, a VM. Nothing here touches them.

**Flatpak and Snap browsers** may not read `/etc/firefox/policies/` or
`/etc/chromium/policies/managed/`. They still eat layers 1-3. A Flatpak
Firefox needs its policy in
`/var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/.../policies/`.

**Containers.**  Traffic from Docker/Podman containers traverses the `forward`
hook, not `output`, so the nftables rules here do not cover it.

**The blocklist is a list.**  ~77k domains, refreshed daily, and it will never
be complete. New domains appear constantly. The DNS filter is the part that
generalises; `/etc/hosts` is belt-and-braces.

**Search engines other than Google/Bing** are not SafeSearch-pinned.

**Your approvers are human.**  If they rubber-stamp everything, you have a
24-hour delay and nothing else. Pick people who will actually ask why.

**Approval email is identified by the `From:` header** and nothing stronger.
No DKIM check, no signatures. Run `test-email` regularly: a silently broken
mailbox means alerts nobody ever receives.

**The GUI runs as you.**  Secrets typed into the wizard are piped over stdin
rather than written to disk, but a process you own can be attached to by a
debugger you own. Again: friction, not secrecy.

### Performance note

A ~77k-line `/etc/hosts` is read by glibc on every uncached lookup and adds a
few milliseconds each time. If that bothers you, set `enforce.hosts` to
`false` - layers 2 and 3 still block the same domains at the resolver, you
just lose the SafeSearch pinning.

### Packaging note

`/etc/hosts` is marked immutable. It's `%config(noreplace)` in Fedora's
`setup` package, so upgrades write `.rpmnew` rather than failing, but if a dnf
transaction ever complains about it: `sudo chattr -i /etc/hosts`, run it, and
the daemon re-locks the file within 45 seconds.

---

## Development

```bash
export PORNBLOCK_PREFIX=/tmp/pb-sandbox     # relocates every path
python3 pornblock.py setup --answers answers.json
python3 pornblock.py install
python3 pornblock.py request-unlock --yes
python3 pornblock.py simulate-approval alice@example.com
echo "the-passphrase" | python3 pornblock.py passphrase --stdin
python3 pornblock.py daemon --once
python3 pornblock.py status
```

In a sandbox nothing real is touched: no `chattr`, no `systemctl`, no `nft`,
no files outside the prefix. `simulate-approval` **only** works there - real
approvals must arrive by email.

```bash
python3 selftest.py     # 74 offline checks, no network, no root
```

Covers reply parsing (including that a quoted APPROVE in a reply must not
approve anything), enforcement idempotency, drift reversion, the three-gate
state machine, passphrase hashing, secret hygiene and the desktop files.
