# ChristWatch (`pornblock`)

A self-hosted, accountability-gated porn blocker for Fedora/systemd Linux,
with a desktop app.

Plenty of things block porn. What this one is for is the other side: turning
it back off takes **three things at once** - a 24-hour cool-off, your friends'
approval, and a passphrase only they know - so it can't happen in the moment,
or quietly.

Your friends can be reached **in a Discord channel** or **by email**. Discord
is the default: no new mailbox, no app password, and approving happens in
front of everyone, which is most of the point. Blocked sites are named in
that channel **as they are asked for**, not only in the evening's report.

If several of you are doing this in the same server, [group
mode](#several-of-you-one-server) adds one shared channel where every
member's machine says it is still running - so somebody quietly uninstalling
is something the group sees, rather than something it works out months later.

**Setting it up for the first time?** [SETUP.md](SETUP.md) is the linear
version of this document: half an hour, in order, with the mistakes called
out. This file is the reference.

```
LOCKED  --ask to unlock-->  PENDING  --24h timer            --.
                                     + N approvals by email  >--> UNLOCKED
                                     + partner passphrase   --'      |
   ^                            |                                    |
   +------- cancel / any DENY --+---------- 60 min, then auto --------+
```

* **`pornblock`** - the CLI and the root daemon that does the work.
* **ChristWatch** - the GTK4/libadwaita app in your app grid. It shows the
  three gates as a checklist, counts down the cool-off, and takes you through
  first-time setup including the step where your friend types the secrets.

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
  Routine repairs - the wifi reconnecting and handing out its own DNS, a
  lock flag the blocker's own update left off - are fixed and logged but not
  posted, and news that needs nobody to act (an update, a cancelled request)
  is posted without pinging anyone. What does ping your friends is worth
  reading.
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
| 3b. phones | Watches the one device-wide DNS setting on your Android phones and says so in the channel when it changes or stops reporting | nothing on this machine |
| 4. browsers | Forces DoH to the filter, SafeSearch, YouTube Restricted, no private/incognito, blocks `about:config` and `chrome://flags` | `/etc/firefox/policies/policies.json`, `/etc/chromium/policies/managed/pornblock.json`, `/etc/opt/chrome/policies/managed/pornblock.json` |

Layer 3 deliberately touches **only** the `pornblock` table. firewalld and
everything else in your ruleset are left alone.

---

## Install

Installing happens in **two stages**, and they are deliberately separate:

| Stage | What it does | Needs a friend? |
|---|---|---|
| **1. Get the app** | Puts ChristWatch in your app menu and `pornblock` on your PATH. **Nothing is blocked.** | No |
| **2. Arm it** | The wizard: your details, your approvers, the mailbox, the secrets. Blocking goes live. | Yes, for the last page |

### Stage 1 - pick whichever suits you

**Fedora: download the `.rpm` and double-click it.** Grab it from the
project's Releases page. Your software centre installs it and ChristWatch
appears in the app grid. Dependencies are handled for you.

**Any distribution: unpack the download and double-click `Install
ChristWatch`.** It opens a terminal, checks what you are missing, offers to
install it with your package manager, and puts the app in place. If your
file manager will not run it, mark it executable first (right-click →
Properties → Permissions), or run `./install.sh` from a terminal.

**From a terminal:**

```bash
git clone https://github.com/EasternProdigy/christwatch && cd porn-block
./install.sh
```

### Stage 2 - open ChristWatch and go through the wizard

If you set up from the terminal without arming it, the app opens on a
**"Set up, but not switched on"** screen with a single **Activate
protection** button. Nothing is blocked and nothing is recorded until you
press it.

Six pages: you, your approvers, the friction, the mailbox, **your friend's
turn at the keyboard**, and install. It ends by writing the config, enabling
the service and switching blocking on.

Terminal equivalent:

```bash
sudo pornblock setup        # same questions
sudo pornblock test-email   # prove SMTP+IMAP work BEFORE you rely on them
sudo pornblock install      # units, enable, lock down
sudo pornblock status
```

### Discord (the default)

One bot, made once, in whatever server you and your friends already use.
The wizard walks it, and each step opens the page it is talking about:

1. **Make it.** Opens the developer portal. New Application, name it, Bot,
   Reset Token, copy what it shows you.
2. **Paste the token.** A bot token begins with its own application id, so
   from here the app knows which bot you mean and builds the next two links
   itself.
3. **Put it in your server.** Opens an invite asking for exactly four
   permissions: View Channel, Send Messages, Read Message History, Add
   Reactions.
4. **Let it read the channel.** Opens that bot's settings page. Switch on
   **Message Content Intent**, then press **Save Changes** at the bottom -
   the toggle does nothing until you do. Without it every message arrives
   blank.

   The check does not take the portal's word for this. It reads the channel:
   words from a person getting through is proof it works, messages arriving
   blank is proof it does not, and an empty channel is neither, which it says
   rather than claiming failure.

   If it is off, approvals still get through when the person **mentions the
   bot** in the message - a message that mentions it always carries its text.
   The bot says so in the channel by itself when it notices it has gone deaf.
5. **Pick the channel.** Press *Find channels* and choose from the list. No
   Developer Mode, no copying ids. There is a box for pasting one if you
   prefer.

Then press **Ask them to check in**. It posts one short message in the
channel and everyone who taps the tick becomes an approver, names and all -
nobody copies an 18-digit id, and nobody has to type anything the bot might
not be allowed to read. **There is no time limit**: the question stays up and
the app keeps watching, so your friends can answer tonight or tomorrow.

**Privately** does the same by direct message to people you pick out of the
channel, if you would rather the whole server did not watch you set this up.
Anyone whose DMs are shut is named so you can ask them another way.

```bash
# what that button runs, if you prefer a terminal
echo '{"discord":{"bot_token":"...","channel_id":"..."}}' | pornblock check-discord
echo '{"discord":{"bot_token":"...","channel_id":"..."}}' | pornblock discord-checkin --wait 120
```

Requests, approvals, denials, tamper alerts and the nightly report all go to
that one channel. **Approving is one tap**: the bot puts a tick and a cross
under the request, and your friends press one. Taking the tick back takes the
approval back, any time before it is granted. Typing `APPROVE <code>` still
works for anyone who prefers it.

A tap is worth more than convenience here - a reaction carries a user id and
nothing else, so it works whether or not the Message Content intent is on,
and it cannot be forged by anyone who is not that person.

Enrolment can be private, but approving is not: it happens in the channel,
where everyone can see it. DMs to the bot are ignored for approvals on
purpose.

**Why this is stronger than email.** An email approval is matched on a `From:`
header, which anyone can forge from any SMTP server. A Discord message carries
a user id you cannot spoof without owning your friend's account. The bot token
is not the weak point either: it lets this machine post and read in the
channel, but it can never approve anything.

**What the record pins.** Moving the alerts to a channel your friends are not
in is the same as switching them off, so the install record pins both the
transport and the channel id. Changing either reverts and tells everybody.

### Email

Setup asks for a **dedicated mailbox** with an **app password**. Pick the
provider from a list and the server settings fill themselves in - they stay
folded away unless your provider is an unusual one. The page tells you where
that provider hides its app passwords.

On the next page, once your friend has typed the password, **Check the
mailbox now** logs in to SMTP and IMAP and tells you whether it works, before
anything is installed. It sends nothing, writes nothing and needs no root:

```bash
echo '{"email":{"address":"...","smtp_host":"...","imap_host":"..."}}' \
    | pornblock check-mailbox
```

### The step where you look away

Near the end, setup says **hand the keyboard to your friend**. They type two
things:

1. **The mailbox app password.** If *you* know it, you can log into the
   approval mailbox and send `APPROVE` to yourself. Them typing it is what
   makes the email gate mean anything.
2. **The partner passphrase.** Stored as a salted PBKDF2-SHA256 hash
   (600k iterations). Even after the timer expires and your friends approve,
   an unlock needs this typed in.

No friend available today? Leave the passphrase blank and set it later - the
app carries a "one gate short" banner until someone does. Everything else
still works.

### Removing the package does not unblock you

`dnf remove christwatch` takes away the packaged copies and leaves the armed
installation exactly where it is. That is on purpose. The only supported way
out is `pornblock uninstall`, which refuses outside a granted unlock window.

### Sharing it, and cutting a release

```bash
./packaging/build-rpm.sh     # -> dist/christwatch-<version>-1.fc*.noarch.rpm
```

Needs `rpm-build`. The spec runs `selftest.py` as its `%check`, so a package
cannot be built from code that fails its own tests. Pushing a `v*` tag runs
the same build in CI and attaches the `.rpm` to a GitHub Release, which is
what your friends download and double-click.

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
/usr/share/christwatch/             the packaged copy, if installed by RPM
/usr/local/bin/pornblock            the managed copy (immutable once armed)
/usr/local/bin/pornblock-gui        the desktop app
/usr/share/applications/christwatch.desktop
/usr/share/icons/hicolor/scalable/apps/christwatch.svg
/etc/systemd/system/pornblock.service            Restart=always
/etc/systemd/system/pornblock-watchdog.{service,timer}   every 60s
```

With `harden --on`, two more - both removed again by `harden --off`:

```
/etc/cron.d/christwatch             the re-armer that is not systemd
/etc/profile.d/christwatch.sh       the warning every terminal prints
```

And one outside our own territory, written only because our own domain
tracking is what makes the journal chatty. `tracking.journal_cap_mb: 0`
opts out; `uninstall` removes it:

```
/etc/systemd/journald.conf.d/90-pornblock.conf   SystemMaxUse, default 512M
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
sudo pornblock phone            # what your phones are doing
sudo pornblock harden           # what makes taking this off hard
sudo pornblock activity         # what happened on this machine today
sudo pornblock group            # who else is still running it
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

> **Two friends, both required?** Then your quorum *is* unanimity, and the
> recovery rule hands the passphrase over the moment they both approve - so
> it is not really a third gate. `status` says so, and the wizard warns you
> while it is still one click to change. Three approvers with a quorum of
> two, or `passphrase_recovery: false`, gives you the third gate back.

---

## Making it hard to take off

You are root. Nothing here stops you, and this program will not pretend
otherwise. What `harden` does is close the *quiet* routes, so that every way
out is slow, loud, and something you have to mean.

```bash
sudo pornblock harden --on     # the extra nets
sudo pornblock harden          # what is in place, and what each layer costs
sudo pornblock harden --grub   # the last one; your friend types the password
sudo pornblock harden --off    # said out loud to your approvers
```

### The nets, and what each one is worth

| Layer | Closes | Costs you |
|---|---|---|
| The two systemd units | Stopping one of them | Stop the other too |
| **cron, every minute** | Stopping **both** units, or deleting the program | Delete `/etc/cron.d/christwatch` as well - and until you do, it is back within a minute and your friends have been told |
| **The terminal warning** | Forgetting you turned it off | Nothing. It is a line in `/etc/profile.d` |
| **Boot menu password** | Editing the boot line into a root shell with none of this running | A friend holds it |

The cron line is the important one. Before it, `systemctl disable --now
pornblock.service pornblock-watchdog.timer` left nothing running and said
nothing to anybody. Measured on a real machine after `--on`:

```
16:21:04  both units stopped, nothing of ChristWatch running
16:22:01  cron re-enabled and restarted them
16:22:05  "Blocker was stopped - watchdog restarted it" posted to the channel
```

Sixty-one seconds, and a message your friends can see.

If the program itself is deleted, the same cron line falls back to the copy
the installer kept at `/var/lib/pornblock/pornblock.py.installed`, which puts
the binary back.

### The boot menu is the only genuinely silent way out

Editing the kernel line at the GRUB menu (`init=/bin/bash`) gives you a root
shell with no daemon, no cron and no network - so nothing is re-applied and
nothing is said. `harden --grub` closes it by putting a password on editing
boot entries. Booting normally is unaffected: Fedora marks the existing
entries `--unrestricted`, so nobody is asked for it just to start the
machine.

Once it is set, the daemon watches it. Changing or removing that password is
reported to your approvers like any other tamper.

### What it still does not do

Everything above assumes something of this is running when you act. It is
defence in depth against a tired person at 2am, not against a determined one
with an afternoon. With root and a clear head you can stop cron, delete the
cron file, remove the units, drop the immutable flags and unpick each
blocking layer by hand. That takes maybe ten deliberate minutes, and
depending on the order, some of it gets reported before you finish.

That is the honest ceiling of this design, and raising it further means
giving up root - see the note below.

### If you ever do want the real thing

The only way this genuinely stops you is if you are not root: your account
out of `wheel`, the root password and the boot menu password held by a
friend, and firmware locked against USB boot. Then the ceiling becomes
"open the laptop and clear the CMOS", which is hours of deliberate work.
The cost is that you cannot install a package or debug a service without a
phone call, which is why it is not the default.

---

## Your phone

The laptop is half your day. This covers the other half.

Neither phone runs a copy of the blocker, and neither one needs to. Android
and iOS both have a system-wide setting that sends every app's lookups to a
resolver of your choosing, and pointing it at the filtering resolver blocks
the same sites the laptop blocks. On Android that setting lives in
`Settings.Global`, which every profile on the device shares - so **one change
covers your owner profile and your second profile at once**, and there is
only one copy of it for anyone to switch off.

So the software's job here is not to block. It is to make switching it off
something your friends find out about.

```bash
sudo pornblock phone --add "my phone"          # Android
sudo pornblock phone --add "my iphone" --ios   # iPhone
sudo pornblock phone                           # how they are doing
sudo pornblock phone --remove "my phone"
```

`--add` finishes by putting a page on your home network and printing the
address, with a QR code for it. In the desktop app the same thing is
**Set up a phone** → **Add a phone**, which shows the code on screen. Point
the phone's camera at it and everything the phone needs is there: the
app, the pairing link, the hostname to type, or the iPhone profile. The
address stops working after twenty minutes. Nothing is emailed to yourself,
and nothing is left in your downloads.

### Android

The page hands you a small app. It has no filter in it and asks for no
unusual permission - it reads one system setting once an hour and posts to a
**webhook** for your channel, which can write in that one channel and read
nothing, anywhere. The bot token never leaves the laptop.

It posts when the setting changes, and once a day when it has not, so
*silence is itself an answer*: if the app is uninstalled or stopped, the
laptop notices within `phone.silence_hours` (36 by default) and tells your
friends that the phone has gone quiet.

#### One setting covers every profile

Private DNS lives in Android's `Settings.Global`, which every profile on the
device shares. There is one copy of it and no way to have a different one per
profile - DNS is resolved by a system service, not by each profile
separately.

So **set it once, in the owner profile, and your second profile is filtered
too** - with nothing installed there at all. The app does not do the
blocking and is not needed in both profiles for the blocking to work.

Check it in ten seconds: switch to your second profile and try a site you
know is blocked. It will fail to resolve, because the resolver it is asking
is the one the owner profile pinned.

There is a second effect worth knowing about. On a standard GrapheneOS
setup a secondary profile is not an admin user, and the Private DNS screen
is admin-only - so the profile you spend your time in usually *cannot* turn
the filtering off even if you want it to. Worth confirming on your own
phone: open Settings -> Network & internet in the second profile and see
whether Private DNS is editable there.

#### Why you might still install it twice

Only one reason: noticing that the app was removed. Each copy reports for
itself, so they show up separately -

```
[ ok ] Pixel (owner)             android  filtering, last heard 34m ago
[FAIL] Pixel (second profile)    android  silent for 2d 4h
```

- and a copy that disappears goes quiet, which the laptop notices within 36
hours. One copy is enough for the blocking and enough to see the setting
change. The second is there so that removing one does not go unmentioned.
Same page, same pairing link, no need to add the phone twice.

The setting itself, if you would rather type it:
Settings → Network & internet → Private DNS → *Private DNS provider
hostname* → `family.cloudflare-dns.com`.

### iPhone

iOS has no way for an app to watch this, so there is no app. What the page
gives you instead is a configuration profile that sets encrypted DNS for the
whole phone, and the honest lock on it is a **removal password your friend
types on your laptop**. Until someone enters it, iOS greys out the Remove
button.

Same bargain as everything else here: erasing the phone clears it, and the
password sits in the profile in plain text, which is exactly why that file is
served to the phone over your own network and never saved anywhere.

### What it does not cover

- A browser with its own DNS built in - Firefox on Android, or any app
  shipping its own DoH - goes around the system setting. Vanadium and Chrome
  turn their own secure DNS off when Private DNS is on, so they follow it.
- A VPN app replaces DNS for the whole device. Nothing here stops one being
  installed.
- On Android, you can turn Private DNS off in about four taps. That is the
  point: it is quick, and it is reported.

---

## Several of you, one server

This is what happens about a month in. You set it up, you tell a friend,
they want one - and now there are four of you in the same Discord server
running four blockers that know nothing about each other.

Group mode adds one shared channel, the **lobby**, where every member's
machine keeps one message and edits it every half hour:

```
Will's blocker is running (LOCKED) - checked in 20:17
CWG1 {"v":1,"m":"216…","n":"Will","h":"will-laptop","s":"LOCKED","at":1758…}
```

An edit notifies nobody and does not mark the channel unread, so the lobby
holds one line per person rather than a new one every half hour.

Nothing central runs, and that is deliberate. Each machine still enforces by
itself, still answers to its own approvers, still keeps its own channel.
**Nobody gains any power over anybody else's blocker** - the lobby cannot
approve anything, cannot unlock anything and cannot change anybody's
settings. What it adds is the one thing four separate installs otherwise
cannot see: who stopped.

### Silence is the whole point

Nobody announces that they uninstalled it. They stop mentioning it, and
three weeks later nobody can quite remember whether Sam is still running it
or quietly dropped out in July.

A machine that is running posts every thirty minutes. A machine that is not,
does not. After `group.silence_hours` - twelve by default - one of the other
machines says so in the lobby, by name, and pings them:

> **Jordan has gone quiet.**
>
> Their machine has not posted here for 14h 0m 0s. It normally does every 30m 0s.
>
> The blocker reports for itself, so this is what it looks like when it has
> stopped running - uninstalled, switched off, or the machine is simply away
> for a while. Worth asking which.

Only one machine says it. Every member is watching the same lobby, so
without that you would get one post per member and a channel nobody reads.
The lowest member id still being heard from does the talking; there is no
election and nothing to agree on, and if the speaker is itself the machine
that went quiet, the next id along has already taken the job.

**Leaving properly is not the same as walking out.** `group --leave` posts a
farewell the other machines understand, and they take you off the roster
instead of calling you a quitter twelve hours later. Leaving is a loosening
like any other, so it only works during an unlock.

### Laying the server out

The layout that works:

```
#christwatch          the lobby. Everyone. Roster, and who went quiet.
#cw-will              Will's requests, approvals, alerts, nightly report
#cw-sam               Sam's
#cw-jordan            Jordan's
```

Separate channels are the default because the nightly report is the
*complete* list of domains that person's machine looked up, and four of
those in one channel is unreadable as well as more exposure than anybody
signed up for.

You can all share one channel if you would rather - point everyone's
`discord.channel_id` at it and use it as the lobby too. Every post is
prefixed with whose machine is talking (`[ChristWatch: Will]`) so it stays
readable, and approvals still cannot be confused between people because each
request carries its own code. It is noisier and everyone reads everyone's
detail. `group --join` warns you when you do this rather than refusing.

**One bot or a bot each?** One bot for the server is much less setup and it
is what most groups will do. A bot each is better, for one specific reason -
see below.

### Joining

```bash
sudo pornblock group --join \
    --lobby  1234567890123456789 \
    --me     9876543210987654321 \
    --name   "Will" \
    --group  "the lads"
```

`--lobby` is the shared channel's id; `--me` is your own Discord user id
(Developer Mode on, right-click yourself → Copy User ID). Your machine posts
its first line immediately and says hello in the lobby.

### The roster

```bash
sudo pornblock group           # who is still running it
sudo pornblock group --post    # ...and put that in the lobby
sudo pornblock group --beat    # post this machine's line right now
sudo pornblock group --json    # machine-readable
sudo pornblock group --leave   # during an unlock only
```

```
  the lads - who is still running it
  ==================================

  !! Jordan                 silent for 1d 6h 0m 0s - last heard from Mon 10:39
     Sam                    PENDING, 1 of 2 approved, earliest Tue 17:39, 7 blocked today
     Will (you)             locked, 0 blocked today

  3 members. Drawn from what each machine posted here, Tue 16:39.
  1 to ask about: Jordan
```

Everyone in the group shows up in `pornblock status` and in the app's health
list too, so a member who went quiet is visible without going looking.

### What the lobby does and does not prove

**It carries state, not content.** Mode, timers, how many blocked lookups
today, whether the phones are reporting. Nobody in the lobby sees anybody
else's domains, apps or screen time - that stays in each person's own
channel, in front of the people they chose.

**A line says who it is from. It does not prove it.** If your group shares
one bot then every line in the lobby has the same author, and a member could
post one claiming to be somebody else - covering for a machine that is no
longer running. What the lobby genuinely buys you is that *absence* is
visible. It does not stop somebody determined to fake being present.

**A bot each closes most of that.** With separate bots each member's line
arrives from a different account, and the program records who first
published each member id and says so in the channel if that ever changes:

> **Sam's line in the lobby changed hands**
>
> Until now Sam's own machine posted their line in the lobby. This one came
> from a different account.

**Names in the lobby are other people's text.** They arrive over a channel
anyone in the server can post to and get printed into a roster, so backticks,
newlines and mention text are stripped out of them before they are shown. A
member can still pick a silly name; they cannot forge a row for somebody who
is not there, and it is the user id, never the name, that identifies who a
line is about.

**Silence is also what a laptop on holiday looks like.** Twelve hours of
nothing is a question, not a verdict, and the message says so. If your group
travels a lot, raise `group.silence_hours`.

### Settings

In `/etc/pornblock/config.json`:

| Setting | Default | What it does |
|---|---|---|
| `group.enabled` | `false` | whether this machine is in a group at all |
| `group.name` | `""` | what you call yourselves; shown on the roster |
| `group.lobby_channel_id` | `""` | the shared channel everyone can see |
| `group.member_id` | `""` | your own Discord user id |
| `group.member_name` | `""` | how the roster names you (defaults to `owner_name`) |
| `group.heartbeat_minutes` | `30` | how often this machine posts its line |
| `group.silence_hours` | `12` | how long of nothing before somebody is called quiet |
| `group.announce_silence` | `true` | whether to say it in the lobby, or only record it |
| `group.share_counts` | `true` | put today's blocked-lookup count in the line |

Which lobby this machine answers to is pinned in the immutable install
record, the same as the approver list and the channel. Editing yourself out
of the group by hand is reverted and said out loud; leaving for real is
`group --leave`, during an unlock.

**Moving to a different lobby is allowed and needs no unlock.** Re-run
`group --join --lobby <new id>` and the record moves with you - you are
still reporting to a room your friends are in, which is the thing being
pinned. Only walking out altogether is gated.

**A word on the heartbeat, if you share one channel.** Each member's line is
one message edited in place, so sharing the lobby with an alert channel adds
one message per person, once. The line sits where it was first posted and
scrolls up out of the way; a separate `#christwatch` lobby still keeps
everybody's status in one place you can glance at.

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
| `tracking.enabled` | `true` | Record anything at all |
| `tracking.dns_log` | `true` | Log every domain looked up |
| `tracking.digest_hour` | `20` | Local hour the daily report is emailed |
| `tracking.keep_days` | `90` | How long daily logs are kept |
| `tracking.top_n` | `15` | Rows per section in the report |
| `tracking.report_apps` | `false` | Put the apps that were open in the daily report (off: every app left open all day shows the same time) |
| `tracking.report_domains` | `false` | Put the most looked-up domains in the daily report (off: they are mostly telemetry and CDNs) |
| `updates.repo` | - | Git URL to pull new versions from |
| `updates.branch` | `main` | Branch to track |
| `updates.check_minutes` | `15` | How often the daemon looks (cheap: `git ls-remote`) |
| `updates.auto_apply` | `true` | Install new versions with no prompting |
| `updates.require_unlock` | `false` | Only update inside an unlock window |
| `enforce.*` | all on | Turn individual layers off |
| `enforce.block_extensions` | `false` | Blanket block on browser extension installs |
| `blocked_extension_ids` | empty | Specific add-on IDs to block, per browser |

### The catch: the config is not fully yours any more

`install-record.json` is immutable and holds the approvers, the quorum, the
cool-off, the window, the passphrase policy and the update source. On every
pass the daemon
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

## What it records

Once it is switched on, it keeps a daily log and emails your approvers a
report every evening.

| Recorded | How |
|---|---|
| **Screen time** | Seconds where your session was active, unlocked and not idle (logind) |
| **Applications** | Time each app was *open* while you were at the machine, from its systemd cgroup |
| **Every domain looked up** | Parsed from systemd-resolved's own query log |
| **Blocked attempts** | Domains requested that are on the blocklist, counted separately |
| **DNS bypass attempts** | nftables counters on the drop rules - something trying to reach another resolver |

```bash
sudo pornblock activity              # today
sudo pornblock activity --domains    # ...including everything looked up
sudo pornblock activity --day 2026-09-20
sudo pornblock activity --send       # email the report now
```

The app shows a **Today** panel with the same numbers and a **Full report**
button. Aggregates live in the world-readable status file so the app can
show them without a password; the list of what you actually looked up is
root-only, so seeing that costs an authentication prompt.

Days are kept for `tracking.keep_days` (90) and then deleted.

### Said as it happens, not just in the evening

The report above arrives at eight. By then the afternoon it is describing is
over, and there is nothing anybody can do about it but read.

So the blocked part is also said straight away, in the channel:

> **[ChristWatch] 2 blocked sites were just asked for**
>
> Will on will-laptop, 14:32
>
> &nbsp;&nbsp;pornhub.com - 3rd time today
> &nbsp;&nbsp;xvideos.com - 1st time today
>
> Refused by the resolver. None of them loaded.

Nothing extra is recorded to do this. It is the same resolver log the
nightly report is built from, read as it arrives instead of at the end of
the day.

The cost is noise, and nearly all of the tuning here is about noise - a
channel that buzzes forty times in an afternoon gets muted, and a muted
channel is worth less than no channel at all.

| Setting | Default | What it does |
|---|---|---|
| `live_alerts` | `true` | the whole thing |
| `live_alert_names` | `true` | name the site; `false` posts only a count |
| `live_alert_ping` | `false` | no phone buzz for these - being in the channel is enough |
| `live_alert_gap_seconds` | `120` | never two posts closer together than this |
| `live_alert_repeat_minutes` | `60` | the same site is not mentioned again inside this |
| `live_alert_max_domains` | `8` | names per post; anything beyond is counted |
| `live_alert_when_unlocked` | `false` | stay quiet during an unlock your friends approved |

One page load fires a dozen lookups and a stubborn afternoon fires hundreds.
With those defaults, that afternoon is a handful of messages naming the
sites that actually mattered.

**During an unlock it says nothing.** Your friends already agreed to that
hour, so shouting through it is noise - and every line of it is still in the
evening's report. Set `live_alert_when_unlocked` to `true` if you want it
anyway.

**It does not fire for sites the resolver never saw.** A browser doing its
own encrypted DNS is caught by the firewall, not by this, and shows up as
`dns bypass drops` in the daily report instead.

**If Discord is unreachable the post is dropped, not held.** Everything else
here queues and retries; this one does not, on purpose. "Just asked for"
arriving three hours late describes nothing that is still happening, and an
outage would otherwise release the whole backlog at once. The evening report
still carries every line of it.

### Be clear about what this means

**Your approvers get a list of every domain your machine looked up.** Not
just the blocked ones - your banking, your health searches, your job
hunting, the lot. That is what "core + every domain" buys: there is nowhere
to hide, including places you might reasonably want to. Set
`tracking.dns_log` to `false` to keep screen time, apps and blocked attempts
without the full browsing list.

**It does not record keystrokes or take screenshots**, and it will not be
made to. That kind of capture sweeps up passwords, card numbers and other
people's messages in your chats, and all of it would be emailed to your
friends. The accountability value does not come close to justifying it.

**App time is "open", not "looked at".** Wayland deliberately does not let a
background process see which window is in front. A browser left open all day
reads as all day.

**Domain logging needs systemd-resolved at debug level**, which the daemon
sets and re-asserts. That makes the journal considerably noisier; journald's
own size caps still apply.

## Updating from GitHub

Point it at a repo once and it will pull new versions.

```json
"updates": {
  "enabled": true,
  "repo": "https://github.com/EasternProdigy/christwatch",
  "branch": "main",
  "check_minutes": 15,
  "auto_apply": true,
  "require_unlock": false
}
```

**Out of the box this behaves like a real application: you push, and within
about fifteen minutes every machine running it is on the new version, with
nobody touching anything.**

The poll is cheap - a `git ls-remote` that returns one line. Nothing is
downloaded until the branch head actually moves.

Then `sudo pornblock install` once, which pins that source into the immutable
install record. After that:

```bash
sudo pornblock update --check   # is there a newer version?
sudo pornblock update           # fetch, vet, install, restart
```

Either way, without editing JSON:

```bash
sudo pornblock update-source --auto      # apply new versions by itself
sudo pornblock update-source --no-auto   # tell me, and I will press the button
```

That switch is deliberately *not* pinned in the install record, because it
decides nothing about where code comes from - only whether you are asked
first. Where it comes from is pinned, and repointing it needs a granted
unlock.

**Applying by itself only happens on a version bump.** A candidate whose
`VERSION` is not higher than the installed one is reported but not
installed, however green it is - so work in progress on the branch does not
go out to everybody as root just because it passed the tests. Bumping
`VERSION` is the deliberate act that says this one is meant for people.

```bash
sudo pornblock update     # takes it anyway, bump or no bump
```

Set `updates.auto_needs_version_bump: false` if you really do want every
commit. On top of that, a candidate still has to compile, declare a version,
pass the project's own self-test in a sandbox, keep your arrangement intact
and start cleanly - or it is rolled back and your approvers are told.

Set `auto_apply: false` if you would rather approve each one; the app then
shows a banner with an **Install** button instead.

### Your setup is not part of the update

Updates replace two files: `/usr/local/bin/pornblock` and `pornblock-gui`.
Everything that makes this *yours* lives somewhere else and is never touched:

| | |
|---|---|
| `/etc/pornblock/config.json` | approvers, timings, channel, filter |
| `/etc/pornblock/secrets.json` | bot token, passphrase hash |
| `/etc/pornblock/install-record.json` | the pinned arrangement |
| `/var/lib/pornblock/` | state, blocklist, what it has recorded |

A new version that adds a setting gets a default for it, so an old settings
file keeps working - there is a config from the first release frozen into the
test suite, and any change that stops it loading fails the build. A change
that needs more than a default gets a migration step, and a settings file
written by a *newer* version is left alone rather than rewritten backwards,
because that case is a rollback.

And then there is the check that does not rely on any of that being right.
Before an update is accepted, the machine writes down what it knows about
your arrangement - who your approvers are, how long the wait is, which
channel, whether it is armed, whether it is locked - and asks the new version
the same questions. If a single answer differs, the update is thrown away,
the previous version is put back, and everyone is told what it would have
changed:

```
  1.3.0 was NOT installed. You are still on 1.2.1, with everything as it was.
  rolled back 1.3.0: it would have changed your setup: configured was True
  and is now False; approvers was ['111...', '222...'] and is now None
```

That is not a hypothetical - it is rehearsed in the test suite and against a
real machine, with a build that passes every test and then looks for its
settings in the wrong place.

**What happens before new code is allowed to run as root:**

1. It is fetched from the **pinned** repo and branch. Repointing `repo` or
   `branch` in the config while locked is reverted and emailed to everyone.
2. If it is byte-identical to what is installed, nothing happens.
3. The new `pornblock.py` must compile and must declare a `VERSION`.
4. **The candidate must pass its own `selftest.py`** in a throwaway sandbox.
   A version that quietly removed the passphrase gate would fail those checks
   and be refused. This is a real gate, not a formality.
5. Updates are refused while a request is `PENDING` - you do not get to
   update your way out mid-request.
6. The new copy has to *run here* before the daemon is handed over to it:
   it is installed, then probed with `--version` and `status --json`. If
   either fails, the previous version is put straight back and everyone is
   emailed. A push that passes the tests but dies on a real machine cannot
   take your blocking down with it.
7. Applying one emails all approvers with the version, commit and subject.

Set `require_unlock: true` to only allow updates inside a granted unlock
window. That closes the hole below completely, at the cost of needing 24
hours to take a security fix.

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

**The lobby cannot prove who posted a line.**  If your group shares one bot,
every heartbeat in the lobby has the same author, so a member could post one
claiming to be somebody whose machine has actually stopped. The lobby makes
*absence* visible, which is the failure nobody announces about themselves;
it does not stop somebody determined to fake being present. A bot each
closes most of it - then a member's line arriving from a new account is
itself said out loud. See [Several of you, one
server](#several-of-you-one-server).

**A group member can simply not be in the group.**  Nothing about the lobby
is enforced across machines, because nothing can be: each blocker is root on
its own machine and answers to its own approvers. Somebody who edits
themselves out has it reverted and said out loud on *their* machine - which
is worth something, and is not the same as being unable to.

**Live alerts are only as good as the resolver's view.**  They fire on what
systemd-resolved was asked for. A browser with its own encrypted DNS is
caught by the firewall instead and shows up as a bypass count, not a named
site; an app using a VPN is not seen at all. They also need
`tracking.dns_log`, so switching that off to keep your browsing private
switches these off with it.

**You can read the mailbox password.**  Your friend types it, but it is stored
in `/etc/pornblock/secrets.json`, which root can read. Splitting it into its
own immutable 0600 file keeps it out of casual sight and out of the GUI and
the status snapshot - it does not hide it from a determined you. The
passphrase is different: only a hash is kept, so that one really does need
your friend.

**The updater runs code as root, automatically.**  Be clear-eyed about what
auto-apply means: if you own the repository, **you can switch off your own
blocker by pushing a commit**, and within about fifteen minutes it will have
happened, on every machine running your build, with no cool-off and no
approvals. It is the single most convenient bypass here and it is on by
default, because you asked for something that behaves like a real
application. Those two wishes genuinely conflict.

What still stands between you and it: the source is pinned in the immutable
record and cannot be repointed while locked; the candidate has to pass the
project's own self-test, so the obvious edits - removing the passphrase
gate, dropping the quorum - are caught and refused; and every applied
update emails all of your approvers with the version, the commit hash and
its subject line. So it is loud. It is not prevented.

If you want the blocker to genuinely hold against you, pick one:

* **Have an approver own the repository** and track their fork. Then
  auto-update is a feature rather than a hole - you can still send them pull
  requests, and they decide what lands on your machine.
* `updates.require_unlock: true` - updates only apply inside a granted
  unlock window.
* `updates.auto_apply: false` - you still have to press the button, which
  at least means the bypass is not silent.
* `updates.enabled: false` - no updater at all.

**DNS-over-HTTPS from non-browser apps.**  The big technical one. DoH is HTTPS
on port 443 and is indistinguishable from normal web traffic. Browsers are
pinned to the filter by policy, and the firewall rejects 443 to a list of
well-known public resolvers - but any app that hardcodes an obscure DoH
endpoint, or any DoH server not on that list, gets through. Closing this
properly needs allowlist-style egress filtering, which would break ordinary
use of the machine.

**The extra nets do not stop a root user either.**  `harden` closes the
quiet routes - stopping both systemd units at once, deleting the program,
editing the boot line - but everything it adds is a file that root can
delete. The point is that deleting each one is a separate deliberate act,
and that until you have done all of them, the blocker comes back within a
minute and says so. It buys you friction and witnesses, not immunity.

**Your phone is watched, not held.**  The Android app cannot stop you
changing the setting and it cannot stop you uninstalling it - no app can,
without being a device-owner app you provision from a factory reset. What it
can do is post the change to your channel, and go quiet in a way the laptop
notices. On an iPhone even the watching is impossible: the only real lock
there is the removal password your friend holds. Both are friction plus
witnesses, which is what the rest of this program is too.

**The phone's webhook is in the pairing link.**  Anyone who gets that link
can post messages into your channel as the phone - including a fake "still
on" once a day, which would hide a real phone going quiet. It travels from
the laptop to the phone over your own network and is not emailed or stored;
`sudo pornblock phone --remove` and making a new webhook in Discord is the
fix if it ever leaks.

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

**DNSSEC validation is off, deliberately.** A filtering resolver answers some
questions differently on purpose - `google.com` points at forcesafesearch,
blocked domains point at nowhere - and those answers are not the ones the
zone signed. Validating them on this machine rejects them as forged and the
machine loses DNS entirely, which is exactly the bug that shipped in 1.4.0.
What protects a lookup here is the TLS connection to a resolver whose
certificate is checked, and that stays on. The same reason is why every
server is pinned as `1.1.1.3#family.cloudflare-dns.com` rather than a bare
address, on links as well as globally: with a bare address, systemd-resolved
checks the certificate against the address, and Cloudflare's certificate does
not list the family ones.

**Your approvers are human.**  If they rubber-stamp everything, you have a
24-hour delay and nothing else. Pick people who will actually ask why.

**Approval email is identified by the `From:` header** and nothing stronger.
No DKIM check, no signatures - anyone who can reach an SMTP server can forge
an approval from your friend's address. This is the main reason Discord is the
default: a message there carries a user id you cannot spoof. Either way, run
`test-email` regularly, because a silently broken channel means alerts nobody
ever receives.

**On Discord, you can read the bot token** - it lives on a machine you are
root on. It cannot approve anything, but it can post as the bot, so someone
determined could write a convincing-looking fake alert in the channel. It also
means you could revoke the token and go quiet; the machine would stay locked
and your friends would stop hearing from it, which is its own kind of tell.

**Discord itself is a dependency.** If it is down, or the bot is kicked, no
approval can arrive. The machine stays locked and keeps enforcing - the safe
failure - but the honest unlock path is closed until it comes back.

**The GUI runs as you.**  Secrets typed into the wizard are piped over stdin
rather than written to disk, but a process you own can be attached to by a
debugger you own. Again: friction, not secrecy.

### What this costs you, measured

Short version: nothing you will feel. Longer version, from a real machine:

| | |
|---|---|
| Repeat lookup (resolved's cache) | **0 ms** |
| First lookup of a domain, over DNS-over-TLS | 17-110 ms, and the first one after a restart pays the TLS handshake |
| nftables lockdown | 15 rules on the output hook, unmeasurable |
| `/etc/hosts` with the 70k list | ~5 ms of parsing on **every** lookup, because glibc re-reads the whole 2 MB file each time |
| `/etc/hosts` without it | 4 KB, nothing to speak of |
| Domain tracking | systemd-resolved at debug level: ~28,000 journal lines an hour on a machine in use, which is why `tracking.journal_cap_mb` bounds the journal at 512 MB |
| Private DNS on the phone | no extra hop - it replaces the resolver rather than sitting in front of one, and it is encrypted either way |
| The phone app | one HTTPS post a day, one setting read an hour, no VPN slot and no always-on service |

That last row is why `enforce.hosts_blocklist` defaults to **off**. The
resolver blocks the same sites for free, so the file keeps only the SafeSearch
pinning and anything you add yourself:

```bash
sudo pornblock block somewhere.example   # something slipped through
sudo pornblock block --list
sudo pornblock block --remove somewhere.example   # said out loud to your approvers
```

Turn the big list back on with `"enforce": {"hosts_blocklist": true}` if you
want the belt as well as the braces - it does catch niche sites the resolver's
categories miss.

**Your browser does not use any of this anyway.** The Firefox and Chromium
policies lock DNS-over-HTTPS to the same filtering resolver, so pages resolve
through the browser's own encrypted connection. `/etc/hosts` and
systemd-resolved never enter into it - which also means the hosts list was
never what blocked porn in your browser.

**The domain log is the one real cost.** Tracking which domains were looked up
means systemd-resolved logs every query at debug level, which is tens of lines
a second into the journal. It costs disk, not latency. `"tracking":
{"dns_log": false}` switches it off; screen time, app time and blocked
attempts all keep working, and you lose the list of sites.

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
python3 selftest.py     # 86 offline checks, no network, no root, no display
```

Covers reply parsing (including that a quoted APPROVE in a reply must not
approve anything), enforcement idempotency, drift reversion, the three-gate
state machine, passphrase hashing, secret hygiene, the desktop files and the
update-candidate vetting. It deliberately needs no display, because the
updater runs it to vet a candidate version.

The desktop app has its own suite, which does need a display:

```bash
gtk4-broadwayd :9 &
GDK_BACKEND=broadway BROADWAY_DISPLAY=:9 python3 guitest.py   # 30 checks
```

That one also asserts every symbolic icon name resolves in the icon theme -
a missing name renders as a broken-image square, and `checkbox-symbolic`
draws a tick rather than an empty box, which is exactly the sort of thing
that makes a careful UI look sloppy.
