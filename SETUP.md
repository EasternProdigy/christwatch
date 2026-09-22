# Setting up ChristWatch

A step-by-step guide for someone doing this for the first time. The
[README](README.md) is the reference manual; this is the path through it.

**Time:** about 30 minutes, most of it waiting for downloads.
**You will need:** a Linux machine you are root on, a Discord server you and
your friends are already in, and **one friend available for five minutes at
the end**. That last one is not optional - the whole thing hinges on it.

---

## Before you start: what you are agreeing to

Read this properly. People skip it and then get a surprise on day two.

1. **Turning it off takes 24 hours, your friends, and a password you do not
   have.** Not one of the three. All three, at once. There is no button that
   skips the wait, and the person who built it cannot help you either.

2. **Your friends will see what you look up.** By default, every domain your
   machine resolves goes into a report they get every evening - your banking,
   your job hunting, your health searches, all of it. Blocked sites are also
   posted in the channel *as they happen*, by name, within a couple of
   minutes. You can turn the full browsing list off and keep the blocked-site
   part (see [Tuning](README.md#tuning)); you cannot turn off the part where
   somebody finds out.

3. **You are root, so none of this is unbreakable.** Anyone with root and
   fifteen focused minutes can take it apart. What it buys you is delay,
   friction, and having to explain yourself. That is the actual mechanism.
   If you want something you genuinely cannot undo, this is the wrong tool
   and the README says so at length.

4. **Pick your friend carefully.** They will hold a passphrase you cannot
   recover and they will get every alert. It should be someone who will
   actually say no, and who you would be embarrassed to explain yourself to.
   A friend who will type the passphrase for you the first time you ask has
   cost you nothing but their evening.

If all four of those are fine, carry on.

---

## Step 1 - Get the app on the machine

**Nothing is blocked by this step.** It only puts the app in your menu.

**Fedora:** download the `.rpm` from the project's Releases page and
double-click it. Your software centre handles the dependencies.

**Anything else:** unpack the download and double-click **Install
ChristWatch**. It opens a terminal, tells you what is missing, offers to
install it, and puts the app in place. If your file manager refuses to run
it, mark it executable first (right-click → Properties → Permissions).

**From a terminal:**

```bash
git clone https://github.com/EasternProdigy/christwatch && cd porn-block
./install.sh
```

Open **ChristWatch** from your app grid. It will say it is not armed yet.
That is correct.

---

## Step 2 - Make the Discord bot

Do this before the wizard asks, so you are not scrambling mid-setup.

1. Go to <https://discord.com/developers/applications> → **New Application**.
   Name it whatever you like.
2. **Bot** in the sidebar → **Reset Token** → copy what it shows you. This is
   the only time it shows you. Paste it somewhere for the next five minutes.
3. Still on the Bot page, switch on **Message Content Intent**, then scroll
   down and press **Save Changes**. The toggle does nothing until you press
   save, and without it every message your friends type arrives blank.
4. Leave the tab open. The wizard builds the invite link for you from the
   token, so you do not need to copy the application id.

The bot only ever needs four permissions: View Channel, Send Messages, Read
Message History, Add Reactions. The invite link asks for exactly those.

> **Why a bot and not just email?** An email approval is matched on a `From:`
> header, which anyone can forge. A Discord reaction carries a user id that
> you cannot fake without owning your friend's account. And approving happens
> in front of everyone, which is most of the point.

---

## Step 3 - Make the channels

In your Discord server:

- **One channel for you.** Call it `#cw-yourname`. Your requests, approvals,
  alerts and nightly reports go here.
- **If other people are going to use this too,** also make `#christwatch` as
  a shared lobby, and give each person their own `#cw-name` channel. See
  [Step 7](#step-7---join-the-group).

Everyone who might approve an unlock needs to be able to see your channel.
That is the point of it.

To get a channel's id: Discord Settings → Advanced → **Developer Mode** on,
then right-click the channel → **Copy Channel ID**. The wizard can also just
list the channels the bot can see, so you usually do not need this.

---

## Step 4 - Run the wizard

Open **ChristWatch** and work through it. It asks for:

- **Your name and email.**
- **The bot token** from step 2. From here it builds the invite link and the
  settings link itself.
- **Which channel.** Press *Find channels* and pick from the list.
- **Your approvers.** Press **Ask them to check in**. It posts one short
  message in the channel, and everyone who taps the tick becomes an approver,
  names and all. Nobody has to copy an 18-digit id. **There is no time
  limit** - your friends can answer tonight or tomorrow and the app keeps
  watching.
- **How many must approve** (2 is a sensible default), **the cool-off**
  (24 hours), and **how long an unlock lasts** (60 minutes).

From a terminal instead:

```bash
sudo pornblock setup
```

You can check the bot works before committing to anything - this posts
nothing and needs no root:

```bash
echo '{"discord":{"bot_token":"...","channel_id":"..."}}' | pornblock check-discord
```

---

## Step 5 - The step where you look away

This is the one that matters, and it is the one people fudge.

The last page of the wizard asks for a **partner passphrase**. **Your friend
types it, not you.** Hand them the keyboard and look at the wall. It is
stored only as a hash, so nobody - not you, not them, not the program - can
read it back out of the machine.

It is the third gate. The 24-hour timer runs out on its own and your friends
might approve without thinking, but this one needs a person to deliberately
choose to help you, in the moment, out loud.

If you type it yourself you have built an elaborate machine with your own
name on the key, and you will find that out at 2am.

Then arm it:

```bash
sudo pornblock install
```

Blocking is now live. Check it:

```bash
sudo pornblock status
```

---

## Step 6 - Your phone

Your laptop is half your day. Skipping this is the most common way people
end up with a blocker that does nothing.

Neither phone runs a copy of this. Both have a system-wide setting that
sends every app's lookups to a resolver that will not answer for porn.

**Android:**

```bash
sudo pornblock phone --add "Pixel"
```

That hands you a link to open on the phone. Install the small app, tap
through, and set Private DNS. The app reports to your channel once a day; if
it stops reporting, that is said out loud - because uninstalling the app is
easier than changing the setting, so silence is treated as an answer.

**iPhone:**

```bash
sudo pornblock phone --add "iPhone" --ios
```

You get a configuration profile. Your friend sets the removal password on it,
the same way they set the passphrase.

See [Your phone](README.md#your-phone) for what this does and does not cover
(short version: a VPN app or a browser with its own DNS goes around it).

---

## Step 7 - Join the group

Skip this if you are the only one using it.

If several of you are doing this in the same server, one shared **lobby**
channel makes the group visible to itself. Every member's machine posts a
short line there every half hour saying it is still running. Nothing central
runs and nobody gains any power over anybody else's blocker.

The point is not the roster. The point is that a machine which stops running
the blocker stops posting, and after twelve hours one of the other machines
says so by name. Nobody announces that they uninstalled it - this is how the
group finds out anyway.

```bash
sudo pornblock group --join \
    --lobby  1234567890123456789 \
    --me     9876543210987654321 \
    --name   "Will" \
    --group  "the lads"
```

`--lobby` is the shared channel's id, `--me` is your own Discord user id
(right-click yourself → Copy User ID, with Developer Mode on).

Then:

```bash
sudo pornblock group          # who is still running it
sudo pornblock group --post   # put that roster in the lobby
```

Full details, including what the lobby does and does not prove, are in
[Several of you, one server](README.md#several-of-you-one-server).

---

## Day one

```bash
sudo pornblock status         # mode, timers, health of every layer
sudo pornblock activity       # what happened on this machine today
sudo pornblock group          # who else is still running it
```

Try asking for an unlock once, now, while nothing is urgent, so that you
have seen the flow before the first time you actually want it:

```bash
sudo pornblock request-unlock --reason "testing this works"
sudo pornblock cancel
```

Cancelling is always allowed and always the right answer.

---

## When something is wrong

**Messages from my friends arrive blank.** Message Content Intent is off, or
you did not press Save Changes. Go back to step 2.4. In the meantime,
approvals still work if the person **mentions the bot** in their message, or
taps the tick reaction - a reaction never needs that intent.

**The bot cannot see the channel.** Re-run the invite link from the wizard
and check the bot actually joined the server. `pornblock check-discord`
tells you which of the two it is.

**Nothing is being blocked.** `sudo pornblock status` lists every layer and
which one is unhappy. `sudo pornblock enforce` forces a pass right now.

**My machine is slow to resolve names.** You probably switched on
`enforce.hosts_blocklist`, which writes 77,000 names into `/etc/hosts` and
costs roughly 5ms per lookup, forever. It is off by default for that reason -
the filtering resolver blocks the same sites for free.

**I have lost the passphrase / my friend is unreachable.** Unanimous approval
from every approver substitutes for it, if `passphrase_recovery` is on (it is
by default). See [If the passphrase is lost](README.md#if-the-passphrase-is-lost).

**I want it gone.** `sudo pornblock uninstall`, which only works during an
unlock - so it costs you the full 24 hours, the approvals and the passphrase,
same as everything else. That is deliberate.

---

## Telling your friends

If you want to hand this to someone, here is the short version to paste:

> I'm using this thing called ChristWatch. It blocks porn on my laptop and
> phone, and the part that matters is that turning it back off needs a
> 24-hour wait, two of you to approve it in our Discord, and a passphrase one
> of you sets that I never see.
>
> What it needs from you: tap a tick in the channel when I ask to unlock, or
> don't. That's it. You'll also see a message when my machine asks for a
> blocked site, and a summary each evening.
>
> If you want one too, the setup guide is here and takes about half an hour:
> <https://github.com/EasternProdigy/christwatch/blob/main/SETUP.md>

If they set one up as well, put both of you in the same lobby (step 7) so
you can each see the other is still running it.
