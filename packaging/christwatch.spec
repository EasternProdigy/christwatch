Name:           christwatch
Version:        1.9.0
Release:        1%{?dist}
Summary:        Accountability-gated content blocker

License:        MIT
URL:            https://github.com/EasternProdigy/christwatch
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3 >= 3.9
Requires:       python3-gobject
Requires:       gtk4
Requires:       libadwaita
Requires:       adwaita-icon-theme
Requires:       nftables
Requires:       e2fsprogs
Requires:       systemd
Requires:       systemd-resolved
Requires:       polkit
Requires:       git-core
Recommends:     desktop-file-utils

%description
Blocks porn at the system level and makes turning it back off slow, awkward
and impossible to do quietly. An unlock needs three things at once: a
cool-off timer, approval by email from a quorum of friends, and a passphrase
only they know. Every request, approval, denial and tamper attempt is emailed
to all of them.

Installing this package only puts the app on the machine; nothing is blocked
until you open ChristWatch and go through the setup wizard.

Removing this package does NOT switch blocking off. That is deliberate.
Use "pornblock uninstall", which only works inside a granted unlock window.

%prep
%autosetup -n %{name}-%{version}

%build
# Pure python, nothing to compile.

%install
install -d -m 0755 %{buildroot}%{_datadir}/%{name}
install -m 0755 pornblock.py pornblock_gui.py %{buildroot}%{_datadir}/%{name}/
install -m 0644 selftest.py guitest.py christwatch.svg README.md LICENSE \
    %{buildroot}%{_datadir}/%{name}/

%check
# Runs entirely in a throwaway prefix; touches nothing outside it.
cd %{_builddir}/%{name}-%{version} && python3 selftest.py

%post
# Stage one: place the program, the desktop entry and the icon. Nothing is
# armed and nothing is made immutable until the user runs the wizard.
%{_datadir}/%{name}/pornblock.py install-app >/dev/null 2>&1 || :

%postun
# Intentionally empty. Erasing the package must not be a way to unblock
# yourself - the managed copies in /usr/local/bin and any armed enforcement
# are left exactly as they are.
:

%files
%license LICENSE
%doc README.md
%{_datadir}/%{name}/

%changelog
* Wed Sep 23 2026 William Mezitis <wmezitis@gmail.com> - 1.9.0-1
- Set up a phone by scanning a QR code: in the app and in the
  terminal. The phone page walks through Android's install prompts,
  and a missing Discord permission is one button, not a stuck screen.
- Routine self-repairs (wifi handing out its own DNS, a lock flag our
  own update left off) are fixed and logged, not posted.
- Updates, cancellations and other news nobody has to act on are
  posted without pinging, and updates without a link preview.
- The daily report drops the app and top-domain lists by default.
- Each group heartbeat is one message edited in place.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.8.1-1
- A live blocked-site post is dropped during an outage, not replayed
  hours later as though it were still happening.
- The install record follows the group lobby when you move it.
- Names from other members cannot break the roster's formatting.
- The release gate is exercised by the test suite, not just grepped.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.8.0-1
- Name a blocked site in the channel as it is asked for, not only
  in the evening's report.
- Group mode: several people in one Discord server, one shared
  lobby, and a machine that stops running the blocker is seen to.
- SETUP.md: a linear first-time setup guide.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.5.0-1
- Keep /etc/hosts small; the resolver does the blocking.
- New: block a site by hand.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.4.1-1
- Fix DNS breaking system-wide: pin links with the TLS name, DNSSEC off.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.4.0-1
- Optional: stop asking for a password for this program's commands.
- Stop offering an update you already have.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.3.0-1
- An update that would change your setup is rolled back.
- Stop reporting a DNS-over-TLS resolver as the wrong resolver.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.2.1-1
- Checking in is a tap, and waits as long as you need.
- Shorter messages in the channel.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.2.0-1
- Approve by tapping a tick under the request.
- Ask approvers privately by direct message.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.1.4-1
- Tell apart the three reasons the bot might not read a channel.
- Approvals get through by mentioning the bot even if the intent is off.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.1.3-1
- Prove the Message Content intent by reading the channel.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.1.2-1
- Fix the channel picker reading only the last line of the reply.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.1.1-1
- The app walks you through making the Discord bot.

* Tue Sep 22 2026 William Mezitis <wmezitis@gmail.com> - 1.1.0-1
- Run the whole thing over a Discord channel instead of email.

* Mon Sep 21 2026 William Mezitis <wmezitis@gmail.com> - 1.0.3-1
- Pick your mail provider instead of typing SMTP and IMAP servers.
- Check the mailbox password before installing anything.

* Mon Sep 21 2026 William Mezitis <wmezitis@gmail.com> - 1.0.2-1
- Warn when a unanimous quorum makes the passphrase gate inert.
- Dashboard hero carries the lock state as colour.

* Mon Sep 21 2026 William Mezitis <wmezitis@gmail.com> - 1.0.1-1
- Orthodox cross on the app icon; plainer wording on the first setup page.

* Mon Sep 21 2026 William Mezitis <wmezitis@gmail.com> - 1.0.0-1
- First packaged release.
