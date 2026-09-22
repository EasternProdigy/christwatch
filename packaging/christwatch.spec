Name:           christwatch
Version:        1.0.2
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
* Mon Sep 21 2026 William Mezitis <wmezitis@gmail.com> - 1.0.2-1
- Warn when a unanimous quorum makes the passphrase gate inert.
- Dashboard hero carries the lock state as colour.

* Mon Sep 21 2026 William Mezitis <wmezitis@gmail.com> - 1.0.1-1
- Orthodox cross on the app icon; plainer wording on the first setup page.

* Mon Sep 21 2026 William Mezitis <wmezitis@gmail.com> - 1.0.0-1
- First packaged release.
