# The signing key in this folder is not a secret

`christwatch.jks` is committed on purpose, password `christwatch`, and anyone
reading this repo has it.

Android refuses to upgrade an app in place unless the new version carries the
same signature as the old one. A key held privately would mean only one person
could ever ship an update, and a key generated fresh in CI would mean every
release had to be uninstalled and reinstalled by hand - losing the pairing
each time.

Nothing about your setup rests on this key. The phone app does not hold your
bot token; it holds a write-only webhook for one channel, handed to it when
you pair it. What keeps you honest is that two friends are watching the
channel, which is true whoever signed the APK.
