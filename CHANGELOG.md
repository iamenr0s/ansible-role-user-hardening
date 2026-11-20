# Changelog

## 1.0.0
- Split out of the iamenr0s.linux_hardening collection.
- Password hashes are no longer kept in host facts: `/etc/shadow` is read with `no_log` and dropped once parsed.
- Check mode: remediate previews changes and skips the re-audit; read-only tasks run in check mode.
- Home directories of exempt accounts are no longer changed.
- `linux_hardening_user_inactive_days` must be an integer or null; anything else fails validation.
- Account parsing and classification moved from inline Jinja to unit-tested filter plugins; a malformed `/etc/passwd` line now fails instead of being read as UID 0. NIS compat lines (`+`/`-`) are skipped; only local accounts are checked.
- `linux_hardening_user_exempt` now defaults to `[root]`: the `sync`, `shutdown` and `halt` shells count as non-login, so overriding the list no longer requires repeating them.
- Empty password fields in `/etc/passwd` (unshadowed accounts) are reported; they are report-only because locking `/etc/shadow` does not close them.
- The INACTIVE default is set with `lineinfile` in `/etc/default/useradd` instead of `useradd -D -f`, so it shows a diff and is backed up when `linux_hardening_backup` is true.
- A remediation re-audit and a plain audit now fail with different messages ("could not fix" vs "found").
- Setting `linux_hardening_profile` to anything but `cis_level1` prints a notice that this role ignores it.
