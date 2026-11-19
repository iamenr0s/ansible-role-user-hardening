# Changelog

## 1.0.0
- Split out of the iamenr0s.linux_hardening collection.
- Password hashes are no longer kept in host facts: `/etc/shadow` is read with `no_log` and dropped once parsed.
- Check mode: remediate previews changes and skips the re-audit; read-only tasks run in check mode.
- Home directories of exempt accounts are no longer changed.
- `linux_hardening_user_inactive_days` must be an integer or null; anything else fails validation.
