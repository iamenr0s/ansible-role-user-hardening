[![Molecule](https://github.com/iamenr0s/ansible-role-user-hardening/actions/workflows/molecule.yml/badge.svg)](https://github.com/iamenr0s/ansible-role-user-hardening/actions/workflows/molecule.yml) ![Ansible Role](https://img.shields.io/ansible/role/d/iamenr0s/user_hardening) [![CodeFactor](https://www.codefactor.io/repository/github/iamenr0s/ansible-role-user-hardening/badge)](https://www.codefactor.io/repository/github/iamenr0s/ansible-role-user-hardening)

# Ansible Role: User Hardening

> Standalone copy of `user_hardening` from the [iamenr0s.linux_hardening](https://github.com/iamenr0s/linux-hardening-collection) collection. Variables keep the collection-wide `linux_hardening_*` prefix.

Audit-first hygiene for **local** accounts (`/etc/passwd`, `/etc/shadow`). It does not create or manage users; use a user-management role for that. Password ageing and complexity belong to `password_policy`, PAM to `pam_hardening`, sudoers to `sudo_hardening`.

## Checks
| Check | Remediation |
|---|---|
| Account with an empty password | locked (`usermod -L`); key logins keep working |
| System account (UID below `UID_MIN`) with a login shell | shell set to `/usr/sbin/nologin` |
| Interactive user's home with group-write or any "other" access | `g-w,o-rwx` |
| `useradd -D` INACTIVE differs from 30 days | `useradd -D -f 30` |
| UID 0 account other than root | **reported only** |
| Duplicate UIDs | **reported only** |

`UID_MIN` is read from `/etc/login.defs` (default 1000). Remediation never touches `root, sync, shutdown, halt`, anything in `linux_hardening_user_exempt`, or the Ansible user.

## Modes
`audit` (default) is read-only and sets `linux_hardening_user_findings` (`key, expected, actual, fixable`). `remediate` needs `linux_hardening_confirm_remediation: true`; `/etc/passwd` and `/etc/shadow` are copied to `linux_hardening_user_backup_dir` first. After remediation only *fixable* findings fail the run.

## Variables
See `defaults/main.yml` and `meta/argument_specs.yml`. Each fix has an on/off switch (`..._lock_empty_passwords`, `..._fix_system_shells`, `..._fix_home_permissions`); `..._inactive_days: null` leaves the default unmanaged.

## Example
```yaml
- hosts: all
  roles:
    - role: iamenr0s.linux_hardening.user_hardening
      vars:
        linux_hardening_mode: remediate
        linux_hardening_confirm_remediation: true
        linux_hardening_user_exempt: [root, sync, shutdown, halt, postgres]
```

## Impact
Service accounts that really need a shell (e.g. `su - postgres`) must be listed in `linux_hardening_user_exempt`, otherwise they get `nologin`. Tightened home directories can break shared-home setups.

## Verification
Molecule `default` (remediate, idempotence, re-audit, backups, exempt account untouched), `audit` (reports, changes nothing), `refuse`. Tested: AlmaLinux 9, Ubuntu 24.04, Debian 13.

## Rollback
Restore `passwd.<timestamp>` / `shadow.<timestamp>` from `/var/backups/linux-hardening` (careful: this also reverts any other account change made since).

## Known gaps
- Local files only; LDAP/SSSD accounts are not examined.
- Not checked yet: `.rhosts`/`.netrc`/`.forward` files, root's primary GID, shell timeout/umask, orphaned home ownership.
- Duplicate names/GIDs and groups are not audited.
- CIS IDs not mapped.

CI & Release (maintainers)
----------------------------
A single workflow (`.github/workflows/molecule.yml`) runs lint and the full Molecule distro matrix on pushes to `main`, PRs, and `v*` tags. On `v*` tags, a `release` job publishes to Ansible Galaxy after all tests pass.

One-time setup:

```bash
# Galaxy publishing key (environment-scoped, get it from galaxy.ansible.com/ui/token)
gh secret set GALAXY_API_KEY --repo iamenr0s/ansible-role-user-hardening

# Code scanning notifications (Slack webhook URL; for Discord append /slack to the webhook URL)
gh secret set SECURITY_ALERT_WEBHOOK --repo iamenr0s/ansible-role-user-hardening
```

`.github/workflows/code-scanning-notify.yml` polls the code-scanning API every 6 hours and posts new or updated open alerts to that webhook (GitHub Actions cannot trigger on `code_scanning_alert` directly).

To release: tag a commit `vX.Y.Z` and push the tag — CI gates the Galaxy publish.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
local pipeline commands and pull request checklist. This project follows the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md) — GitHub private vulnerability reporting, no
public issues for security bugs.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## License

This project is licensed under the [MIT License](LICENSE).

## Author Information

Author: iamenr0s

Galaxy: `iamenr0s.user_hardening`
