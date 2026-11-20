[![Molecule](https://github.com/iamenr0s/ansible-role-user-hardening/actions/workflows/molecule.yml/badge.svg)](https://github.com/iamenr0s/ansible-role-user-hardening/actions/workflows/molecule.yml) ![Ansible Role](https://img.shields.io/ansible/role/d/iamenr0s/user_hardening) [![CodeFactor](https://www.codefactor.io/repository/github/iamenr0s/ansible-role-user-hardening/badge)](https://www.codefactor.io/repository/github/iamenr0s/ansible-role-user-hardening)

# Ansible Role: User Hardening

This role audits and hardens **local** accounts (`/etc/passwd`, `/etc/shadow`) on Debian/Ubuntu, RHEL/AlmaLinux/RockyLinux and Fedora servers. It does not create or manage users; use a user-management role for that.

Features
--------
- Audit mode by default: read-only, and reports every deviation. Changes need `linux_hardening_confirm_remediation: true`.
- Locks accounts with an empty password, gives system accounts a `nologin` shell, tightens home directory permissions and sets the `useradd` INACTIVE default.
- Reports UID 0 accounts other than root, duplicate UIDs and empty `/etc/passwd` password fields but never changes them.
- Never touches accounts in `linux_hardening_user_exempt` (default `root`) or the Ansible user.
- Backs up `/etc/passwd`, `/etc/shadow` and `/etc/default/useradd` before changing them.
- Password ageing and complexity belong to `password_policy`, PAM to `pam_hardening`, sudoers to `sudo_hardening` in the `iamenr0s.linux_hardening` collection.

## Requirements
Root privileges (`become: true`): the role reads `/etc/shadow` and runs `useradd`. No collection or role dependencies.

## What it checks
| Check | Remediation |
|---|---|
| Account with an empty password | locked (`usermod -L`); key logins keep working |
| System account (UID below `UID_MIN`) with a login shell (`nologin`, `false`, `sync`, `shutdown`, `halt` are not) | shell set to `/usr/sbin/nologin` |
| Interactive user's home with group-write or any "other" access | `g-w,o-rwx` |
| `useradd -D` INACTIVE differs from 30 days | `INACTIVE=30` in `/etc/default/useradd` |
| UID 0 account other than root | **reported only** |
| Duplicate UIDs | **reported only** |
| Empty password field in `/etc/passwd` (not shadowed) | **reported only** (fix with `pwconv` or set a password) |

`UID_MIN` is read from `/etc/login.defs` (default 1000). Each fix has an on/off switch (`..._lock_empty_passwords`, `..._fix_system_shells`, `..._fix_home_permissions`); `..._inactive_days: null` leaves the default unmanaged.

## Variable names
Variables use the collection-wide `linux_hardening_*` prefix (shared with sibling roles) rather than `user_hardening_*`. Full list: `defaults/main.yml` and `meta/argument_specs.yml`. `linux_hardening_profile` is reserved here: this role applies the same checks for every profile.

## Modes
`audit` (default) is read-only and sets `linux_hardening_user_findings` (`key, expected, actual, fixable`). `remediate` needs `linux_hardening_confirm_remediation: true`; `/etc/passwd` and `/etc/shadow` are copied to `linux_hardening_user_backup_dir` first (when `linux_hardening_backup` is true). After remediation only fixable findings fail the run. `--check` with `remediate` previews the changes and skips the re-audit.

## Safety
- Service accounts that really need a shell (e.g. `su - postgres`) must be listed in `linux_hardening_user_exempt`, otherwise they get `nologin`.
- Locking an empty-password account blocks password logins only; SSH key logins keep working.
- Tightened home directories can break shared-home setups.
- Only `ansible_user` is auto-exempted. If you connect via `remote_user`/`ansible.cfg` or a local connection, add that account to `linux_hardening_user_exempt`.

## Example
```yaml
- hosts: all
  become: true
  roles:
    - role: iamenr0s.user_hardening
      vars:
        linux_hardening_mode: remediate
        linux_hardening_confirm_remediation: true
        linux_hardening_user_exempt: [root, postgres]
```

## Verification
Unit tests for the parsing filters in `filter_plugins/` (`pytest tests/unit`, also run by pre-commit). Molecule `default` (remediate, idempotence, re-audit, backups, exempt account untouched), `audit` (reports, changes nothing), `refuse`. Tested: AlmaLinux 9, Ubuntu 24.04, Debian 13. CI matrix: AlmaLinux 8–10, Rocky 8–10, Fedora 42–44, Debian 12–13, Ubuntu 22.04/24.04.

## Rollback
Restore `passwd.<timestamp>` / `shadow.<timestamp>` from `/var/backups/linux-hardening` (careful: this also reverts any other account change made since). `/etc/default/useradd` is backed up next to itself (`useradd.<pid>.<date>~`); restore that file to undo the INACTIVE change.

**Idempotent:** true. **Atomic:** false: accounts are changed one at a time, so a failed run can leave some fixes applied (backups cover recovery).

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
