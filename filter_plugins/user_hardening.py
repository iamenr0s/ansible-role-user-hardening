"""Filters that parse local account files and classify accounts for user_hardening.

Filters (all pure Python, no host access):

``user_hardening_parse_accounts(passwd, shadow, login_defs)``
    Input: the text of /etc/passwd, /etc/shadow and /etc/login.defs.
    Output: ``{'uid_min': int, 'accounts': [{'name', 'uid', 'home', 'shell', 'empty_pw'}]}``.
    Only whether a password field is empty is kept, never the hash.

``user_hardening_offenders(db, exempt)``
    Input: the parse_accounts result and a list of exempt account names.
    Output: ``{'empty_password': [name], 'system_shell': [name], 'extra_uid0': [name],
    'duplicate_uid': [uid], 'interactive': [{'name', 'home'}]}``.

``user_hardening_open_homes(stat_results)``
    Input: the ``results`` of an ``ansible.builtin.stat`` loop over ``offenders['interactive']``.
    Output: the loop items (``{'name', 'home'}``) whose home is a directory with group-write or any
    "other" permission.

``user_hardening_findings(lists, too_open_homes, inactive, inactive_days, nologin_shell, ...)``
    Input: the offenders result plus the observed state and the role switches.
    Output: ``[{'key', 'expected', 'actual', 'fixable'}]``.

Example::

    - ansible.builtin.set_fact:
        db: "{{ passwd | user_hardening_parse_accounts(shadow, login_defs) }}"
    - ansible.builtin.set_fact:
        lists: "{{ db | user_hardening_offenders(['root']) }}"
    - ansible.builtin.set_fact:
        found: >-
          {{ lists | user_hardening_findings([], -1, 30, '/usr/sbin/nologin',
                                             fix_home_permissions=false) }}
"""

from __future__ import annotations

import re
from typing import Any

# sync/shutdown/halt run one command and exit, so they are not login shells either.
NOLOGIN_SUFFIXES = ("nologin", "/false", "/sync", "/shutdown", "/halt")


def _lines(text: str) -> list[str]:
    """Return the meaningful lines of an account file.

    :param text: file contents
    :return: lines that are not empty, comments, or NIS compat markers (``+``/``-``)
    """
    return [line for line in text.splitlines() if line and not line.startswith(("#", "+", "-"))]


def parse_accounts(passwd: str, shadow: str, login_defs: str) -> dict[str, Any]:
    """Parse local account files.

    :param passwd: contents of /etc/passwd
    :param shadow: contents of /etc/shadow; only whether field 2 is empty is kept
    :param login_defs: contents of /etc/login.defs; UID_MIN defaults to 1000
    :raises ValueError: on a passwd entry with fewer than 6 fields or a non-numeric UID
    :return: ``{'uid_min': int, 'accounts': [{'name', 'uid', 'home', 'shell', 'empty_pw'}]}``
    """
    empty_pw = {}
    for line in _lines(shadow):
        fields = line.split(":")
        empty_pw[fields[0]] = len(fields) > 1 and fields[1] == ""

    accounts = []
    for line in _lines(passwd):
        fields = line.split(":")
        if len(fields) < 6 or not fields[2].isdigit():
            raise ValueError("malformed /etc/passwd entry for '%s'" % fields[0])
        accounts.append({
            "name": fields[0],
            "uid": int(fields[2]),
            "home": fields[5],
            "shell": fields[6] if len(fields) > 6 else "",
            "empty_pw": empty_pw.get(fields[0], False),
        })

    uid_min = re.search(r"(?m)^UID_MIN\s+(\d+)", login_defs)
    return {"uid_min": int(uid_min.group(1)) if uid_min else 1000, "accounts": accounts}


def offenders(db: dict[str, Any], exempt: list[str]) -> dict[str, list]:
    """Classify accounts into the lists that audit and configure act on.

    :param db: result of :func:`parse_accounts`
    :param exempt: account names skipped by the password, shell and home checks
    :return: ``{'empty_password', 'system_shell', 'extra_uid0', 'duplicate_uid', 'interactive'}``
    """
    out = {"empty_password": [], "system_shell": [], "extra_uid0": [], "duplicate_uid": [], "interactive": []}
    seen = set()
    for acct in db["accounts"]:
        name, uid, home = acct["name"], acct["uid"], acct["home"]
        login = not acct["shell"].endswith(NOLOGIN_SUFFIXES)
        if acct["empty_pw"] and name not in exempt:
            out["empty_password"].append(name)
        if 0 < uid < db["uid_min"] and login and name not in exempt:
            out["system_shell"].append(name)
        if uid == 0 and name != "root":
            out["extra_uid0"].append(name)
        if uid in seen and uid not in out["duplicate_uid"]:
            out["duplicate_uid"].append(uid)
        seen.add(uid)
        if db["uid_min"] <= uid < 65534 and login and home.startswith("/") and name not in exempt:
            out["interactive"].append({"name": name, "home": home})
    return out


def open_homes(stat_results: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Select home directories that are too open.

    :param stat_results: ``results`` of a stat loop whose items are ``{'name', 'home'}``
    :return: the items whose path is a directory with group-write or any "other" permission bit
    """
    return [r["item"] for r in stat_results
            if r["stat"].get("isdir") and int(r["stat"]["mode"], 8) & 0o027]


def findings(lists: dict[str, list], too_open_homes: list[dict[str, str]], inactive: int | str,
             inactive_days: int | str | None, nologin_shell: str, lock_empty_passwords: bool = True,
             fix_system_shells: bool = True, fix_home_permissions: bool = True) -> list[dict[str, Any]]:
    """Compare offender lists with the desired state.

    :param lists: result of :func:`offenders`
    :param too_open_homes: ``[{'name', 'home'}]`` whose home directory is too open
    :param inactive: current ``useradd -D`` INACTIVE value
    :param inactive_days: desired INACTIVE value, or None to skip the check
    :param nologin_shell: shell expected for system accounts
    :param lock_empty_passwords: report empty passwords
    :param fix_system_shells: report system accounts with a login shell
    :param fix_home_permissions: report open home directories
    :return: ``[{'key', 'expected', 'actual', 'fixable'}]``; UID 0 and duplicate UIDs are never fixable
    """
    out = []

    def add(key: str, expected: str, actual: str, fixable: bool) -> None:
        out.append({"key": key, "expected": expected, "actual": actual, "fixable": fixable})

    if lock_empty_passwords:
        for name in lists["empty_password"]:
            add("empty password: %s" % name, "locked", "empty", True)
    if fix_system_shells:
        for name in lists["system_shell"]:
            add("system account shell: %s" % name, nologin_shell, "login shell", True)
    if fix_home_permissions:
        for home in too_open_homes:
            add("home directory: %s" % home["home"], "no group-write, no other access", "too open", True)
    if inactive_days is not None and int(inactive) != int(inactive_days):
        add("useradd INACTIVE", str(int(inactive_days)), str(int(inactive)), True)
    for name in lists["extra_uid0"]:
        add("UID 0 account: %s" % name, "only root", "extra UID 0", False)
    for uid in lists["duplicate_uid"]:
        add("duplicate UID: %s" % uid, "unique", "shared", False)
    return out


class FilterModule:
    """Register the user_hardening filters."""

    def filters(self) -> dict[str, Any]:
        """Return the filter name to function map.

        :return: filter mapping
        """
        return {
            "user_hardening_parse_accounts": parse_accounts,
            "user_hardening_offenders": offenders,
            "user_hardening_open_homes": open_homes,
            "user_hardening_findings": findings,
        }
