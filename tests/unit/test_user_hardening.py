import importlib.util
import pathlib

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "user_hardening", pathlib.Path(__file__).parents[2] / "filter_plugins" / "user_hardening.py")
uh = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(uh)

PASSWD = """\
# comment
root:x:0:0:root:/root:/bin/bash
toor:x:0:0::/root:/bin/sh
sync:x:5:0:sync:/sbin:/bin/sync
svc:x:401:401::/var/lib/svc:/bin/bash
quiet:x:402:402::/var/lib/quiet:/usr/sbin/nologin
alice:x:1500:1500::/home/alice:/bin/bash
twin:x:1500:1500::/home/twin:/bin/bash
nobody:x:65534:65534::/nonexistent:/bin/false
"""
SHADOW = "root:$6$hash:1::::::\nalice::1::::::\nsvc:!:1::::::\ntwin::1::::::\n"
LOGIN_DEFS = "# defs\nUID_MIN\t\t\t 1000\n"


@pytest.fixture
def db():
    return uh.parse_accounts(PASSWD, SHADOW, LOGIN_DEFS)


def test_parse_keeps_no_hash(db):
    assert db["uid_min"] == 1000
    root = db["accounts"][0]
    assert root == {"name": "root", "uid": 0, "home": "/root", "shell": "/bin/bash", "empty_pw": False}
    assert "$6$hash" not in repr(db)


def test_parse_defaults_uid_min_and_rejects_malformed():
    assert uh.parse_accounts("", "", "")["uid_min"] == 1000
    with pytest.raises(ValueError, match="bad"):
        uh.parse_accounts("bad:x:notanumber:0::/:/bin/sh\n", "", "")


def test_parse_skips_nis_compat_lines():
    db = uh.parse_accounts("root:x:0:0::/root:/bin/bash\n+::::::\n-baduser::::::\n+@netgrp\n", "+::::::::\n", "")
    assert [a["name"] for a in db["accounts"]] == ["root"]


def test_open_homes():
    def res(home, mode, isdir=True):
        return {"item": {"name": home, "home": home}, "stat": {"isdir": isdir, "mode": mode}}

    results = [res("/a", "0750"), res("/b", "0770"), res("/c", "0701"), res("/d", "0755", False),
               {"item": {"name": "e", "home": "/e"}, "stat": {"exists": False}}]
    assert [h["home"] for h in uh.open_homes(results)] == ["/b", "/c"]


def test_offenders(db):
    lists = uh.offenders(db, ["root", "twin"])
    assert lists["empty_password"] == ["alice"]
    assert lists["system_shell"] == ["svc"]  # sync runs /bin/sync, quiet has nologin
    assert lists["extra_uid0"] == ["toor"]
    assert lists["duplicate_uid"] == [0, 1500]
    assert lists["interactive"] == [{"name": "alice", "home": "/home/alice"}]  # nobody: 65534 and /bin/false


def test_findings_respects_switches_and_report_only(db):
    lists = uh.offenders(db, ["root", "twin"])
    homes = [{"name": "alice", "home": "/home/alice"}]
    all_on = uh.findings(lists, homes, inactive=-1, inactive_days=30, nologin_shell="/usr/sbin/nologin")
    assert [f["key"] for f in all_on] == [
        "empty password: alice", "system account shell: svc", "home directory: /home/alice",
        "useradd INACTIVE", "UID 0 account: toor", "duplicate UID: 0", "duplicate UID: 1500"]
    assert all_on[3]["expected"] == "30" and all_on[3]["actual"] == "-1"
    assert [f["fixable"] for f in all_on] == [True] * 4 + [False] * 3

    off = uh.findings(lists, homes, inactive="30", inactive_days=None, nologin_shell="/usr/sbin/nologin",
                      lock_empty_passwords=False, fix_system_shells=False, fix_home_permissions=False)
    assert all(not f["fixable"] for f in off)
