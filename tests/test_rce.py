"""Tests for the RCE reachability assessment and the timing-based execution
verifier. No network: a fake oracle answers assess()'s catalog conditions from a
set of PRESENT check keys, and simulates request latency for send_raw() based on
which primitives 'execute'."""

from __future__ import annotations

import re

from blindsqli import rce
from blindsqli.rce import ExecVerdict, Status
from blindsqli.result_types import HttpResponse, OracleObservation, OracleResult


class _Cfg:
    def __init__(self):
        self.request_timeout = 10.0
        self.max_retries = 3


class FakeRceOracle:
    """`present_keys` -> those MSSQL_CHECKS answer TRUE (others FALSE, or UNKNOWN
    if listed). `executes` maps a directive ('waitfor'/'sleep'/'ping') to whether
    a probe carrying it actually sleeps, so send_raw can simulate latency."""

    def __init__(self, present_keys=(), unknown_keys=(), executes=None):
        self._by_condition = {c.condition: c.key for c in rce.MSSQL_CHECKS}
        self.present = set(present_keys)
        self.unknown = set(unknown_keys)
        self.executes = executes or {}
        self.requests_completed = 0
        self.requests_failed = 0
        self.config = _Cfg()

    def ensure_classifier(self):
        pass

    def ask(self, condition):
        self.requests_completed += 1
        key = self._by_condition.get(condition)
        if key in self.unknown:
            return OracleObservation(condition, OracleResult.UNKNOWN, 1)
        res = OracleResult.TRUE if key in self.present else OracleResult.FALSE
        return OracleObservation(condition, res, 1)

    def send_raw(self, injected):
        self.requests_completed += 1
        secs = 0.0
        m = re.search(r"WAITFOR DELAY '00:00:(\d+)'", injected)
        if m and self.executes.get("waitfor"):
            secs = int(m.group(1))
        m = re.search(r"sleep (\d+)", injected)
        if m and self.executes.get("sleep"):
            secs = int(m.group(1))
        m = re.search(r"ping -n (\d+)", injected)
        if m and self.executes.get("ping"):
            secs = int(m.group(1)) - 1
        return HttpResponse(status=200, body="ok", length=2, headers={}, elapsed=0.01 + secs)


class FakeEngine:
    def __init__(self, oracle):
        self.oracle = oracle
        self._cancel = False

    def cancelled(self):
        return self._cancel


# --------------------------------------------------------------- assess()

def test_assess_maps_present_absent_unknown():
    oracle = FakeRceOracle(present_keys={"sysadmin", "xp_cmdshell_present"},
                           unknown_keys={"clr_enabled"})
    findings = rce.assess(FakeEngine(oracle))
    st = {f.key: f.status for f in findings}
    assert st["sysadmin"] is Status.PRESENT
    assert st["xp_cmdshell_present"] is Status.PRESENT
    assert st["clr_enabled"] is Status.UNKNOWN
    assert st["xp_cmdshell_enabled"] is Status.ABSENT
    assert len(findings) == len(rce.MSSQL_CHECKS)


def test_summary_vulnerable_when_xp_cmdshell_enabled():
    oracle = FakeRceOracle(present_keys={"xp_cmdshell_enabled"})
    summary = rce.summarize(rce.assess(FakeEngine(oracle)))
    assert summary["verdict"] == "VULNERABLE"


def test_summary_vulnerable_when_privileged_and_proc_present():
    oracle = FakeRceOracle(present_keys={"sysadmin", "xp_cmdshell_present"})
    summary = rce.summarize(rce.assess(FakeEngine(oracle)))
    assert summary["verdict"] == "VULNERABLE"
    assert summary["privileged_login"] is True


def test_summary_likely_when_only_alter_settings():
    oracle = FakeRceOracle(present_keys={"alter_settings"})
    summary = rce.summarize(rce.assess(FakeEngine(oracle)))
    assert summary["verdict"] == "LIKELY"


def test_summary_not_reachable_when_nothing_present():
    summary = rce.summarize(rce.assess(FakeEngine(FakeRceOracle())))
    assert summary["verdict"] == "NOT REACHABLE"


def test_summary_inconclusive_on_unknown():
    oracle = FakeRceOracle(unknown_keys={"xp_cmdshell_enabled"})
    summary = rce.summarize(rce.assess(FakeEngine(oracle)))
    assert summary["verdict"] == "INCONCLUSIVE"


def test_assess_honours_cancellation():
    engine = FakeEngine(FakeRceOracle())
    engine._cancel = True
    assert rce.assess(engine) == []


# ------------------------------------------------------ verify_execution()

def test_waitfor_control_confirms_when_it_sleeps():
    oracle = FakeRceOracle(executes={"waitfor": True})
    res = rce.verify_execution(FakeEngine(oracle),
                               rce.EXEC_PROBES_BY_KEY["waitfor"], delay=4)
    assert res.verdict is ExecVerdict.CONFIRMED
    assert res.proves_os_exec is False


def test_xp_cmdshell_not_confirmed_when_disabled():
    # waitfor executes (channel works) but the OS primitive does not.
    oracle = FakeRceOracle(executes={"waitfor": True, "sleep": False})
    res = rce.verify_execution(FakeEngine(oracle),
                               rce.EXEC_PROBES_BY_KEY["xp_cmdshell_nix"], delay=4)
    assert res.verdict is ExecVerdict.NOT_CONFIRMED
    assert res.proves_os_exec is True


def test_xp_cmdshell_confirmed_when_it_sleeps():
    oracle = FakeRceOracle(executes={"sleep": True})
    res = rce.verify_execution(FakeEngine(oracle),
                               rce.EXEC_PROBES_BY_KEY["xp_cmdshell_nix"], delay=3)
    assert res.verdict is ExecVerdict.CONFIRMED
    assert res.proves_os_exec is True


def test_ping_probe_confirmed_when_it_sleeps():
    oracle = FakeRceOracle(executes={"ping": True})
    res = rce.verify_execution(FakeEngine(oracle),
                               rce.EXEC_PROBES_BY_KEY["xp_cmdshell_win"], delay=4)
    assert res.verdict is ExecVerdict.CONFIRMED


def test_verify_restores_config_after_probing():
    oracle = FakeRceOracle(executes={"waitfor": True})
    rce.verify_execution(FakeEngine(oracle),
                         rce.EXEC_PROBES_BY_KEY["waitfor"], delay=5)
    assert oracle.config.request_timeout == 10.0
    assert oracle.config.max_retries == 3


def test_verify_rejects_bad_payload_template():
    oracle = FakeRceOracle()
    try:
        rce.verify_execution(FakeEngine(oracle),
                             rce.EXEC_PROBES_BY_KEY["waitfor"],
                             payload_template="no placeholder")
    except ValueError:
        return
    raise AssertionError("expected ValueError for a template without {sql}")


def test_resolve_exec_probes_auto_and_custom():
    auto = rce.resolve_exec_probes(["auto"])
    assert [p.key for p in auto] == ["waitfor", "xp_cmdshell_nix", "xp_cmdshell_win"]
    custom = rce.resolve_exec_probes(None, "WAITFOR DELAY '00:00:{secs:02d}'")
    assert len(custom) == 1 and custom[0].key == "custom"


def test_resolve_exec_probes_rejects_unknown():
    for bad in (["nope"],):
        try:
            rce.resolve_exec_probes(bad)
        except ValueError:
            break
    else:
        raise AssertionError("expected ValueError for an unknown probe")


def test_exec_result_to_dict_roundtrips():
    oracle = FakeRceOracle(executes={"waitfor": True})
    res = rce.verify_execution(FakeEngine(oracle),
                               rce.EXEC_PROBES_BY_KEY["waitfor"], delay=4)
    d = res.to_dict()
    assert d["verdict"] == "CONFIRMED"
    assert d["trials"] and "elapsed_s" in d["trials"][0]
