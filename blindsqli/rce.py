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
