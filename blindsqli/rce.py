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
from dataclasses import dataclass, field
from typing import List, Optional

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


# All conditions are COUNT/CAST-wrapped so a missing row or a denied view reads
# as a clean FALSE rather than NULL. They are read-only catalog/permission
# queries; none of them changes server state.
MSSQL_CHECKS: List[RceCheck] = [
    # ---- privilege context ------------------------------------------------
    RceCheck(
        "sysadmin", "Current login is in the sysadmin server role", "privilege",
        "critical", "IS_SRVROLEMEMBER('sysadmin') = 1",
        "sysadmin can enable and use every execution primitive below.",
        "Run the app under a least-privilege login; never sysadmin."),
    RceCheck(
        "control_server", "Current login has CONTROL SERVER", "privilege",
        "critical",
        "(SELECT COUNT(*) FROM sys.fn_my_permissions(NULL,'SERVER') "
        "WHERE permission_name='CONTROL SERVER') > 0",
        "CONTROL SERVER is sysadmin-equivalent for configuration purposes.",
        "Revoke CONTROL SERVER from application logins."),
    RceCheck(
        "securityadmin", "Current login is in securityadmin", "privilege",
        "high", "IS_SRVROLEMEMBER('securityadmin') = 1",
        "securityadmin can grant itself further rights (privilege escalation).",
        "Remove application logins from securityadmin."),
    RceCheck(
        "impersonate_any", "Login can IMPERSONATE ANY LOGIN", "privilege",
        "high",
        "(SELECT COUNT(*) FROM sys.fn_my_permissions(NULL,'SERVER') "
        "WHERE permission_name='IMPERSONATE ANY LOGIN') > 0",
        "Allows impersonating sa / a sysadmin to reach the primitives below.",
        "Revoke IMPERSONATE ANY LOGIN."),
    RceCheck(
        "db_owner", "Current principal is db_owner in the current DB", "privilege",
        "medium", "IS_MEMBER('db_owner') = 1",
        "db_owner enables trustworthy/CLR and stored-procedure abuse paths.",
        "Avoid db_owner for application principals."),

    # ---- execution primitives --------------------------------------------
    RceCheck(
        "xp_cmdshell_enabled", "xp_cmdshell is enabled", "exec-primitive",
        "critical",
        "(SELECT CAST(value_in_use AS INT) FROM sys.configurations "
        "WHERE name='xp_cmdshell') = 1",
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
        "low",
        "(SELECT CAST(value_in_use AS INT) FROM sys.configurations "
        "WHERE name='show advanced options') = 1",
        "Advanced options (incl. xp_cmdshell) are togglable in-session.",
        "Leave 'show advanced options' at 0 outside maintenance."),
    RceCheck(
        "ole_automation", "OLE Automation Procedures enabled", "exec-primitive",
        "high",
        "(SELECT CAST(value_in_use AS INT) FROM sys.configurations "
        "WHERE name='Ole Automation Procedures') = 1",
        "sp_OACreate/sp_OAMethod can spawn objects and run code.",
        "Disable 'Ole Automation Procedures'."),
    RceCheck(
        "clr_enabled", "CLR integration enabled", "exec-primitive",
        "high",
        "(SELECT CAST(value_in_use AS INT) FROM sys.configurations "