"""サブフォルダの lockfile と、OSV-Scanner で見る lockfile（pub・Go・Cargo など）。

OSV-Scanner は手元に無いので、公式の出力の形（results → packages → groups.max_severity）をまねた偽のコマンドで確かめる。
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from test_vulnscan import RepoCase

OSV_RESULT = json.dumps(
    {
        "results": [
            {
                "source": {"path": "/abs/app/pubspec.lock", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "http", "version": "0.13.0", "ecosystem": "Pub"},
                        "vulnerabilities": [
                            {"id": "GHSA-4rgh-jx4f-qfcq", "summary": "CRLF injection", "aliases": ["CVE-2020-35669"]}
                        ],
                        "groups": [
                            {
                                "ids": ["GHSA-4rgh-jx4f-qfcq"],
                                "aliases": ["GHSA-4rgh-jx4f-qfcq", "CVE-2020-35669"],
                                "max_severity": "7.5",
                            }
                        ],
                    }
                ],
            }
        ]
    }
)


class Case(RepoCase):
    def setUp(self) -> None:
        super().setUp()
        self.bin = self.root / "_bin"
        self.bin.mkdir()
        self.log = self.root / "_log"

    def fake_tool(self, name: str, stdout: str = "", stderr: str = "", code: int = 0) -> None:
        script = (
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" > "{self.log}.{name}.args"\n'
            f'pwd > "{self.log}.{name}.cwd"\n'
            f"printf '%s' '{stdout}'\n"
            f"printf '%s' '{stderr}' >&2\n"
            f"exit {code}\n"
        )
        path = self.bin / name
        path.write_text(script, "utf-8")
        path.chmod(0o755)

    def scan_deps(self):
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}):
            return self.scan(deps=True)

    def findings(self, result, rule_id) -> list:
        return [f for f in result.findings if f.rule_id == rule_id]

    def logged(self, name: str, kind: str) -> str:
        return Path(f"{self.log}.{name}.{kind}").read_text().strip()


class NestedLockfileTests(Case):
    def test_lockfile_in_subfolder_is_audited_there(self) -> None:
        self.write({"functions/package.json": "{}\n", "functions/package-lock.json": "{}\n"})
        self.fake_tool(
            "npm",
            stdout='{"auditReportVersion": 2, "vulnerabilities": {"minimist": {"severity": "critical", '
            '"range": "<=0.2.3", "via": [], "fixAvailable": true}}}',
            code=1,
        )
        (finding,) = self.findings(self.scan_deps(), "DEP-001")
        self.assertEqual(finding.location.path, "functions/package-lock.json")
        self.assertEqual(Path(self.logged("npm", "cwd")).resolve(), (self.root / "functions").resolve())

    def test_lockfiles_in_excluded_folders_are_ignored(self) -> None:
        self.write({"node_modules/x/package-lock.json": "{}\n", "a.js": "1\n"})
        self.fake_tool("npm", stdout='{"auditReportVersion": 2, "vulnerabilities": {}}')
        self.scan_deps()
        self.assertFalse(Path(f"{self.log}.npm.args").exists())


class OsvScannerTests(Case):
    def test_pubspec_lock_is_audited_with_osv_scanner(self) -> None:
        self.write({"app/pubspec.yaml": "name: app\n", "app/pubspec.lock": "packages:\n"})
        self.fake_tool("osv-scanner", stdout=OSV_RESULT, code=1)
        (finding,) = self.findings(self.scan_deps(), "DEP-001")
        self.assertEqual(finding.location.path, "app/pubspec.lock")
        self.assertEqual(finding.severity.label, "high")
        self.assertIn("http", finding.title)
        self.assertIn("CVE-2020-35669", finding.message)
        args = self.logged("osv-scanner", "args").split("\n")
        # lockfile はまとめて 1 回で渡すので、リポジトリの直下からの相対パスになる
        self.assertEqual(args[:4], ["scan", "source", "-L", "app/pubspec.lock"])
        self.assertIn("--format=json", args)

    def test_go_mod_skips_call_analysis(self) -> None:
        self.write({"go.mod": "module x\n"})
        self.fake_tool("osv-scanner", stdout='{"results": []}')
        self.assertEqual(self.findings(self.scan_deps(), "DEP-001"), [])
        self.assertIn("--no-call-analysis=go", self.logged("osv-scanner", "args").split("\n"))

    def test_missing_osv_scanner_is_high_with_hint(self) -> None:
        # 調べていないのに --fail-on high の CI を通さない（ほかの監査ツールが無いときと同じ）
        self.write({"pubspec.lock": "packages:\n"})
        (finding,) = self.findings(self.scan_deps(), "DEP-010")
        self.assertEqual(finding.severity.label, "high")
        self.assertIn("osv-scanner", finding.remediation)

    def test_osv_scanner_error_is_failure(self) -> None:
        self.write({"Cargo.lock": "version = 3\n"})
        self.fake_tool("osv-scanner", stderr="failed to query api.osv.dev", code=127)
        (finding,) = self.findings(self.scan_deps(), "DEP-011")
        self.assertEqual(finding.severity.label, "high")

    def test_no_packages_is_not_failure(self) -> None:
        self.write({"uv.lock": "version = 1\n"})
        self.fake_tool("osv-scanner", stderr="No package sources found", code=128)
        result = self.scan_deps()
        self.assertEqual(self.findings(result, "DEP-011"), [])
        self.assertEqual(self.findings(result, "DEP-001"), [])

    def test_binary_bun_lockfile_is_unsupported(self) -> None:
        self.write({"bun.lockb": "x\n"})
        self.fake_tool("osv-scanner", stdout='{"results": []}')
        self.assertTrue(self.findings(self.scan_deps(), "DEP-012"))


if __name__ == "__main__":
    unittest.main()
