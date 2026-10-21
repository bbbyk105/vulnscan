"""レビューで見つかった不具合の再現テスト（2026-10-21）。

偽の秘密情報は、このファイル自体が検出されないよう連結して組み立てる。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_vulnscan import ROOT, RepoCase

from vulnscan.ignore import write_baseline
from vulnscan.report import render_json, render_markdown, render_text
from vulnscan.rules import all_rule_meta

FAKE_AWS = "AK" + "IA" + "Q" * 16
FAKE_GH = "gh" + "p_" + "A" * 36
FAKE_STRIPE = "sk" + "_live_" + "B" * 24
KEY_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "FAKE" * 20
PEM_BEGIN = "-----" + "BEGIN PRIVATE" + " KEY-----"
PEM_END = "-----" + "END PRIVATE" + " KEY-----"


def all_output(result) -> str:
    return "\n".join([render_text(result), render_markdown(result), render_json(result)])


class Case(RepoCase):
    def run_cli(self, *args, cwd=None, pythonpath=None):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(pythonpath or ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "vulnscan", *args],
            cwd=str(cwd or self.root),
            capture_output=True,
            text=True,
            env=env,
        )

    def findings(self, result, rule_id) -> list:
        return [f for f in result.findings if f.rule_id == rule_id]


class MaskingTests(Case):
    def test_second_secret_on_same_line_is_masked(self) -> None:
        self.write({"multi.js": f'const cfg = {{ key: "{FAKE_AWS}", token: "{FAKE_GH}" }};\n'})
        out = all_output(self.scan())
        self.assertNotIn(FAKE_AWS, out)
        self.assertNotIn(FAKE_GH, out)

    def test_secret_on_line_of_non_secret_finding_is_masked(self) -> None:
        self.write(
            {
                "tls.js": "const agent = new https.Agent({ rejectUnauthorized: false }); "
                f'const k = "{FAKE_STRIPE}";\n'
            }
        )
        result = self.scan()
        self.assertTrue(self.findings(result, "TLS-001"))
        self.assertNotIn(FAKE_STRIPE, all_output(result))

    def test_private_key_body_in_json_is_masked(self) -> None:
        self.write(
            {
                "sa.json": '{"type":"service_account","private_key":"'
                + PEM_BEGIN
                + "\\n"
                + KEY_BODY
                + "\\n"
                + PEM_END
                + '\\n"}\n'
            }
        )
        result = self.scan()
        self.assertTrue(self.findings(result, "SEC-001"))
        self.assertNotIn(KEY_BODY[:24], all_output(result))

    def test_short_secret_reveals_little(self) -> None:
        value = "hunter2!xy"
        self.write({"short.py": f'password = "{value}"\n'})
        (finding,) = self.findings(self.scan(), "SEC-013")
        for i in range(len(value) - 2):
            self.assertNotIn(value[i : i + 3], finding.evidence)

    def test_reveal_secrets_still_shows_value(self) -> None:
        # 再現ではなく、マスクを広げたあとも --reveal-secrets が効くことの確認
        self.write({"aws.js": f'const key = "{FAKE_AWS}";\n'})
        proc = self.run_cli("scan", ".", "--reveal-secrets", "--format", "json", "--fail-on", "never")
        self.assertIn(FAKE_AWS, proc.stdout)


class DependencyAuditTests(Case):
    def setUp(self) -> None:
        super().setUp()
        self.bin = self.root / "_bin"
        self.bin.mkdir()
        self.log = self.root / "_log"

    def fake_tool(self, name: str, stdout: str = "", stderr: str = "", code: int = 0) -> None:
        # PATH は self.bin だけにするので、シェルの組み込みだけで書く
        script = (
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" > "{self.log}.{name}.args"\n'
            f'printf "%s" "$YARN_IGNORE_PATH" > "{self.log}.{name}.env"\n'
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

    def test_failed_npm_audit_is_reported(self) -> None:
        self.write({"package.json": "{}\n", "package-lock.json": "{}\n"})
        self.fake_tool(
            "npm",
            stdout='{"message": "request failed, reason: connect ECONNREFUSED", "error": {"summary": ""}}',
            code=1,
        )
        (finding,) = self.findings(self.scan_deps(), "DEP-011")
        self.assertEqual(finding.severity.label, "high")

    def test_missing_audit_tool_is_reported(self) -> None:
        self.write({"package.json": "{}\n", "package-lock.json": "{}\n"})
        (finding,) = self.findings(self.scan_deps(), "DEP-010")
        self.assertEqual(finding.severity.label, "high")

    def test_unsupported_lockfile_is_reported(self) -> None:
        self.write({"go.mod": "module x\n", "go.sum": "x v1 h1:abc=\n"})
        self.assertTrue(self.findings(self.scan_deps(), "DEP-012"))

    def test_yarn_without_audit_summary_is_failure(self) -> None:
        # Yarn 2 以降には `yarn audit` が無く、JSON ではない使い方のエラーが出る
        self.write({"package.json": "{}\n", "yarn.lock": "\n"})
        self.fake_tool("yarn", stdout="Usage Error: Could not find a script named audit", code=1)
        self.assertTrue(self.findings(self.scan_deps(), "DEP-011"))

    def test_yarn_ignores_repository_yarn_path(self) -> None:
        self.write({"package.json": "{}\n", "yarn.lock": "\n"})
        self.fake_tool("yarn", stdout='{"type":"auditSummary","data":{}}')
        self.scan_deps()
        self.assertEqual(Path(f"{self.log}.yarn.env").read_text(), "1")

    def test_pip_audit_current_json_format(self) -> None:
        self.write({"requirements.txt": "requests==2.19.0\n"})
        self.fake_tool(
            "pip-audit",
            stdout='{"dependencies": [{"name": "requests", "version": "2.19.0", '
            '"vulns": [{"id": "PYSEC-2018-28", "fix_versions": ["2.20.0"]}]}], "fixes": []}',
            code=1,
        )
        self.assertTrue(self.findings(self.scan_deps(), "DEP-001"))

    def test_composer_audits_lock_without_plugins(self) -> None:
        self.write({"composer.json": "{}\n", "composer.lock": '{"packages": []}\n'})
        self.fake_tool("composer", stdout='{"advisories": {}}')
        self.scan_deps()
        args = Path(f"{self.log}.composer.args").read_text().split()
        self.assertIn("--locked", args)
        self.assertIn("--no-plugins", args)


class ChangedTests(Case):
    def make_pr_branch(self) -> None:
        self.write({"old.py": "eval(legacy)\n"})
        self.git("init", "-q", "-b", "main")
        self.git("add", "-A")
        self.git("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "base")
        self.git("checkout", "-q", "-b", "feature")
        self.write({"app.py": "eval(user_input)\n"})
        self.git("add", "-A")
        self.git("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "pr")

    def test_base_scans_only_pr_changes(self) -> None:
        # PR の CI は作業ツリーがきれいなので、--changed だけでは 0 ファイルになっていた
        self.make_pr_branch()
        proc = self.run_cli("scan", ".", "--base", "main", "--fail-on", "high")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("app.py:1", proc.stdout)
        self.assertNotIn("old.py", proc.stdout)

    def test_options_are_not_abbreviated(self) -> None:
        # --base が無い版では --baseline の省略として受け付けられていた
        self.write({"a.ts": "1\n"})
        proc = self.run_cli("scan", ".", "--baseli", "x.json")
        self.assertEqual(proc.returncode, 2)

    def test_unknown_base_is_error(self) -> None:
        # 差分が取れないまま 0 ファイルで「合格」にしない（shallow clone の CI など）
        self.make_pr_branch()
        proc = self.run_cli("scan", ".", "--base", "no-such-branch", "--fail-on", "high")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("差分", proc.stderr)


class VendoredCopyTests(Case):
    def test_copy_inside_scanned_repo_is_not_scanned(self) -> None:
        # README の CI 例: vulnscan をリポジトリの ./vulnscan に置いて、リポジトリ全体を流す
        copy = self.root / "vulnscan"
        ignore = shutil.ignore_patterns("__pycache__", "reports")
        shutil.copytree(ROOT / "src", copy / "src", ignore=ignore)
        shutil.copytree(ROOT / "tests", copy / "tests", ignore=ignore)
        shutil.copy(ROOT / "README.md", copy / "README.md")
        self.write({"app.py": "x = 1\n"})
        self.init_git()
        proc = self.run_cli("scan", ".", "--fail-on", "high", pythonpath=copy / "src")
        self.assertEqual(proc.returncode, 0, proc.stdout)


class DetectionGapTests(Case):
    def test_secret_in_comment_is_detected(self) -> None:
        self.write(
            {
                "old.py": f"# old key: {FAKE_GH}\nx = 1\n",
                "conf.yml": f"# STRIPE_KEY: {FAKE_STRIPE}\nfoo: bar\n",
            }
        )
        result = self.scan()
        self.assertTrue(self.findings(result, "SEC-006"))
        self.assertTrue(self.findings(result, "SEC-005"))

    def test_quoted_key_password_is_detected(self) -> None:
        self.write(
            {
                "config.json": '{"password": "Prod-Pa55word-2026"}\n',
                "config.py": 'DB = {"password": "Prod-Pa55word-2026"}\n',
            }
        )
        paths = {f.location.path for f in self.findings(self.scan(), "SEC-013")}
        self.assertEqual(paths, {"config.json", "config.py"})

    def test_unquoted_yaml_password_is_detected(self) -> None:
        self.write({"settings.yml": "database:\n  password: Prod-Pa55word-2026\n"})
        self.assertTrue(self.findings(self.scan(), "SEC-015"))

    def test_tracked_env_file_in_subdirectory(self) -> None:
        self.write({"apps/web/.env": "DB_PASSWORD=Prod-Pa55word-2026\n", "index.js": "1\n"})
        self.init_git()
        result = self.scan()
        self.assertEqual([f.location.path for f in self.findings(result, "FILE-001")], ["apps/web/.env"])
        self.assertTrue(self.findings(result, "SEC-016"))
        self.assertNotIn("Prod-Pa55word-2026", all_output(result))

    def test_child_process_exec_variants(self) -> None:
        self.write(
            {
                "run.js": "const cp = require('child_process');\n"
                "cp.exec('ls ' + req.query.dir);\n"
                "child_process.execSync(`rm -rf ${input}`);\n"
                "require('child_process').exec(cmd);\n"
                "const m = /a/.exec(text);\n"
            }
        )
        lines = {f.location.line for f in self.findings(self.scan(), "INJ-005")}
        self.assertEqual(lines, {2, 3, 4})

    def test_subdirectory_of_git_repo_respects_gitignore(self) -> None:
        self.write({".gitignore": "*.local.py\n", "src/app.py": "x = 1\n"})
        self.init_git()
        self.write({"src/creds.local.py": 'api_key = "' + "Z" * 30 + '"\n'})
        result = scan_subdir(self.root / "src")
        self.assertEqual(result.findings, [])
        self.assertTrue(result.stats["git"])

    def test_duplicate_lines_are_reported_separately(self) -> None:
        self.write({"dup.ts": "el.innerHTML = a;\nfoo();\nel.innerHTML = a;\n"})
        lines = {f.location.line for f in self.findings(self.scan(), "XSS-002")}
        self.assertEqual(lines, {1, 3})

    def test_baseline_does_not_hide_new_duplicate(self) -> None:
        self.write({"dup.ts": "el.innerHTML = a;\n"})
        baseline = self.root / "baseline.json"
        write_baseline(baseline, self.scan().findings)
        self.write({"dup.ts": "el.innerHTML = a;\nfoo();\nel.innerHTML = a;\n"})
        self.assertEqual(len(self.scan(baseline=baseline).findings), 1)


def scan_subdir(path: Path):
    from vulnscan.engine import ScanOptions, scan
    from vulnscan.models import Severity

    return scan(path, ScanOptions(min_severity=Severity.INFO))


class FalsePositiveRegressionTests(Case):
    def test_method_named_eval_is_not_flagged(self) -> None:
        self.write(
            {
                "train.py": "model.eval()\n",
                "scrape.ts": "const t = await page.$eval('h1', (e) => e.textContent);\n",
                "real.js": "window.eval(code);\neval(code);\n",
            }
        )
        paths = {(f.location.path, f.location.line) for f in self.findings(self.scan(), "INJ-001")}
        self.assertEqual(paths, {("real.js", 1), ("real.js", 2)})

    def test_ui_text_is_not_flagged_as_password(self) -> None:
        self.write(
            {
                "i18n.ts": 'export const ja = { password: "パスワードを入力してください" };\n'
                'export const en = { password: "Password must be 8 characters" };\n'
            }
        )
        self.assertFalse(self.findings(self.scan(), "SEC-013"))

    def test_ternary_after_password_string_is_not_flagged(self) -> None:
        # 引用符で囲んだキーを許したときに入った誤検知（caroot の AuthForm.tsx）
        self.write(
            {"form.tsx": '<input autoComplete={mode === "signup" ? "new-password" : "current-password"} />\n'}
        )
        self.assertFalse(self.findings(self.scan(), "SEC-013"))

    def test_numeric_github_context_is_not_flagged(self) -> None:
        self.write(
            {
                ".github/workflows/ci.yml": "on: pull_request\njobs:\n  t:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: echo ${{ github.event.pull_request.number }}\n"
                "      - run: git checkout ${{ github.event.pull_request.head.sha }}\n"
            }
        )
        self.assertFalse(self.findings(self.scan(), "CI-001"))


class SmallFixTests(Case):
    def test_repo_rules_can_be_explained(self) -> None:
        for rule_id in ("FILE-001", "FILE-002", "FILE-003"):
            proc = self.run_cli("explain", rule_id)
            self.assertEqual(proc.returncode, 0, rule_id)
        listed = json.loads(self.run_cli("rules", "--json").stdout)
        self.assertIn("FILE-001", {item["id"] for item in listed})

    def test_invalid_expires_does_not_suppress(self) -> None:
        self.write(
            {
                "a.ts": "el.innerHTML = userInput;\n",
                ".vulnscanignore": "XSS-002  *  expires=2026/12/31  # 書き間違い\n",
            }
        )
        result = self.scan()
        self.assertTrue(self.findings(result, "XSS-002"))
        self.assertIn("expires", render_text(result))

    def test_unexpected_error_exits_with_2(self) -> None:
        self.write({"a.ts": "1\n", "afile": "x\n"})
        proc = self.run_cli("scan", ".", "-o", "afile/report.md")
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_header_rule_count_matches_rule_list(self) -> None:
        self.write({"a.ts": "1\n"})
        self.assertIn(f"{len(all_rule_meta())} ルール", render_text(self.scan()))


if __name__ == "__main__":
    unittest.main()
