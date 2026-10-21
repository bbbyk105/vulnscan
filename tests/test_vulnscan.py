"""vulnscan の動作テスト（標準ライブラリのみ）。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vulnscan.engine import ScanOptions, scan  # noqa: E402
from vulnscan.ignore import write_baseline  # noqa: E402
from vulnscan.models import Severity  # noqa: E402
from vulnscan.report import render_json, render_markdown, render_sarif  # noqa: E402

FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


class RepoCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, files: dict) -> None:
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, "utf-8")

    def git(self, *args) -> None:
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def init_git(self) -> None:
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "init")

    def scan(self, **kwargs):
        options = ScanOptions(min_severity=Severity.INFO, **kwargs)
        return scan(self.root, options)

    def ids(self, result) -> set:
        return {f.rule_id for f in result.findings}


class SecretTests(RepoCase):
    def test_detects_aws_key_and_hardcoded_password(self) -> None:
        self.write(
            {
                "src/aws.js": f'const key = "{FAKE_AWS}";\n',
                "app.py": 'password = "SuperSecret123"\n',
            }
        )
        result = self.scan()
        self.assertIn("SEC-002", self.ids(result))
        self.assertIn("SEC-013", self.ids(result))

    def test_masks_secret_in_snippet(self) -> None:
        self.write({"src/aws.js": f'const key = "{FAKE_AWS}";\n'})
        result = self.scan()
        finding = next(f for f in result.findings if f.rule_id == "SEC-002")
        self.assertNotIn(FAKE_AWS, finding.location.snippet)
        self.assertIn("…", finding.location.snippet)

    def test_private_key_header(self) -> None:
        self.write({"keys/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"})
        self.assertIn("SEC-001", self.ids(self.scan()))

    def test_env_file_tracked_by_git(self) -> None:
        self.write({".env": "APP_SECRET=abc\n", "index.js": "console.log(1)\n"})
        self.init_git()
        self.assertIn("FILE-001", self.ids(self.scan()))

    def test_public_env_secret(self) -> None:
        self.write(
            {
                ".env.local": "NEXT_PUBLIC_STRIPE_SECRET=abcdef123456\n",
                "app.js": "console.log(1)\n",
            }
        )
        self.assertIn("FILE-003", self.ids(self.scan()))


class FalsePositiveTests(RepoCase):
    def test_env_reference_is_not_flagged(self) -> None:
        self.write({"app.py": 'password = os.getenv("DB_PASSWORD")\n'})
        self.assertNotIn("SEC-013", self.ids(self.scan()))

    def test_placeholder_password_is_not_flagged(self) -> None:
        self.write({"app.py": 'password = "password"\n'})
        self.assertNotIn("SEC-013", self.ids(self.scan()))

    def test_parameterized_query_is_not_flagged(self) -> None:
        self.write(
            {
                "db.py": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
            }
        )
        self.assertNotIn("INJ-008", self.ids(self.scan()))

    def test_orm_column_path_is_not_flagged(self) -> None:
        self.write(
            {
                "src/order.ts": "db.raw(`teaTypes.${tea.id}.processOrder`)\n",
            }
        )
        self.assertNotIn("INJ-009", self.ids(self.scan()))

    def test_comment_mention_is_not_flagged(self) -> None:
        self.write({"lib/blog.ts": "// 本文は dangerouslySetInnerHTML で描く\nconst a = 1;\n"})
        self.assertNotIn("XSS-001", self.ids(self.scan()))

    def test_firebase_generated_config_is_not_flagged(self) -> None:
        key = "AIza" + "A" * 35
        self.write({"android/app/google-services.json": f'{{"api_key": "{key}"}}\n'})
        self.assertNotIn("SEC-004", self.ids(self.scan()))


class InjectionTests(RepoCase):
    def test_eval_and_pickle(self) -> None:
        self.write(
            {
                "app.py": "eval(user_input)\nimport pickle\npickle.loads(data)\n",
            }
        )
        ids = self.ids(self.scan())
        self.assertIn("INJ-001", ids)
        self.assertIn("INJ-010", ids)

    def test_shell_true(self) -> None:
        self.write(
            {
                "app.py": "subprocess.run(\n    cmd,\n    shell=True,\n)\n",
            }
        )
        self.assertIn("INJ-003", self.ids(self.scan()))

    def test_js_sql_template(self) -> None:
        self.write({"db.js": "db.query(`SELECT * FROM users WHERE id = ${id}`)\n"})
        self.assertIn("INJ-009", self.ids(self.scan()))

    def test_tls_verification_disabled(self) -> None:
        self.write(
            {
                "api.py": "requests.get(url, verify=False)\n",
                "tls.js": "const agent = new https.Agent({ rejectUnauthorized: false });\n",
            }
        )
        ids = self.ids(self.scan())
        self.assertIn("TLS-003", ids)
        self.assertIn("TLS-001", ids)


class ConfigTests(RepoCase):
    def test_docker_and_workflow(self) -> None:
        self.write(
            {
                "Dockerfile": "FROM node:20\nENV DB_PASSWORD=supersecret\n",
                ".github/workflows/ci.yml": (
                    "on: pull_request_target\n"
                    "jobs:\n"
                    "  test:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "        with:\n"
                    "          ref: ${{ github.event.pull_request.head.sha }}\n"
                    '      - run: echo "${{ github.event.pull_request.title }}"\n'
                ),
            }
        )
        ids = self.ids(self.scan())
        self.assertIn("CFG-007", ids)
        self.assertIn("CFG-010", ids)
        self.assertIn("CI-001", ids)
        self.assertIn("CI-002", ids)

    def test_unpinned_dependency(self) -> None:
        self.write({"package.json": '{"dependencies": {"left-pad": "latest"}}\n'})
        self.assertIn("DEP-002", self.ids(self.scan()))


class SuppressionTests(RepoCase):
    def test_ignore_file(self) -> None:
        self.write(
            {
                "src/a.ts": "el.innerHTML = userInput;\n",
                ".vulnscanignore": "XSS-002  *  # 検証済み\n",
            }
        )
        result = self.scan()
        self.assertNotIn("XSS-002", self.ids(result))
        self.assertTrue(any(f.rule_id == "XSS-002" for f in result.suppressed))

    def test_baseline(self) -> None:
        self.write({"src/a.ts": "el.innerHTML = userInput;\n"})
        first = self.scan()
        baseline = self.root / "baseline.json"
        write_baseline(baseline, first.findings)

        second = self.scan(baseline=baseline)
        self.assertEqual(second.findings, [])
        self.assertTrue(second.suppressed)


class ReportTests(RepoCase):
    def test_json_and_sarif_are_valid(self) -> None:
        self.write(
            {
                "src/a.ts": "el.innerHTML = userInput;\n",
                "src/aws.js": f'const key = "{FAKE_AWS}";\n',
            }
        )
        result = self.scan()

        data = json.loads(render_json(result))
        self.assertEqual(data["tool"], "vulnscan")
        self.assertTrue(data["findings"])
        self.assertNotIn(FAKE_AWS, render_json(result))

        sarif = json.loads(render_sarif(result))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])

        markdown = render_markdown(result)
        self.assertIn("セキュリティスキャン結果", markdown)


class CliTests(RepoCase):
    def run_cli(self, *args):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "vulnscan", *args],
            cwd=str(self.root),
            capture_output=True,
            text=True,
            env=env,
        )

    def test_exit_code_on_high(self) -> None:
        self.write({"src/a.ts": "el.innerHTML = userInput;\n"})
        proc = self.run_cli("scan", ".", "--fail-on", "high")
        self.assertEqual(proc.returncode, 0)  # medium なので high では失敗しない

        self.write({"src/b.py": f'aws = "{FAKE_AWS}"\n'})
        proc = self.run_cli("scan", ".", "--fail-on", "high")
        self.assertEqual(proc.returncode, 1)

    def test_explain(self) -> None:
        proc = self.run_cli("explain", "SEC-002")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("AWS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
