"""言語の選び方（--lang・番号での選択）と、言語・フレームワークの自動の見分け。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from test_vulnscan import ROOT, RepoCase

from vulnscan.detect import choose_languages, detect, parse_languages
from vulnscan.models import ScanError
from vulnscan.report import render_text


class Case(RepoCase):
    def run_cli(self, *args, stdin: str = ""):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "vulnscan", *args],
            cwd=str(self.root),
            capture_output=True,
            text=True,
            env=env,
            input=stdin,
        )


class ParseLanguagesTests(unittest.TestCase):
    def test_aliases(self) -> None:
        self.assertEqual(parse_languages("js"), ["javascript"])
        self.assertEqual(parse_languages("TypeScript"), ["javascript"])
        self.assertEqual(parse_languages("javascript/typescript"), ["javascript"])
        self.assertEqual(parse_languages("flutter, py"), ["dart", "python"])
        self.assertEqual(parse_languages("kotlin,go"), ["java", "go"])

    def test_unknown_language_is_error(self) -> None:
        with self.assertRaises(ScanError) as ctx:
            parse_languages("cobol")
        self.assertIn("cobol", str(ctx.exception))


class ChooseLanguagesTests(unittest.TestCase):
    detected = [
        {"language": "javascript", "label": "JavaScript/TypeScript", "files": 10, "rules": 17},
        {"language": "python", "label": "Python", "files": 3, "rules": 12},
        {"language": "dart", "label": "Dart", "files": 5, "rules": 5},
    ]

    def test_empty_answer_means_all(self) -> None:
        # すべて＝絞らない（--lang を付けないときと同じ）
        self.assertIsNone(choose_languages(self.detected, ""))

    def test_numbers_and_names(self) -> None:
        self.assertEqual(choose_languages(self.detected, "1,3"), ["javascript", "dart"])
        self.assertEqual(choose_languages(self.detected, "py"), ["python"])

    def test_out_of_range_is_error(self) -> None:
        with self.assertRaises(ScanError):
            choose_languages(self.detected, "4")


class LanguageFilterTests(Case):
    def test_lang_limits_files(self) -> None:
        self.write({"web/a.ts": "eval(x)\n", "tool.py": "eval(x)\n"})
        proc = self.run_cli("scan", ".", "--lang", "ts", "--format", "json", "--fail-on", "never")
        data = json.loads(proc.stdout)
        self.assertEqual({f["path"] for f in data["findings"]}, {"web/a.ts"})
        self.assertEqual([item["language"] for item in data["languages"]], ["javascript"])

    def test_lang_without_value_needs_a_terminal(self) -> None:
        self.write({"a.ts": "1\n"})
        proc = self.run_cli("scan", ".", "--lang")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--lang", proc.stderr)

    def test_label_uses_slash_without_spaces(self) -> None:
        self.write({"a.ts": "1\n", "b.dart": "void main() {}\n"})
        text = render_text(self.scan())
        self.assertIn("JavaScript/TypeScript 1", text)
        self.assertIn("、", text.split("言語: ", 1)[1].splitlines()[0])


class FrameworkDetectionTests(Case):
    def ids(self) -> set:
        return {item["id"] for item in detect(self.root)["frameworks"]}

    def test_js_frameworks_from_package_json(self) -> None:
        self.write(
            {
                "package.json": json.dumps({"dependencies": {"next": "16.0.0", "@supabase/supabase-js": "2"}}),
                "apps/mobile/package.json": json.dumps({"dependencies": {"expo": "54", "react-native": "0.81"}}),
                "apps/api/package.json": json.dumps({"dependencies": {"hono": "4"}, "devDependencies": {"wrangler": "4"}}),
            }
        )
        self.assertEqual(self.ids(), {"nextjs", "supabase", "expo", "hono", "cloudflare"})

    def test_flutter_and_firebase(self) -> None:
        self.write(
            {
                "app/pubspec.yaml": "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n  firebase_core: ^3.0.0\n",
                "firestore.rules": "rules_version = '2';\n",
            }
        )
        self.assertEqual(self.ids(), {"flutter", "firebase"})

    def test_python_frameworks(self) -> None:
        self.write(
            {
                "manage.py": "import django\n",
                "svc/requirements.txt": "fastapi==0.115.0\nuvicorn\n",
            }
        )
        self.assertEqual(self.ids(), {"django", "fastapi"})

    def test_detect_cli_json(self) -> None:
        self.write({"package.json": json.dumps({"dependencies": {"express": "5"}}), "server.js": "1\n"})
        proc = self.run_cli("detect", ".", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual([f["id"] for f in data["frameworks"]], ["express"])
        self.assertEqual(data["frameworks"][0]["evidence"], "package.json")
        self.assertEqual(data["languages"][0]["language"], "javascript")

    def test_scan_report_shows_frameworks(self) -> None:
        self.write({"package.json": json.dumps({"dependencies": {"next": "16"}}), "a.ts": "1\n"})
        self.assertIn("フレームワーク: Next.js", render_text(self.scan()))


if __name__ == "__main__":
    unittest.main()
