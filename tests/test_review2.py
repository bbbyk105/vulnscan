"""2 回目のレビュー（2026-10-21、言語の選択・プラットフォームのルール・依存）で見つかった不具合の再現テスト。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_vulnscan import ROOT, RepoCase

from vulnscan.detect import choose_languages
from vulnscan.engine import ScanOptions, scan
from vulnscan.models import Severity
from vulnscan.report import NO_LANGUAGE_RULES


class Case(RepoCase):
    def setUp(self) -> None:
        super().setUp()
        self.bin = self.root / "_bin"
        self.bin.mkdir()
        self.log = self.root / "_log"
        # git は使えるが、監査ツール（npm・osv-scanner など）は無い PATH
        self.path_env = f"{self.bin}:/usr/bin:/bin"

    def fake_tool(self, name: str, stdout: str = "", code: int = 0) -> None:
        script = (
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" >> "{self.log}.{name}.args"\n'
            f'printf "call\\n" >> "{self.log}.{name}.calls"\n'
            f"printf '%s' '{stdout}'\n"
            f"exit {code}\n"
        )
        path = self.bin / name
        path.write_text(script, "utf-8")
        path.chmod(0o755)

    def run_scan(self, **kwargs):
        with mock.patch.dict(os.environ, {"PATH": self.path_env}):
            return scan(self.root, ScanOptions(min_severity=Severity.INFO, **kwargs))

    def run_cli(self, *args):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "vulnscan", *args], cwd=str(self.root), capture_output=True, text=True, env=env
        )

    def rules(self, result) -> set:
        return {f.rule_id for f in result.findings}

    def of(self, result, rule_id) -> list:
        return [f for f in result.findings if f.rule_id == rule_id]


class LanguageFilterKeepsConfigFiles(Case):
    # 1: --lang で、言語の無いファイル（manifest・plist・.rules・.env・package.json）まで落としていた
    def test_flutter_keeps_mobile_and_firebase_files(self) -> None:
        self.write(
            {
                "lib/main.dart": "void main() {}\n",
                "android/app/src/main/AndroidManifest.xml": '<application android:debuggable="true">\n',
                "ios/Runner/Info.plist": "<key>NSAllowsArbitraryLoads</key>\n<true/>\n",
                "firestore.rules": "allow read, write: if true;\n",
                "tool.py": "eval(x)\n",
            }
        )
        ids = self.rules(self.run_scan(languages=("dart",)))
        self.assertTrue({"CFG-015", "TLS-009", "AUTH-006"} <= ids, ids)
        self.assertNotIn("INJ-001", ids)

    def test_js_keeps_package_json_and_env(self) -> None:
        self.write(
            {
                "package.json": '{"dependencies": {"left-pad": "latest"}}\n',
                "apps/web/.env": "DB_PASSWORD=Prod-Pa55word-2026\n",
                "web/a.ts": "eval(x)\n",
                "lib/x.dart": "client.badCertificateCallback = (c, h, p) => true;\n",
            }
        )
        ids = self.rules(self.run_scan(languages=("javascript",)))
        self.assertTrue({"DEP-002", "SEC-016", "INJ-001"} <= ids, ids)
        self.assertNotIn("TLS-006", ids)


class PickerAllMeansNoFilter(unittest.TestCase):
    # 2: 空のまま Enter（すべて）が、見つかった言語だけに絞っていた
    def test_empty_answer_returns_none(self) -> None:
        detected = [{"language": "dart", "label": "Dart/Flutter", "files": 1, "rules": 5}]
        self.assertIsNone(choose_languages(detected, ""))


class PickerUsesScanFiles(Case):
    # 14: 一覧を別に集めていた（--changed などと数が合わない）
    def test_picker_sees_only_changed_files(self) -> None:
        self.write({"a.ts": "1\n"})
        self.init_git()
        self.write({"b.py": "eval(x)\n"})
        seen = []

        def pick(detected):
            seen.extend(item["language"] for item in detected)
            return None

        result = self.run_scan(changed_only=True, pick_languages=pick)
        self.assertEqual(seen, ["python"])
        self.assertIn("INJ-001", self.rules(result))


class GitignoredLockfiles(Case):
    # 3: .gitignore で除外した lockfile を監査せず、「調べていない」とも出さなかった
    def test_ignored_lockfiles_are_still_audited(self) -> None:
        self.write({".gitignore": "pubspec.lock\n", "pubspec.yaml": "name: a\n", "app/pubspec.yaml": "name: b\n"})
        self.init_git()
        self.write({"pubspec.lock": "packages:\n", "app/pubspec.lock": "packages:\n"})
        paths = {f.location.path for f in self.run_scan(deps=True).findings if f.rule_id.startswith("DEP-")}
        self.assertEqual(paths, {"pubspec.lock", "app/pubspec.lock"})


class MissingOsvScannerIsHigh(Case):
    # 4: osv-scanner が無いと「低」で、--fail-on high の CI が調べずに通っていた
    def test_missing_osv_scanner(self) -> None:
        self.write({"go.mod": "module x\n"})
        (finding,) = self.of(self.run_scan(deps=True), "DEP-010")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("osv-scanner", finding.remediation)


class GoSqlBindParameters(Case):
    # 5: 1 つ目の引数の SQL の変数を ctx として読み、バインドする値の Sprintf を SQL の組み立てと取っていた
    def test_bind_parameter_is_not_flagged(self) -> None:
        self.write(
            {
                "store.go": 'rows, _ := db.Query(searchSQL, fmt.Sprintf("%%%s%%", term))\n'
                'tx.Exec(insertSQL, "user-" + name)\n'
                'rows, _ := conn.Query(ctx, fmt.Sprintf("SELECT * FROM t WHERE a = %s", a))\n'
            }
        )
        lines = {f.location.line for f in self.of(self.run_scan(), "INJ-014")}
        self.assertEqual(lines, {3})


class GoSqlFragments(Case):
    # 全プロジェクトに流して見つかった誤検知（artex-global で高が約 95 件）: 列の名前の定数や、プレースホルダで作った
    # 条件をつなぐのは Go ではふつうで、値は入らない。値を SQL の引用符の中につなぐ形だけを当てる
    def test_constant_fragments_are_not_flagged(self) -> None:
        self.write(
            {
                "db.go": "rows, err := d.Query(`SELECT ` + cols + ` FROM t WHERE id=$1`, id)\n"
                'err = s.db.QueryRow("SELECT count(*) FROM assets WHERE "+where, args...).Scan(&n)\n'
                "_, err := d.Exec(`UPDATE t SET error='` + msg + `' WHERE id=$1`, id)\n"
                "row := db.QueryRow(\"SELECT * FROM t WHERE name = '\" + name + \"'\")\n"
            }
        )
        self.assertEqual({f.location.line for f in self.of(self.run_scan(), "INJ-014")}, {3, 4})


class GoCryptoRandAlias(Case):
    # 6: crypto/rand を rand、math/rand を別名で読み込んだファイルで、crypto/rand の呼び出しを当てていた
    def test_crypto_rand_is_not_flagged(self) -> None:
        self.write(
            {
                "token.go": 'import (\n\t"crypto/rand"\n\tmrand "math/rand"\n)\n'
                "func newToken() { rand.Read(b) }\n"
                "func jitter() int { return mrand.Intn(10) }\n"
            }
        )
        self.assertEqual(self.of(self.run_scan(), "CRY-007"), [])


class MultilineRulesSkipComments(Case):
    # 7: 複数行のルールは、当たった文字列でコメントかを見ていて、コメントアウトした行も当てていた
    def test_commented_out_callback(self) -> None:
        self.write({"lib/http.dart": "// client.badCertificateCallback = (c, h, p) => true;\nvoid main() {}\n"})
        self.assertEqual(self.of(self.run_scan(), "TLS-006"), [])


class FirebaseIfTrueConditions(Case):
    # 8: `if true && …` を「誰でも書ける」と取っていた
    def test_if_true_with_and(self) -> None:
        self.write(
            {
                "firestore.rules": "allow write: if true && request.auth != null;\n"
                "allow write: if true || request.auth != null;\n"
                "allow read: if true && isMember();\n"
            }
        )
        result = self.run_scan()
        self.assertEqual({f.location.line for f in self.of(result, "AUTH-006")}, {2})
        self.assertEqual(self.of(result, "AUTH-007"), [])


class DependencyFilesRespectExcludesAndTests(Case):
    # 9: --exclude を見ず、テスト用のフォルダの lockfile も「高」で出していた
    def test_excluded_lockfile_is_skipped(self) -> None:
        self.write({"examples/demo/pubspec.lock": "packages:\n", "a.ts": "1\n"})
        result = self.run_scan(deps=True, exclude=("examples/*",))
        self.assertEqual([f for f in result.findings if f.rule_id.startswith("DEP-")], [])

    def test_fixture_lockfile_is_low(self) -> None:
        self.write({"tests/fixtures/app/package-lock.json": "{}\n", "a.ts": "1\n"})
        self.fake_tool(
            "npm",
            stdout='{"auditReportVersion": 2, "vulnerabilities": {"minimist": {"severity": "critical", '
            '"range": "<=0.2.3", "via": [], "fixAvailable": true}}}',
            code=1,
        )
        (finding,) = self.of(self.run_scan(deps=True), "DEP-001")
        self.assertEqual(finding.severity, Severity.LOW)


class FrameworksWithChanged(Case):
    # 10: --changed / --base のとき、変更したファイルだけからフレームワークを見分けていた
    def test_frameworks_from_whole_repo(self) -> None:
        self.write({"package.json": json.dumps({"dependencies": {"next": "16"}}), "a.ts": "1\n"})
        self.init_git()
        self.write({"a.ts": "2\n"})
        result = self.run_scan(changed_only=True)
        self.assertEqual([f["id"] for f in result.frameworks], ["nextjs"])


class NewLockfilesAreNotContentScanned(Case):
    # 11: 新しく対応した lockfile の中身まで、全部のルールで走査していた
    def test_lockfile_contents_are_skipped(self) -> None:
        line = 'password = "SuperSecret123"\n'
        self.write({"uv.lock": line, "bun.lock": line, "pubspec.lock": line, "a.ts": "1\n"})
        result = self.run_scan()
        self.assertEqual(self.of(result, "SEC-013"), [])
        self.assertEqual(result.stats["files_scanned"], 1)


class LangBeforePath(Case):
    # 12: `scan --lang <フォルダ>` で、フォルダを言語の名前として読んでいた
    def test_path_after_bare_lang(self) -> None:
        self.write({"app/a.ts": "1\n"})
        proc = self.run_cli("scan", "--lang", str(self.root / "app"))
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("知らない言語", proc.stderr)
        self.assertIn("--lang に言語を指定", proc.stderr)


class OsvScannerIsBatched(Case):
    # 13: lockfile ごとに osv-scanner を起動していた
    def test_one_call_for_all_lockfiles(self) -> None:
        self.write({"app/pubspec.lock": "packages:\n", "svc/Cargo.lock": "version = 3\n"})

        def result_for(rel, name):
            return {
                "source": {"path": f"{self.root}/{rel}", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": name, "version": "1.0.0", "ecosystem": "x"},
                        "vulnerabilities": [{"id": f"GHSA-{name}", "summary": "s"}],
                        "groups": [{"ids": [f"GHSA-{name}"], "max_severity": "5.0"}],
                    }
                ],
            }

        out = json.dumps({"results": [result_for("app/pubspec.lock", "http"), result_for("svc/Cargo.lock", "time")]})
        self.fake_tool("osv-scanner", stdout=out, code=1)
        result = self.run_scan(deps=True)
        self.assertEqual(Path(f"{self.log}.osv-scanner.calls").read_text().count("call"), 1)
        paths = {f.location.path for f in self.of(result, "DEP-001")}
        self.assertEqual(paths, {"app/pubspec.lock", "svc/Cargo.lock"})


class SharedWording(Case):
    # 15: 「言語のルールなし」の文言が、レポート・detect・番号の一覧で 3 通りあった
    def test_detect_uses_report_wording(self) -> None:
        self.write({"AppDelegate.swift": "import UIKit\n"})
        self.assertIn(NO_LANGUAGE_RULES, self.run_cli("detect", ".").stdout)



class WrapperThroughSymlink(Case):
    # スキルを symlink で入れたとき、<スキルのフォルダ>/../../vulnscan で動くこと（SKILL.md の CLI の見つけ方）
    def test_wrapper_via_symlinked_skill_folder(self) -> None:
        (self.root / "skills").mkdir()
        os.symlink(ROOT / "skills" / "vulnscan", self.root / "skills" / "vulnscan")
        wrapper = self.root / "skills" / "vulnscan" / ".." / ".." / "vulnscan"
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        proc = subprocess.run([str(wrapper), "--version"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("vulnscan", proc.stdout)

if __name__ == "__main__":
    unittest.main()
