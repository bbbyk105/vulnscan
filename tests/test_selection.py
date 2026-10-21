"""言語の選び方（--lang・番号での選択）と、言語・フレームワークの自動の見分け。"""

from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

try:
    import termios
except ImportError:  # Windows
    termios = None

from test_vulnscan import ROOT, RepoCase

from vulnscan.detect import choose_languages, detect, parse_languages
from vulnscan.models import ScanError
from vulnscan import picker
from vulnscan.picker import ALL, CANCEL, DOWN, ENTER, TOGGLE, UP, PickerState, decode_key, fit_width, read_key
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


class PickerStateTests(unittest.TestCase):
    # 端末で --lang に値を付けないときの一覧。矢印キーで動かし、スペースで選ぶ（2026-10-22、番号を打つ形から変えた）
    def press(self, count: int, *keys: str):
        state = PickerState(count)
        result = None
        for key in keys:
            result = state.press(key)
            if result:
                break
        return state, result

    def test_move_and_toggle_with_space(self) -> None:
        state, result = self.press(3, DOWN, TOGGLE, DOWN, TOGGLE, UP, TOGGLE, ENTER)
        self.assertEqual((result, state.chosen()), ("done", [2]))

    def test_enter_without_a_choice_means_all(self) -> None:
        state, result = self.press(3, ENTER)
        self.assertEqual((result, state.chosen()), ("done", []))

    def test_cursor_wraps_around(self) -> None:
        state, _ = self.press(3, UP)
        self.assertEqual(state.cursor, 2)
        state, _ = self.press(3, UP, DOWN, DOWN)
        self.assertEqual(state.cursor, 1)

    def test_a_toggles_everything(self) -> None:
        state, _ = self.press(3, ALL)
        self.assertEqual(state.chosen(), [0, 1, 2])
        state, _ = self.press(3, ALL, ALL)
        self.assertEqual(state.chosen(), [])

    def test_digits_toggle_that_row(self) -> None:
        state, _ = self.press(3, "3", "9")
        self.assertEqual((state.cursor, state.chosen()), (2, [2]))

    def test_cancel(self) -> None:
        _, result = self.press(3, DOWN, CANCEL)
        self.assertEqual(result, "cancel")

    def test_decode_keys(self) -> None:
        for raw, key in [
            ("k", UP),
            ("j", DOWN),
            (" ", TOGGLE),
            ("a", ALL),
            ("\n", ENTER),
            ("\r", ENTER),
            ("\x1b", CANCEL),
            ("q", CANCEL),
            ("2", "2"),
        ]:
            self.assertEqual(decode_key(raw), key, repr(raw))


class ReadKeyTests(unittest.TestCase):
    # 端末から 1 キーずつ読む所。パイプに流し、最後に書く側を閉じる（入力の終わり）
    def keys(self, data: bytes, count: int) -> list:
        r, w = os.pipe()
        os.write(w, data)
        os.close(w)
        try:
            return [read_key(r) for _ in range(count)]
        finally:
            os.close(r)

    def test_arrows_with_modifiers_move_and_other_sequences_are_ignored(self) -> None:
        # ESC の続きを 3 バイトまでしか読まず、Ctrl+↑（ESC[1;5A）の「5」が 5 行目を付け外ししていた
        self.assertEqual(self.keys(b"\x1b[1;5A", 2), [UP, CANCEL])
        self.assertEqual(self.keys(b"\x1b[1;2B", 2), [DOWN, CANCEL])
        self.assertEqual(self.keys(b"\x1bOA", 2), [UP, CANCEL])
        self.assertEqual(self.keys(b"\x1b[15~ ", 3), ["", TOGGLE, CANCEL])

    def test_full_width_space_and_digits(self) -> None:
        # 日本語入力が ON のときのスペース（U+3000）と全角数字を、1 バイトずつ読んで捨てていた
        self.assertEqual(self.keys("\u3000".encode(), 2), [TOGGLE, CANCEL])
        self.assertEqual(self.keys("１".encode(), 2), ["1", CANCEL])

    def test_end_of_input_cancels_and_ctrl_d_decides(self) -> None:
        # 入力の終わりで空回りしていた。Ctrl-D は番号の形のときと同じく「決める」
        self.assertEqual(self.keys(b"", 2), [CANCEL, CANCEL])
        self.assertEqual(self.keys(b"\x04", 2), [ENTER, CANCEL])

    def test_escape_alone_cancels(self) -> None:
        self.assertEqual(self.keys(b"\x1b", 1), [CANCEL])


class FitWidthTests(unittest.TestCase):
    # 端末の幅を超えて折り返すと、描き直しの戻り先がずれて一覧が崩れていた
    def test_cuts_to_the_terminal_width(self) -> None:
        self.assertEqual(fit_width("abcdef", 4), "abc")
        self.assertEqual(fit_width("あいう", 5), "あい")
        self.assertEqual(fit_width("ab", 80), "ab")

    def test_unknown_width_does_not_cut(self) -> None:
        # 幅を 0 と報告する端末（疑似端末・一部の CI）で、一覧の行が全部消えていた
        self.assertEqual(fit_width("abc", 0), "abc")


class NumberedFallbackTests(unittest.TestCase):
    detected = ChooseLanguagesTests.detected

    def test_dumb_terminal_cannot_read_single_keys(self) -> None:
        class Tty(io.StringIO):
            def isatty(self) -> bool:
                return True

        with mock.patch.dict(os.environ, {"TERM": "dumb"}):
            self.assertFalse(picker.available(Tty(), Tty()))

    def test_numbers_when_single_keys_cannot_be_read(self) -> None:
        from vulnscan import cli

        err = io.StringIO()
        with mock.patch.object(picker, "available", return_value=False), mock.patch.object(
            sys, "stdin", io.StringIO("2\n")
        ), mock.patch.object(sys, "stderr", err):
            self.assertEqual(cli.ask_languages(self.detected), ["python"])
        self.assertIn("  2) Python", err.getvalue())


class PickerInTerminalTests(Case):
    def setUp(self) -> None:
        super().setUp()
        if not hasattr(os, "openpty"):
            self.skipTest("os.openpty が無い")
        try:
            self.master, self.slave = os.openpty()
        except OSError as exc:  # Sandbox などで疑似端末を開けないとき
            self.skipTest(f"疑似端末を開けない: {exc}")
        self.attrs_before = termios.tcgetattr(self.slave)
        self.proc = None
        self.reader = None
        self.screen = b""
        # 後片付けの順番が大事: 子を止め、slave を閉じて読み取りのスレッドを終わらせてから master を閉じる
        # （読み取りの途中の master を閉じると、macOS では close が終わらない）
        self.addCleanup(self.cleanup)
        self.write({"web/a.ts": "eval(x)\n", "web/b.ts": "eval(y)\n", "tool.py": "eval(z)\n"})

    def start(self, stderr=None) -> None:
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), TERM="xterm")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "vulnscan", "scan", ".", "--lang", "--format", "json", "--fail-on", "never"],
            cwd=str(self.root),
            stdin=self.slave,
            stderr=self.slave if stderr is None else stderr,
            stdout=subprocess.PIPE,
            env=env,
        )
        self.reader = threading.Thread(target=self.drain, daemon=True)
        self.reader.start()

    def close_slave(self) -> None:
        if self.slave is not None:
            os.close(self.slave)
            self.slave = None
        if self.reader is not None:
            self.reader.join(timeout=5)

    def cleanup(self) -> None:
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            if self.proc.stdout:
                self.proc.stdout.close()
        self.close_slave()
        os.close(self.master)

    def drain(self) -> None:
        # 画面への出力を読み続ける（読まないと、描き直しで書く側が止まることがある）
        while True:
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                return
            if not chunk:
                return
            self.screen += chunk

    def wait_for(self, text: bytes) -> None:
        deadline = time.monotonic() + 10
        while text not in self.screen:
            self.assertLess(time.monotonic(), deadline, "出ない: " + self.screen.decode(errors="replace"))
            time.sleep(0.02)

    def finish(self) -> bytes:
        out, _ = self.proc.communicate(timeout=30)
        # 子が終わったあとの端末の設定を写してから slave を閉じ、読み取りのスレッドが残りを読み終えるのを待つ
        self.attrs_after = termios.tcgetattr(self.slave)
        self.close_slave()
        return out

    def assert_terminal_restored(self) -> None:
        self.assertIn(b"\x1b[?25h", self.screen)

        def comparable(attrs: list) -> list:
            # PENDIN は、行で読む形に戻したときにカーネルが自分で立てる（macOS）。vulnscan が戻すものではない
            return attrs[:3] + [attrs[3] & ~getattr(termios, "PENDIN", 0)] + attrs[4:]

        self.assertEqual(comparable(self.attrs_after), comparable(self.attrs_before))

    def test_arrow_space_and_enter_pick_the_second_language(self) -> None:
        self.start()
        self.wait_for(b"[ ]")
        for keys in (b"\x1b[B", b" ", b"\r"):  # ↓ で 2 行目（Python）へ、スペースで選び、Enter
            os.write(self.master, keys)
        data = json.loads(self.finish())
        self.assertEqual([item["language"] for item in data["languages"]], ["python"])
        self.assertEqual({f["path"] for f in data["findings"]}, {"tool.py"})
        self.assert_terminal_restored()

    def test_keys_typed_before_the_list_appears_are_kept(self) -> None:
        # 端末を切り替えるときに、既定の TCSAFLUSH が先に打ったキーを捨てていた（2026-10-22）
        self.start()
        os.write(self.master, b"\x1b[B \r")
        data = json.loads(self.finish())
        self.assertEqual([item["language"] for item in data["languages"]], ["python"])

    def test_q_cancels_and_restores_the_terminal(self) -> None:
        self.start()
        self.wait_for(b"[ ]")
        os.write(self.master, b"q")
        self.finish()
        self.assertEqual(self.proc.returncode, 2)
        self.assert_terminal_restored()

    def test_sigterm_restores_the_terminal(self) -> None:
        # kill で止めると、文字が画面に出ない cbreak のまま、カーソルも消えたまま残っていた
        self.start()
        self.wait_for(b"[ ]")
        self.proc.send_signal(signal.SIGTERM)
        self.finish()
        self.assert_terminal_restored()

    def test_stderr_not_a_terminal_needs_a_value(self) -> None:
        # stderr だけをファイルに向けると、見えない問いのまま入力を待ち続けていた
        with open(self.root / "err.log", "w") as err:
            self.start(stderr=err)
            self.finish()
        self.assertEqual(self.proc.returncode, 2)
        self.assertIn("--lang", (self.root / "err.log").read_text())


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
