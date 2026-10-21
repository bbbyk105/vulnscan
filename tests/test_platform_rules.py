"""Dart/Flutter・Android/iOS・Firebase のルールと Go のルール。"""

from __future__ import annotations

import unittest

from test_vulnscan import RepoCase


class Case(RepoCase):
    def lines_of(self, rule_id: str) -> set:
        return {(f.location.path, f.location.line) for f in self.scan().findings if f.rule_id == rule_id}


class DartRuleTests(Case):
    def test_bad_certificate_callback(self) -> None:
        self.write(
            {
                "lib/http.dart": "final client = HttpClient()\n"
                "  ..badCertificateCallback = (cert, host, port) => true;\n"
                "client.badCertificateCallback = (X509Certificate c, String h, int p) {\n"
                "  return true;\n"
                "};\n"
                "client.badCertificateCallback = (c, h, p) => h == 'localhost';\n"
            }
        )
        self.assertEqual(self.lines_of("TLS-006"), {("lib/http.dart", 2), ("lib/http.dart", 3)})

    def test_cleartext_url(self) -> None:
        self.write(
            {
                "lib/api.dart": "final a = Uri.parse('http://api.example.com/v1');\n"
                "const baseUrl = \"http://backend.example.com\";\n"
                "final b = Uri.http('api.example.com', '/v1');\n"
                "final c = Uri.parse('https://api.example.com');\n"
                "final d = Uri.parse('http://10.0.2.2:8080');\n"
                "final e = Uri.http('localhost:5001', '/');\n"
            }
        )
        self.assertEqual(
            self.lines_of("TLS-007"), {("lib/api.dart", 1), ("lib/api.dart", 2), ("lib/api.dart", 3)}
        )

    def test_token_in_shared_preferences(self) -> None:
        self.write(
            {
                "lib/store.dart": "import 'package:shared_preferences/shared_preferences.dart';\n"
                "await prefs.setString('access_token', token);\n"
                "await prefs.setString(kRefreshTokenKey, token);\n"
                "await prefs.setString('theme', 'dark');\n"
            }
        )
        self.assertEqual(self.lines_of("CFG-012"), {("lib/store.dart", 2), ("lib/store.dart", 3)})

    def test_session_reason_is_not_a_secret(self) -> None:
        # attendance-management の auth_session_store.dart（ログアウトした理由を保存している）
        self.write(
            {
                "lib/store.dart": "import 'package:shared_preferences/shared_preferences.dart';\n"
                "await prefs.setString(authSessionReasonKey, reason.name);\n"
                "await prefs.setString('session_id', id);\n"
            }
        )
        self.assertEqual(self.lines_of("CFG-012"), {("lib/store.dart", 3)})

    def test_cleartext_in_integration_test_is_low(self) -> None:
        self.write({"app/integration_test/helpers/emu.dart": "Uri _authUri(String path) => Uri.http('$host:$port', path);\n"})
        (finding,) = [f for f in self.scan().findings if f.rule_id == "TLS-007"]
        self.assertEqual(finding.severity.label, "low")

    def test_token_printed(self) -> None:
        self.write(
            {
                "lib/auth.dart": "print('token: $token');\n"
                "debugPrint('id: ${user.idToken}');\n"
                "print('パスワードを再設定しました');\n"
            }
        )
        self.assertEqual(self.lines_of("CFG-013"), {("lib/auth.dart", 1), ("lib/auth.dart", 2)})

    def test_webview_javascript(self) -> None:
        self.write(
            {"lib/web.dart": "controller.setJavaScriptMode(JavaScriptMode.unrestricted);\n"}
        )
        self.assertEqual(self.lines_of("CFG-014"), {("lib/web.dart", 1)})


class MobileConfigTests(Case):
    def test_android_manifest(self) -> None:
        manifest = '<application android:usesCleartextTraffic="true" android:debuggable="true">\n'
        self.write(
            {
                "app/src/main/AndroidManifest.xml": manifest,
                "app/src/debug/AndroidManifest.xml": manifest,
            }
        )
        self.assertEqual(self.lines_of("TLS-008"), {("app/src/main/AndroidManifest.xml", 1)})
        self.assertEqual(self.lines_of("CFG-015"), {("app/src/main/AndroidManifest.xml", 1)})

    def test_ios_arbitrary_loads(self) -> None:
        self.write(
            {
                "ios/Runner/Info.plist": "<dict>\n  <key>NSAllowsArbitraryLoads</key>\n  <true/>\n</dict>\n",
                "ios/Other/Info.plist": "<dict>\n  <key>NSAllowsArbitraryLoads</key>\n  <false/>\n</dict>\n",
            }
        )
        self.assertEqual(self.lines_of("TLS-009"), {("ios/Runner/Info.plist", 2)})


class FirebaseRulesTests(Case):
    def test_open_rules(self) -> None:
        self.write(
            {
                "firestore.rules": "service cloud.firestore {\n"
                "  match /public/{id} { allow read: if true; }\n"
                "  match /logs/{id} { allow read, write: if true; }\n"
                "  match /tmp/{id} { allow write: if request.time < timestamp.date(2026, 12, 1); }\n"
                "  match /users/{uid} { allow read, write: if request.auth.uid == uid; }\n"
                "}\n"
            }
        )
        self.assertEqual(self.lines_of("AUTH-006"), {("firestore.rules", 3)})
        self.assertEqual(self.lines_of("AUTH-007"), {("firestore.rules", 2)})
        self.assertEqual(self.lines_of("AUTH-008"), {("firestore.rules", 4)})


class GoRuleTests(Case):
    def test_sql_built_with_sprintf_or_concat(self) -> None:
        self.write(
            {
                "store.go": 'rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n'
                'row := db.QueryRowContext(r.Context(), "SELECT * FROM t WHERE name = \'" + name + "\'")\n'
                'rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)\n'
            }
        )
        self.assertEqual(self.lines_of("INJ-014"), {("store.go", 1), ("store.go", 2)})

    def test_placeholders_and_integers_are_not_flagged(self) -> None:
        # artex-global で当たった、値を入れない組み立て
        self.write(
            {
                "store.go": 'res, err := s.db.Exec("DELETE FROM assets WHERE id IN ("+strings.Join(placeholders, ",")+")", args...)\n'
                "conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, pages))\n"
                "db.Query(\"SELECT * FROM t WHERE name = '\" + name + \"'\")\n"
            }
        )
        # 3 行目は当たる側の確かめ（値を SQL の引用符の中につなぐ）
        self.assertEqual(self.lines_of("INJ-014"), {("store.go", 3)})

    def test_sql_in_go_test_is_low(self) -> None:
        self.write({"store_test.go": "m.pg.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON tasks`, name))\n"})
        (finding,) = [f for f in self.scan().findings if f.rule_id == "INJ-014"]
        self.assertEqual(finding.severity.label, "low")

    def test_shell_command(self) -> None:
        self.write(
            {
                "run.go": 'out, _ := exec.Command("sh", "-c", "convert "+name).Output()\n'
                'cmd := exec.CommandContext(ctx, "/bin/bash", "-c", script)\n'
                'out, _ := exec.Command("git", "rev-parse", "HEAD").Output()\n'
            }
        )
        self.assertEqual(self.lines_of("INJ-015"), {("run.go", 1), ("run.go", 2)})

    def test_text_template_in_http_handler(self) -> None:
        self.write(
            {
                "web.go": 'import (\n\t"net/http"\n\t"text/template"\n)\nfunc h(w http.ResponseWriter, r *http.Request) {}\n',
                "gen.go": 'import "text/template"\n',
            }
        )
        self.assertEqual(self.lines_of("XSS-006"), {("web.go", 3)})

    def test_math_rand_for_tokens(self) -> None:
        self.write(
            {
                "token.go": 'import "math/rand"\nfunc newToken() string { return fmt.Sprint(rand.Int63()) }\n'
                "func jitter() int { return rand.Intn(100) }\n",
            }
        )
        self.assertEqual(self.lines_of("CRY-007"), {("token.go", 2)})

    def test_server_without_timeouts(self) -> None:
        self.write({"main.go": 'log.Fatal(http.ListenAndServe(":8080", mux))\n'})
        self.assertEqual(self.lines_of("CFG-016"), {("main.go", 1)})


if __name__ == "__main__":
    unittest.main()
