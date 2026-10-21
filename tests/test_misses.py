"""スキルの試しで見つかった取りこぼしの再現テスト（2026-10-22）。

偽の秘密情報は、このファイル自体が検出されないよう連結して組み立てる。
"""

from __future__ import annotations

import unittest

from test_regressions import Case, all_output

FAKE_PW = "Zq8v" + "T3kLm2NpQ7"


class PrefixedSecretNamesAreFlagged(Case):
    # SEC-013 は名前がちょうど password などのものにしか当たらず、SMTP_PASSWORD・JWT_SECRET などを拾わなかった
    def test_names_with_a_prefix_are_flagged(self) -> None:
        names = [
            "SMTP_PASSWORD",
            "DB_PASSWORD",
            "dbPassword",
            "JWT_SECRET",
            "GOOGLE_CLIENT_SECRET",
            "GITHUB_ACCESS_TOKEN",
            "secretKey",
            "STRIPE_SECRET_KEY",
        ]
        self.write({"src/config.ts": "".join(f'export const {n} = "{FAKE_PW}";\n' for n in names)})
        lines = sorted(f.location.line for f in self.findings(self.scan(), "SEC-013"))
        self.assertEqual(lines, list(range(1, len(names) + 1)))

    def test_quoted_and_yaml_keys_with_a_prefix_are_flagged(self) -> None:
        self.write(
            {
                "settings.json": f'{{"env": {{"SMTP_PASSWORD": "{FAKE_PW}"}}}}\n',
                "config.yml": f'smtp_password: "{FAKE_PW}"\n',
                "go/main.go": f'dbPassword := "{FAKE_PW}"\n',
            }
        )
        paths = {f.location.path for f in self.findings(self.scan(), "SEC-013")}
        self.assertEqual(paths, {"settings.json", "config.yml", "go/main.go"})

    def test_prefixed_secret_is_masked(self) -> None:
        self.write({"mail.ts": f'const SMTP_PASSWORD = "{FAKE_PW}";\n'})
        result = self.scan()
        self.assertTrue(self.findings(result, "SEC-013"))
        self.assertNotIn(FAKE_PW, all_output(result))


class PrefixedNamesKeepTheOldExclusions(Case):
    # 名前を広げても、道・i18n のキー・autocomplete の値・環境変数の参照は拾わない
    def test_routes_keys_and_env_references_are_not_flagged(self) -> None:
        self.write(
            {
                "src/routes.ts": 'export const FORGOT_PASSWORD = "/forgot-password";\n',
                "src/labels.ts": 'labels.password = "auth.password.label";\n',
                "src/form.ts": 'const AUTOCOMPLETE_PASSWORD = "current-password";\n',
                "src/env.ts": "const SMTP_PASSWORD = process.env.SMTP_PASSWORD;\n",
                "src/ui.ts": 'const forgotPassword = "Forgot password?";\n',
                "src/default.ts": 'const DEFAULT_PASSWORD = "changeme";\n',
            }
        )
        self.assertEqual(self.findings(self.scan(), "SEC-013"), [])

    def test_names_that_only_start_with_a_credential_word_are_not_flagged(self) -> None:
        self.write({"src/form.ts": 'const passwordField = "password-input-1";\nconst secretName = "app-secret-v2";\n'})
        self.assertEqual(self.findings(self.scan(), "SEC-013"), [])

    def test_values_that_are_not_secrets_are_not_flagged(self) -> None:
        # ~/Projects の 40 件で流したときに、名前を広げて増えた誤検知の形
        turnstile_test = "1x" + "0" * 31 + "AA"
        self.write(
            {
                "src/oauth.ts": 'const OAUTH_TOKEN = "https://oauth2.googleapis.com/token";\n',
                "supabase/config.toml": 's3_secret_key = "env(S3_SECRET_KEY)"\n',
                "src/perm.py": "PERMS = {'ASSETS_RISK_WEAK_PWD': 'RISK_WEAK'}\n",
                "scripts/verify.mjs": 'const env = { OPENAI_API_KEY: "local-test-key" };\n',
                "docs/setup.md": '"channelSecret": "your-secret"\n',
                "lib/turnstile.ts": f'const TEST_SECRET = "{turnstile_test}";\n',
                "src/purchases.ts": 'const RC_IOS_API_KEY = "appl_' + "AbCdEfGh1234" + '";\n',
                "reset.sh": '[[ -n "${POSTGRES_PASSWORD:-}" ]] && export PGPASSWORD="$POSTGRES_PASSWORD"\n',
                "docs/notion.html": '<pre><code>api_key: "__notionApi__"</code></pre>\n',
            }
        )
        self.assertEqual(self.findings(self.scan(), "SEC-013"), [])

    def test_real_secret_next_to_an_excluded_value_is_still_flagged(self) -> None:
        # 外す形を行全体に当てると、同じ行の本物まで消えていた
        self.write({"src/auth.ts": f"return json({{ refreshToken: 'lhc1.encrypted', accessToken: '{FAKE_PW}' }});\n"})
        self.assertEqual(len(self.findings(self.scan(), "SEC-013")), 1)

    def test_mixed_case_value_with_underscores_is_flagged(self) -> None:
        self.write({"src/config.ts": 'const DB_PASSWORD = "Hq7m_W2xT_z9Lp";\n'})
        self.assertEqual(len(self.findings(self.scan(), "SEC-013")), 1)


class ReviewOfTheWiderSecretRule(Case):
    # /code-review の指摘（2026-10-22）。値の除外が広すぎた・マスクまで狭めた・=> の誤検知・行全体の unless

    def test_real_secrets_with_digits_dots_or_slashes_are_flagged(self) -> None:
        values = ["p4ss" + "w0rd.2024", "LIVE_" + "4F9A2B7C8D1E3F5A", "ABCD_" + "1234_EFGH", "/Xk3n9" + "Qz8LmPq2Rv7Tw"]
        self.write({"src/a.py": "".join(f'password = "{v}"\n' for v in values)})
        self.assertEqual(len(self.findings(self.scan(), "SEC-013")), len(values))

    def test_secret_is_masked_in_other_findings_on_the_line(self) -> None:
        value = "p4ss" + "w0rd.2024"
        self.write({"tls.js": f"new https.Agent({{ rejectUnauthorized: false }}); const password = '{value}';\n"})
        self.assertNotIn(value, all_output(self.scan()))

    def test_php_and_ruby_hashes_and_kebab_keys_are_flagged(self) -> None:
        self.write(
            {
                "config/db.php": f"return ['db_password' => '{FAKE_PW}'];\n",
                "config/mail.rb": f'MAIL = {{ :smtp_password => "{FAKE_PW}" }}\n',
                "src/client.ts": f"fetch(url, {{ headers: {{ 'X-Api-Key': '{FAKE_PW}' }} }});\n",
                "settings.json": f'{{"smtp-password": "{FAKE_PW}"}}\n',
            }
        )
        paths = {f.location.path for f in self.findings(self.scan(), "SEC-013")}
        self.assertEqual(paths, {"config/db.php", "config/mail.rb", "src/client.ts", "settings.json"})

    def test_validation_rules_hashes_and_arrow_params_are_not_flagged(self) -> None:
        bcrypt = "$2y$10$" + "92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi"
        self.write(
            {
                "app/Http/Requests/Register.php": "'password' => 'required|string|min:8|confirmed',\n"
                "'new_password' => 'required|min:8',\n",
                "database/factories/UserFactory.php": f"'password' => '{bcrypt}',\n",
                "src/log.js": "const safe = items.map(password => '[FILTERED]');\n",
            }
        )
        self.assertEqual(self.findings(self.scan(), "SEC-013"), [])

    def test_identifier_like_values_are_not_flagged(self) -> None:
        self.write(
            {
                "src/form.ts": "const field = mode === 'reset' ? 'newPassword' : 'currentPassword';\n",
                "src/enum.ts": "enum Step { ResetPassword = 'ResetPassword' }\n",
                "src/names.ts": "export const CONFIRM_PASSWORD = 'confirmPassword';\n",
                "src/actions.ts": "export const RESET_PASSWORD = 'auth/RESET_PASSWORD';\n",
                "src/keys.ts": "export const TOKEN_SECRET = '@app/secret';\n",
                "locales/de.json": '{"showPassword": "Anzeigen"}\n',
            }
        )
        self.assertEqual(self.findings(self.scan(), "SEC-013"), [])

    def test_other_text_on_the_line_does_not_hide_the_secret(self) -> None:
        self.write(
            {
                "src/a.ts": f"const creds: Record<string, string> = {{ SMTP_PASSWORD: '{FAKE_PW}' }};\n",
                "src/b.ts": f"const cfg = {{ mode: 'test', apiKey: '{FAKE_PW}' }};\n",
                "src/c.ts": f"const smtp = {{ host: process.env.SMTP_HOST, SMTP_PASSWORD: '{FAKE_PW}' }};\n",
            }
        )
        paths = {f.location.path for f in self.findings(self.scan(), "SEC-013")}
        self.assertEqual(paths, {"src/a.ts", "src/b.ts", "src/c.ts"})

    def test_backtick_values_are_flagged_unless_interpolated(self) -> None:
        self.write(
            {
                "main.go": f"dbPassword := `{FAKE_PW}`\n",
                "src/admin.js": f"const ADMIN_PASSWORD = `{FAKE_PW}`;\n",
                "src/env.js": "const DB_PASSWORD = `${process.env.DB_PASSWORD}`;\n",
            }
        )
        paths = {f.location.path for f in self.findings(self.scan(), "SEC-013")}
        self.assertEqual(paths, {"main.go", "src/admin.js"})

    def test_env_files_are_left_to_sec016(self) -> None:
        self.write({".env": f'DB_PASSWORD="{FAKE_PW}"\n', "a.ts": "1\n"})
        result = self.scan()
        self.assertEqual(self.findings(result, "SEC-013"), [])
        self.assertEqual(len(self.findings(result, "SEC-016")), 1)


class SqlCallsBeyondQuery(Case):
    # INJ-009 は query・execute・raw しか見ず、sqlite3 の db.all などで組み立てた SQL を拾わなかった
    def test_sqlite_and_prisma_calls_are_flagged(self) -> None:
        self.write(
            {
                "src/db.js": "db.all(`SELECT * FROM users WHERE name = '${name}'`, cb);\n"
                'db.get("SELECT * FROM users WHERE id = " + id, cb);\n'
                "db.run(`DELETE FROM sessions WHERE token = '${token}'`);\n"
                "db.exec(`UPDATE users SET name = '${name}'`);\n"
                "const stmt = db.prepare(`INSERT INTO logs VALUES ('${msg}')`);\n"
                "await prisma.$queryRawUnsafe(`SELECT * FROM posts WHERE slug = '${slug}'`);\n"
                "db.get(`SELECT * FROM users WHERE id = ${id}`, cb);\n"
                "db.all(\"SELECT * FROM users WHERE name = '\" + name + \"'\", cb);\n"
            }
        )
        lines = sorted(f.location.line for f in self.findings(self.scan(), "INJ-009"))
        self.assertEqual(lines, [1, 2, 3, 4, 5, 6, 7, 8])

    def test_query_builders_that_bind_values_are_not_flagged(self) -> None:
        # ~/Projects で流したときに増えた 103 件の大半。組み立てるのは列の一覧・WHERE・IN (?, ?) で、値はバインドする
        self.write(
            {
                "src/routes.js": "const total = db.prepare(`SELECT COUNT(*) as n FROM products ${where}`).get(...params);\n"
                "db.prepare(`UPDATE events SET ${setClauses.join(', ')} WHERE id = ?`).bind(...values, id);\n"
                "db.prepare(`SELECT * FROM friends WHERE line_user_id IN (${placeholders})`).bind(...ids);\n"
                "db.prepare(`UPDATE t SET status='pending', at=datetime('now','localtime') WHERE id IN (${ids.map(() => '?').join(',')})`);\n"
                "db.prepare('UPDATE products SET ' + fields.join(',') + ' WHERE id=?').run(...params);\n"
                "db.prepare(`SELECT id FROM line_accounts WHERE ${column} = ? LIMIT 1`).bind(value);\n"
            }
        )
        self.assertEqual(self.findings(self.scan(), "INJ-009"), [])

    def test_closed_sql_string_before_concat_is_not_flagged(self) -> None:
        # /code-review の指摘: 連結の枝が閉じた引用符の組を読み飛ばさず、閉じの ' を開きと見ていた
        self.write(
            {
                "src/db.js": "db.all(\"SELECT * FROM users WHERE status = 'active'\" +\n"
                "  \" AND id = ?\", [id], cb);\n"
                "db.get('SELECT * FROM t WHERE name = \"bob\"' + ' AND id = ?', [id]);\n"
            }
        )
        self.assertEqual(self.findings(self.scan(), "INJ-009"), [])

    def test_other_quotes_operators_and_calls_are_flagged(self) -> None:
        self.write(
            {
                "src/db.js": 'db.all(`SELECT * FROM users WHERE name = "${name}"`, cb);\n'
                "db.all(`SELECT * FROM t WHERE \\`name\\` = '${n}'`);\n"
                "db.each(`SELECT * FROM t WHERE n LIKE '%${q}%'`, cb);\n"
                "await prisma.$executeRawUnsafe(`DELETE FROM t WHERE id = ${id}`);\n"
                "db.all(`SELECT * FROM t WHERE age > ${age}`);\n"
            }
        )
        lines = sorted(f.location.line for f in self.findings(self.scan(), "INJ-009"))
        self.assertEqual(lines, [1, 2, 3, 4, 5])

    def test_routes_caches_and_placeholders_are_not_flagged(self) -> None:
        self.write(
            {
                "src/app.js": "router.get(`/delete/${id}`, handler);\n"
                'app.get("/users/" + id + "/delete", handler);\n'
                "cache.get(`select:${key}`);\n"
                'db.all("SELECT * FROM users WHERE id = ?", [id], cb);\n'
                "db.get(`SELECT * FROM users WHERE id = ?`, [id], cb);\n"
            }
        )
        self.assertEqual(self.findings(self.scan(), "INJ-009"), [])


if __name__ == "__main__":
    unittest.main()
