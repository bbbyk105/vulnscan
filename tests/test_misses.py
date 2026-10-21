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


class QueryExecuteRawFollowTheSameRule(Case):
    # PR #3 の残り: query・execute・raw は、どこに ${} があっても拾っていた（新しく足した呼び方より誤検知が多い）
    def test_query_builders_through_query_execute_raw_are_not_flagged(self) -> None:
        self.write(
            {
                "src/repo.js": "const r = await pool.query(`SELECT COUNT(*) FROM products ${where}`, params);\n"
                "await db.query(`UPDATE events SET ${setClauses.join(', ')} WHERE id = $1`, values);\n"
                "await client.query(`SELECT * FROM t WHERE id IN (${placeholders})`, ids);\n"
                "await conn.execute('UPDATE products SET ' + fields.join(',') + ' WHERE id=?', params);\n"
                "await knex.raw(`SELECT ${cols.join(',')} FROM users WHERE id = ?`, [id]);\n"
            }
        )
        self.assertEqual(self.findings(self.scan(), "INJ-009"), [])

    def test_joined_values_through_query_execute_raw_are_flagged(self) -> None:
        self.write(
            {
                "src/repo.js": "db.query(`SELECT * FROM users WHERE id = ${id}`);\n"
                "pool.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n"
                "knex.raw(`DATE(created_at) = '${date}' AND deleted_at IS NULL FROM x`);\n"
                "await conn.execute(`DELETE FROM t WHERE id = ${id}`);\n"
                # 入れ子のテンプレートで値を引用符にくくる（~/Projects で main だけが拾っていた形）
                'sql.raw(`${column} in (${values.map((v) => `\'${v}\'`).join(", ")})`);\n'
            }
        )
        lines = sorted(f.location.line for f in self.findings(self.scan(), "INJ-009"))
        self.assertEqual(lines, [1, 2, 3, 4, 5])


class SqlInTestsIsLow(Case):
    # PR #3 の残り: テストのファイルで定数をつないだ SQL が「高」で出ていた
    def test_sql_in_test_files_is_low(self) -> None:
        self.write(
            {
                "src/order.test.ts": "sqlite.exec(`update orders set status = 'shipped' where id = '${ORDER}'`);\n",
                "src/order.ts": "sqlite.exec(`update orders set status = 'shipped' where id = '${id}'`);\n",
            }
        )
        severities = {f.location.path: f.severity.name for f in self.findings(self.scan(), "INJ-009")}
        self.assertEqual(severities, {"src/order.test.ts": "LOW", "src/order.ts": "HIGH"})


class SecondReviewOfInj009(Case):
    # 2 回目の /code-review の指摘（2026-10-22）。main で拾えていたものの後退と、識別子の誤検知
    def test_values_joined_after_the_first_literal_are_flagged(self) -> None:
        self.write(
            {
                "src/db.js": 'connection.query("SELECT * FROM " + table + " WHERE id = " + id);\n'
                'db.query("SELECT * FROM t " + where + " AND b = " + b);\n'
            }
        )
        self.assertEqual(sorted(f.location.line for f in self.findings(self.scan(), "INJ-009")), [1, 2])

    def test_values_after_or_inside_nested_templates_are_flagged(self) -> None:
        self.write(
            {
                "src/db.js": "db.query(`SELECT ${fields.map(f => `t.${f}`).join(', ')} FROM t WHERE name = '${name}'`);\n"
                "db.query(`SELECT * FROM t WHERE a = 1 ${cond ? `AND id = ${id}` : ''}`);\n"
                "db.all(`SELECT * FROM t WHERE 1 ${q ? `AND name LIKE '%${q}%'` : ''}`);\n"
            }
        )
        self.assertEqual(sorted(f.location.line for f in self.findings(self.scan(), "INJ-009")), [1, 2, 3])

    def test_ilike_generics_and_escaped_quotes_are_flagged(self) -> None:
        self.write(
            {
                "src/db.ts": "db.query(`SELECT * FROM users WHERE name ILIKE ${q}`);\n"
                "prisma.$queryRawUnsafe<User[]>(`SELECT * FROM users WHERE id = ${id}`);\n"
                "db.all<Row>(`SELECT * FROM t WHERE a = '${a}'`);\n"
                "db.query<User>(`SELECT * FROM t WHERE id = ${id}`);\n"
                "db.query('SELECT * FROM t WHERE name = \\'' + name + '\\'');\n"
                'db.query("SELECT * FROM t WHERE a = \\"" + a + "\\"");\n'
                "db.query(`SELECT * FROM t WHERE name = \\'${name}\\'`);\n"
            }
        )
        self.assertEqual(
            sorted(f.location.line for f in self.findings(self.scan(), "INJ-009")), [1, 2, 3, 4, 5, 6, 7]
        )

    def test_long_concat_chain_does_not_hang(self) -> None:
        # 連結の式の部分と前の \s* が空白を取り合い、続く数だけ組み合わせが増えて止まらなくなっていた
        import signal

        line = 'db.query("SELECT a" + ' + 'x + "b" + ' * 2000 + "1);\n"
        self.write({"src/db.js": line})

        def timeout(*_args):
            raise TimeoutError("INJ-009 が 5 秒で終わらない")

        old = signal.signal(signal.SIGALRM, timeout)
        signal.alarm(5)
        try:
            self.scan()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)

    def test_quoted_identifiers_are_not_flagged(self) -> None:
        self.write(
            {
                "src/db.js": 'db.query(`SELECT ${cols.map((c) => `"${c}"`).join(",")} FROM users WHERE id = $1`, [id]);\n'
                'pool.query(`SELECT * FROM "${table}" WHERE id = $1`, [id]);\n'
            }
        )
        self.assertEqual(self.findings(self.scan(), "INJ-009"), [])


class SecondReviewOfSec013(Case):
    def test_weak_fixed_passwords_are_flagged(self) -> None:
        values = ["topsecret", "supersecretpassword", "mysecretpassword", "monkeyking", "MySecretP@ss"]
        self.write({"src/a.py": "".join(f'password = "{v}"\n' for v in values)})
        self.assertEqual(len(self.findings(self.scan(), "SEC-013")), len(values))

    def test_values_that_only_start_like_a_reference_are_flagged(self) -> None:
        self.write(
            {
                "src/a.py": 'password = "$uperS3cret!"\npassword = "__Zq8vT3kL"\n'
                'api_key = "https://user:Zq8vT3kLm2@host"\n'
            }
        )
        self.assertEqual(len(self.findings(self.scan(), "SEC-013")), 3)

    def test_backtick_value_does_not_run_into_the_next_assignment(self) -> None:
        self.write({"src/c.js": f"const c={{apiKey:`{FAKE_PW}`,password:`changeme`}};\n"})
        self.assertEqual(len(self.findings(self.scan(), "SEC-013")), 1)

    def test_other_laravel_rules_and_translations_are_not_flagged(self) -> None:
        self.write(
            {
                "app/Http/Requests/Update.php": "'password' => 'confirmed|min:8',\n"
                "'password' => 'string|min:8|confirmed',\n"
                "'password' => 'required_with:password_confirmation',\n"
                "'password' => 'confirmed',\n"
                "'current_password' => 'current_password:web',\n",
                "lang/de/validation.php": "'password' => 'Passwort',\n",
            }
        )
        self.assertEqual(self.findings(self.scan(), "SEC-013"), [])

    def test_tokens_other_rules_report_are_not_counted_twice(self) -> None:
        from test_regressions import FAKE_GH, FAKE_STRIPE

        openai = "sk-" + "proj-" + "A" * 40
        self.write(
            {
                "src/keys.ts": f'const OPENAI_API_KEY = "{openai}";\n'
                f'const STRIPE_SECRET_KEY = "{FAKE_STRIPE}";\n'
                f'const GITHUB_ACCESS_TOKEN = "{FAKE_GH}";\n'
            }
        )
        result = self.scan()
        self.assertEqual(self.findings(result, "SEC-013"), [])
        self.assertTrue(self.findings(result, "SEC-005"))
        self.assertTrue(self.findings(result, "SEC-006"))
        self.assertTrue(self.findings(result, "SEC-008"))

    def test_env_lines_with_comments_hyphens_and_pwd_are_flagged_by_sec016(self) -> None:
        self.write(
            {
                ".env": f'PASSWORD="{FAKE_PW}"  # x\n'
                f'api-key="{FAKE_PW}"\n'
                f'DB_PASSWORD="{FAKE_PW}" # prod\n'
                f'# OLD_DB_PASSWORD="{FAKE_PW}"\n'
                f'DB_PWD="{FAKE_PW}"\n'
                "PWD=/Users/someone/project\n",
                "a.ts": "1\n",
            }
        )
        result = self.scan()
        self.assertEqual(sorted(f.location.line for f in self.findings(result, "SEC-016")), [1, 2, 3, 4, 5])
        self.assertEqual(self.findings(result, "SEC-013"), [])

    def test_excluded_values_are_still_masked_in_other_findings(self) -> None:
        # SEC-013 では出さない値も、ほかのルールの証拠では伏せる（その行の指紋は一度変わる。README に書いた）
        self.write({"tls.js": 'new https.Agent({ rejectUnauthorized: false }); const FORGOT_PASSWORD = "/forgot-password";\n'})
        out = all_output(self.scan())
        self.assertNotIn("/forgot-password", out)


if __name__ == "__main__":
    unittest.main()
