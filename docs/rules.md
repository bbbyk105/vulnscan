**English** | [日本語](rules.ja.md)

# Rule details

How some rules decide what to report. For the list of rules, run `./vulnscan rules`; for one rule, `./vulnscan explain <ID>`.

## SEC-013: hard-coded passwords and API keys

**What it reports**: names that end with `password`, `secret`, `secret_key`, `api_key`, `access_token` and the like (including `SMTP_PASSWORD`, `dbPassword` and `'X-Api-Key'`) assigned an ASCII value without spaces, in quotes or backticks. Values with spaces are skipped so that UI text is not reported.

- Assignments: `=`, `:` and Go's `:=`; `=>` only after a quoted name or a Ruby symbol (not arrow functions).
- `.env`-style files are left to SEC-016, which also reads commented-out lines, trailing comments and `_PWD`.
- Translation files (JSON, YAML, PHP and the like under `lang/`, `locales/`, `i18n/` and similar folders) are not scanned.

**Values not treated as secrets** (other values on the same line are still checked):

| Kind | Examples |
|---|---|
| References | `process.env`, `${…}`, a whole value of `"$VAR"` |
| Placeholders | `changeme`, `your-…`, `<…>`, `__…`, `xxxxxx` |
| Addresses | URLs (unless they contain `user:pass@`), `env()`, lowercase paths |
| Names, not values | i18n keys (`auth.password.label`), uppercase identifiers made of letters and `_`, camelCase or `/`-separated values that name a credential (`'newPassword'`, `'auth/RESET_PASSWORD'`) |
| Words | values made only of lowercase words (`"local-test-key"`); letters-only values on names with a prefix (`"showPassword": "Anzeigen"`) |
| Other formats | Laravel validation rules, bcrypt hashes |
| Public values | Turnstile's test secret, RevenueCat public keys |
| Reported elsewhere | tokens that SEC-002 and SEC-005 to SEC-011 already report (so they are not counted twice) |

As a result, weak passwords made only of lowercase words (`"my-super-secret"`) and letters-only passwords on names with a prefix (`DB_PASSWORD = "topsecret"`) are not reported. The same value is reported when the name is exactly `password`.

Values that are not treated as secrets are still masked in the evidence of other findings. When the masking changes, other findings on that line get a new fingerprint once; regenerate your baseline if you use one.

## INJ-009: SQL built in JavaScript/TypeScript

**Calls it looks at**: `query`, `execute` and `raw`, and the sqlite3, better-sqlite3 and Prisma calls `all`, `get`, `run`, `each`, `exec`, `prepare`, `$queryRawUnsafe` and `$executeRawUnsafe` (with TypeScript type arguments such as `<User[]>` too). The sqlite3, better-sqlite3 and Prisma calls are only checked when the string starts with an SQL verb, so `router.get(...)` and caches are not reported.

**It only reports where a value is joined**:

- inside SQL `'…'` (including `\'`)
- `${}` or concatenation right after `=`, `<`, `>`, `LIKE`, `ILIKE`, `GLOB` or `REGEXP`
- `"…"` only right after a comparison, because Postgres also uses it for identifiers

For concatenation it checks every string in `"…" + expression + "…"`, and stops at an expression that contains quotes. It also looks inside nested templates (`` ${cond ? `AND id = ${id}` : ''} ``).

**Not reported**: building column lists, `WHERE` clauses or `IN (?, ?)` while binding the values (the same rule as Go's INJ-014). Column names, table names and sort order taken from input (`SET ${field}=?`, `ORDER BY ${sort}`) and values in positions without quotes or operators (`LIMIT ${n}`) are not reported either; read them in review. Findings in test files are low.

## `--deps`: dependency audits

| Lockfiles | Audited with |
|---|---|
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (Yarn 1), `requirements.txt`, `composer.lock` | their own audit tools |
| `pubspec.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `bun.lock` and others | `osv-scanner` |
| `bun.lockb` | none; reported as not checked (DEP-012, low) |

- Lockfiles in subfolders and lockfiles excluded by `.gitignore` are audited too; `--exclude` applies. Findings for lockfiles in test folders are low.
- A missing audit tool (DEP-010) or a failed audit (DEP-011) is reported as high, so a project that was not checked never passes. This includes a missing `osv-scanner`.
- The handling of `osv-scanner`'s output follows its official documentation and has not yet been checked against real output.

## `.env` files

The `.env` at the root is read even when it is gitignored, to check exposure such as `NEXT_PUBLIC_` (its contents are never sent anywhere). `.env` files in subfolders are read only when they are committed or not excluded by `.gitignore`.
