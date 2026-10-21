**English** | [日本語](README.ja.md)

# vulnscan

A static analysis CLI for finding the weak spots in your own code.

- **Read-only** — never changes the files it scans
- **Local** — no network access by default
- **No dependencies** — runs on the Python 3.9+ standard library
- **Tells you how to fix it** — each finding says what is risky and how to fix it

> **Reports are in Japanese.** The scan output, the rule messages and the agent skill (`skills/`) are written in Japanese; only this README is translated. Rule IDs, paths, CWE and OWASP references are language-neutral, and `--format json` / `--format sarif` are easy to process in any language.

> This tool is for checking repositories you maintain.
> It does not attack external hosts, scan ports, steal credentials or generate malware.

---

## Quick start

```sh
git clone https://github.com/bbbyk105/vulnscan.git
cd vulnscan

# Run it directly (no install)
./vulnscan scan /path/to/your-app

# Or install it
python3 -m pip install -e .
vulnscan scan .
```

Example output (中 means medium):

```
vulnscan 0.1.0 — /path/to/your-app
2026-10-21 19:18 · 84 ファイル · 86 ルール · 0.11 秒

合計 2 件（中 2）

■ 中 (2)

  XSS-001  dangerouslySetInnerHTML の使用
    components/JsonLd.tsx:14
    └ dangerouslySetInnerHTML={{ __html: JSON.stringify(graph) }}
    理由: HTML を直接挿入しています。値がユーザー入力なら XSS になります。
    修正: DOMPurify などでサニタイズするか、テキストとして描画してください。
    クロスサイトスクリプティング / CWE-79 / A03:2021
```

## Commands

```sh
# Basic
./vulnscan scan <path>

# Save as Markdown / JSON / SARIF
./vulnscan scan . --format md   -o security-report.md
./vulnscan scan . --format json -o vulnscan.json
./vulnscan scan . --format sarif -o vulnscan.sarif   # for GitHub Code Scanning

# Filter by severity or category
./vulnscan scan . --min-severity medium
./vulnscan scan . --category secret --category injection

# Also check dependencies for known CVEs (uses the network)
./vulnscan scan . --deps

# Only files with uncommitted changes (for pre-commit)
./vulnscan scan . --changed --fail-on high

# Only the PR's changes (for CI: the diff from base plus uncommitted changes)
./vulnscan scan . --base origin/main --fail-on high

# Pick languages (js, ts, py, flutter, go, ...; comma-separated)
./vulnscan scan . --lang js,py
./vulnscan scan . --lang            # without a value, pick from the languages found by number (terminal only)

# Only detect languages and frameworks (no scan)
./vulnscan detect .
./vulnscan detect . --json

# List the rules and explain one
./vulnscan rules
./vulnscan explain SEC-013

# Exit codes for CI: 0 = pass / 1 = findings at or above the threshold / 2 = error
./vulnscan scan . --fail-on high
```

## What it checks

| Category | Examples |
|---|---|
| Secrets | AWS / Stripe / GitHub tokens, private keys, plain-text values in YAML and `.env`-style files, committed `.env` files (subfolders too), environment variables exposed to the client |
| Injection | `eval`, `shell=True`, SQL built by string concatenation, `pickle` / `yaml.load`, PHP `unserialize` |
| XSS | `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, serving SVG directly |
| Crypto and randomness | MD5 / SHA1, AES-ECB, `Math.random` / `random` for tokens |
| Authentication and authorization | JWT `alg: none`, `verify=False`, wildcard CORS, disabled CSRF |
| Transport security | `rejectUnauthorized: false`, `InsecureSkipVerify`, `verify=False` |
| Misconfiguration | `DEBUG=True`, secrets in a Dockerfile `ENV`, running as root, `privileged: true` |
| CI/CD | script injection in GitHub Actions, unsafe checkouts in `pull_request_target` |
| Mobile and Firebase | disabled certificate checks, cleartext traffic and tokens in SharedPreferences in Dart; Android `usesCleartextTraffic` and `debuggable`; iOS ATS exceptions; `if true` in Firestore / Storage rules |
| Dependencies | `npm audit` / `pnpm audit` / `yarn audit` / `pip-audit` / `composer audit`; pub, Go, Cargo, Bundler, Poetry, uv and others through `osv-scanner` (with `--deps`; lockfiles in subfolders too; an audit that cannot run is reported as high) |

See every rule with `./vulnscan rules` and the details of one with `./vulnscan explain <ID>`.

### Coverage by language

The 19 secret rules apply to files in every language. The rules for risky code are per language.

| Language | Rules | Also |
|---|---:|---|
| JavaScript/TypeScript | 17 | |
| Python | 12 | |
| PHP | 7 | |
| Go | 6 | |
| Dart/Flutter | 5 | Android manifest (2), iOS Info.plist (1), Firebase rules (3) |
| Ruby | 3 | |
| Java/Kotlin/Scala | 1 | |
| Swift, shell, Rust, C/C++ and others | 0 | |
| Dockerfile, YAML, GitHub Actions, .env | 2, 2, 2, 1 | |

At the end of the report, vulnscan lists the languages it found with their rule counts, and the frameworks it detected. A language with no rules is marked as checked for leftover secrets only (秘密の置き忘れだけを確認); cover that part with a code review or with the agent skill below.

```
言語: Dart/Flutter 211（5 ルール）、JavaScript/TypeScript 211（17 ルール）、Swift 3（言語のルールなし。秘密の置き忘れだけを確認）
フレームワーク: Firebase（functions/package.json）、Flutter（app/pubspec.yaml）
```

Detected frameworks: Next.js, Expo/React Native, Express, Hono, Supabase, Firebase, Flutter, Cloudflare Workers, Django, FastAPI, Flask, Rails and Laravel. They are detected from marker files such as the dependencies in `package.json`, `pubspec.yaml`, `requirements*.txt` and `pyproject.toml`, `firebase.json` and `wrangler.toml`, including monorepo subfolders.

### Picking languages

`--lang js,py` scans only files in those languages (names such as `js`, `ts`, `javascript/typescript`, `py`, `flutter`, `dart`, `go` and `kotlin` work).
`--lang` without a value lists the languages found with numbers; type your choice and press Enter (an empty answer means all).

```
見る言語を選んでください（番号か名前をカンマ区切りで。空のまま Enter ですべて）:
  1) Dart/Flutter  211 ファイル  5 ルール
  2) JavaScript/TypeScript  211 ファイル  17 ルール
> 1
```

Outside a terminal (CI, agents) you cannot pick by number, so pass a value.
`--lang` only drops code files in the languages you did not pick. Files without a language (`AndroidManifest.xml`, `Info.plist`, `firestore.rules`, `.env`, `package.json` and so on) and configuration languages (YAML, Dockerfile) are always scanned, so the Android, iOS and Firebase rules still apply with `--lang flutter`. The committed-`.env` check and `--deps` look at the whole repository. An empty answer to the numbered list is the same as no `--lang`.

## Using it from an agent

[skills/vulnscan/SKILL.md](skills/vulnscan/SKILL.md) is a playbook (in Japanese) for letting Claude Code or another agent use vulnscan.
The agent runs vulnscan, reads the code behind each finding to sort real issues from false positives,
then reads what vulnscan cannot see — languages without rules, and things a regex cannot catch (authorization, other users' data, SSRF and so on) —
with the [checklists](skills/vulnscan/references/checklists.md), and reports. It does not change any files while checking. When only a branch or PR is checked, it also reads the changed code itself.

Install it for Claude Code (run this in the cloned vulnscan folder):

```sh
ln -s "$(pwd)/skills/vulnscan" ~/.claude/skills/vulnscan
```

Then ask "check this repository with vulnscan" or "run a security check before release". For other agents, have them read SKILL.md first.

The JSON that agents read (`--format json`) declares its shape with `schema_version` (currently 1).

| Key | Contents |
|---|---|
| `summary` | counts per severity |
| `languages` | `[{language, label, files, rules}]`; `rules` is the number of rules for that language only |
| `frameworks` | `[{id, label, evidence}]`; `evidence` is the marker file that identified it |
| `findings` | `[{rule, title, severity, category, path, line, column, evidence, message, remediation, cwe, owasp, fingerprint}]`; `evidence` is masked |
| `warnings` | mistakes in `.vulnscanignore` and the like |
| `stats` | `files_scanned`, `files_skipped`, `skipped_reasons`, `suppressed`, `git`, `deps_enabled` and more |

The `files` in `languages` add up to less than `files_scanned`, because Markdown, JSON, XML and similar files are not counted as a language.

## Reducing false positives

### 1. `.vulnscanignore`

Put it at the project root.

```
# rule ID  path glob  # reason (optional)
SEC-013     legacy/**              # move to environment variables by 2026-12-31
XSS-001     components/JsonLd.tsx  # static JSON-LD only
*           vendor/**              # third-party vendor code
```

Add `expires=2026-12-31` to make a line expire. A line with a malformed date (such as `2026/12/31`) or extra words is not used, so that it cannot become a suppression with no expiry; it is listed under the notes (注意) in the report.

```
SEC-013  scripts/seed.js  expires=2026-12-31  # fixed password for the demo
```

### 2. Baseline

When you know the current findings and only want to stop new ones, use a baseline.

```sh
./vulnscan baseline .
./vulnscan scan . --baseline .vulnscan-baseline.json --fail-on medium
```

Findings are matched by fingerprint (rule ID + path + the content of the line), so a finding that moves to another line stays suppressed. If more identical lines appear in the same file, the extra ones are reported as new findings.

## Using it in CI

Example `.github/workflows/vulnscan.yml`:

```yaml
name: vulnscan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # needed for the --base diff
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install vulnscan
        run: python -m pip install -e ./vulnscan
      - name: Scan
        # only the PR's changes; drop --base to scan everything
        run: vulnscan scan . --base "origin/$GITHUB_BASE_REF" --format sarif -o vulnscan.sarif --fail-on high
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vulnscan.sarif
```

A copy of vulnscan at `./vulnscan` (its rule regexes and tests) is left out of the scan automatically.
If the `--base` diff cannot be taken (a wrong branch name, a shallow `fetch-depth` and so on), vulnscan stops with exit code 2 instead of passing with 0 files.

For pre-commit:

```yaml
- repo: local
  hooks:
    - id: vulnscan
      name: vulnscan
      entry: ./vulnscan/vulnscan scan . --changed --fail-on high
      language: system
      pass_filenames: false
```

## Using it safely

- Secrets it finds are **masked by default** (shown like `AKIA…AB`). Secrets on an evidence line are masked in every finding, whichever rule reported it. Values shorter than 12 characters are fully masked; values shorter than 20 show only their first 2 characters.
- Add `--reveal-secrets` only when you need the full value. Keep in mind that it stays in your terminal history and in reports.
- Only with `--deps` do `npm` / `pnpm` / `yarn` / `pip-audit` / `composer` query their registries.
- With `--deps`, a missing tool (DEP-010) or a failed audit (DEP-011) is reported as high, so a project that was not checked never passes.
- `--deps` runs the audit tools inside the target repository. yarn's `yarn-path` and composer plugins are not loaded, but pip-audit installs the dependencies into a temporary environment to resolve them, so package build steps may run. **Do not use `--deps` on repositories you do not maintain.**
- Targets are local paths. There is no option to pass a URL.

## Limitations

- It is regex-based static analysis without data-flow analysis, so **there are false positives and missed issues**.
- It never attacks a running app. Cover authorization logic and the actual configuration with code review and by checking the running app.
- Binaries, files over 1.5 MB and the contents of lockfiles are not scanned (change the size limit with `--max-file-size`).
- `--deps` audits `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` (Yarn 1) / `requirements.txt` / `composer.lock` with their own audit tools, and `pubspec.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `bun.lock` and others with `osv-scanner` (including those in subfolders and those excluded by `.gitignore`; `--exclude` applies; findings for lockfiles in test folders are low). Without `osv-scanner`, those lockfiles are reported as DEP-010 (high), like any other missing audit tool. `bun.lockb` cannot be read by any tool, so it is only reported as not checked (DEP-012, low). The handling of `osv-scanner`'s output follows its official documentation and has not yet been checked against real output.
- SEC-013 (hard-coded passwords) looks at names that end with `password`, `secret`, `secret_key`, `api_key`, `access_token` and the like (including `SMTP_PASSWORD`, `dbPassword` and `'X-Api-Key'`) assigned an ASCII value without spaces in quotes or backticks (so that UI text is not reported). Assignments are `=`, `:` and Go's `:=`; `=>` only after a quoted name or a Ruby symbol. `.env`-style files are left to SEC-016 (which also reads commented-out lines, trailing comments and `_PWD`), and translation files (JSON, YAML, PHP and the like under `lang/`, `locales/`, `i18n/` and similar folders) are not scanned.
  - These values are not treated as secrets (other values on the same line are still checked): references (`process.env`, `${…}`, a whole value of `"$VAR"`), placeholders (`changeme`, `your-…`, `<…>`, `__…`, `xxxxxx`), URLs (unless they contain `user:pass@`), `env()`, lowercase paths, i18n keys (`auth.password.label`), uppercase identifiers made only of letters and `_`, values made only of lowercase words (`"local-test-key"`), camelCase or `/`-separated values that name a credential (`'newPassword'`, `'auth/RESET_PASSWORD'`), letters-only values on names with a prefix (`"showPassword": "Anzeigen"`), Laravel validation rules, bcrypt hashes, values meant to be public (Turnstile's test secret, RevenueCat public keys), and tokens that other rules (SEC-002 and SEC-005 to SEC-011) already report, so they are not counted twice. As a result, weak passwords made only of lowercase words (`"my-super-secret"`) and letters-only passwords on names with a prefix (`DB_PASSWORD = "topsecret"`) are not reported (the same value is reported when the name is exactly `password`).
  - Values that are not treated as secrets are still masked in the evidence of other findings. Because more names are matched now, more values are masked, and other findings on those lines get a new fingerprint once (regenerate your baseline if you use one).
- INJ-009 (SQL built in JS) looks at `query`, `execute` and `raw`, and at the sqlite3, better-sqlite3 and Prisma calls `all`, `get`, `run`, `each`, `exec`, `prepare`, `$queryRawUnsafe` and `$executeRawUnsafe` (TypeScript type arguments such as `<User[]>` too). In every case it only reports where a value is joined: inside SQL `'…'` (including `\'`), or `${}` and concatenation right after `=`, `<`, `>`, `LIKE`, `ILIKE`, `GLOB` or `REGEXP`. `"…"` counts only right after a comparison, because Postgres also uses it for identifiers. For concatenation it checks every string in `"…" + expression + "…"` (it stops at an expression that contains quotes). It also looks inside nested templates (`${cond ? `AND id = ${id}` : ''}`). The sqlite3, better-sqlite3 and Prisma calls are only checked when the string starts with an SQL verb. Building column lists, `WHERE` clauses or `IN (?, ?)` while binding the values is not reported. Findings in test files are low.
- The `.env` at the root is read even when it is gitignored, to check exposure such as `NEXT_PUBLIC_` (its contents are never sent anywhere). `.env` files in subfolders are read only when they are committed or not excluded by `.gitignore`.
- Findings are a starting point for review. Always fix them together with tests.

## Adding a rule

Add it to `src/vulnscan/rules/code.py`. Write the messages in Japanese, like the other rules.

```python
LineRule(
    id="INJ-999",
    title="危険な関数の使用",
    severity=Severity.HIGH,
    category="injection",
    pattern=r"\bdangerous_function\s*\(",
    languages=("python",),
    message="外部入力が渡ると任意コード実行になります。",
    remediation="安全な代替関数を使ってください。",
    cwe="CWE-78",
),
```

`languages` takes `python` / `javascript` / `php` / `ruby` / `go` / `java` / `docker` / `yaml` and others.
`multiline=True` matches across lines, and `require_file` / `require_line` narrow down when the rule applies.

## Development

In the vulnscan folder:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Layout:

```
vulnscan/
├── vulnscan              # wrapper that needs no install
├── src/vulnscan/
│   ├── cli.py            # command line
│   ├── engine.py         # runs the scan
│   ├── files.py          # lists files (respects .gitignore)
│   ├── ignore.py         # suppression list / baseline
│   ├── report.py         # text / Markdown / JSON / SARIF
│   └── rules/            # detection rules
├── skills/vulnscan/      # playbook and checklists for agents (Japanese)
├── tests/
└── scripts/scan-all.sh   # scans every project next to the vulnscan folder
```

## License

MIT
