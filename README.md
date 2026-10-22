**English** | [日本語](README.ja.md)

# vulnscan

[![Release](https://img.shields.io/github/v/release/bbbyk105/vulnscan)](https://github.com/bbbyk105/vulnscan/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)

A read-only static analysis CLI that finds leftover secrets and risky code in repositories you maintain.

- **Read-only** — never changes the files it scans
- **Local** — no network access by default
- **No dependencies** — runs on the Python 3.9+ standard library
- **Tells you how to fix it** — each finding says what is risky and how to fix it

> [!NOTE]
> **Reports are in Japanese.** The scan output, the rule messages and the agent skill (`skills/`) are written in Japanese. Rule IDs, paths, CWE and OWASP references are language-neutral, and `--format json` / `--format sarif` are easy to process in any language.

> [!IMPORTANT]
> vulnscan is for checking repositories you maintain. It does not attack external hosts, scan ports, steal credentials or generate malware.

**Contents**: [Quick start](#quick-start) · [Commands](#commands) · [What it checks](#what-it-checks) · [Picking languages](#picking-languages) · [Using it from an agent](#using-it-from-an-agent) · [Reducing false positives](#reducing-false-positives) · [Using it in CI](#using-it-in-ci) · [Using it safely](#using-it-safely) · [Limitations](#limitations) · [Development](#development)

## Quick start

```sh
git clone https://github.com/bbbyk105/vulnscan.git
cd vulnscan
./vulnscan scan /path/to/your-app     # no install needed
```

To use it as the `vulnscan` command, run `python3 -m pip install -e .`.

Example output (中 means medium):

```
vulnscan 0.2.0 — /path/to/your-app
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

| To | Run |
|---|---|
| Scan a folder | `./vulnscan scan <path>` |
| Save the report | `--format md -o report.md` · `--format json -o vulnscan.json` · `--format sarif -o vulnscan.sarif` (GitHub Code Scanning) |
| Filter | `--min-severity medium` · `--category secret --category injection` |
| Check dependencies for known CVEs (uses the network) | `--deps` |
| Scan only uncommitted changes (pre-commit) | `--changed --fail-on high` |
| Scan only a PR's changes (CI) | `--base origin/main --fail-on high` |
| Pick languages | `--lang js,py`, or `--lang` alone to choose from a list |
| Detect languages and frameworks without scanning | `./vulnscan detect .` (`--json` for JSON) |
| See the rules | `./vulnscan rules` · `./vulnscan explain SEC-013` |

Exit codes for CI with `--fail-on`: `0` pass, `1` findings at or above the threshold, `2` error.

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
| Mobile and Firebase | Dart certificate checks, cleartext traffic and tokens in SharedPreferences; Android `usesCleartextTraffic` and `debuggable`; iOS ATS exceptions; `if true` in Firestore / Storage rules |
| Shell scripts | `curl … \| sh`, `eval "$@"`, `curl -k`, `StrictHostKeyChecking=no`, `chmod 777`, `rm -rf "$DIR/"*` with a variable that may be empty |
| Dependencies | `npm` / `pnpm` / `yarn` / `pip-audit` / `composer` audits, and `osv-scanner` for pub, Go, Cargo, Bundler, Poetry, uv and others (with `--deps`) |

The 19 secret rules apply to files in every language. The rules for risky code are per language:

| Language | Rules | Also |
|---|---:|---|
| JavaScript/TypeScript | 17 | |
| Python | 12 | |
| PHP | 7 | |
| Go | 6 | |
| Shell | 6 | `.sh`, `.bash`, `.zsh` and `.fish` files |
| Dart/Flutter | 5 | Android manifest (2), iOS Info.plist (1), Firebase rules (3) |
| Ruby | 3 | |
| Java/Kotlin/Scala | 1 | |
| Swift, Rust, C/C++ and others | 0 | only checked for leftover secrets |
| Dockerfile, YAML, GitHub Actions, .env | 2, 2, 2, 1 | |

The report ends with the languages found and the frameworks detected (Next.js, Expo/React Native, Express, Hono, Supabase, Firebase, Flutter, Cloudflare Workers, Django, FastAPI, Flask, Rails and Laravel, from marker files such as `package.json` and `pubspec.yaml`, monorepo subfolders included). Cover languages without rules with a code review or the [agent skill](#using-it-from-an-agent). How some rules decide what to report is in [docs/rules.md](docs/rules.md).

## Picking languages

`--lang js,py` scans only files in those languages (`js`, `ts`, `py`, `flutter`, `dart`, `go`, `kotlin` and other names work).

Run `--lang` without a value in a terminal to choose from the languages found:

```
見る言語を選んでください:
↑↓ で動かす・スペースで選ぶ・a ですべて・Enter で決める（何も選ばずに Enter ですべて）・q でやめる
  [ ] JavaScript/TypeScript  3 ファイル  17 ルール
› [x] Python  1 ファイル  12 ルール
  [ ] Dart/Flutter  1 ファイル  5 ルール
```

| Key | Does |
|---|---|
| ↑ ↓ (or `k` `j`) | move |
| Space | select or unselect |
| `a` | select or unselect all |
| `1`–`9` | select or unselect that row |
| Enter | scan the selected languages (all of them if none is selected) |
| `q` or Esc | cancel |

Outside a terminal (CI, agents), pass a value. Where the terminal cannot read single keys (such as Windows), the list asks for numbers or names instead.

`--lang` only drops code files in the languages you did not pick. Files without a language (`AndroidManifest.xml`, `Info.plist`, `firestore.rules`, `.env`, `package.json` and so on) and configuration files (YAML, Dockerfile) are always scanned, so the Android, iOS and Firebase rules still apply with `--lang flutter`. The committed-`.env` check and `--deps` look at the whole repository.

## Using it from an agent

[skills/vulnscan/SKILL.md](skills/vulnscan/SKILL.md) is a playbook (in Japanese) for letting Claude Code or another agent use vulnscan. The agent:

1. runs vulnscan and reads the code behind each finding to sort real issues from false positives,
2. reads what vulnscan cannot see — languages without rules, and things a regex cannot catch (authorization, other users' data, SSRF and so on) — with the [checklists](skills/vulnscan/references/checklists.md),
3. reports, without changing any files. For a branch or PR, it also reads the changed code itself.

Install it for Claude Code (in the cloned vulnscan folder), then ask "check this repository with vulnscan":

```sh
ln -s "$(pwd)/skills/vulnscan" ~/.claude/skills/vulnscan
```

For other agents, have them read SKILL.md first.

<details>
<summary>JSON output (--format json, schema_version 1)</summary>

| Key | Contents |
|---|---|
| `summary` | counts per severity |
| `languages` | `[{language, label, files, rules}]`; `rules` is the number of rules for that language only |
| `frameworks` | `[{id, label, evidence}]`; `evidence` is the marker file that identified it |
| `findings` | `[{rule, title, severity, category, path, line, column, evidence, message, remediation, cwe, owasp, fingerprint}]`; `evidence` is masked |
| `warnings` | mistakes in `.vulnscanignore` and the like |
| `stats` | `files_scanned`, `files_skipped`, `skipped_reasons`, `suppressed`, `git`, `deps_enabled` and more |

The `files` in `languages` add up to less than `files_scanned`, because Markdown, JSON, XML and similar files are not counted as a language.

</details>

## Reducing false positives

**`.vulnscanignore`** at the project root suppresses findings by rule and path. Add `expires=YYYY-MM-DD` to make a line expire; a line with a malformed date or extra words is not used and is listed under the notes (注意) in the report.

```
# rule ID  path glob  # reason (optional)
SEC-013     legacy/**              # move to environment variables by 2026-12-31
XSS-001     components/JsonLd.tsx  # static JSON-LD only
*           vendor/**              # third-party vendor code
SEC-013     scripts/seed.js  expires=2026-12-31  # fixed password for the demo
```

**A baseline** keeps the findings you already know about and stops only new ones:

```sh
./vulnscan baseline .
./vulnscan scan . --baseline .vulnscan-baseline.json --fail-on medium
```

Findings are matched by fingerprint (rule ID + path + the content of the line), so a finding that moves to another line stays suppressed. Extra identical lines in the same file are reported as new.

## Using it in CI

Put vulnscan at `./vulnscan` in your repository; vulnscan leaves its own copy out of the scan. If the `--base` diff cannot be taken (a wrong branch name, a shallow `fetch-depth` and so on), it stops with exit code 2 instead of passing with 0 files.

<details>
<summary>GitHub Actions (.github/workflows/vulnscan.yml)</summary>

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

</details>

<details>
<summary>pre-commit</summary>

```yaml
- repo: local
  hooks:
    - id: vulnscan
      name: vulnscan
      entry: ./vulnscan/vulnscan scan . --changed --fail-on high
      language: system
      pass_filenames: false
```

</details>

## Using it safely

- Secrets are **masked by default** (shown like `AKIA…AB`), in every finding whichever rule reported it. Values shorter than 12 characters are fully masked; values shorter than 20 show only their first 2 characters.
- `--reveal-secrets` shows full values. It stays in your terminal history and in reports, so use it only when you need it.
- Only `--deps` uses the network: `npm` / `pnpm` / `yarn` / `pip-audit` / `composer` query their registries. A missing tool or a failed audit is reported as high, so a project that was not checked never passes.
- `--deps` runs audit tools inside the target repository. yarn's `yarn-path` and composer plugins are not loaded, but pip-audit installs the dependencies into a temporary environment, so package build steps may run. **Do not use `--deps` on repositories you do not maintain.**
- Targets are local paths. There is no option to pass a URL.

## Limitations

- It is regex-based static analysis without data-flow analysis, so **there are false positives and missed issues**. Treat findings as a starting point for review, and fix them together with tests.
- It never attacks a running app. Cover authorization logic and the actual configuration with code review and by checking the running app.
- Binaries, files over 1.5 MB (`--max-file-size`) and the contents of lockfiles are not scanned.
- Details on what SEC-013 (hard-coded passwords) and INJ-009 (SQL in JS) report, how `--deps` audits each lockfile, and how `.env` files are read: [docs/rules.md](docs/rules.md).

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

To add a rule, append a `LineRule` to `src/vulnscan/rules/code.py`. Write its messages in Japanese, like the other rules.

<details>
<summary>Example rule and layout</summary>

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

`languages` takes `python` / `javascript` / `php` / `ruby` / `go` / `java` / `docker` / `yaml` and others. `multiline=True` matches across lines, and `require_file` / `require_line` narrow down when the rule applies.

```
vulnscan/
├── vulnscan              # wrapper that needs no install
├── src/vulnscan/
│   ├── cli.py            # command line
│   ├── engine.py         # runs the scan
│   ├── files.py          # lists files (respects .gitignore)
│   ├── ignore.py         # suppression list / baseline
│   ├── picker.py         # the language list for --lang
│   ├── report.py         # text / Markdown / JSON / SARIF
│   └── rules/            # detection rules
├── skills/vulnscan/      # playbook and checklists for agents (Japanese)
├── docs/rules.md         # rule details
├── tests/
└── scripts/scan-all.sh   # scans every project next to the vulnscan folder
```

</details>

## License

MIT
