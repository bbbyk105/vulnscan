[English](README.md) | **日本語**

# vulnscan

[![Release](https://img.shields.io/github/v/release/bbbyk105/vulnscan)](https://github.com/bbbyk105/vulnscan/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)

自分が管理しているリポジトリの、秘密の置き忘れと危ない書き方を探す、読み取り専用の静的解析 CLI です。

- **読み取り専用** — 対象のファイルを変えません
- **ローカル完結** — 既定ではネットワークに接続しません
- **依存ゼロ** — Python 3.9 以上の標準ライブラリだけで動きます
- **日本語レポート** — 何が危ないのか、どう直すのかまで出します

> [!IMPORTANT]
> 自分が管理しているリポジトリを調べるためのものです。外部ホストへの攻撃、ポートスキャン、認証情報の窃取、マルウェアの生成はしません。

**目次**: [クイックスタート](#クイックスタート) · [主なコマンド](#主なコマンド) · [何を検査するか](#何を検査するか) · [言語を選ぶ](#言語を選ぶ) · [エージェントから使う](#エージェントから使う) · [誤検知を減らす](#誤検知を減らす) · [CI に組み込む](#ci-に組み込む) · [安全な使い方](#安全な使い方) · [限界](#限界) · [開発](#開発)

## クイックスタート

```sh
git clone https://github.com/bbbyk105/vulnscan.git
cd vulnscan
./vulnscan scan /path/to/your-app     # インストール不要
```

`vulnscan` コマンドとして使うなら `python3 -m pip install -e .` を流します。

出力例:

```
vulnscan 0.3.0 — /path/to/your-app
2026-10-21 19:18 · 84 ファイル · 92 ルール · 0.11 秒

合計 2 件（中 2）

■ 中 (2)

  XSS-001  dangerouslySetInnerHTML の使用
    components/JsonLd.tsx:14
    └ dangerouslySetInnerHTML={{ __html: JSON.stringify(graph) }}
    理由: HTML を直接挿入しています。値がユーザー入力なら XSS になります。
    修正: DOMPurify などでサニタイズするか、テキストとして描画してください。
    クロスサイトスクリプティング / CWE-79 / A03:2021
```

## 主なコマンド

| やりたいこと | コマンド |
|---|---|
| フォルダを調べる | `./vulnscan scan <path>` |
| レポートを保存する | `--format md -o report.md` · `--format json -o vulnscan.json` · `--format sarif -o vulnscan.sarif`（GitHub Code Scanning 用） |
| 絞る | `--min-severity medium` · `--category secret --category injection` |
| 依存の既知の CVE も調べる（ネットワークを使う） | `--deps` |
| コミットしていない変更だけ（pre-commit 用） | `--changed --fail-on high` |
| PR の差分だけ（CI 用） | `--base origin/main --fail-on high` |
| 言語を選ぶ | `--lang js,py`、または `--lang` だけで一覧から選ぶ |
| 言語とフレームワークを見分けるだけ（スキャンしない） | `./vulnscan detect .`（JSON は `--json`） |
| ルールを見る | `./vulnscan rules` · `./vulnscan explain SEC-013` |

`--fail-on` を付けたときの終了コード: `0` 合格、`1` 閾値以上の指摘あり、`2` エラー。

## 何を検査するか

| カテゴリ | 例 |
|---|---|
| 秘密情報の露出 | AWS / Stripe / GitHub トークン、秘密鍵、YAML・`.env` 形式に平文で書いた値、`.env` のコミット（サブフォルダも）、クライアントに露出する環境変数 |
| インジェクション | `eval`、`shell=True`、SQL の文字列連結、`pickle` / `yaml.load`、PHP の `unserialize` |
| XSS | `dangerouslySetInnerHTML`、`innerHTML`、`v-html`、SVG の直接配信 |
| 暗号・乱数 | MD5 / SHA1、AES-ECB、トークン生成への `Math.random` / `random` |
| 認証・認可 | JWT の `alg: none`、`verify=False`、CORS ワイルドカード、CSRF 無効化 |
| 通信の安全性 | `rejectUnauthorized: false`、`InsecureSkipVerify`、`verify=False` |
| 設定ミス | `DEBUG=True`、Dockerfile の `ENV` に秘密情報、root 実行、`privileged: true` |
| CI/CD | GitHub Actions のスクリプトインジェクション、`pull_request_target` の危険な checkout |
| モバイル・Firebase | Dart の証明書の検証の無効化・平文の通信・SharedPreferences のトークン、Android の `usesCleartextTraffic`・`debuggable`、iOS の ATS の例外、Firestore / Storage のルールの `if true` |
| シェルスクリプト | `curl … \| sh`、`eval "$@"`、`curl -k`、`StrictHostKeyChecking=no`、`chmod 777`、`$DIR` が空のおそれがある `rm -rf "$DIR/"*` |
| 依存関係 | `npm` / `pnpm` / `yarn` / `pip-audit` / `composer` の監査、pub・Go・Cargo・Bundler・Poetry・uv などは `osv-scanner`（`--deps` 時） |

秘密のルール（19）はどの言語のファイルにも効きます。危ない書き方のルールは言語ごとです。

| 言語 | ルール | ほかに |
|---|---:|---|
| JavaScript/TypeScript | 17 | |
| Python | 12 | |
| PHP | 7 | |
| Go | 6 | |
| シェル | 6 | `.sh`・`.bash`・`.zsh`・`.fish` のファイル |
| Dart/Flutter | 5 | Android の manifest（2）・iOS の Info.plist（1）・Firebase のルール（3） |
| Ruby | 3 | |
| Java/Kotlin/Scala | 1 | |
| Swift・Rust・C/C++ など | 0 | 秘密の置き忘れだけを確認 |
| Dockerfile・YAML・GitHub Actions・.env | 2・2・2・1 | |

レポートの最後に、見つかった言語と、見分けたフレームワークを出します（Next.js・Expo/React Native・Express・Hono・Supabase・Firebase・Flutter・Cloudflare Workers・Django・FastAPI・Flask・Rails・Laravel。`package.json`・`pubspec.yaml` などの目印のファイルから。monorepo のサブフォルダも見ます）。ルールの無い言語は、コードレビューか[エージェント](#エージェントから使う)で補ってください。いくつかのルールがどこまで検出するかは [docs/rules.ja.md](docs/rules.ja.md) にあります。

## 言語を選ぶ

`--lang js,py` で、その言語のファイルだけを見ます（`js`・`ts`・`py`・`flutter`・`dart`・`go`・`kotlin`・`sh` などの名前が使えます）。

端末で `--lang` だけを付けると、見つかった言語の一覧から選べます。

```
見る言語を選んでください:
↑↓ で動かす・スペースで選ぶ・a ですべて・Enter で決める（何も選ばずに Enter ですべて）・q でやめる
  [ ] JavaScript/TypeScript  3 ファイル  17 ルール
› [x] Python  1 ファイル  12 ルール
  [ ] Dart/Flutter  1 ファイル  5 ルール
```

| キー | すること |
|---|---|
| ↑ ↓（`k` `j` でも） | 動かす |
| スペース | 選ぶ・外す |
| `a` | すべてを選ぶ・外す |
| `1`〜`9` | その番号の行を選ぶ・外す |
| Enter | 選んだ言語で調べる（何も選ばなければすべて） |
| `q` か Esc | やめる |

端末でないとき（CI・エージェント）は、値を付けてください。1 文字ずつ読めない端末（Windows など）では、番号か名前を打って選びます。

`--lang` で外すのは、選ばなかった言語のコードのファイルだけです。言語の無いファイル（`AndroidManifest.xml`・`Info.plist`・`firestore.rules`・`.env`・`package.json` など）と設定のファイル（YAML・Dockerfile）はいつも見るので、`--lang flutter` でも Android・iOS・Firebase のルールが効きます。`.env` のコミットの確認と `--deps` はリポジトリ全体を見ます。

## エージェントから使う

[skills/vulnscan/SKILL.md](skills/vulnscan/SKILL.md) は、Claude Code などのエージェントに vulnscan を使わせるための手順書です。エージェントは:

1. vulnscan を流し、指摘ごとにコードを読んで本物か誤検知かを分け、
2. vulnscan が見ていない部分（言語のルールが無い部分と、認可・他人のデータ・SSRF など正規表現では見えない観点）を[チェックリスト](skills/vulnscan/references/checklists.md)に沿って読み、
3. ファイルを変えずに報告します。ブランチや PR の変更だけを見るときは、変わったコードそのものも読みます。

Claude Code に入れて（clone した vulnscan のフォルダで実行）、「vulnscan でこのリポジトリを見て」と頼みます。

```sh
ln -s "$(pwd)/skills/vulnscan" ~/.claude/skills/vulnscan
```

ほかのエージェントでは、SKILL.md を読ませてから頼んでください。

<details>
<summary>JSON の形（--format json、schema_version 1）</summary>

| キー | 中身 |
|---|---|
| `summary` | 重要度ごとの件数 |
| `languages` | `[{language, label, files, rules}]`。`rules` はその言語だけに効くルールの数 |
| `frameworks` | `[{id, label, evidence}]`。`evidence` は見分けた目印のファイル |
| `findings` | `[{rule, title, severity, category, path, line, column, evidence, message, remediation, cwe, owasp, fingerprint}]`。`evidence` はマスク済み |
| `warnings` | `.vulnscanignore` の書き間違いなど |
| `stats` | `files_scanned`・`files_skipped`・`skipped_reasons`・`suppressed`・`git`・`deps_enabled` など |

`languages` の `files` の合計は `files_scanned` より少なくなります（Markdown・JSON・XML などは言語に数えません）。

</details>

## 誤検知を減らす

**`.vulnscanignore`** をプロジェクト直下に置くと、ルールとパスで指摘を抑えられます。`expires=YYYY-MM-DD` を付けると期限付きになります。日付の書き方が違う行や余分な語がある行は使わず、レポートの「注意」に出します。

```
# ルールID  パスglob  # 理由（任意）
SEC-013     legacy/**              # 2026-12-31 までに環境変数へ移行
XSS-001     components/JsonLd.tsx  # 静的JSON-LDのみ
*           vendor/**              # 外部ベンダーコード
SEC-013     scripts/seed.js  expires=2026-12-31  # デモ用の固定パスワード
```

**ベースライン**は、今ある指摘を把握済みとして、新しく増えたものだけを止めます。

```sh
./vulnscan baseline .
./vulnscan scan . --baseline .vulnscan-baseline.json --fail-on medium
```

指摘の指紋（ルールID + パス + 該当行の内容）で照合するので、行が移動しても同じ指摘は抑えられます。同じファイルに同じ内容の行が増えた場合は、増えた分を新しい指摘として出します。

## CI に組み込む

vulnscan をリポジトリの `./vulnscan` に置きます。vulnscan 自身（ルールの正規表現やテスト）は走査の対象から自動で外します。`--base` の差分を取れないとき（ブランチ名の誤り、`fetch-depth` が浅いなど）は、0 ファイルで合格にせず終了コード 2 で止まります。

<details>
<summary>GitHub Actions（.github/workflows/vulnscan.yml）</summary>

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
          fetch-depth: 0   # --base で差分を取るため
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install vulnscan
        run: python -m pip install -e ./vulnscan
      - name: Scan
        # PR の差分だけを見る。全体を見るなら --base を外す
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

## 安全な使い方

- 見つけた秘密は**既定で伏せます**（`AKIA…AB` のように表示）。どのルールの指摘でも、証拠の行の秘密は伏せます。12 文字未満の値は全部を、20 文字未満の値は先頭 2 文字以外を伏せます。
- 全文を見たいときだけ `--reveal-secrets` を付けてください。ターミナルの履歴やレポートに残ります。
- ネットワークを使うのは `--deps` のときだけです（`npm` / `pnpm` / `yarn` / `pip-audit` / `composer` がレジストリに問い合わせます）。ツールが無い・失敗したときは「高」で出し、調べていないのに合格にはしません。
- `--deps` は対象のリポジトリの中で監査ツールを動かします。yarn の `yarn-path` と composer のプラグインは読み込まないようにしていますが、pip-audit は依存を一時環境に入れて解決するため、パッケージのビルド処理が動くことがあります。**自分が管理していないリポジトリには `--deps` を使わないでください。**
- 調べる対象はローカルのパスです。URL を渡す機能はありません。

## 限界

- 正規表現ベースの静的解析で、データの流れは追いません。**誤検知も検知漏れもあります**。検出結果は「レビューの入口」として扱い、直すときは必ずテストとセットにしてください。
- 動いているアプリへの攻撃はしません。認可のロジックの穴や設定の実態は、コードレビューと実際の動作の確認で補ってください。
- バイナリ、1.5MB を超えるファイル（`--max-file-size`）、lockfile の中身は走査しません。
- シェルスクリプトは 1 行ずつ検査します。拡張子の無いスクリプト、Dockerfile の `RUN`、GitHub Actions の `run:` は検査しません。CFG-018（`rm -rf "$DIR/"*`）は、関数の中で `$DIR` を確認していても考慮しません。
- SEC-013（ハードコードしたパスワード）・INJ-009（JS の SQL）・シェルスクリプトのルールがどこまで検出するか、`--deps` が lockfile ごとに何で監査するか、`.env` をどう読むかは [docs/rules.ja.md](docs/rules.ja.md) にあります。

## 開発

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

ルールを足すときは、`src/vulnscan/rules/code.py` に `LineRule` を足します。

<details>
<summary>ルールの例と構成</summary>

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

`languages` は `python` / `javascript` / `php` / `ruby` / `go` / `java` / `shell` / `docker` / `yaml` など。`multiline=True` で複数行にまたがって照合し、`shell_view=True` でシェルスクリプトのコメントと `echo` の文字列を照合から外し、`require_file` / `require_line` で前提条件を絞れます。

```
vulnscan/
├── vulnscan              # インストール不要のラッパー
├── src/vulnscan/
│   ├── cli.py            # コマンドライン
│   ├── engine.py         # スキャン実行
│   ├── files.py          # ファイル列挙（gitignore 尊重）
│   ├── ignore.py         # 抑制リスト / ベースライン
│   ├── picker.py         # --lang の言語の一覧
│   ├── report.py         # text / Markdown / JSON / SARIF
│   └── rules/            # 検出ルール
├── skills/vulnscan/      # エージェント向けの手順書とチェックリスト
├── docs/rules.ja.md      # ルールの細かい決まり
├── tests/
└── scripts/scan-all.sh   # vulnscan と同じ階層のプロジェクトをまとめてスキャン
```

</details>

## ライセンス

MIT
