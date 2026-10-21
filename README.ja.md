[English](README.md) | **日本語**

# vulnscan

自分のコードの弱点を、自分で見つけるための静的解析CLIです。

- **読み取り専用** — 対象ファイルを変更しません
- **ローカル完結** — 既定ではネットワークに接続しません
- **依存ゼロ** — Python 3.9+ の標準ライブラリだけで動きます
- **日本語レポート** — 何が危ないのか、どう直すのかまで出力します

> このツールは、自分が管理しているリポジトリを調べるためのものです。
> 外部ホストへの攻撃、ポートスキャン、認証情報の窃取、マルウェア生成は行いません。

---

## クイックスタート

```sh
git clone https://github.com/bbbyk105/vulnscan.git
cd vulnscan

# そのまま実行（インストール不要）
./vulnscan scan /path/to/your-app

# インストールして使う場合
python3 -m pip install -e .
vulnscan scan .
```

出力例:

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

## 主なコマンド

```sh
# 基本
./vulnscan scan <path>

# Markdown / JSON / SARIF で保存
./vulnscan scan . --format md   -o security-report.md
./vulnscan scan . --format json -o vulnscan.json
./vulnscan scan . --format sarif -o vulnscan.sarif   # GitHub Code Scanning 用

# 重要度・カテゴリで絞る
./vulnscan scan . --min-severity medium
./vulnscan scan . --category secret --category injection

# 依存パッケージの既知CVEも調べる（ネットワーク使用）
./vulnscan scan . --deps

# コミットしていない変更ファイルだけ（pre-commit 用）
./vulnscan scan . --changed --fail-on high

# PR の差分だけ（CI 用。base との差分＋コミットしていない変更）
./vulnscan scan . --base origin/main --fail-on high

# 言語を選んで見る（js・ts・py・flutter・go など。カンマで複数）
./vulnscan scan . --lang js,py
./vulnscan scan . --lang            # 値を付けないと、見つかった言語から番号で選ぶ（端末のときだけ）

# 言語とフレームワークを見分けるだけ（スキャンはしない）
./vulnscan detect .
./vulnscan detect . --json

# ルール一覧と説明
./vulnscan rules
./vulnscan explain SEC-013

# CI 用の終了コード: 0=合格 / 1=閾値以上の指摘あり / 2=エラー
./vulnscan scan . --fail-on high
```

## 何を検査するか

| カテゴリ | 例 |
|---|---|
| 秘密情報の露出 | AWS / Stripe / GitHub トークン、秘密鍵、YAML・`.env` 形式に平文で書いた値、`.env` のコミット（サブフォルダも）、クライアント露出する環境変数 |
| インジェクション | `eval`、`shell=True`、SQL の文字列連結、`pickle` / `yaml.load`、PHP の `unserialize` |
| XSS | `dangerouslySetInnerHTML`、`innerHTML`、`v-html`、SVG の直接配信 |
| 暗号・乱数 | MD5 / SHA1、AES-ECB、トークン生成への `Math.random` / `random` |
| 認証・認可 | JWT の `alg: none`、`verify=False`、CORS ワイルドカード、CSRF 無効化 |
| 通信の安全性 | `rejectUnauthorized: false`、`InsecureSkipVerify`、`verify=False` |
| 設定ミス | `DEBUG=True`、Dockerfile の `ENV` に秘密情報、root 実行、`privileged: true` |
| CI/CD | GitHub Actions のスクリプトインジェクション、`pull_request_target` の危険な checkout |
| モバイル・Firebase | Dart の証明書の検証の無効化・平文の通信・SharedPreferences のトークン、Android の `usesCleartextTraffic`・`debuggable`、iOS の ATS の例外、Firestore / Storage のルールの `if true` |
| 依存関係 | `npm audit` / `pnpm audit` / `yarn audit` / `pip-audit` / `composer audit`、pub・Go・Cargo・Bundler・Poetry・uv などは `osv-scanner`（`--deps` 時。サブフォルダの lockfile も見る。監査できなかったときは「高」で出す） |

全ルールは `./vulnscan rules`、詳細は `./vulnscan explain <ID>` で確認できます。

### 言語ごとの守備範囲

秘密のルール（19）はどの言語のファイルにも効きます。危ない書き方のルールは言語ごとです。

| 言語 | ルール | ほかに |
|---|---:|---|
| JavaScript/TypeScript | 17 | |
| Python | 12 | |
| PHP | 7 | |
| Go | 6 | |
| Dart/Flutter | 5 | Android の manifest（2）・iOS の Info.plist（1）・Firebase のルール（3） |
| Ruby | 3 | |
| Java/Kotlin/Scala | 1 | |
| Swift・シェル・Rust・C/C++ など | 0 | |
| Dockerfile・YAML・GitHub Actions・.env | 2・2・2・1 | |

レポートの最後に、見つかった言語とその言語のルールの数、見分けたフレームワークを出します。0 個の言語は「秘密の置き忘れだけを確認」と出るので、その部分はコードレビューか、下の「エージェントから使う」で補ってください。

```
言語: Dart/Flutter 211（5 ルール）、JavaScript/TypeScript 211（17 ルール）、Swift 3（言語のルールなし。秘密の置き忘れだけを確認）
フレームワーク: Firebase（functions/package.json）、Flutter（app/pubspec.yaml）
```

見分けるフレームワーク: Next.js・Expo/React Native・Express・Hono・Supabase・Firebase・Flutter・Cloudflare Workers・Django・FastAPI・Flask・Rails・Laravel（`package.json` の依存、`pubspec.yaml`、`requirements*.txt`・`pyproject.toml`、`firebase.json`・`wrangler.toml` などの目印のファイルから。monorepo のサブフォルダも見ます）。

### 言語を選ぶ

`--lang js,py` で、その言語のファイルだけを見ます（`js`・`ts`・`javascript/typescript`・`py`・`flutter`・`dart`・`go`・`kotlin` などの名前が使えます）。
`--lang` だけで値を付けないと、見つかった言語を番号つきで出すので、選んで Enter を押します（空のまま Enter ですべて）。

```
見る言語を選んでください（番号か名前をカンマ区切りで。空のまま Enter ですべて）:
  1) Dart/Flutter  211 ファイル  5 ルール
  2) JavaScript/TypeScript  211 ファイル  17 ルール
> 1
```

端末でないとき（CI・エージェント）は番号では選べないので、値を付けてください。
`--lang` で外すのは、選ばなかった言語のコードのファイルだけです。言語の無いファイル（`AndroidManifest.xml`・`Info.plist`・`firestore.rules`・`.env`・`package.json` など）と設定の言語（YAML・Dockerfile）はいつも見るので、`--lang flutter` でも Android・iOS・Firebase のルールが効きます。`.env` のコミットの確認と `--deps` はリポジトリ全体を見ます。番号の一覧で空のまま Enter を押すと、`--lang` を付けないときと同じになります。

## エージェントから使う

[skills/vulnscan/SKILL.md](skills/vulnscan/SKILL.md) は、Claude Code などのエージェントに vulnscan を使わせるための手順書です。
エージェントは vulnscan を流したあと、指摘ごとにコードを読んで本物か誤検知かを分け、
言語のルールが無い部分と、正規表現では見えない観点（認可・他人のデータ・SSRF など）を
[チェックリスト](skills/vulnscan/references/checklists.md) に沿って読み、まとめて報告します。調べている間はファイルを変えません。

Claude Code に入れる（clone した vulnscan のフォルダで実行）:

```sh
ln -s "$(pwd)/skills/vulnscan" ~/.claude/skills/vulnscan
```

そのあと「vulnscan でこのリポジトリを見て」「公開前にセキュリティチェックして」と頼むと使われます。
ほかのエージェントでは、SKILL.md を読ませてから頼んでください。

エージェントが読む JSON（`--format json`）の形は `schema_version` で示します（いまは 1）。

| キー | 中身 |
|---|---|
| `summary` | 重要度ごとの件数 |
| `languages` | `[{language, label, files, rules}]`。`rules` はその言語だけに効くルールの数 |
| `frameworks` | `[{id, label, evidence}]`。`evidence` は見分けた目印のファイル |
| `findings` | `[{rule, title, severity, category, path, line, column, evidence, message, remediation, cwe, owasp, fingerprint}]`。`evidence` はマスク済み |
| `warnings` | `.vulnscanignore` の書き間違いなど |
| `stats` | `files_scanned`・`files_skipped`・`skipped_reasons`・`suppressed`・`git`・`deps_enabled` など |

`languages` の `files` の合計は `files_scanned` より少なくなります（Markdown・JSON・XML などは言語に数えません）。

## 誤検知を減らす

### 1. `.vulnscanignore`

プロジェクト直下に置きます。

```
# ルールID  パスglob  # 理由（任意）
SEC-013     legacy/**              # 2026-12-31 までに環境変数へ移行
XSS-001     components/JsonLd.tsx  # 静的JSON-LDのみ
*           vendor/**              # 外部ベンダーコード
```

`expires=2026-12-31` を付けると期限付きにできます。日付の書き方が違う行（`2026/12/31` など）や余分な語がある行は、期限なしで効いてしまわないよう使わず、レポートの「注意」に出します。

```
SEC-013  scripts/seed.js  expires=2026-12-31  # デモ用の固定パスワード
```

### 2. ベースライン

「今ある指摘は把握済み。新しく増えたものだけ止めたい」ときはベースラインを使います。

```sh
./vulnscan baseline .
./vulnscan scan . --baseline .vulnscan-baseline.json --fail-on medium
```

指摘の指紋（ルールID + パス + 該当行の内容）で照合するので、行が移動しても同じ指摘は抑制されます。同じファイルに同じ内容の行が増えた場合は、増えた分を新しい指摘として出します。

## CI に組み込む

`.github/workflows/vulnscan.yml` の例:

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

`./vulnscan` に置いた vulnscan 自身（ルールの正規表現やテスト）は、走査の対象から自動で外します。
`--base` の差分を取れないとき（ブランチ名の誤り、`fetch-depth` が浅いなど）は、0 ファイルで合格にせず終了コード 2 で止まります。

pre-commit なら:

```yaml
- repo: local
  hooks:
    - id: vulnscan
      name: vulnscan
      entry: ./vulnscan/vulnscan scan . --changed --fail-on high
      language: system
      pass_filenames: false
```

## 安全な使い方

- 検出した秘密情報は**既定でマスク**されます（`AKIA…AB` のように表示）。どのルールの指摘でも、証拠の行に含まれる秘密は全部伏せます。12 文字未満の値は全部を、20 文字未満の値は先頭 2 文字以外を伏せます。
- 全文を見たいときだけ `--reveal-secrets` を付けてください。ターミナル履歴やレポートに残る点に注意してください。
- `--deps` を付けたときだけ、`npm` / `pnpm` / `yarn` / `pip-audit` / `composer` がレジストリへ問い合わせます。
- `--deps` は、ツールが無い（DEP-010）・失敗した（DEP-011）ときも「高」の指摘として出し、調べていないのに合格にはしません。
- `--deps` は対象のリポジトリの中で監査ツールを動かします。yarn の `yarn-path` と composer のプラグインは読み込まないようにしていますが、pip-audit は依存を一時環境に入れて解決するため、パッケージのビルド処理が動くことがあります。**自分が管理していないリポジトリには `--deps` を使わないでください。**
- スキャン対象はローカルパスです。URL を渡す機能はありません。

## 限界

- 正規表現ベースの静的解析です。データフロー解析はしないため、**誤検知も検知漏れもあります**。
- 「動いているアプリへの攻撃」はしません。認可のロジック穴や設定の実態は、コードレビューや実際の動作確認で補ってください。
- バイナリ、1.5MB を超えるファイル、lockfile の中身は走査しません（`--max-file-size` で変更可）。
- `--deps` は、`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`（Yarn 1）/ `requirements.txt` / `composer.lock` をそれぞれの監査ツールで、`pubspec.lock`・`go.mod`・`Cargo.lock`・`Gemfile.lock`・`poetry.lock`・`Pipfile.lock`・`uv.lock`・`bun.lock` などを `osv-scanner` で調べます（サブフォルダのものと、`.gitignore` で除外したものも。`--exclude` は効きます。テスト用のフォルダの lockfile の指摘は「低」にします）。`osv-scanner` が無いときは、ほかの監査ツールが無いときと同じく DEP-010（高）です。`bun.lockb` はどのツールでも見られないので「調べていない」（DEP-012、低）と出すだけです。`osv-scanner` の出力の形は公式の説明に合わせて作ってあり、実物ではまだ確かめていません。
- SEC-013（ハードコードしたパスワード）は、名前が `password`・`secret`・`secret_key`・`api_key`・`access_token` などで終わるもの（`SMTP_PASSWORD`・`dbPassword`・`'X-Api-Key'` を含む）に、引用符かバッククォートで囲んだ、空白を含まない ASCII の値が直接入っているものを見ます（画面の文言を拾わないため）。代入は `=`・`:`・Go の `:=`、`=>` は引用符の名前と Ruby のシンボルだけです。`.env` 形式のファイルは SEC-016（コメントにした行・行末のコメント・`_PWD` も見ます）、翻訳のファイル（`lang/`・`locales/`・`i18n/` などの下の JSON・YAML・PHP など）は見ません。
  - 次の値は秘密と見なしません（同じ行のほかの値は見ます）: 参照（`process.env`・`${…}`・値の全体が `"$VAR"`）、仮の値（`changeme`・`your-…`・`<…>`・`__…`・`xxxxxx`）、URL（`user:pass@` の入ったものは見ます）・`env()`・小文字だけの道、i18n のキー（`auth.password.label`）、英字と `_` だけの大文字の識別子、小文字の単語だけの値（`"local-test-key"`）、camelCase か `/` で区切った名前を表す値（`'newPassword'`・`'auth/RESET_PASSWORD'`）、名前の前に言葉が付いたものの英字だけの値（`"showPassword": "Anzeigen"`）、Laravel の検証ルール、bcrypt のハッシュ、公開前提の値（Turnstile の試験用の秘密、RevenueCat の公開キー）、ほかのルール（SEC-002・005〜011）が見るトークンの形の値（二重に数えないため）。そのため、小文字の単語だけの弱いパスワード（`"my-super-secret"`）と、名前の前に言葉が付いたものの英字だけのパスワード（`DB_PASSWORD = "topsecret"`）は拾いません（名前がちょうど `password` なら、同じ値でも拾います）。
  - 秘密と見なさない値も、ほかのルールの証拠の中では伏せます。名前を広げたので伏せる値が増え、その行のほかの指摘は指紋が一度変わります（ベースラインを使っているなら作り直してください）。
- INJ-009（JS の SQL の組み立て）は、`query`・`execute`・`raw` と、sqlite3・better-sqlite3・Prisma の `all`・`get`・`run`・`each`・`exec`・`prepare`・`$queryRawUnsafe`・`$executeRawUnsafe` を見ます（TypeScript の型引数 `<User[]>` も）。どれも、値をつなぐ所だけです: SQL の `'…'` の中（`\'` を含む）、`=`・`<`・`>`・`LIKE`・`ILIKE`・`GLOB`・`REGEXP` の直後の `${}` や連結。`"…"` は Postgres の識別子でもあるので、比べる演算子の直後のものだけです。連結は `"…" + 式 + "…"` と続く文字列のどれかを見ます（間の式に引用符があるとその先は見ません）。入れ子のテンプレート（`${cond ? `AND id = ${id}` : ''}`）の中も見ます。後者の呼び方は、文字列が SQL の動詞で始まるものだけです。列の一覧・`WHERE`・`IN (?, ?)` を組み立てて値をバインドする書き方は対象外です。テストのファイルの指摘は「低」にします。
- 直下の `.env` は `.gitignore` されていても、`NEXT_PUBLIC_` などの露出チェックのために読みます（内容は外部送信しません）。サブフォルダの `.env` は、git に入っているものと `.gitignore` で除外されていないものだけを見ます。
- 検出結果は「レビューの入口」です。修正は必ずテストとセットで行ってください。

## ルールを追加する

`src/vulnscan/rules/code.py` に追記するだけです。

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

`languages` は `python` / `javascript` / `php` / `ruby` / `go` / `java` / `docker` / `yaml` など。
`multiline=True` で複数行、`require_file` / `require_line` で前提条件を絞れます。

## 開発

vulnscan のフォルダで:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

構成:

```
vulnscan/
├── vulnscan              # インストール不要のラッパー
├── src/vulnscan/
│   ├── cli.py            # コマンドライン
│   ├── engine.py         # スキャン実行
│   ├── files.py          # ファイル列挙（gitignore 尊重）
│   ├── ignore.py         # 抑制リスト / ベースライン
│   ├── report.py         # text / Markdown / JSON / SARIF
│   └── rules/            # 検出ルール
├── skills/vulnscan/      # エージェント向けの手順書とチェックリスト
├── tests/
└── scripts/scan-all.sh   # vulnscan と同じ階層のプロジェクトをまとめてスキャン
```

## ライセンス

MIT
