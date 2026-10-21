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
cd ~/Projects/vulnscan

# そのまま実行（インストール不要）
./vulnscan scan ~/Projects/portfolio2026-playground

# インストールして使う場合
python3 -m pip install -e .
vulnscan scan .
```

出力例:

```
vulnscan 0.1.0 — /Users/you/Projects/myapp
2026-10-21 19:18 · 84 ファイル · 70 ルール · 0.11 秒

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
| 依存関係 | `npm audit` / `pnpm audit` / `yarn audit` / `pip-audit` / `composer audit`（`--deps` 時。監査できなかったときは「高」で出す） |

全ルールは `./vulnscan rules`、詳細は `./vulnscan explain <ID>` で確認できます。

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
- `--deps` が調べるのは直下の `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`（Yarn 1）/ `requirements.txt` / `composer.lock` だけです。bun・Poetry・uv・Pipenv・Cargo・Go・Bundler の lockfile は「対象外」（DEP-012）と出すだけです。
- SEC-013（ハードコードしたパスワード）は、空白を含まない ASCII の値だけを見ます（画面の文言を拾わないため）。
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

```sh
cd ~/Projects/vulnscan
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
├── tests/
└── scripts/scan-all.sh   # Projects 配下をまとめてスキャン
```

## ライセンス

MIT
