[English](rules.md) | **日本語**

# ルールの細かい決まり

いくつかのルールが、何を出して何を出さないか。ルールの一覧は `./vulnscan rules`、1 つの説明は `./vulnscan explain <ID>` で見られます。

## SEC-013: ハードコードしたパスワード・API キー

**出すもの**: 名前が `password`・`secret`・`secret_key`・`api_key`・`access_token` などで終わるもの（`SMTP_PASSWORD`・`dbPassword`・`'X-Api-Key'` を含む）に、引用符かバッククォートで囲んだ、空白を含まない ASCII の値が直接入っているもの。空白を含む値は、画面の文言を拾わないよう見ません。

- 代入は `=`・`:`・Go の `:=`。`=>` は引用符の名前と Ruby のシンボルだけ（矢印関数は見ない）。
- `.env` 形式のファイルは SEC-016 が見ます（コメントにした行・行末のコメント・`_PWD` も見ます）。
- 翻訳のファイル（`lang/`・`locales/`・`i18n/` などの下の JSON・YAML・PHP など）は見ません。

**秘密と見なさない値**（同じ行のほかの値は見ます）:

| 種類 | 例 |
|---|---|
| 参照 | `process.env`・`${…}`・値の全体が `"$VAR"` |
| 仮の値 | `changeme`・`your-…`・`<…>`・`__…`・`xxxxxx` |
| 場所 | URL（`user:pass@` の入ったものは見る）・`env()`・小文字だけの道 |
| 値ではなく名前 | i18n のキー（`auth.password.label`）、英字と `_` だけの大文字の識別子、camelCase か `/` で区切った名前を表す値（`'newPassword'`・`'auth/RESET_PASSWORD'`） |
| 単語 | 小文字の単語だけの値（`"local-test-key"`）、名前の前に言葉が付いたものの英字だけの値（`"showPassword": "Anzeigen"`） |
| ほかの形式 | Laravel の検証ルール、bcrypt のハッシュ |
| 公開前提の値 | Turnstile の試験用の秘密、RevenueCat の公開キー |
| ほかのルールが出すもの | SEC-002・005〜011 が見るトークンの形の値（二重に数えないため） |

そのため、小文字の単語だけの弱いパスワード（`"my-super-secret"`）と、名前の前に言葉が付いたものの英字だけのパスワード（`DB_PASSWORD = "topsecret"`）は拾いません。名前がちょうど `password` なら、同じ値でも拾います。

秘密と見なさない値も、ほかのルールの指摘の証拠の中では伏せます。伏せ方が変わると、その行のほかの指摘は指紋が一度変わります。ベースラインを使っているなら作り直してください。

## INJ-009: JavaScript/TypeScript での SQL の組み立て

**見る呼び方**: `query`・`execute`・`raw` と、sqlite3・better-sqlite3・Prisma の `all`・`get`・`run`・`each`・`exec`・`prepare`・`$queryRawUnsafe`・`$executeRawUnsafe`（TypeScript の型引数 `<User[]>` を付けたものも）。sqlite3・better-sqlite3・Prisma の呼び方は、文字列が SQL の動詞で始まるものだけを見ます（`router.get(...)` やキャッシュを拾わないため）。

**値をつなぐ所だけを出します**:

- SQL の `'…'` の中（`\'` を含む）
- `=`・`<`・`>`・`LIKE`・`ILIKE`・`GLOB`・`REGEXP` の直後の `${}` や連結
- `"…"` は、比べる演算子の直後のものだけ（Postgres では識別子にも使うため）

連結は `"…" + 式 + "…"` と続く文字列のどれかを見ます（間の式に引用符があるとその先は見ません）。入れ子のテンプレート（`` ${cond ? `AND id = ${id}` : ''} ``）の中も見ます。

**出さないもの**: 列の一覧・`WHERE`・`IN (?, ?)` を組み立てて値をバインドする書き方（Go の INJ-014 と同じ決まり）。外から受け取った列名・テーブル名・並べ方（`SET ${field}=?`・`ORDER BY ${sort}`）と、引用符も演算子も無い値の位置（`LIMIT ${n}`）も出さないので、レビューで読んでください。テストのファイルの指摘は「低」です。

## `--deps`: 依存の監査

| lockfile | 監査に使うもの |
|---|---|
| `package-lock.json`・`pnpm-lock.yaml`・`yarn.lock`（Yarn 1）・`requirements.txt`・`composer.lock` | それぞれの監査ツール |
| `pubspec.lock`・`go.mod`・`Cargo.lock`・`Gemfile.lock`・`poetry.lock`・`Pipfile.lock`・`uv.lock`・`bun.lock` など | `osv-scanner` |
| `bun.lockb` | どのツールでも見られない。「調べていない」と出すだけ（DEP-012、低） |

- サブフォルダの lockfile と、`.gitignore` で除外した lockfile も監査します（`--exclude` は効きます）。テスト用のフォルダの lockfile の指摘は「低」です。
- 監査ツールが無い（DEP-010）・失敗した（DEP-011）ときは「高」で出し、調べていないのに合格にはしません。`osv-scanner` が無いときも同じです。
- `osv-scanner` の出力の形は公式の説明に合わせて作ってあり、実物ではまだ確かめていません。

## `.env` のファイル

直下の `.env` は `.gitignore` されていても、`NEXT_PUBLIC_` などの露出チェックのために読みます（内容は外部送信しません）。サブフォルダの `.env` は、git に入っているものと `.gitignore` で除外されていないものだけを見ます。
