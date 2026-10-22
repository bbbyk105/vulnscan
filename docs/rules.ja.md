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

## INJ-018〜INJ-022: Ruby・PHP・Java/Kotlin・C#・Rust での SQL の組み立て

INJ-009 と同じく、**値をつなぐ所だけを出します**。SQL の `'…'` の中と、`=`・`<`・`>`・`LIKE`・`ILIKE`・`GLOB`・`REGEXP` の直後です。連結は、`"…" + 式 + "…"` と続く文字列のどれかが値の位置で終わるものを見ます（間の式に引用符があるとその先は見ません）。

**出さないもの**:

- 列・テーブルの名前をつなぐ所（`"#{table}.id"`・`"FROM " + table`）。比べる演算子の直後でも、後ろに `.列名` が続くもの（`= #{table_name}.id`・`= {$wpdb->postmeta}.post_id`）は、テーブルで修飾した列名と見て出しません
- 引用符も演算子も無い値の位置（`IN (#{ids})`・`LIMIT #{n}`）と、`SET` の右辺の列名（`#{col} = #{col} + 1`）。レビューで読んでください
- マイグレーション（`db/migrate/`・`db/post_migrate/`・`database/migrations/`・`db/migration/`・`Migrations/` のフォルダ。`DataMigrations/` のように名前の最後が同じだけのフォルダは見る）

テストのファイルの指摘は「低」です。

| ルール | 見る呼び方 | つなぎ方 |
|---|---|---|
| INJ-018（Ruby） | `where`・`having`・`find_by`・`find_by_sql`・`joins`・`update_all`（受け手の無い `where(…)` も）、受け手のある `execute`・`exec_query`・`select_all` など（Capistrano・Chef の `execute "…"` は見ない）、`where.not` | `#{}`、`+`。配列で書いた条件 `where(["…"])` も見る。定数の `#{WORK_MEM}` と、全体を整数にした `#{params[:id].to_i}` は出さない。引用符を付ける `connection.quote`・配列を渡した `sanitize_sql([…])` は比べる演算子の直後だけ、引用符を付けない `quote_string` は SQL の `'…'` の中だけで出さない。`sanitize_sql_like`（`%` と `_` だけ）と文字列を渡した `sanitize_sql` は出す |
| INJ-019（PHP） | `whereRaw`・`selectRaw`・`orderByRaw` など、`DB::select`・`DB::statement` など、`$wpdb->query`・`get_results` など（`$this->wpdb->` も）、`mysqli_query`・`pg_query`。PDO の `->query`・`exec`・`prepare` は、文字列が SQL の動詞で始まるものだけ | `"…$x"`・`"…{$x}"`、`.`。`(int)`・`intval`・`absint` を通したものは出さない。引用符を付ける `$pdo->quote`・`$this->db->escape` は比べる演算子の直後だけ、`esc_sql`・`mysqli_real_escape_string` は SQL の `'…'` の中だけで出さない |
| INJ-020（Java/Kotlin/Scala） | `executeQuery`・`execute`・`prepareStatement`・`createQuery`・`createNativeQuery`・`rawQuery`・`execSQL`、JdbcTemplate の `query`・`update` など。Android の SQLiteDatabase の `update`・`delete`・`query` の where 句（`db.delete("users", "id = " + id, null)`。受け手が `db`・`mDb`・`database`・`writableDatabase`・`getWritableDatabase()` など、名前が db か database で終わるもの） | `+`、Kotlin の `$x`・`${x}`、Scala の `s"…$x"` |
| INJ-021（C#） | EF Core の `FromSqlRaw`・`ExecuteSqlRaw`・`SqlQueryRaw`、Dapper の `Query`・`Execute` など（型引数 `<User>`・`<(int, string)>` と名前付きの引数 `sql:` も）、`new SqlCommand(…)` などのコマンド、`CommandText =`（オブジェクト初期化子の中も） | `$"…{x}"`、`+`、`string.Format` |
| INJ-022（Rust） | sqlx の `query`・`query_as`（`::<_, (i64,)>` も）、diesel の `sql_query`、rusqlite・tokio-postgres の `execute`・`query` など | `format!` |

INJ-020〜022 は、文字列が SQL の文（`SELECT`・`INSERT`・`UPDATE`・`DELETE`・`WITH`、JPQL の `FROM` など）で始まるものだけを出します（Android の where 句は除く）。SQL の文字列をその場に書いたものだけを見ます。先に変数に入れた SQL（`String sql = "…" + name;` のあとの `executeQuery(sql)`）と、Kotlin・C# の `"""…"""`、Rust の `r#"…"#` は見ません。

## シェルスクリプト

`.sh`・`.bash`・`.zsh`・`.fish` のファイルを、1 行ずつ見ます。拡張子の無いスクリプト（`#!/bin/sh` で始まるものも）、Dockerfile の `RUN`、GitHub Actions の `run:` は見ません。行末の `\` で次の行に続けたコマンドはつなげて読みません（CFG-018 の `if` の条件だけはつなげて読みます）。fish の単一引用符の中の `\'` も扱いません。

照合の前に、各行からシェルが実行しない所を消します。

- コメント: 語の頭の `#` からあと（`$#`・`${x#…}`・URL の中の `#` は残す）
- 表示するだけのコマンドに渡した、引用符の中の文字: `echo`・`printf`・`print`・`say`・`usage`・`die`・`fail`・`abort`・`fatal`・`log`・`info`・`warn`・`warning`・`error`・`err`・`debug`・`msg`・`note`・`notice`・`success` と、それらの前に `log_`・`print_`・`echo_`、後ろに `_msg` を付けた名前（`log_info`・`print_error`・`warn_msg`）。`log_exec` のように引数を実行するヘルパーは含めません。中の `$(…)` は実行されるので残す。端末への表示には `>&2`・`> /dev/null` も含む。
- データとして読むコマンドに渡したヒアドキュメントの本文（`cat <<EOF`）。`sh`・`bash`・`zsh`・`ssh`・`su`・`python`・`perl`・`ruby`・`node`・`php` に渡したものはコマンドとして読む。

出力を表示する以外に使うものは消しません。ファイルに書くもの（`echo "StrictHostKeyChecking no" >> "$SSH_CONFIG"`）、パイプでほかのコマンドに渡すもの（`echo "…" | sh`・`| sudo tee`）、`$(…)` で受け取るものです。まとめた出力をファイル・パイプに渡すもの（`{ …; } >> cfg`・`for …; done >> cfg`・`if …; fi | sh`。複数行も）と、`exec >> file` のあとの行も同じです。ほかのコマンドの引用符の中はそのまま読みます（`STATUS="$(curl -sk …)"`・`git -c "http.sslVerify=false"`）。

- **INJ-016（中）ダウンロードしたスクリプトをそのまま実行**: `curl`・`wget` の出力を `sh`・`bash`・`zsh`・`python`・`perl`・`ruby`・`node`・`php`・fish の `source` に渡すもの。`/bin/bash`・`/usr/bin/env -i bash`・`sudo`・`doas`・`|&`・`2>&1`、間にほかのコマンドを挟んだもの（`| gunzip | sh`・`| tr -d '\r' | bash`・`| sudo tee x | bash`）も含みます。`bash <(curl …)`・`bash -s stable < <(curl …)`・`bash <<< "$(curl …)"`・`source <(curl …)`・`bash -c "$(curl …)"`・`bash -e -c "$(curl …)"`・`eval "$(curl …)"` と、それらのバッククォートの形も出します。出さないもの:
  - 渡した先にスクリプトか `-c`・`-e`・`-r` を付けたもの（`bash -e -c` のようにほかのオプションのあとも）。取ってきたものをデータとして読むだけなので（`python3 -c 'import json…'`・`bash ./parse.sh`）
  - ファイルに保存してからあとで実行するもの
- **INJ-017（中）引数を `eval`・`sh -c` に渡す**: 引数をそのまま渡すものだけです（`eval "$@"`・`eval $1`・`bash -c "$1"`・`eval "$1=$2"`・`eval "$1=\"$2\""`）。出さないもの:
  - `eval "$(ssh-agent -s)"` と、ほかの変数の `eval`
  - 値を名前で渡す `eval "$1=\$value"`
  - 単一引用符の中の引数（`eval '$@'`。値がコマンドとして読み直されない）
- **TLS-010（高）証明書の検証の無効化**: `curl -k`・`--insecure`（`-sk` のようにまとめたものも）、`wget --no-check-certificate`、`pip --trusted-host`、git の `http.sslVerify` を `false`・`no`・`off`・`0` にするもの（大文字小文字を問わず、URL ごとの `http.<url>.sslVerify` も）、`GIT_SSL_NO_VERIFY=`（git は値に関係なく検証しない）、npm・yarn・pnpm の `strict-ssl false`。宛先の URL がどれも `localhost`・`127.0.0.1`・`0.0.0.0`・`[::1]` で、引数（引用符の中も）に変数・`$(…)`・バッククォートの無い `curl`・`wget` は出しません。その名前で始まるだけのホスト（`localhost.example`）と、その名前がユーザー名の部分にあるもの（`localhost:pw@example.com` のつなぐ先は example.com）は手元と見ません。テストのファイルの指摘は「低」です。
- **TLS-011（中）SSH のホスト鍵を確かめない**: `StrictHostKeyChecking=no`・`off`・`false`（`-oStrictHostKeyChecking=no` と続けて書いたものも）。`accept-new` は出しません。
- **CFG-017（中）誰でも書き込める権限**: `chmod`・`mkdir -m`・`mkdir --mode=`・`install -m` に渡した、ほかのユーザーが書き込めるモード（`777`・`666`・`66`・`2777`・`"777"`・`o+w`・`a+w`）と `umask 000`。出さないもの: sticky ビットつきの `1777`（`/tmp` のような共有の置き場）、`g+w`、`+w`、ほかの人の書き込みを外す指定も含む記号のモード（`a+rw,o-w`）。
- **CFG-018（低）`/` を消しうる `rm -r`**: 変数のあとが `/` か `/*` だけのもの（`"$DIR/"*`・`"$DIR"/`・`$1/`）。変数が空だと `/` になります。コマンドの頭の `rm` を見ます（`if`・`!`・`sudo -E`・`sudo -u user`・`doas`・`$SUDO`・`\rm` のあとも）。出さないもの:
  - `"${DIR:?}/"*` と、変数のあとにパスが続くもの（`"$DIR/build"`）
  - サブコマンドの `rm`（`git rm`・`aws s3 rm`）
  - rm より前で、空なら止める形で確かめている変数。迷いようのない形だけを数えます。確かめるのは変数そのもので（`"$DIR/bin"`・`"${DIR:-x}"` は数えない）、同じ確かめの中にほかの条件（かっこの中の `-o`・`-a`・`&&`・`||`）が無いもの。`[ ]`・`test` の `-n`・`-d`・`-e` は引用符が要る（`[ -n $DIR ]` は DIR が空だと `[ -n ]` になり、いつも真）。ほかのコマンドに渡す文字列の中（`ssh host '[ -n "$D" ] || exit'`）と `$(…)` の中の確かめは数えません。数える形:
    - 同じ行: `[ -n "$DIR" ] && rm …`・`[ -z "$DIR" ] || rm …`（間に `;`・`&`、`&&` のあとの `||`・`||` のあとの `&&` が無いもの）、`if [ -n "$DIR" ]; then … rm …`（`else`・`elif`・`fi` より前）
    - ブロックの中: 行の頭から書いた `if [ -n "$DIR" ]`（`-d` も。条件に `||` が無いもの。行末の `\` で続けた条件も読む）の `then` の枝の行の rm、`[ -n "$DIR" ] && {` … `}` の中の rm
    - ファイルの最後まで。ただし一番外側（関数・`if`・`case`・ループ・`( … )`・`{ … }` の外。複数行のものも）で、同じ行のそれより前に条件が無いものだけ:
      - `${DIR:?}`・`${DIR:=既定値}`（`: "${DIR:?}"`・`DIR=${1:?}`）
      - `[ -n "$DIR" ] || exit`・`[ -z "$DIR" ] && exit`（`{ …; exit 1; }` も）・`[ -z "$DIR" ] && DIR=値`
      - 行の頭から書いた `if [ -z "$DIR" ]`（`elif` でなく、条件に `&&` が無いもの）の `then` の枝で、入れ子の条件の外で `exit` するか、`DIR` に空にならない値を入れるもの

    `exit` の代わりに、同じファイルで条件を挟まずに exit するように定義した関数（`die() { echo "$*" >&2; exit 1; }`）も数えます。そういう定義の無い `die`・`fail`・`usage` は exit しないかもしれないので数えません。`return` も数えません（スクリプトの一番外側では、bash はエラーを出して先に進む）。

    確かめが効くのは、その変数を入れ直すまでです（`DIR=…`・`read DIR`・`local DIR`・`unset DIR`・`for DIR in`、`$1` は `shift`・`set --`）。一番外側で確かめた `$1` は、関数の中の `$1`（関数の引数）には効きません。関数やブロックの中の確かめは追わないので、関数の中で確かめてから消すものは「低」で出ます。rm の中で `"${DIR:?}/"*` と書いてください。
  - rm を実行する時点で空にならない変数。rm より前の 1 行に単独で、空にならない値を 1 回だけ入れたもの。値は `/` と `.` 以外の固定の文字を含むもの（`OUT="$ROOT/dist"`。`"$PREFIX/"` は含まない）か、そういう既定値のもの（`${X:-既定値}`）。その行は `if`・`case`・ループ・関数・`( … )`・`{ … }`・ヒアドキュメントの外にあり、ファイルのほかの所で入れ直し・読み込み（`read`・`IFS= read`・`for`・`select`・`printf -v`）・空にする（`unset`・`local`）をしていないもの。代入と rm の間で、ほかのファイルを読み込んで（`.`・`source`）いないもの。

  CFG-018 は `.fish` のファイルを見ません（`if … end`・`and`・`or` を読めないため）。

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
