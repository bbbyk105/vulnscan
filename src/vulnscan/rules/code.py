"""コードパターンの検出ルール（インジェクション / XSS / 暗号 / 認証 / TLS / 設定）。"""

from __future__ import annotations

from ..models import Severity
from .base import LineRule, shell_args

# INJ-009 で sqlite3・better-sqlite3・Prisma の呼び方を見るときの、SQL の頭の動詞
_SQL_START = r"(?:select|insert|update|delete|replace|with)\s"
# 値をつなぐ所の手前の、比べる演算子
_SQL_COMPARE = r"(?:[=<>]|\b(?:i?like|glob|regexp)\b)\s*"
# INJ-009 の、値をつなぐ所。' の中（エスケープした \' を含む）と、比べる演算子の直後。
# "…" は Postgres では識別子（"${table}"・列の一覧）なので、比べる演算子の直後のものだけを値と見る
_SQL_TEMPLATE_TAIL = r"(?:'[^'`]*|\\'[^'`\\]*|" + _SQL_COMPARE + r"(?:\"[^\"`]*|\\\"[^\"`\\]*)?)\$\{"
# ` の中を読み進める。閉じた引用符の組・${…}（中の入れ子のテンプレートを含む）・\ のエスケープを読み飛ばし、
# 開いたままの引用符だけを値の中と見る
_SQL_TEMPLATE_BODY = r"(?:[^`'\"$\\]|\\.|\$(?!\{)|'[^'`]*'|\"[^\"`]*\"|\$\{(?:[^{}`]|`[^`]*`)*\})*?"
_SQL_TEMPLATE_VALUE = (
    r"(?:" + _SQL_TEMPLATE_BODY + _SQL_TEMPLATE_TAIL
    # 入れ子のテンプレートの中の値（${cond ? `AND id = ${id}` : ''}・values.map((v) => `'${v}'`)）
    + r"|[^`]*`" + _SQL_TEMPLATE_BODY + _SQL_TEMPLATE_TAIL + r")"
)
# "…" + と '…' + の連結で、文字列が値をつなぐ所で終わるもの
_SQL_DOUBLE_QUOTED_VALUE = (
    r"(?:[^\"'\\]|\\.|'[^'\"]*')*?(?:'[^'\"]*|" + _SQL_COMPARE + r"(?:\\\"[^\"\\]*)?)\"\s*\+"
)
_SQL_SINGLE_QUOTED_VALUE = (
    r"(?:[^'\"\\]|\\.|\"[^\"']*\")*?(?:\\'[^'\\]*|" + _SQL_COMPARE + r"(?:\"[^\"']*)?)'\s*\+"
)
_SQL_LITERAL = r"(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')"
# 文字列 + 式 + 文字列 … の、どれかの文字列が値をつなぐ所で終わるもの（"SELECT * FROM " + t + " WHERE id = " + id）。
# 間の式に引用符があると（fields.join(',')）その先は見ない。式は空白で始めない
# （前の \s* と空白を取り合うと、続く数だけ組み合わせが増えて止まらなくなる）
_SQL_CONCAT_VALUE = (
    r"(?:" + _SQL_LITERAL + r"\s*\+\s*(?:[^\s\"'`;+][^\"'`;+]*\+\s*)?)*?"
    r"(?:\"" + _SQL_DOUBLE_QUOTED_VALUE + r"|'" + _SQL_SINGLE_QUOTED_VALUE + r")"
)
# 呼び出しの名前と ( の間の、TypeScript の型引数（$queryRawUnsafe<User[]>(…)）
_TS_TYPE_ARGS = r"\s*(?:<[^()]*?>)?\s*\("

# Ruby・PHP・Java/Kotlin・C#・Rust の SQL のルールの部品。INJ-009・INJ-014 と同じく、値をつなぐ所だけを見る:
# SQL の '…' の中と、比べる演算子の直後。列・テーブルの名前をつなぐ所（"#{table}.id"・"FROM " + table）は見ない
_SQL_COMPARE_ANY_CASE = r"(?:[=<>]|\b(?i:i?like|glob|regexp)\b)\s*"
# "…" の中身。閉じた '…' は組で読み飛ばし、開いたままの ' だけを値の中と見る（'…' の中身の " も同じ）
_DQ_SQL_BODY = r"(?:[^\"'\\\n]|\\.|'[^'\"\n]*')*?"
_SQ_SQL_BODY = r"(?:[^'\"\\\n]|\\.|\"[^'\"\n]*\")*?"


# 比べる演算子の直後の埋め込みのあとに .列名 が続くものは、テーブルで修飾した列名（= #{table}.id）
_NOT_QUALIFIED = r"(?!\.[A-Za-z_])"


def _sql_hole(hole: str, value_hole: str) -> str:
    """"…" の中の、値の位置にある埋め込み（Ruby の #{}・PHP の $x・Kotlin の ${}・C# と Rust の {}）。

    hole は SQL の '…' の中の埋め込みの始まり。value_hole は比べる演算子の直後の埋め込みの全体で、
    後ろに _NOT_QUALIFIED を付けて、テーブルで修飾した列名を外す。
    """
    return r"\"" + _DQ_SQL_BODY + r"(?:'[^'\"\n]*" + hole + r"|" + _SQL_COMPARE_ANY_CASE + value_hole + r")"


# 埋め込みの中身は 200 文字まで読む（区切らないと、閉じない = { が並ぶ行で、埋め込みごとに行末まで読む）
_HOLE_BODY = r"[^}\n]{0,200}\}"


def _sql_brace_hole(start: str = r"\{(?!\{)") -> str:
    """C#・Rust の {…}（{{ は文字の {）と、string.Format の {0}。"""
    return _sql_hole(start, start + _HOLE_BODY + _NOT_QUALIFIED)


def _sql_concat(op: str, op_char: str, quoted_safe: str = "", value_safe: str = "") -> str:
    """"…" と '…' を op（+ か PHP の .）でつなぐもので、どれかの文字列が値の位置で終わるもの。

    "… = '" + name も、"SELECT * FROM " + table + " WHERE id = " + id も見る（INJ-009 の連結と同じ読み方）。
    間の式に引用符があると、その先は見ない。式は空白で始めない（演算子の後ろの空白と取り合わないため）。
    quoted_safe・value_safe は、SQL の '…' の中・比べる演算子の直後につないでも安全な式の始まり（エスケープ・数への変換）。
    引用符を自分で付ける関数（quote）は '…' の中では引用符が二重になって値が外に出るので、value_safe にだけ入れる。
    """
    literal = r"(?:\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*')"
    expression = r"[^\s\"'`;" + op_char + r"][^\"'`;" + op_char + r"]*"
    quoted_guard = r"(?!\s*(?:" + quoted_safe + r"))" if quoted_safe else ""
    value_guard = r"(?!\s*(?:" + value_safe + r"))" if value_safe else ""
    return (
        r"(?:" + literal + r"\s*" + op + r"\s*(?:" + expression + op + r"\s*)?)*?"
        # 前の文字列で開いた ' を閉じて始まる文字列（"…a = '" . esc_sql($a) . "' AND b = '" . $b）も、閉じる引用符を読み飛ばして見る
        r"(?:\"'?" + _DQ_SQL_BODY + r"(?:'[^'\"\n]*\"\s*" + op + quoted_guard
        + r"|" + _SQL_COMPARE_ANY_CASE + r"\"\s*" + op + value_guard + r")"
        r"|'\"?" + _SQ_SQL_BODY + r"(?:\"[^'\"\n]*'\s*" + op + quoted_guard
        + r"|" + _SQL_COMPARE_ANY_CASE + r"'\s*" + op + value_guard + r"))"
    )


# 引数の文字列が SQL の文の始まりか（INJ-020〜022。メソッド名の update( や、英文の中の from では当てない）。
# FROM は JPQL・HQL の始まり
_SQL_STATEMENT = r"\s*(?i:select|insert|update|delete|replace|merge|with|from)\s"
# C# の型引数（<User>・<(int Id, string Name)>・<Dictionary<string, int>>）
_GENERIC_ARGS = r"<[^<>\n]*(?:<[^<>\n]*>[^<>\n]*)*>"
_RB_SQL_CALLS = (
    r"where|rewhere|having|find_by!?|find_by_sql|count_by_sql|joins|update_all|execute|exec_query"
    r"|exec_update|exec_delete|select_all|select_one|select_value|select_values|select_rows"
)
# 受け手なしでも見る名前（モデルの scope・クラスメソッドの中の where(...)）。execute などは Capistrano・Chef の
# シェルを実行する DSL と同じ名前なので、受け手のあるもの（connection.execute）だけを見る
_RB_BARE_SQL_CALLS = r"where|rewhere|having|find_by!?|find_by_sql|count_by_sql|joins|update_all"
# Ruby の #{…} で、値として見ないもの: 定数（#{WORK_MEM}）と、全体を整数にしたもの（#{params[:id].to_i}。|| などで
# ほかの値とつないだものは見る）。引用符を付けてエスケープする connection.quote・配列で渡した sanitize_sql
# （sanitize_sql(["… ?", x])。文字列を渡すとそのまま返す）は、比べる演算子の直後だけで外す（'…' の中では引用符が二重になる）。
# 引用符を付けない quote_string は、SQL の '…' の中だけで外す。sanitize_sql_like（% と _ だけ）は見る
_RB_SAFE = r"[A-Z][A-Z0-9_]*\}|[^}\s|&?]{0,100}?\.to_[ifr]\s*\}"
_RB_HOLE = r"#\{(?!" + _RB_SAFE + r"|[^}\n]{0,100}?\bquote_string\s*\()"
_RB_VALUE_HOLE = (
    r"#\{(?!" + _RB_SAFE + r"|[^}\n]{0,100}?(?:\bquote\s*\(|\bsanitize_sql(?:_array|_for_conditions)?\s*\(\s*\[))"
    + _HOLE_BODY + _NOT_QUALIFIED
)
# PHP の "…$x"・"…{$x}"・"…$obj->prop"・"…$arr[0]"
_PHP_HOLE = r"\{?\$[A-Za-z_]"
_PHP_VALUE_HOLE = (
    r"(?:\{\$" + _HOLE_BODY + r"|\$[A-Za-z_]\w*\b(?:->[A-Za-z_]\w*\b|\[[^\]\n]{0,100}\])?)(?!\.[A-Za-z_]|->|\[)"
)
# PHP の連結で、つないでも安全な値: 数への変換はどこでも。引用符を付けてエスケープするもの（PDO の quote・DB::getPdo()->quote・
# CodeIgniter の $this->db->escape）は比べる演算子の直後だけ、引用符を付けないエスケープ（esc_sql・real_escape_string）は '…' の中だけ
_PHP_CAST = r"\(\s*(?:int|integer|float|double|bool)\s*\)|(?:intval|floatval|boolval|absint)\s*\("
_PHP_VALUE_SAFE = _PHP_CAST + r"|(?:\$\w+|\w+(?:::\w+)?\s*\(\s*\))(?:->\w+(?:\s*\(\s*\))?)*->(?:quote|escape)\s*\("
_PHP_QUOTED_SAFE = (
    _PHP_CAST + r"|(?:esc_sql|mysqli_real_escape_string|pg_escape_string|addslashes)\s*\("
    r"|\$\w+(?:->\w+)*->(?:real_escape_string|escape_string)\s*\("
)
# Kotlin の "…$x"・"…${x}"
_KT_HOLE = r"\$\{?[A-Za-z_]"
_KT_VALUE_HOLE = r"\$(?:\{" + _HOLE_BODY + r"|[A-Za-z_]\w*\b)" + _NOT_QUALIFIED
# マイグレーション（Rails・Laravel・Flyway・EF Core）。開発者が流すもので、つなぐのはテーブル名や定数（外の値は入らない）
_MIGRATIONS = tuple(
    glob
    for folder in ("db/migrate", "db/post_migrate", "database/migrations", "db/migration", "Migrations")
    for glob in (folder + "/*", "*/" + folder + "/*")
)

# Blade の {!! !!} で、外の値が入らない形: CSRF・メソッドの隠しフィールド、ページ送り（$books->links()）、
# 置き換えの無い翻訳の文（置き換えの値はエスケープされないので、引数が 2 つのものは見る）
_BLADE_SAFE = (
    r"csrf_field\s*\(\s*\)|method_field\s*\([^()\n]*\)"
    # ページ送りの links()（$users->withQueryString()->links()・->appends(request()->query())->links() も）。
    # render() は Markdown などを HTML にするものにも使う名前なので外さない
    r"|\$\w+(?:->\w+\s*\((?:[^()\n]|\([^()\n]*\))*\))*->links\s*\([^()\n]*\)"
    r"|(?:trans|__)\s*\(\s*(?:'[^'\n]*'|\"[^\"\n]*\")\s*\)"
)


# シェルのルールの部品。どれも shell_code を通した行（コメントと、echo などで表示するだけの文字列を消したもの）に使う
_SH_DOWNLOAD = r"\b(?:curl|wget)\b"
# 名前の前後が語の続き（refresh・shasum・node_modules）でないもの。/bin/bash の bash も当たる
_SH_SHELL = r"(?<![\w.-])(?:ba|z|da|k)?sh(?![\w.-])"
_SH_INTERPRETER = r"(?<![\w.-])(?:python[0-9.]*|perl|ruby|node|php)(?![\w.-])"
# sudo・doas のオプションの引数（-u root）は - で始まらないものだけ（-a -a … を分け方の組み合わせで読まない）
_SH_SUDO = r"(?:(?:sudo|doas)\s+(?:-\S+\s+(?:[\w.][\w.-]*\s+)?)*)?"
# パイプ（|| は除く）と、間に挟むフィルター（| gunzip | sh・| tr -d '\r' | bash・| tee x | bash）
_SH_PIPE = r"\|(?!\|)&?\s*"
_SH_FILTER = r"[^\s|;&]" + shell_args(r"(?:curl|wget)")
# $(…) と `…`（eval `curl …`）
_SH_SUBSTITUTION = r"(?:\$\(|`)\s*"
# シェルの名前のあとの引数（bash -s stable < <(curl …)）。数を区切る（bash が並ぶ行で、位置ごとに行末まで読まない）
_SH_SHELL_ARGS = r"(?:\s+[^\s|;&<>]+){0,10}"
# ほかの人が書き込めるモード。数字は最後の桁に書き込み（2・3・6・7）があるもの（777・66・2777。1777 のような
# sticky ビットつきは /tmp と同じ共有の置き場なので外す）。記号は o・a に + か = で w を付けるもの（a+w・u+x,o+w）。
# 同じモードの中で o-w・a-w と外すもの（a+rw,o-w）は出さない。どの部分も重ならない形にして、長いモードでも 1 回で読む
_SH_OCTAL_WW = r"0*[0246]?[0-7]{0,2}[2367]"
_SH_SYMBOLIC_WW = (
    r"(?!\S*?(?<![^\s,\"'])(?=[ug]*[oa])[ugoa]*-[rxXstugo]*w)"
    r"(?:[ugoa]*[-+=][rwxXstugo]*,)*?(?=[ug]*[oa])[ugoa]*[+=](?=[rxXstugo]*w)[rwxXstugo]*"
)
_SH_MODE_WW = r"[\"']?(?:" + _SH_OCTAL_WW + r"|" + _SH_SYMBOLIC_WW + r")[\"']?(?=[\s,;&|)]|$)"
# パイプの先の、sudo・パス・env（| sudo -E /bin/bash・| /usr/bin/env -i bash）
_SH_LAUNCHER = _SH_SUDO + r"(?:(?:/[\w.-]+)*/)?(?:env\s+(?:-\S+\s+)*(?:\w+=[^\s;&|()]*\s+)*(?:(?:/[\w.-]+)*/)?)?"
# 標準入力を実行するもの。シェルは、-c（引数の文字列を実行する）かスクリプトを渡したものを外す
# （-s を付けたあとの語は、標準入力のスクリプトへの引数）。ほかは -c・-e・-r・スクリプトを渡したものを外す
_SH_RUNS_STDIN = (
    r"(?:" + _SH_SHELL + r"(?!(?:\s+-[A-Za-rt-z]+)*\s+(?:-[A-Za-z]*c|(?!\d*[<>&])[^\s\-;&|)<>]))"
    r"|" + _SH_INTERPRETER + r"(?=\s*(?:-(?:\s|$)|$|[;&|)]|\d*[<>]))"
    r"|source(?=\s*(?:-\s*)?(?:$|[;&|)]|\d*[<>])))"
)
# 手元の宛先。名前の続き（localhost.attacker.example）と、@ の前のユーザー名・パスワード
# （localhost:pw@evil.example のつなぐ先は evil.example）は外す
_SH_LOCAL_HOSTS = r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?![\w.@-])(?![^/\s\"'@]*@)"
# TLS-010 で外す当たり: curl・wget のコマンド全体（引用符の中も）で、宛先がどれも手元（localhost など）で、
# 変数・$(…)・`…` も渡していないもの（curl -k https://localhost:8443）。pip（信頼するホストは URL ではない）は外さない
_SH_ONLY_LOCAL = r"^(?:curl|wget)\b(?=.*://" + _SH_LOCAL_HOSTS + r")(?!.*(?:://(?!" + _SH_LOCAL_HOSTS + r")|[$`]))"


RULES = [
    # ---------------------------------------------------------------- injection
    LineRule(
        id="INJ-001",
        title="動的コード実行（eval）",
        severity=Severity.HIGH,
        category="injection",
        # model.eval()（PyTorch）や page.$eval()（Playwright）のようなメソッドは対象外。
        # window.eval / binding.eval（Ruby）は本物の eval なので拾う
        pattern=r"(?:(?<![.$\w])|\b(?:window|globalThis|self|builtins|binding)\.)eval\s*\(",
        languages=("python", "javascript", "php", "ruby"),
        message="外部入力が eval に渡ると、任意のコードを実行されます。",
        remediation="eval をやめ、JSON.parse や明示的な分岐・辞書引きに置き換えてください。",
        cwe="CWE-95",
        owasp="A03:2021",
    ),
    LineRule(
        id="INJ-002",
        title="文字列からの関数生成（new Function）",
        severity=Severity.MEDIUM,
        category="injection",
        pattern=r"\bnew\s+Function\s*\(",
        languages=("javascript",),
        message="文字列を関数として評価しており、入力によっては任意コード実行になります。",
        remediation="new Function を避け、静的な関数やパーサーを使ってください。",
        cwe="CWE-95",
    ),
    LineRule(
        id="INJ-003",
        title="シェル経由のコマンド実行（shell=True）",
        severity=Severity.HIGH,
        category="injection",
        pattern=r"subprocess\.(?:run|call|check_call|check_output|Popen)\s*\([\s\S]{0,400}?shell\s*=\s*True",
        languages=("python",),
        message="shell=True で文字列を組み立てると、コマンドインジェクションになります。",
        remediation="shell=False にして引数をリストで渡すか、shlex.quote でエスケープしてください。",
        cwe="CWE-78",
        owasp="A03:2021",
        multiline=True,
    ),
    LineRule(
        id="INJ-004",
        title="os.system / os.popen によるコマンド実行",
        severity=Severity.HIGH,
        category="injection",
        pattern=r"\bos\.(?:system|popen)\s*\(",
        languages=("python",),
        message="シェルに文字列を渡しており、入力次第で任意コマンドが実行されます。",
        remediation="subprocess.run([...], shell=False) に置き換えてください。",
        cwe="CWE-78",
    ),
    LineRule(
        id="INJ-005",
        title="child_process の exec / execSync によるコマンド実行",
        severity=Severity.HIGH,
        category="injection",
        # exec(…)・cp.exec(…)・child_process.execSync(…)・require('child_process').exec(…)。
        # 正規表現の /a/.exec(…) は対象外
        pattern=r"(?:(?<![.$\w])|\b(?:child_process|childProcess|cp)\.|child_process[\"']\)\.)(?:exec|execSync)\s*\(",
        languages=("javascript",),
        require_file=r"child_process",
        message="exec / execSync はシェルを介して文字列を実行するため、入力の混入でコマンドインジェクションになります。",
        remediation="execFile / spawn を使い、引数を配列で渡してください。",
        cwe="CWE-78",
    ),
    LineRule(
        id="INJ-006",
        title="Runtime.exec によるコマンド実行",
        severity=Severity.HIGH,
        category="injection",
        pattern=r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
        languages=("java",),
        message="文字列をそのままシェルに渡しており、コマンドインジェクションの危険があります。",
        remediation="ProcessBuilder に引数をリストで渡してください。",
        cwe="CWE-78",
    ),
    LineRule(
        id="INJ-007",
        title="PHP のシェル実行関数",
        severity=Severity.HIGH,
        category="injection",
        pattern=r"(?<![\w>])(?:shell_exec|passthru|proc_open|system|popen)\s*\(",
        languages=("php",),
        message="外部入力をそのままシェルに渡すとコマンドインジェクションになります。",
        remediation="escapeshellarg / escapeshellcmd を使うか、PHP の関数で処理を置き換えてください。",
        cwe="CWE-78",
    ),
    LineRule(
        id="INJ-008",
        title="SQL を文字列連結・f文字列で組み立てています",
        severity=Severity.HIGH,
        category="injection",
        pattern=r"(?i)\b(?:execute|executemany)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:\+|%|\.format\s*\())",
        languages=("python",),
        message="値を SQL 文字列に直接埋め込むと SQL インジェクションになります。",
        remediation="プレースホルダ（%s / :name）とパラメータ引数を使ってください。",
        cwe="CWE-89",
        owasp="A03:2021",
    ),
    LineRule(
        id="INJ-009",
        title="SQL をテンプレートリテラル・連結で組み立てています",
        severity=Severity.HIGH,
        category="injection",
        # 値をつなぐ所だけを見る（SQL の引用符の中の ${}・= < > LIKE の直後の ${} や連結）。列の一覧・WHERE・IN (?, ?) の
        # 組み立ては値をバインドするので対象外（Go の INJ-014 と同じ決まり）
        pattern=(
            # query・execute・raw は SQL のための呼び方なので、文字列の頭は問わない（knex.raw の断片を含む）
            r"(?i)\b(?:query|execute|raw)"
            + _TS_TYPE_ARGS
            + r"\s*(?:`"
            + _SQL_TEMPLATE_VALUE
            + r"|"
            + _SQL_CONCAT_VALUE
            # sqlite3・better-sqlite3・Prisma の呼び方。ルーターやキャッシュの get と分けるため、文字列が SQL の動詞で始まるものだけ
            + r")|\b(?:all|get|run|each|exec|prepare|queryRawUnsafe|executeRawUnsafe)"
            + _TS_TYPE_ARGS
            + r"\s*(?:`\s*"
            + _SQL_START
            + _SQL_TEMPLATE_VALUE
            + r"|(?=[\"']\s*"
            + _SQL_START
            + r")"
            + _SQL_CONCAT_VALUE
            + r")"
        ),
        languages=("javascript",),
        require_line=r"(?i)\b(?:select|insert|update|delete|from|where|values)\b",
        message="値を SQL に直接連結すると SQL インジェクションになります。",
        remediation="プレースホルダ（$1 / ?）とパラメータ配列を使ってください。",
        cwe="CWE-89",
        owasp="A03:2021",
        # テストは固定の値を SQL につないで準備することが多く、外からの値は届かない
        test_severity=Severity.LOW,
    ),
    LineRule(
        id="INJ-010",
        title="pickle による安全でないデシリアライズ",
        severity=Severity.HIGH,
        category="injection",
        pattern=r"\bpickle\.loads?\s*\(",
        languages=("python",),
        message="信頼できないデータを pickle で読み込むと任意コード実行になります。",
        remediation="JSON などの安全な形式に置き換えるか、署名付きデータのみを読み込んでください。",
        cwe="CWE-502",
    ),
    LineRule(
        id="INJ-011",
        title="yaml.load を SafeLoader なしで使用",
        severity=Severity.MEDIUM,
        category="injection",
        pattern=r"\byaml\.load\s*\(",
        languages=("python",),
        unless=r"(?:SafeLoader|safe_load|Loader\s*=\s*yaml\.SafeLoader)",
        message="yaml.load は任意の Python オブジェクトを生成でき、入力次第で危険です。",
        remediation="yaml.safe_load か Loader=yaml.SafeLoader を使ってください。",
        cwe="CWE-502",
    ),
    LineRule(
        id="INJ-012",
        title="PHP の unserialize",
        severity=Severity.HIGH,
        category="injection",
        pattern=r"\bunserialize\s*\(",
        languages=("php",),
        message="信頼できない入力を unserialize するとオブジェクトインジェクションになります。",
        remediation="json_decode を使い、許可したクラスだけを復元してください。",
        cwe="CWE-502",
    ),
    LineRule(
        id="INJ-013",
        title="Ruby の Marshal.load",
        severity=Severity.MEDIUM,
        category="injection",
        pattern=r"\bMarshal\.load\s*\(",
        languages=("ruby",),
        message="信頼できないデータの Marshal.load は任意コード実行につながります。",
        remediation="JSON など安全な形式に置き換えてください。",
        cwe="CWE-502",
    ),
    # --------------------------------------------------------------------- xss
    LineRule(
        id="XSS-001",
        title="dangerouslySetInnerHTML の使用",
        severity=Severity.MEDIUM,
        category="xss",
        pattern=r"dangerouslySetInnerHTML",
        languages=("javascript",),
        message="HTML を直接挿入しています。値がユーザー入力なら XSS になります。",
        remediation="DOMPurify などでサニタイズするか、テキストとして描画してください。",
        cwe="CWE-79",
        owasp="A03:2021",
    ),
    LineRule(
        id="XSS-002",
        title="innerHTML への代入",
        severity=Severity.MEDIUM,
        category="xss",
        pattern=r"\.innerHTML\s*=",
        languages=("javascript",),
        unless=r"\.innerHTML\s*=\s*(?:''|\"\"|``|null|undefined)\s*;?\s*$",
        message="innerHTML に外部入力を入れるとスクリプトが実行されます。",
        remediation="textContent を使うか、サニタイズしてから挿入してください。",
        cwe="CWE-79",
    ),
    LineRule(
        id="XSS-003",
        title="document.write の使用",
        severity=Severity.MEDIUM,
        category="xss",
        pattern=r"\bdocument\.write(?:ln)?\s*\(",
        languages=("javascript",),
        message="document.write は入力によって XSS になります。",
        remediation="DOM API で要素を作成して挿入してください。",
        cwe="CWE-79",
    ),
    LineRule(
        id="XSS-004",
        title="v-html による HTML 挿入",
        severity=Severity.MEDIUM,
        category="xss",
        pattern=r"\bv-html\s*=",
        languages=("javascript",),
        message="v-html はエスケープされない HTML を描画します。",
        remediation="サニタイズした値だけを渡すか、テキスト補間を使ってください。",
        cwe="CWE-79",
    ),
    LineRule(
        id="XSS-005",
        title="Angular の innerHTML バインド",
        severity=Severity.MEDIUM,
        category="xss",
        pattern=r"\[innerHTML\]",
        languages=("javascript",),
        message="[innerHTML] はサニタイズされますが、bypassSecurityTrustHtml と併用すると危険です。",
        remediation="信頼できる値だけを渡し、bypassSecurityTrustHtml を避けてください。",
        cwe="CWE-79",
    ),
    # ------------------------------------------------------------------ crypto
    LineRule(
        id="CRY-001",
        title="弱いハッシュ（MD5 / SHA1）を直接使用",
        severity=Severity.MEDIUM,
        category="crypto",
        pattern=r"\bcreateHash\s*\(\s*[\"'](?:md5|sha1)[\"']",
        languages=("javascript",),
        message="MD5 / SHA1 はパスワードや署名には使えません。",
        remediation="パスワードは bcrypt / argon2、完全性は SHA-256 以上を使ってください。",
        cwe="CWE-327",
    ),
    LineRule(
        id="CRY-002",
        title="弱いハッシュ関数の使用",
        severity=Severity.LOW,
        category="crypto",
        pattern=r"(?i)\b(?:md5|sha1)\s*\(",
        languages=("python", "php", "ruby"),
        message="MD5 / SHA1 は衝突攻撃が可能で、セキュリティ用途には不適切です。",
        remediation="用途に応じて SHA-256 以上か、bcrypt / argon2 を使ってください（チェックサム用途なら可）。",
        cwe="CWE-327",
    ),
    LineRule(
        id="CRY-003",
        title="AES の ECB モード",
        severity=Severity.MEDIUM,
        category="crypto",
        pattern=r"(?i)AES[/-](?:128|192|256)[/-]ECB|aes-(?:128|192|256)-ecb",
        message="ECB モードは同じ平文が同じ暗号文になり、パターンが漏れます。",
        remediation="AES-GCM（認証付き暗号）を使ってください。",
        cwe="CWE-327",
    ),
    LineRule(
        id="CRY-004",
        title="トークン生成に Math.random を使用",
        severity=Severity.MEDIUM,
        category="crypto",
        pattern=r"\bMath\.random\s*\(\s*\)",
        languages=("javascript",),
        require_line=r"(?i)(?:token|secret|password|passwd|nonce|otp|reset|session)",
        message="Math.random は暗号学的に安全ではなく、予測可能です。",
        remediation="crypto.randomUUID() か crypto.getRandomValues() を使ってください。",
        cwe="CWE-338",
    ),
    LineRule(
        id="CRY-005",
        title="トークン生成に random モジュールを使用",
        severity=Severity.MEDIUM,
        category="crypto",
        pattern=r"\brandom\.(?:random|randint|randrange|choice|choices|getrandbits)\s*\(",
        languages=("python",),
        require_line=r"(?i)(?:token|secret|password|passwd|nonce|otp|reset|session)",
        message="random モジュールは暗号学的に安全ではありません。",
        remediation="secrets モジュール（secrets.token_urlsafe など）を使ってください。",
        cwe="CWE-338",
    ),
    LineRule(
        id="CRY-006",
        title="古い暗号方式（DES / RC4）",
        severity=Severity.MEDIUM,
        category="crypto",
        pattern=r"(?i)createCipheriv?\s*\(\s*[\"'](?:des|des3|rc4|rc2)",
        languages=("javascript",),
        message="DES / RC4 は既に解読可能で、使用すべきではありません。",
        remediation="AES-GCM に置き換えてください。",
        cwe="CWE-327",
    ),
    # --------------------------------------------------------------------- tls
    LineRule(
        id="TLS-001",
        title="TLS 証明書の検証を無効化（rejectUnauthorized: false）",
        severity=Severity.HIGH,
        category="tls",
        pattern=r"rejectUnauthorized\s*:\s*false",
        languages=("javascript",),
        message="証明書検証を切ると中間者攻撃を受けます。",
        remediation="検証を有効に戻し、必要なら CA を正しく設定してください。",
        cwe="CWE-295",
    ),
    LineRule(
        id="TLS-002",
        title="NODE_TLS_REJECT_UNAUTHORIZED=0",
        severity=Severity.HIGH,
        category="tls",
        pattern=r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0",
        message="Node.js 全体の TLS 検証が無効になります。",
        remediation="この設定を削除し、自己署名証明書は NODE_EXTRA_CA_CERTS で信頼してください。",
        cwe="CWE-295",
    ),
    LineRule(
        id="TLS-003",
        title="requests の verify=False",
        severity=Severity.HIGH,
        category="tls",
        pattern=r"\bverify\s*=\s*False",
        languages=("python",),
        message="HTTP クライアントの証明書検証が無効です。",
        remediation="verify=True（既定）に戻し、社内 CA は REQUESTS_CA_BUNDLE で指定してください。",
        cwe="CWE-295",
    ),
    LineRule(
        id="TLS-004",
        title="InsecureSkipVerify: true",
        severity=Severity.HIGH,
        category="tls",
        pattern=r"InsecureSkipVerify\s*:\s*true",
        languages=("go",),
        message="Go の TLS 検証が無効化されています。",
        remediation="InsecureSkipVerify を false にし、RootCAs を設定してください。",
        cwe="CWE-295",
    ),
    LineRule(
        id="TLS-005",
        title="CURLOPT_SSL_VERIFYPEER の無効化",
        severity=Severity.HIGH,
        category="tls",
        pattern=r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)",
        languages=("php",),
        message="cURL の証明書検証が無効です。",
        remediation="検証を有効（true）にしてください。",
        cwe="CWE-295",
    ),
    # -------------------------------------------------------------------- auth
    LineRule(
        id="AUTH-001",
        title="JWT の alg: none を許可",
        severity=Severity.CRITICAL,
        category="auth",
        pattern=r"algorithms\s*:\s*\[[^\]]*[\"']none[\"']",
        message="署名なしトークンを受け入れる設定で、認証バイパスになります。",
        remediation="許可アルゴリズムを RS256 / ES256 などに固定してください。",
        cwe="CWE-347",
        owasp="A07:2021",
    ),
    LineRule(
        id="AUTH-002",
        title="JWT 検証の無効化（verify=False）",
        severity=Severity.CRITICAL,
        category="auth",
        pattern=r"\bjwt\.decode\s*\([^)\n]*verify\s*=\s*False",
        languages=("python",),
        message="署名検証なしで JWT を復号しており、改ざんされたトークンを受け入れます。",
        remediation="verify=True にし、algorithms を明示してください。",
        cwe="CWE-347",
    ),
    LineRule(
        id="AUTH-003",
        title="JWT を検証せずに decode している可能性",
        severity=Severity.LOW,
        category="auth",
        pattern=r"\bjwt\.decode\s*\(",
        languages=("javascript",),
        unless=r"(?:verify|publicKey|secret|complete|algorithms)",
        message="jsonwebtoken の decode は署名を検証しません。認証判定に使うと危険です。",
        remediation="jwt.verify を使い、秘密鍵と algorithms を明示してください。",
        cwe="CWE-347",
    ),
    LineRule(
        id="AUTH-004",
        title="CORS で Origin: * を返しています",
        severity=Severity.MEDIUM,
        category="auth",
        pattern=r"Access-Control-Allow-Origin[\"']?\s*[:=,]\s*[\"']\*[\"']",
        message="認証情報を扱う API でワイルドカードを許可すると、任意サイトから操作されます。",
        remediation="許可する Origin を明示し、credentials と * を併用しないでください。",
        cwe="CWE-942",
    ),
    LineRule(
        id="AUTH-005",
        title="CSRF 保護の無効化",
        severity=Severity.MEDIUM,
        category="auth",
        pattern=(
            r"\bcsrf\s*(?::\s*false|_exempt\b"
            # Spring Security: csrf().disable()・csrf(AbstractHttpConfigurer::disable)・csrf(c -> c.disable())・
            # csrf(c -> { c.disable(); })・Kotlin の csrf { disable() }・csrf { it.disable() }・csrf { c -> c.disable() }
            r"|\(\s*\)\s*\.\s*disable\b"
            r"|\(\s*(?:[\w.]*::disable\b|\(?\w+\)?\s*->\s*(?:\w+\s*\.\s*disable\s*\(|\{\s*\w+\s*\.\s*disable\s*\())"
            r"|\{\s*(?:(?:\w+\s*->\s*)?\w+\s*\.\s*)?disable\s*\(\s*\)\s*\})|@csrf_exempt"
            # Rails
            # ほかの名前と並べたもの（skip_before_action :authenticate_user!, :verify_authenticity_token）と、Rails 5 より前の
            # skip_before_filter も
            r"|\bskip_before_(?:action|filter)(?:\s*\(\s*|\s+)(?::\w+[!?]?\s*,\s*)*:verify_authenticity_token\b"
            r"|\bskip_forgery_protection\b"
            r"|\ballow_forgery_protection\s*=\s*false\b"
        ),
        # Kotlin の csrf {・disable()・} は複数の行に分けて書く。証拠は行全体のまま（1 行で読んでいた前の版と同じ指紋にする）
        multiline=True,
        whole_line_evidence=True,
        # Rails の generator が作る test.rb は、はじめから allow_forgery_protection = false。文書の中の例は設定ではない
        exclude_globs=("*config/environments/test.rb", "*.md", "*.mdx", "*.markdown", "*.rst", "*.adoc", "*.txt"),
        test_severity=Severity.LOW,
        message="CSRF 保護が無効になっており、外部サイトから状態変更を実行される可能性があります。",
        remediation="CSRF トークン検証を有効にしてください。Cookie のセッションを使わない API と、"
        "署名を確かめる Webhook だけなら、無効のままで構いません。",
        cwe="CWE-352",
    ),
    # ------------------------------------------------------------------ config
    LineRule(
        id="CFG-001",
        title="DEBUG が有効になっています",
        severity=Severity.MEDIUM,
        category="config",
        pattern=r"^\s*DEBUG\s*=\s*True\s*$",
        languages=("python",),
        message="本番で DEBUG=True だとスタックトレースや設定値が漏れます。",
        remediation="環境変数で切り替え、本番は False にしてください。",
        cwe="CWE-489",
    ),
    LineRule(
        id="CFG-002",
        title="Flask の debug=True",
        severity=Severity.LOW,
        category="config",
        pattern=r"\.run\s*\([^)]*debug\s*=\s*True",
        languages=("python",),
        message="デバッグモードは本番では無効にしてください。",
        remediation="本番は gunicorn / uwsgi で起動し、debug を無効にしてください。",
        cwe="CWE-489",
    ),
    LineRule(
        id="CFG-003",
        title="PHP の display_errors が有効",
        severity=Severity.LOW,
        category="config",
        pattern=r"(?i)^\s*display_errors\s*=\s*(?:On|1|true)\s*$",
        languages=("php",),
        message="エラー表示はパスや設定の露出につながります。",
        remediation="本番は display_errors=Off、ログ出力のみにしてください。",
        cwe="CWE-209",
    ),
    LineRule(
        id="CFG-004",
        title="WordPress の WP_DEBUG_DISPLAY が有効",
        severity=Severity.MEDIUM,
        category="config",
        pattern=r"WP_DEBUG_DISPLAY[^\n]*,\s*true",
        languages=("php",),
        message="デバッグ表示が有効だと、内部情報が画面に出ます。",
        remediation="wp-config.php で define('WP_DEBUG_DISPLAY', false) にしてください。",
        cwe="CWE-209",
    ),
    LineRule(
        id="CFG-005",
        title="ビルドエラーの無視設定",
        severity=Severity.LOW,
        category="config",
        pattern=r"(?:ignoreBuildErrors|ignoreDuringBuilds)\s*:\s*true",
        languages=("javascript",),
        message="型エラーや lint エラーを無視すると、問題が本番に残ります。",
        remediation="CI で型チェックと lint を必須にし、この設定を外してください。",
        cwe="CWE-1120",
    ),
    LineRule(
        id="CFG-006",
        title="本番でソースマップを公開",
        severity=Severity.INFO,
        category="hardening",
        pattern=r"productionBrowserSourceMaps\s*:\s*true",
        languages=("javascript",),
        message="本番ビルドでソースマップが配信され、実装の詳細が読まれます。",
        remediation="公開が不要なら false にしてください。",
        cwe="CWE-540",
    ),
    LineRule(
        id="CFG-007",
        title="Dockerfile の ENV に秘密情報",
        severity=Severity.HIGH,
        category="config",
        pattern=r"(?i)^\s*ENV\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY)\w*\s*[= ]",
        languages=("docker",),
        message="ENV に書いた値はイメージのレイヤーに残り、誰でも取り出せます。",
        remediation="ビルド引数や Secrets を使い、実行時に環境変数として渡してください。",
        cwe="CWE-798",
    ),
    LineRule(
        id="CFG-008",
        title="特権コンテナの設定",
        severity=Severity.MEDIUM,
        category="config",
        pattern=r"^\s*privileged\s*:\s*true",
        languages=("yaml",),
        message="privileged: true はホストに近い権限を与え、侵害時の影響が大きくなります。",
        remediation="必要な capability だけを追加してください。",
        cwe="CWE-250",
    ),
    LineRule(
        id="CFG-011",
        title="Next.js で SVG の直接配信を許可",
        severity=Severity.MEDIUM,
        category="xss",
        pattern=r"dangerouslyAllowSVG\s*:\s*true",
        languages=("javascript",),
        message="ユーザー提供の SVG をそのまま配信すると、埋め込まれたスクリプトが実行されます。",
        remediation="SVG を許可する場合は contentDispositionType と CSP を併用し、"
        "信頼できる画像だけに限定してください。",
        cwe="CWE-79",
    ),
    # -------------------------------------------------------------- dart / flutter
    LineRule(
        id="TLS-006",
        title="Dart の badCertificateCallback で証明書の検証を無効化",
        severity=Severity.HIGH,
        category="tls",
        pattern=r"badCertificateCallback\s*=\s*\([^)]*\)\s*(?:=>\s*true\b|\{\s*return\s+true\s*;)",
        languages=("dart",),
        multiline=True,
        message="どんな証明書も通すので、公衆 Wi-Fi などで通信を読まれたり書き換えられたりします。",
        remediation="この設定を消してください。自己署名の証明書を使う開発環境なら、デバッグのビルドだけに限ってください。",
        cwe="CWE-295",
    ),
    LineRule(
        id="TLS-007",
        title="Dart で平文の http:// に接続",
        severity=Severity.MEDIUM,
        category="tls",
        # 手元とエミュレータ（localhost・127.0.0.1・10.0.2.2）は対象外
        pattern=r"(?:Uri\.parse\s*\(\s*['\"]http://|(?i:base_?url|api_?url|endpoint)\w*\s*[:=]\s*['\"]http://"
        r"|Uri\.http\s*\(\s*['\"])(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0)",
        languages=("dart",),
        test_severity=Severity.LOW,  # 統合テストからエミュレータにつなぐもの
        message="暗号化されない通信なので、途中で読まれたり書き換えられたりします。",
        remediation="https:// に変えてください（Uri.http は Uri.https に）。",
        cwe="CWE-319",
    ),
    LineRule(
        id="CFG-012",
        title="SharedPreferences にトークン／パスワードを保存",
        severity=Severity.MEDIUM,
        category="secret",
        pattern=r"\.set(?:String|StringList)\s*\(\s*(?:['\"][^'\"]*|[\w.]*)"
        # session だけでは当てない（authSessionReasonKey のような、秘密でない値のキーがある）
        r"(?i:token|password|passwd|secret|jwt|session_?id|api_?key|credential)",
        languages=("dart",),
        require_file=r"SharedPreferences|shared_preferences",
        message="SharedPreferences は暗号化されず、root 化した端末やバックアップから読めます。",
        remediation="flutter_secure_storage など、Keychain / Keystore を使う保存先に移してください。",
        cwe="CWE-922",
    ),
    LineRule(
        id="CFG-013",
        title="print / debugPrint でトークンやパスワードを出力",
        severity=Severity.LOW,
        category="secret",
        pattern=r"\b(?:print|debugPrint)\s*\([^)\n]*\$\{?[\w.]*(?i:token|password|passwd|secret|api_?key|credential)",
        languages=("dart",),
        message="リリースのビルドでも端末のログに出て、ほかのアプリや接続した PC から読めることがあります。",
        remediation="出力から外すか、マスクしてください。デバッグだけで出すなら kDebugMode で囲んでください。",
        cwe="CWE-532",
    ),
    LineRule(
        id="CFG-014",
        title="WebView で JavaScript を有効化",
        severity=Severity.LOW,
        category="xss",
        pattern=r"Java[Ss]criptMode\.unrestricted",
        languages=("dart",),
        message="外の URL を開いたり、JavaScript チャンネルで値を受け取ったりすると、ページ側からアプリを操作されます。",
        remediation="開く URL を自分のドメインに限り、JavaScript チャンネルで受け取る値を確かめてください。",
        cwe="CWE-749",
    ),
    # ------------------------------------------------------------ android / ios
    LineRule(
        id="TLS-008",
        title="Android で平文の通信を許可（usesCleartextTraffic）",
        severity=Severity.MEDIUM,
        category="tls",
        pattern=r"android:usesCleartextTraffic\s*=\s*\"true\"",
        path_globs=("AndroidManifest.xml",),
        exclude_globs=("*/debug/*", "*/profile/*"),
        message="リリースのビルドでも http:// の通信が通り、途中で読まれたり書き換えられたりします。",
        remediation="main の manifest から外してください。エミュレータ用なら debug の manifest に移すか、"
        "network_security_config で 10.0.2.2 と localhost だけを許してください。",
        cwe="CWE-319",
    ),
    LineRule(
        id="CFG-015",
        title="Android の debuggable が有効",
        severity=Severity.HIGH,
        category="config",
        pattern=r"android:debuggable\s*=\s*\"true\"",
        path_globs=("AndroidManifest.xml",),
        exclude_globs=("*/debug/*", "*/profile/*"),
        message="リリースのアプリにデバッガをつないで、メモリや保存したデータを読めます。",
        remediation="manifest から外してください（ビルドの種類で自動で決まります）。",
        cwe="CWE-489",
    ),
    LineRule(
        id="TLS-009",
        title="iOS の ATS で平文の通信を許可（NSAllowsArbitraryLoads）",
        severity=Severity.MEDIUM,
        category="tls",
        pattern=r"NSAllowsArbitraryLoads</key>\s*<true\s*/>",
        path_globs=("*.plist",),
        multiline=True,
        message="すべての接続先で http:// と弱い TLS が通り、途中で読まれたり書き換えられたりします。",
        remediation="外して、どうしても要る接続先だけを NSExceptionDomains で許してください。",
        cwe="CWE-319",
    ),
    # ----------------------------------------------------------------- firebase
    LineRule(
        id="AUTH-006",
        title="Firebase のルールで誰でも書き込める（if true）",
        severity=Severity.HIGH,
        category="auth",
        # `if true && …` は条件付きなので対象外（`|| …` は誰でも通る）
        pattern=r"\ballow\s+[\w\s,]*\b(?:write|create|update|delete)\b[\w\s,]*:\s*if\s+true\s*(?:;|\}|$|\|\|)",
        path_globs=("*.rules",),
        message="ログインしていない人も含めて、誰でもデータを書き換え・削除できます。",
        remediation="request.auth と、その人がメンバーか（doc の有無・role）を条件にしてください。",
        cwe="CWE-284",
        owasp="A01:2021",
    ),
    LineRule(
        id="AUTH-007",
        title="Firebase のルールで誰でも読める（if true）",
        severity=Severity.MEDIUM,
        category="auth",
        pattern=r"\ballow\s+(?:read|get|list)(?:\s*,\s*(?:read|get|list))*\s*:\s*if\s+true\s*(?:;|\}|$|\|\|)",
        path_globs=("*.rules",),
        message="ログインしていない人も含めて、誰でも読めます。公開してよいデータかを確かめてください。",
        remediation="公開のデータでなければ、request.auth とメンバーかどうかを条件にしてください。",
        cwe="CWE-284",
        owasp="A01:2021",
    ),
    LineRule(
        id="AUTH-008",
        title="Firebase のルールにテスト用の期限付き公開",
        severity=Severity.MEDIUM,
        category="auth",
        pattern=r"request\.time\s*<\s*timestamp\.date\s*\(",
        path_globs=("*.rules",),
        message="作ったときのテスト用の設定で、期限までは誰でも読み書きできます。",
        remediation="期限で開ける形をやめ、request.auth とメンバーかどうかを条件にしてください。",
        cwe="CWE-284",
    ),
    # ----------------------------------------------------------------------- go
    LineRule(
        id="INJ-014",
        title="Go で SQL に値を fmt.Sprintf・引用符の中への連結で埋め込んでいます",
        severity=Severity.HIGH,
        category="injection",
        # 1 つ目の引数で読み飛ばすのは ctx・r.Context() などのコンテキストだけ（SQL の変数のあとの、バインドする値は対象外）
        pattern=r"\.(?:Query|QueryRow|Exec|Prepare)(?:Context)?\s*\(\s*"
        r"(?:(?:\w*[cC]tx\w*|[\w.]*Context\(\)|context\.\w+\(\))\s*,\s*)?"
        # 連結は、SQL の引用符の中に値をつなぐ形（"… = '" + name）だけ。列の名前の定数や、プレースホルダで作った
        # 条件をつなぐ（`SELECT ` + cols、"… WHERE " + where）のは Go ではふつうで、値は入らない
        r"(?:fmt\.Sprintf\s*\(|\"[^\"\n]*'\"\s*\+|`[^`]*'`\s*\+)",
        languages=("go",),
        # ? を並べただけのもの（placeholders）と、%d（整数）しか入れない Sprintf は値を埋め込まない
        unless=r"(?i)placeholders?\b|strings\.Repeat\(\s*\"[?$]|fmt\.Sprintf\(\s*[`\"](?:[^`\"%]|%%|%d)*[`\"]",
        test_severity=Severity.LOW,
        message="値を SQL に直接埋め込むと SQL インジェクションになります。",
        remediation="プレースホルダ（? / $1）と引数で渡してください。",
        cwe="CWE-89",
        owasp="A03:2021",
    ),
    LineRule(
        id="INJ-015",
        title="Go でシェル経由のコマンド実行（sh -c）",
        severity=Severity.HIGH,
        category="injection",
        pattern=r"exec\.Command(?:Context)?\s*\(\s*(?:[\w.()]+\s*,\s*)?\"(?:/(?:usr/)?bin/)?(?:ba|z)?sh\"\s*,\s*\"-c\"",
        languages=("go",),
        message="シェルに文字列を渡しており、入力が混ざるとコマンドインジェクションになります。",
        remediation="exec.Command にコマンドと引数を分けて渡してください（シェルを通さない）。",
        cwe="CWE-78",
        owasp="A03:2021",
    ),
    LineRule(
        id="XSS-006",
        title="Go の HTTP ハンドラで text/template を使用",
        severity=Severity.MEDIUM,
        category="xss",
        pattern=r"\"text/template\"",
        languages=("go",),
        require_file=r"http\.ResponseWriter|\"text/html",
        message="text/template は HTML をエスケープしないので、値に入ったスクリプトがそのまま動きます。",
        remediation="HTML を出すなら html/template を使ってください。",
        cwe="CWE-79",
    ),
    LineRule(
        id="CRY-007",
        title="トークン生成に math/rand を使用",
        severity=Severity.MEDIUM,
        category="crypto",
        pattern=r"\brand\.(?:Int\w*|Uint\w*|Float\w*|Read|Perm|N)\s*\(",
        languages=("go",),
        # 別名を付けずに読み込んだときだけ（crypto/rand を rand、math/rand を別名にしたファイルを当てない）
        require_file=r"(?m)^\s*(?:import\s+)?\"math/rand(?:/v2)?\"",
        require_line=r"(?i)(?:token|secret|password|passwd|nonce|otp|reset|session|salt)",
        message="math/rand は暗号学的に安全ではなく、予測できます。",
        remediation="crypto/rand を使ってください。",
        cwe="CWE-338",
    ),
    LineRule(
        id="CFG-016",
        title="タイムアウトの無い HTTP サーバー（http.ListenAndServe）",
        severity=Severity.LOW,
        category="hardening",
        pattern=r"\bhttp\.ListenAndServe(?:TLS)?\s*\(",
        languages=("go",),
        message="タイムアウトが無いと、ゆっくり送り続ける接続で接続の枠を使い切られます（Slowloris）。",
        remediation="http.Server に ReadHeaderTimeout などを設定して ListenAndServe を呼んでください。",
        cwe="CWE-400",
    ),
    # --------------------------------------------------------------------- ruby
    LineRule(
        id="INJ-018",
        title="Rails で SQL に値を #{} や連結で埋め込んでいます",
        severity=Severity.HIGH,
        category="injection",
        pattern=(
            # 受け手なし（モデルの scope・クラスメソッドの中の where(...)）も見る。not は where.not だけ
            # 配列で書いた条件（where(["name = '#{x}'"])）も
            r"(?:\.(?:not|" + _RB_SQL_CALLS + r")|(?<![\w.:@$])(?:" + _RB_BARE_SQL_CALLS + r"))(?:\s*\(\s*|\s+)(?:\[\s*)?"
            r"(?:" + _sql_hole(_RB_HOLE, _RB_VALUE_HOLE) + r"|" + _sql_concat(r"\+", "+") + r")"
        ),
        languages=("ruby",),
        exclude_globs=_MIGRATIONS,
        message="値を SQL の文字列に直接埋め込むと SQL インジェクションになります。",
        remediation='where("name = ?", name) のようにプレースホルダで渡すか、where(name: name) のようにハッシュで渡してください。',
        cwe="CWE-89",
        owasp="A03:2021",
        test_severity=Severity.LOW,
    ),
    LineRule(
        id="AUTH-009",
        title="Rails の permit! で送られた値を全部許可",
        severity=Severity.MEDIUM,
        category="auth",
        pattern=r"\.permit!(?!=)",
        languages=("ruby",),
        test_severity=Severity.LOW,
        message="送られた値を全部受け取るので、role・admin・user_id なども書き換えられます（一括代入）。",
        remediation="permit(:name, :email) のように、受け取る項目を並べてください。",
        cwe="CWE-915",
    ),
    # ---------------------------------------------------------------------- php
    LineRule(
        id="INJ-019",
        title="PHP で SQL に値を埋め込み・連結しています",
        severity=Severity.HIGH,
        category="injection",
        pattern=(
            r"(?:(?:\b(?:whereRaw|orWhereRaw|havingRaw|orHavingRaw|selectRaw|orderByRaw|groupByRaw)"
            r"|\bDB::(?:select|selectOne|scalar|statement|unprepared|insert|update|delete|raw)"
            r"|(?:\$|->)wpdb->(?:query|get_results|get_row|get_var|get_col|prepare)"
            # PDO・mysqli のメソッドは、ほかのクラスの query（$request->query('page')）と分けるため、文字列が SQL の動詞で始まるものだけ
            r"|->(?:query|exec|prepare)(?=\s*\(\s*[\"']" + _SQL_STATEMENT + r"))\s*\("
            # 1 つ目の引数の接続（$conn・$this->db）。pg_query は接続を省ける
            r"|\b(?:mysqli_(?:query|real_query|multi_query)|pg_query)\s*\(\s*(?:\$\w+(?:->\w+)*\s*,)?)\s*"
            r"(?:" + _sql_hole(_PHP_HOLE, _PHP_VALUE_HOLE)
            + r"|" + _sql_concat(r"\.", ".", _PHP_QUOTED_SAFE, _PHP_VALUE_SAFE) + r")"
        ),
        languages=("php",),
        exclude_globs=_MIGRATIONS,
        message="値を SQL の文字列に直接埋め込むと SQL インジェクションになります。",
        remediation="? のプレースホルダとバインドする値（whereRaw('price > ?', [$min])、PDO の prepare と execute）で渡してください。"
        "WordPress は $wpdb->prepare を使ってください。",
        cwe="CWE-89",
        owasp="A03:2021",
        test_severity=Severity.LOW,
    ),
    LineRule(
        id="AUTH-010",
        title="Laravel のモデルで一括代入の保護を外しています",
        severity=Severity.LOW,
        category="auth",
        pattern=r"\$guarded\s*=\s*(?:\[\s*\]|array\s*\(\s*\))|\b(?:Model|Eloquent)::unguard\s*\(",
        languages=("php",),
        # seeder・factory はテストのデータを入れるだけ
        exclude_globs=("database/*", "*/database/*"),
        message="$request->all() を create・update・fill に渡すと、role・is_admin・user_id なども書き換えられます。",
        remediation="$fillable で受け取る列を決めるか、$request->validated()・only() で選んだ値だけを渡してください。",
        cwe="CWE-915",
    ),
    LineRule(
        id="XSS-007",
        title="Blade の {!! !!} でエスケープせずに出力",
        severity=Severity.MEDIUM,
        category="xss",
        pattern=r"\{!!(?!\s*(?:" + _BLADE_SAFE + r")\s*!!\})"
        # e()・htmlspecialchars で先にエスケープしたもの（nl2br(e($text)) も）。後ろに . や ? で続けたもの（e($a) . $b）は見る
        r"(?!\s*(?:nl2br\s*\(\s*)?(?:e|htmlspecialchars|htmlentities)\s*\((?![^!\n]*\)\s*[.?])[^!\n]*!!\})",
        languages=("php",),
        path_globs=("*.blade.php",),
        message="{!! !!} は HTML をエスケープしないので、値に入ったスクリプトがそのまま動きます。",
        remediation="{{ }} で出してください。HTML を出すなら、サニタイズ（HTMLPurifier など）した値だけにしてください。",
        cwe="CWE-79",
    ),
    # ------------------------------------------------------------- java / kotlin
    LineRule(
        id="INJ-020",
        title="Java / Kotlin で SQL に値を連結・埋め込みしています",
        severity=Severity.HIGH,
        category="injection",
        pattern=(
            r"(?:\b(?:executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall"
            r"|createQuery|createNativeQuery|createSQLQuery|rawQuery|execSQL|query|queryForObject|queryForList"
            r"|queryForMap|queryForRowSet|queryForStream|update|batchUpdate)\s*\(\s*(?=s?[\"']" + _SQL_STATEMENT + r")"
            # Android の SQLiteDatabase の where 句（db.update(TABLE, values, "id = " + id, null)・db.delete("users", "id = " + id, null)）。
            # 受け手が db・mDb・database・writableDatabase・getWritableDatabase() のものだけ（progress.update("import", "count = " + n) は見ない）
            r"|(?:\b\w*(?:[dD]b|[dD]atabase)|\bget(?:Writable|Readable)Database\s*\(\s*\))\s*\.\s*(?:update|delete|query)\s*\(\s*"
            r"(?:\"[\w.]+\"|[\w.]+)\s*,\s*(?:(?:new\s+String\s*\[\s*\]\s*)?(?:\{[^{}\n]*\}|[\w.]+(?:\([^()\n]*\))?)\s*,\s*)?)"
            # Kotlin の文字列テンプレート（"… = '$email'"・"… = ${user.id}"）と、Scala の s"…$id" も見る
            r"(?:" + _sql_concat(r"\+", "+") + r"|s?" + _sql_hole(_KT_HOLE, _KT_VALUE_HOLE) + r")"
        ),
        languages=("java",),
        exclude_globs=_MIGRATIONS,
        message="値を SQL の文字列に直接つなぐと SQL インジェクションになります。",
        remediation="PreparedStatement の ? と setString など、JPA の :name と setParameter、JdbcTemplate の引数で渡してください。",
        cwe="CWE-89",
        owasp="A03:2021",
        test_severity=Severity.LOW,
    ),
    LineRule(
        id="INJ-023",
        title="Java / Kotlin の ObjectInputStream・XMLDecoder でのデシリアライズ",
        severity=Severity.MEDIUM,
        category="injection",
        # 完全修飾名（java.io.ObjectInputStream(…)）も見る。無名の継承（new ObjectInputStream(in) { … }・
        # Kotlin の object : ObjectInputStream(input) { … }）もストリームを作る所なので見る
        # （resolveClass を上書きしても、ClassLoader を選ぶだけで読むクラスを絞らないことが多い）
        pattern=r"(?:\bnew\s+|(?<![\w.$]))(?:java\.(?:io|beans)\.)?(?:ObjectInputStream|XMLDecoder)\s*\(",
        languages=("java",),
        # ObjectInputStream を継いだクラスの宣言（Kotlin の class X(…) : ObjectInputStream(…) {。主コンストラクタを複数の行に
        # 書いた ) : ObjectInputStream(…) と、次の行に分けた ObjectInputStream(input) も）
        unless=r"\bclass\s+\w+[^{\n]*:\s*(?:java\.io\.)?ObjectInputStream\s*\("
        r"|^\s*\)\s*:\s*(?:java\.io\.)?ObjectInputStream\s*\("
        r"|^\s*(?:java\.io\.)?ObjectInputStream\s*\([^()\n]*\)\s*(?:\{|$)",
        message="信頼できないデータを読むと、クラスパスにあるクラスの組み合わせで任意のコードを実行されます。",
        remediation="JSON などの形式に置き換えてください。読むなら ObjectInputFilter（JEP 290）で許すクラスを絞ってください。",
        cwe="CWE-502",
    ),
    # ----------------------------------------------------------------------- c#
    LineRule(
        id="INJ-021",
        title="C# で SQL に値を埋め込み・連結しています",
        severity=Severity.HIGH,
        category="injection",
        pattern=(
            # EF Core の *Raw と Dapper（型引数 <User> も）・ADO.NET のコマンド
            r"(?:(?:\b(?:FromSqlRaw|ExecuteSqlRaw(?:Async)?|SqlQueryRaw)"
            r"|\.(?:Query|QueryAsync|QueryFirst\w*|QuerySingle\w*|QueryMultiple\w*|Execute|ExecuteAsync"
            r"|ExecuteScalar\w*|ExecuteReader\w*))\s*(?:" + _GENERIC_ARGS + r")?\s*\("
            r"|\bnew\s+(?:\w+\.)*(?:Sql|Npgsql|MySql|Sqlite|SQLite|OleDb|Odbc|Oracle)Command\s*\("
            # cmd.CommandText = … と、オブジェクト初期化子の { CommandText = … }
            r"|\bCommandText\s*=(?!=))\s*"
            # 名前付きの引数（sql: "…"）
            r"(?:\w+\s*:\s*)?"
            r"(?=(?:\$@?|@\$|@)?\"" + _SQL_STATEMENT + r"|[Ss]tring\.Format\s*\(\s*@?\"" + _SQL_STATEMENT + r")"
            r"(?:(?:\$@?|@\$)" + _sql_brace_hole()
            + r"|@?" + _sql_concat(r"\+", "+")
            + r"|[Ss]tring\.Format\s*\(\s*@?" + _sql_brace_hole(r"\{\d") + r")"
        ),
        languages=("csharp",),
        exclude_globs=_MIGRATIONS,
        message="値を SQL の文字列に直接埋め込むと SQL インジェクションになります。",
        remediation="EF Core は FromSql・ExecuteSql（補間した値をパラメータにする）、ADO.NET は Parameters、"
        "Dapper は匿名型の引数で渡してください。",
        cwe="CWE-89",
        owasp="A03:2021",
        test_severity=Severity.LOW,
    ),
    LineRule(
        id="INJ-024",
        title=".NET の BinaryFormatter などでのデシリアライズ",
        severity=Severity.HIGH,
        category="injection",
        pattern=(
            r"\bnew\s+(?:(?:Binary|Soap|Los|ObjectState)Formatter|NetDataContractSerializer)\b"
            r"|\b(?:(?:Binary|Soap|Los|ObjectState)Formatter|NetDataContractSerializer)\s+\w+\s*=\s*new\s*\("
        ),
        languages=("csharp",),
        message="データの中に書かれた型を作るので、信頼できないデータを読むと任意のコードを実行されます。"
        "Microsoft も、安全に使う方法は無いとしています。",
        remediation="System.Text.Json などに置き換えてください（BinaryFormatter は .NET 9 で使えなくなりました）。",
        cwe="CWE-502",
    ),
    LineRule(
        id="INJ-025",
        title="Json.NET の TypeNameHandling を None 以外にしています",
        severity=Severity.MEDIUM,
        category="injection",
        # 一覧の中身にだけ効く ItemTypeNameHandling も同じ
        pattern=r"\b(?:Item)?TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b",
        languages=("csharp",),
        message="JSON の $type に書かれた型を作るので、外から受け取った JSON を読むと任意のコードを実行されます。",
        remediation="TypeNameHandling.None に戻してください。要るなら、許す型だけを ISerializationBinder で決めてください。",
        cwe="CWE-502",
    ),
    LineRule(
        id="TLS-012",
        title="C# で証明書の検証を無効化（常に true を返すコールバック）",
        severity=Severity.HIGH,
        category="tls",
        pattern=(
            r"\b(?:ServerCertificate(?:Custom)?ValidationCallback|RemoteCertificateValidationCallback)\s*(?:\+?=|\()\s*"
            r"(?:(?:\([^()\n]*\)|\w+)\s*=>\s*(?:true\b|\{\s*return\s+true\s*;)|delegate\s*(?:\([^()\n]*\))?\s*\{\s*return\s+true\s*;)"
            r"|\bDangerousAcceptAnyServerCertificateValidator\b"
        ),
        languages=("csharp",),
        # ラムダの本体を次の行の { から書く（C# のふつうの書き方）
        multiline=True,
        message="どんな証明書も通すので、途中で通信を読まれたり書き換えられたりします。",
        remediation="コールバックを消してください。社内の CA なら、その CA を信頼する設定にしてください。",
        cwe="CWE-295",
    ),
    # --------------------------------------------------------------------- rust
    LineRule(
        id="INJ-022",
        title="Rust で SQL に値を format! で埋め込んでいます",
        severity=Severity.HIGH,
        category="injection",
        pattern=(
            r"\b(?:query|query_as|query_scalar|query_with|query_as_with|sql_query|execute|prepare|prepare_cached"
            r"|query_row|query_map|query_one|query_opt|batch_execute|simple_query)"
            r"\s*(?:::" + _GENERIC_ARGS + r")?\s*\(\s*&?\s*format!\s*\(\s*(?=\"" + _SQL_STATEMENT + r")" + _sql_brace_hole()
        ),
        languages=("rust",),
        exclude_globs=_MIGRATIONS,
        message="値を SQL の文字列に直接埋め込むと SQL インジェクションになります。",
        remediation="$1・? のプレースホルダと bind（sqlx）・params（rusqlite）で渡すか、sqlx の query! マクロを使ってください。",
        cwe="CWE-89",
        owasp="A03:2021",
        test_severity=Severity.LOW,
    ),
    LineRule(
        id="TLS-013",
        title="Rust で証明書の検証を無効化（danger_accept_invalid_certs）",
        severity=Severity.HIGH,
        category="tls",
        pattern=r"\.danger_accept_invalid_(?:certs|hostnames)\s*\(\s*true\s*\)",
        languages=("rust",),
        message="どんな証明書・ホスト名も通すので、途中で通信を読まれたり書き換えられたりします。",
        remediation="外してください。自己署名の証明書なら add_root_certificate でその証明書だけを信頼してください。",
        cwe="CWE-295",
    ),
    # ------------------------------------------------------------ compose・k8s・nginx
    LineRule(
        id="CFG-020",
        title="コンテナに Docker のソケット（docker.sock）を渡しています",
        severity=Severity.MEDIUM,
        category="config",
        # compose の volumes（- /var/run/docker.sock:…・長い書き方の source:）と、Kubernetes の hostPath の下の path:。
        # DOCKER_HOST=unix:///var/run/docker.sock のような、つなぐ先の指定と、Ansible の path: は対象外
        pattern=r"(?m)^[ \t]*-[ \t]*[\"']?[^\s\"'=]*?(?:/var)?/run/docker\.sock\b"
        r"|\bsource[ \t]*:[ \t]*[\"']?(?:/var)?/run/docker\.sock\b"
        r"|\bhostPath[ \t]*:[ \t]*\{?\s*(?:type[ \t]*:[^\n,}]*[\n,]\s*)?path[ \t]*:[ \t]*[\"']?(?:/var)?/run/docker\.sock\b",
        languages=("yaml",),
        multiline=True,
        message="コンテナの中から Docker を操作でき、ホストの root と同じことができます（:ro を付けても同じです）。",
        remediation="本当に要るコンテナだけに限り、docker-socket-proxy などで使える API を絞ってください。",
        cwe="CWE-250",
    ),
    LineRule(
        id="CFG-021",
        title="コンテナがホストのネットワーク・プロセスを共有",
        severity=Severity.MEDIUM,
        category="config",
        pattern=r"^\s*(?:host(?:Network|PID|IPC)\s*:\s*true\b|(?:network_mode|pid|ipc)\s*:\s*[\"']?host[\"']?\s*(?:#.*)?$)",
        languages=("yaml",),
        message="コンテナの中から、ホストの localhost だけで待ち受けるサービスや、ほかのプロセスに触れられます。",
        remediation="外して、要るポートだけを ports で公開してください（Kubernetes の Pod Security Standards は baseline でも禁止）。",
        cwe="CWE-250",
    ),
    LineRule(
        id="CFG-022",
        title="nginx の alias で 1 つ上のフォルダが読める（location の末尾の / の漏れ）",
        severity=Severity.MEDIUM,
        category="config",
        # location が / で終わらず、alias が / で終わるもの（/static../ が /srv/app/static/../ になる）。
        # 正規表現の location（~）と完全一致（=）は対象外。location の中のコメントの行（500 文字まで。区切らないと、
        # 改行の無い長い行で location ごとに行末まで読む）は読み飛ばし、if (…) { … } のような 1 段の入れ子の後ろの alias も見る
        pattern=r"\blocation\s+(?:\^~\s+)?/[^\s{;]*[^/\s{;]\s*\{(?:[^{}#]|#[^\n]{0,500}\n|\{[^{}]*\})*?"
        r"\balias\s+[\"']?[^\s;\"']*/[\"']?\s*;",
        path_globs=("*.conf", "*.conf.template", "*.conf.j2", "nginx.conf*", "*sites-available/*", "*sites-enabled/*"),
        multiline=True,
        message="/static../ のような URL で、alias のフォルダの 1 つ上のファイル（設定・ソース・.env など）を読まれます。",
        remediation="location と alias の末尾の / をそろえてください（location /static/ { alias /srv/app/static/; }）。",
        cwe="CWE-22",
    ),
    # -------------------------------------------------------------------- shell
    LineRule(
        id="INJ-016",
        title="ダウンロードしたスクリプトをそのまま実行（curl | sh）",
        severity=Severity.MEDIUM,
        category="injection",
        pattern=(
            # curl … | sh・wget -qO- … | sudo bash -・curl … | python3 -・curl … | php・fish の | source。
            # |&、間にフィルターを挟んだもの（| gunzip | sh・| sudo tee install.sh | bash）も
            _SH_DOWNLOAD + shell_args(r"(?:curl|wget)") + _SH_PIPE
            + r"(?:" + _SH_FILTER + _SH_PIPE + r")*?" + _SH_LAUNCHER + _SH_RUNS_STDIN
            # bash <(curl …)・bash -s stable < <(curl …)・source <(curl …)・. <(curl …)
            + r"|(?:" + _SH_SHELL + r"|" + _SH_INTERPRETER + r"|\bsource|(?<![\w./-])\.)" + _SH_SHELL_ARGS
            + r"\s*<?\s*<\(\s*" + _SH_DOWNLOAD
            # bash <<< "$(curl …)"
            + r"|(?:" + _SH_SHELL + r"|" + _SH_INTERPRETER + r")" + _SH_SHELL_ARGS + r"\s*<<<\s*[\"']?"
            + _SH_SUBSTITUTION + _SH_DOWNLOAD
            # bash -c "$(curl …)"・bash -e -c "$(curl …)"・python3 -c "$(curl …)"・eval "$(curl …)"・eval `curl …`
            + r"|(?:(?:" + _SH_SHELL + r"|" + _SH_INTERPRETER + r")(?:\s+-[A-Za-z]+){0,10}\s+-[A-Za-z]*[ce]"
            + r"|(?<![\w-])eval)\s+[\"']?" + _SH_SUBSTITUTION + _SH_DOWNLOAD
        ),
        languages=("shell",),
        shell_view=True,
        message="取ってきた中身を確かめずに実行しています。配布元や途中の経路が乗っ取られると、そのまま任意のコードが動きます。",
        remediation="版を固定して取り、sha256 などを確かめてから実行してください。パッケージマネージャで入れられるものは、そちらを使ってください。",
        cwe="CWE-494",
        owasp="A08:2021",
    ),
    LineRule(
        id="INJ-017",
        title="引数をそのまま eval・sh -c に渡しています",
        severity=Severity.MEDIUM,
        category="injection",
        # eval "$@"・eval $1・bash -c "$1"・eval "$1=$2"・eval "$1=\"$2\""。名前を受け取って代入するとき、値を \$ で
        # 渡すもの（eval "$1=\$value"）と、単一引用符の中（eval '$@'。値の中の ; や $(…) は読み直されない）は外す
        pattern=r"(?:(?<![\w-])eval|" + _SH_SHELL + r"\s+-[A-Za-z]*c)\s+\"?\$(?:\{[1-9@*]\}|[1-9@*])(?!\w)(?!\+?=\\\$)",
        languages=("shell",),
        shell_view=True,
        message="引数がもう一度シェルの文として読まれます。空白・引用符・$(…) を含む値でコマンドが変わり、外から渡した値で任意のコマンドが動きます。",
        remediation="\"$@\" でそのまま実行してください（eval・sh -c を通さない）。",
        cwe="CWE-78",
        owasp="A03:2021",
    ),
    LineRule(
        id="TLS-010",
        title="コマンドで証明書の検証を無効化（curl -k など）",
        severity=Severity.HIGH,
        category="tls",
        pattern=(
            # -k は -sk・-fsSLk のようにまとめたものも。--max-time・--keepalive-time は当てない。
            # 当たりはコマンドの終わりまで（宛先がどれも手元のものを、value_unless で外すため）
            r"\bcurl\b" + shell_args("curl") + r"\s(?:-[A-Za-z]*k[A-Za-z]*|--insecure)(?=[\s\"';&|)]|$)"
            + shell_args("curl")
            + r"|\bwget\b" + shell_args("wget") + r"\s--no-check-certificate\b" + shell_args("wget")
            + r"|\bpip3?\b" + shell_args("pip3?") + r"\s--trusted-host\b"
            # git の設定の名前は大文字小文字を区別しない。URL ごとの http.<url>.sslVerify も（URL は次の http. の手前まで）。
            # 真偽は 0・no・off も
            r"|(?i:\bhttp\.(?:(?:(?!\bhttp\.)\S)*\.)?sslverify)(?:\s*=\s*|\s+)[\"']?(?i:false|no|off|0)\b"
            # git は値に関係なく、この変数があれば検証しない
            r"|\bGIT_SSL_NO_VERIFY="
            r"|\b(?:npm|yarn|pnpm)\s+(?:config\s+)?set\s+strict-ssl(?:\s*=\s*|\s+)[\"']?false\b"
        ),
        languages=("shell",),
        shell_view=True,
        value_unless=_SH_ONLY_LOCAL,
        test_severity=Severity.LOW,
        message="証明書を確かめないので、途中の経路で通信を読まれ、書き換えられます。",
        remediation="検証を有効に戻してください。自己署名の証明書なら、curl は --cacert、git は http.sslCAInfo でその証明書を渡してください。",
        cwe="CWE-295",
    ),
    LineRule(
        id="TLS-011",
        title="SSH のホスト鍵の確認を無効化（StrictHostKeyChecking=no）",
        severity=Severity.MEDIUM,
        category="tls",
        # -oStrictHostKeyChecking=no のように -o に続けて書いたものも。OpenSSH は false も off と同じに読む
        pattern=r"(?i)(?:\b|(?<=-o))StrictHostKeyChecking(?:\s*=\s*|\s+)[\"']?(?:no|off|false)\b",
        languages=("shell",),
        shell_view=True,
        message="接続先が本物か確かめないので、なりすました相手に、実行するコマンドや送るファイル、転送した認証情報が渡ります。",
        remediation="接続先のホスト鍵を known_hosts に入れてください（ssh-keyscan の結果を指紋で確かめてから）。"
        "初めての接続だけ受け入れるなら StrictHostKeyChecking=accept-new にしてください。",
        cwe="CWE-322",
    ),
    LineRule(
        id="CFG-017",
        title="誰でも書き込める権限（chmod 777・o+w・umask 000）",
        severity=Severity.MEDIUM,
        category="config",
        pattern=(
            r"\bchmod\s+(?:-[A-Za-z]+\s+|--[\w-]*\s+)*" + _SH_MODE_WW
            # 作るときに権限を付けるもの（mkdir -m 777・install -m 0777・mkdir --mode=777）
            + r"|(?:^|[;&|({]|\b(?:sudo|doas|then|do|else|exec)\s)\s*(?:mkdir|install)\b"
            + shell_args(r"(?:mkdir|install)") + r"\s(?:-m\s*|--mode=)" + _SH_MODE_WW
            + r"|\bumask\s+0*[0-7]?[0-7]?[0145](?=[\s;&|)]|$)"
        ),
        languages=("shell",),
        shell_view=True,
        message="同じマシンのほかのユーザーやプロセスが書き換えられます。スクリプトや設定なら、書き換えた中身が実行されます。",
        remediation="必要な人だけに書き込みを許してください（ファイルは 644・600、フォルダは 755・700 など）。"
        "共有するならグループを分けてください。",
        cwe="CWE-732",
    ),
]
