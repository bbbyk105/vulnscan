"""ルールの共通型。

ルールは「1行の正規表現」か「ファイル全体を見る小さな関数」のどちらか。
どちらも Finding を生成するだけで、対象ファイルは一切変更しない。
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from ..models import Finding, Location, Severity, SourceFile, mask

LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyi"},
    "javascript": {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".vue",
        ".svelte",
        ".astro",
    },
    "php": {".php", ".phtml", ".inc"},
    "ruby": {".rb", ".erb", ".rake"},
    "go": {".go"},
    "java": {".java", ".kt", ".kts", ".scala"},
    "csharp": {".cs"},
    "rust": {".rs"},
    "dart": {".dart"},
    "shell": {".sh", ".bash", ".zsh", ".fish"},
    "sql": {".sql"},
    "yaml": {".yml", ".yaml"},
    "json": {".json"},
}

LANGUAGE_FILENAMES = {
    "docker": ("Dockerfile",),
    "make": ("Makefile", "GNUmakefile"),
}

# 言語のルールはまだ無いが、見つかったことはレポートに出す言語（秘密の置き忘れだけを確認している、と伝えるため）
OTHER_LANGUAGE_EXTENSIONS = {
    "swift": {".swift"},
    "c": {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"},
    "objective-c": {".m", ".mm"},
    "elixir": {".ex", ".exs"},
    "lua": {".lua"},
    "perl": {".pl", ".pm"},
}

# 画面と --lang の言語を選ぶ一覧に出す名前
LANGUAGE_LABELS = {
    "javascript": "JavaScript/TypeScript",
    "python": "Python",
    "php": "PHP",
    "ruby": "Ruby",
    "go": "Go",
    "java": "Java/Kotlin/Scala",
    "csharp": "C#",
    "dart": "Dart/Flutter",
    "shell": "シェル",
    "yaml": "YAML",
    "docker": "Dockerfile",
    "swift": "Swift",
    "rust": "Rust",
    "c": "C/C++",
    "objective-c": "Objective-C",
    "elixir": "Elixir",
    "lua": "Lua",
    "perl": "Perl",
}

# --lang で受け付ける別名（小文字で比べる。表示の名前もそのまま使える）
LANGUAGE_ALIASES = {
    "javascript": ("js", "ts", "javascript", "typescript", "js/ts", "jsx", "tsx", "node"),
    "python": ("py", "python"),
    "php": ("php",),
    "ruby": ("rb", "ruby"),
    "go": ("go", "golang"),
    "java": ("java", "kotlin", "kt", "scala", "java/kotlin"),
    "csharp": ("cs", "c#", "csharp"),
    "dart": ("dart", "flutter"),
    "shell": ("sh", "bash", "zsh", "shell"),
    "yaml": ("yaml", "yml"),
    "docker": ("docker", "dockerfile"),
    "swift": ("swift",),
    "rust": ("rust", "rs"),
    "c": ("c", "cpp", "c++"),
    "objective-c": ("objc", "objective-c"),
    "elixir": ("elixir", "ex"),
    "lua": ("lua",),
    "perl": ("perl", "pl"),
}

# データや手順のファイル。言語ごとの対象範囲には出さない
NON_CODE_LANGUAGES = {"json", "sql", "make"}

# --lang で絞っても、いつも見る設定の言語（言語の無いファイル＝manifest・plist・.rules・.env なども同じく見る）
CONFIG_LANGUAGES = {"yaml", "docker", "json", "sql", "make"}


def language_of(name: str) -> Optional[str]:
    """ファイル名から言語を決める（中身は読まない）。ルールの言語の判定も、--lang の絞り込みも、これだけを使う。"""
    suffix = name[name.rfind(".") :].lower() if "." in name else ""
    for lang, suffixes in (*LANGUAGE_EXTENSIONS.items(), *OTHER_LANGUAGE_EXTENSIONS.items()):
        if suffix in suffixes:
            return lang
    for lang, names in LANGUAGE_FILENAMES.items():
        if any(name == n or name.startswith(n + ".") for n in names):
            return lang
    return None


TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|specs?|fixtures?|mocks?|__mocks__|examples?|e2e|integration[-_]?tests?)(/|$)"
    r"|(^|/)test_[^/]+$"
    r"|_test\.\w+$|_spec\.rb$"
    r"|(^|/)[A-Z]\w*(?:Test|Spec)\.(?:java|kt|cs)$"
    r"|\.(test|spec)\.[^/]+$",
    re.IGNORECASE,
)

# `--reveal-secrets` を付けたときだけ True になる。既定は必ずマスク。
REVEAL_SECRETS = False


def set_reveal_secrets(value: bool) -> None:
    global REVEAL_SECRETS
    REVEAL_SECRETS = value


def matches_any(path: str, globs: Iterable[str]) -> bool:
    if not globs:
        return True
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(name, g) for g in globs)


def language_matches(sf: SourceFile, languages: Iterable[str]) -> bool:
    languages = tuple(languages)
    return not languages or language_of(sf.name) in languages


def _clip(text: str, limit: int = 300) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def redact(text: str) -> str:
    """レポートに出す前に、文字列の中の秘密情報を全部伏せる。

    どのルールの指摘でも証拠には行全体が入るので、当たったルールの値だけでなく、
    同じ行のほかの秘密も伏せる。切り詰めると値の途中で切れて当たらなくなるので、切る前に呼ぶ。
    """
    if REVEAL_SECRETS:
        return text
    from .secrets import RULES as SECRET_RULES

    for rule in SECRET_RULES:
        text = rule.mask_in(text)
    return text


COMMENT_PREFIXES = ("//", "/*", "*", "#", "<!--", "-- ")
# シェルのコメントは # だけ（case の既定の分岐 *) で始まる行はコメントではない）
COMMENT_PREFIXES_BY_LANGUAGE = {"shell": ("#",)}


def _is_comment(line: str, language: Optional[str] = None) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(COMMENT_PREFIXES_BY_LANGUAGE.get(language, COMMENT_PREFIXES))


# 文字を表示するだけのコマンド。引数の引用符の中の文字は、コマンドとして読まない（echo "Install: curl … | sh"）。
# ただし出力をファイルに書く・パイプで渡す・$(…) で受け取るものは、表示するだけではないので読む。
# 名前は決まったものと、その組み合わせ（log_info・print_error・warn_msg）だけ。log_exec・debug_run・logsave のように
# 引数を実行するヘルパーは含めない
_MESSAGE_WORD = r"(?:echo|printf|print|say|usage|die|fail|abort|fatal|log|info|warn|warning|error|err|debug|msg|note|notice|success)"
_MESSAGE_COMMAND = re.compile(r"(?:(?:log|print|echo|say|show)_?)?" + _MESSAGE_WORD + r"(?:_?(?:msg|message))?$")
# コマンドの名前の前に置くもの。この次の語をコマンドの名前と見る
_COMMAND_PREFIXES = {
    "if", "then", "else", "elif", "do", "while", "until", "!", "{", "}",
    "time", "command", "builtin", "exec", "nohup", "sudo", "doas", "env", "xargs",
}  # fmt: skip
_SH_CODE_SPECIAL = re.compile(r"[\s;&|()'\"`$\\#<>]")
# sudo・doas のオプションで、次の語がその値のもの（sudo -u deploy echo の deploy はコマンドの名前ではない）
_SUDO_OPTIONS_WITH_VALUE = {"-u", "-g", "-C", "-D", "-h", "-p", "-R", "-r", "-T", "-t", "-U"}
_SH_DQ_SPECIAL = re.compile(r"[\"\\$`]")
_SH_ANSI_C_QUOTED = re.compile(r"(?:[^'\\]|\\.)*")
_SH_BRACE = re.compile(r"[{}]")
_SH_DQ_PARAMETER = re.compile(r"\$(?:\w+|[@*#?$!-])?")
# 標準出力をファイルに向けるリダイレクト（>・>>・1>・&>・>file）。>&2・2>… は書き込む先がファイルではない
_SH_OUTPUT_REDIRECT = re.compile(r"(\d*|&)(?:>>?|>\|)(&?)(.*)", re.S)
_SH_TERMINAL = {"/dev/null", "/dev/stderr", "/dev/stdout", "/dev/tty", "/dev/fd/1", "/dev/fd/2"}


def _new_frame(closer: str, captured: bool = False) -> dict:
    """コマンドを読む枠（行・$(…)・`…`・( … )）。

    cmd は今の文のコマンドの名前、word は読みかけの語。pending は、表示するだけのコマンドの文字として消す所で、
    文の終わりに、出力をファイル・パイプに渡していなければ消す。captured は $(…)・`…`（出力を受け取る）。
    """
    return {
        "kind": "code", "closer": closer, "captured": captured, "cmd": None, "word": "",
        "pending": [], "deferred": [], "to_file": False, "redirect_next": False, "skip": False, "sudo": False,
    }  # fmt: skip


def _end_word(frame: dict) -> None:
    word = frame["word"]
    frame["word"] = ""
    if not word:
        return
    if frame["redirect_next"]:
        # > のあとの語は、書き込む先
        frame["redirect_next"] = False
        frame["to_file"] |= word not in _SH_TERMINAL
        return
    redirect = _SH_OUTPUT_REDIRECT.match(word)
    if redirect:
        fd, duplicate, target = redirect.groups()
        if fd in ("", "1", "&") and not duplicate:
            if target:
                frame["to_file"] |= target not in _SH_TERMINAL
            else:
                frame["redirect_next"] = True
        return
    if frame["cmd"] is not None or re.match(r"\d*<", word):
        return
    if frame["skip"]:
        # function の次の関数の名前・sudo -u の次のユーザー
        frame["skip"] = False
        return
    if word.startswith("-"):
        frame["skip"] = frame["sudo"] and word in _SUDO_OPTIONS_WITH_VALUE
        return
    frame["sudo"] = word in ("sudo", "doas")
    if word == "function":
        frame["skip"] = True
        return
    # 代入（X=…）・if・! などの前置きの次の語を、コマンドの名前と見る
    if re.match(r"[A-Za-z_]\w*\+?=", word) or word in _COMMAND_PREFIXES:
        return
    frame["cmd"] = word.rsplit("/", 1)[-1]


def _end_statement(frame: dict, out: list, piped: bool = False) -> None:
    """文の終わり。表示するだけのコマンドの文字を消す（出力をパイプ・ファイル・$(…) に渡したものは消さない）。"""
    _end_word(frame)
    spans = [] if piped or frame["to_file"] or frame["captured"] else frame["pending"]
    if frame["closer"] == ")" and not frame["captured"]:
        # ( … ) の中は、閉じたあとの | sh などで決める
        frame["deferred"].extend(spans)
    else:
        for start, end in spans:
            out[start:end] = " " * (end - start)
    frame.update(cmd=None, pending=[], to_file=False, redirect_next=False, skip=False, sudo=False)


def shell_code(line: str, messages: bool = True) -> str:
    """シェルの 1 行から、コマンドとして読む所だけを残す（消した所は空白にし、行の長さは変えない）。

    消すのは、語の頭の # からあと（$#・${x#…}・URL の # はコメントではない）と、echo・printf・warn など
    表示するだけのコマンドに渡した引用符の中の文字（中の $(…)・`…`・$X は実行・展開されるので残す）。
    その出力をファイルに書く・パイプで渡す・$(…) で受け取るもの（echo "…" >> "$SSH_CONFIG"）と、
    ほかのコマンドの引用符の中（"$(curl …)"・git -c "http.sslVerify=false"）は残す。messages=False なら、表示するだけの
    コマンドの文字も残す（出力をファイルに書くまとまりの中。_shell_structure）。
    """
    if "#" not in line and '"' not in line and "'" not in line:
        return line
    out = list(line)
    n = len(line)
    stack = [_new_frame("")]
    i = 0

    def message_span(frame: dict, start: int, end: int) -> None:
        if frame["message"] and end > start:
            frame["owner"]["pending"].append((start, end))

    while i < n:
        frame = stack[-1]
        kind = frame["kind"]
        if kind in ("'", "$'"):
            # bash の $'…' の中は \' を読み飛ばす
            if kind == "$'":
                end = _SH_ANSI_C_QUOTED.match(line, i).end()
            else:
                end = line.find("'", i)
                end = n if end < 0 else end
            message_span(frame, i, end)
            stack.pop()
            i = end + 1
        elif kind == '"':
            m = _SH_DQ_SPECIAL.search(line, i)
            end = m.start() if m else n
            message_span(frame, i, end)
            if not m:
                break
            i, c = end, line[end]
            if c == '"':
                stack.pop()
                i += 1
            elif c == "\\":
                message_span(frame, i, min(i + 2, n))
                i += 2
            elif c == "`":
                stack.append(_new_frame("`", captured=True))
                i += 1
            elif line.startswith("$(", i):
                stack.append(_new_frame(")", captured=True))
                i += 2
            elif line.startswith("${", i):
                stack.append({"kind": "{"})
                i += 2
            else:
                i = _SH_DQ_PARAMETER.match(line, i).end()
        elif kind == "{":
            m = _SH_BRACE.search(line, i)
            if not m:
                break
            if m.group() == "{":
                stack.append({"kind": "{"})
            else:
                stack.pop()
            i = m.end()
        else:
            m = _SH_CODE_SPECIAL.search(line, i)
            end = m.start() if m else n
            frame["word"] += line[i:end]
            if not m:
                break
            i, c = end, line[end]
            if c == "&" and (line[i - 1 : i] in ("<", ">") or line[i + 1 : i + 2] == ">"):
                # >&2・2>&1・&> はリダイレクトで、文の区切りではない
                frame["word"] += c
                i += 1
            elif c in "<>":
                # "text">>file の >> はリダイレクトの始まり。前の語（2> の 2・&> の & は除く）とは分ける
                if not re.fullmatch(r"\d*|&|[<>&\d]*[<>]", frame["word"]):
                    _end_word(frame)
                frame["word"] += c
                i += 1
            elif c.isspace():
                _end_word(frame)
                i += 1
            elif c in ";&|":
                _end_statement(frame, out, piped=c == "|" and line[i + 1 : i + 2] != "|")
                i += 2 if line[i + 1 : i + 2] == c else 1
            elif c == "#" and not frame["word"]:
                out[i:] = " " * (n - i)
                break
            elif c in "'\"":
                cmd = frame["cmd"]
                quote = "$'" if c == "'" and frame["word"].endswith("$") else c
                message = messages and bool(cmd and _MESSAGE_COMMAND.match(cmd))
                stack.append({"kind": quote, "owner": frame, "message": message})
                frame["word"] += c
                i += 1
            elif c == "\\":
                frame["word"] += line[i : i + 2]
                i += 2
            elif c == "`" and frame["closer"] == "`":
                _end_statement(frame, out)
                stack.pop()
                i += 1
            elif c == "`" or line.startswith("$(", i):
                frame["word"] += c
                stack.append(_new_frame("`" if c == "`" else ")", captured=True))
                i += 1 if c == "`" else 2
            elif line.startswith("${", i):
                frame["word"] += c
                stack.append({"kind": "{"})
                i += 2
            elif c == "(":
                _end_word(frame)
                frame["cmd"] = None
                stack.append(_new_frame(")"))
                i += 1
            elif c == ")":
                if frame["closer"] == ")":
                    _end_statement(frame, out)
                    stack.pop()
                    if not frame["captured"]:
                        # ( … ) の中の消す所は、外の文の終わりで決める
                        stack[-1]["pending"].extend(frame["deferred"])
                else:
                    # case の分岐（*) …）。ここから新しい文
                    _end_statement(frame, out)
                i += 1
            else:
                frame["word"] += c
                i += 1
    # 行の終わり。閉じていない枠も、内側から順に文を終える
    for frame in reversed(stack):
        if frame["kind"] == "code":
            _end_statement(frame, out)
            for start, end in frame["deferred"]:
                out[start:end] = " " * (end - start)
    return "".join(out)


# shell_construct_end で、枠の種類ごとに探す記号（\ は次の 1 文字を読み飛ばす）
_SH_CONSTRUCT_SPECIAL = {
    '"': re.compile(r"\\|\"|`|\$\(|\$\{"),
    "`": re.compile(r"\\|`"),
    ")": re.compile(r"\\|'|\"|`|\$\(|\$\{|\$'|\(|\)"),
    "}": re.compile(r"\\|'|\"|\$\(|\{|\}"),
}
_SH_CONSTRUCT_OPEN = {"$(": ")", "${": "}", "$'": "$'", "(": ")", "{": "}", "'": "'", '"': '"', "`": "`"}


def shell_construct_end(line: str, i: int) -> int:
    """line[i] から始まる "…"・'…'・$'…'・$(…)・`…`・${…} を閉じる記号の位置。閉じなければ len(line)。

    入れ子（"$(echo "a")"）も数える。再帰しない（$( が何千も続く行でも止まらない）。
    """
    n = len(line)
    opener = line[i : i + 2] if line[i] == "$" else line[i]
    stack, i = [_SH_CONSTRUCT_OPEN[opener]], i + len(opener)
    while i < n:
        top = stack[-1]
        if top in ("'", "$'"):
            j = line.find("'", i) if top == "'" else _SH_ANSI_C_QUOTED.match(line, i).end()
            if j < 0 or j >= n:
                return n
        else:
            m = _SH_CONSTRUCT_SPECIAL[top].search(line, i)
            if not m:
                return n
            j, c = m.start(), m.group()
            if c == "\\":
                i = j + 2
                continue
            if c != top:
                stack.append(_SH_CONSTRUCT_OPEN[c])
                i = j + len(c)
                continue
        stack.pop()
        if not stack:
            return j
        i = j + 1
    return n


_SH_FLAT_SPECIAL = re.compile(r"[\s;&|()'\"`$\\#]")


def shell_flat(line: str) -> str:
    """骨組みだけの行（同じ長さ）。コメントと、引用符・$(…)・`…` の中を空白にする（区切りの記号は残す）。

    exit・if・代入を数えるときに使う（"$(echo "a; exit")" の中の exit は、親のシェルを終えない）。${…} はそのまま残す。
    """
    out = list(line)
    n = len(line)
    i = 0
    in_word = False
    while i < n:
        m = _SH_FLAT_SPECIAL.search(line, i)
        if not m:
            break
        j, c = m.start(), m.group()
        in_word = in_word or j > i
        if c == "\\":
            i, in_word = j + 2, True
        elif c.isspace() or c in ";&|()":
            i, in_word = j + 1, False
        elif c == "#":
            if not in_word:
                out[j:] = " " * (n - j)
                break
            i = j + 1
        elif c == "$" and line[j + 1 : j + 2] not in ("(", "'", "{"):
            i, in_word = j + 1, True
        else:
            end = shell_construct_end(line, j)
            if not line.startswith("${", j):
                start = j + (2 if c == "$" else 1)
                out[start:end] = " " * (end - start)
            i, in_word = end + 1, True
    return "".join(out)


def shell_word_end(text: str, i: int) -> int:
    """text[i:] から始まる 1 語の終わりの位置。引用符・$(…)・${…}・`…` の中の空白や ; では切らない。"""
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c in "'\"`" or (c == "$" and text[i + 1 : i + 2] in ("(", "{", "'")):
            i = shell_construct_end(text, i) + 1
        elif c.isspace() or c in ";&|<>()":
            break
        else:
            i += 1
    return min(i, n)


# ヒアドキュメント（<<EOF・<<-EOF・<<'EOF'。<<< は除く）と、本文を実行するコマンド（本文をコマンドとして読む）
_SH_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([A-Za-z_][\w.-]*))")
_SH_HEREDOC_RUNS = re.compile(r"(?:sh|bash|zsh|dash|ksh|ssh|su|python[0-9.]*|perl|ruby|node|php)$")
# exec > file のあとの出力は、どれもそのファイルに書く
_SH_EXEC_TO_FILE = re.compile(r"(?:^|[;&|]|\b(?:then|do|else)\s)\s*exec\s+(?:1?>>?|&>>?)(?!&)\s*(\S+)")
# 複数の文をまとめるもの（{ … }・if … fi・for … done など）の始まりと終わり。コマンドの位置のものだけ
_SH_COMPOUND = re.compile(
    r"(?:^|[;&|()]|\b(?:then|do|else)\s)\s*(if|case|for|while|until|select|\{|\}|fi|esac|done)(?=[\s;&|)<>]|$)"
)
# まとめたものの出力を、ファイル・パイプに渡すもの（} >> cfg・done | sh）
_SH_AFTER_BLOCK = re.compile(r"\s*(?:(?:1?>>?|&>>?|>\|)(?!&)\s*(\S+)|\|(?!\|))")


def _heredoc_runs(flat: str, pos: int) -> bool:
    """pos の << を含む文のコマンドが、本文を実行するもの（bash・ssh・python など）か。"""
    for word in re.split(r"[;&|(]", flat[:pos])[-1].split():
        if re.match(r"[A-Za-z_]\w*=", word) or word.startswith("-") or word in _COMMAND_PREFIXES:
            continue
        return bool(_SH_HEREDOC_RUNS.match(word.rsplit("/", 1)[-1]))
    return False


def _shell_structure(sf: SourceFile) -> tuple:
    """ファイル全体を 1 回読んで、各行の shell_code と、ヒアドキュメントの本文の行（0 から）を求める。

    cat などに渡すヒアドキュメントの本文はデータなので空白にする（bash・ssh などに渡すものはコマンドとして読む）。
    出力をファイル・パイプに渡すまとまり（{ …; } >> cfg・for … done | sh）の中と、exec > file のあとの行は、
    echo などの文字も消さない。
    """
    heredoc, flats, waiting = {}, [], []
    for idx, line in enumerate(sf.lines):
        if waiting:
            delimiter, strip_tabs, runs = waiting[0]
            body = line.lstrip("\t") if strip_tabs else line
            if body.rstrip("\r") == delimiter:
                # 終わりの行
                waiting.pop(0)
                runs = False
            heredoc[idx] = runs
            flats.append("")
            continue
        flat = shell_flat(line)
        flats.append(flat)
        for m in _SH_HEREDOC.finditer(line):
            # 引用符の中・コメントの中の << は数えない
            if flat[m.start()] == "<":
                delimiter = next(group for group in m.groups()[1:] if group is not None)
                waiting.append((delimiter, m.group(1) == "-", _heredoc_runs(flat, m.start())))
    kept, stack, exec_from = set(), [], None
    for idx, flat in enumerate(flats):
        if idx in heredoc:
            continue
        if exec_from is None:
            m = _SH_EXEC_TO_FILE.search(flat)
            if m and m.group(1) not in _SH_TERMINAL:
                exec_from = idx
        for m in _SH_COMPOUND.finditer(flat):
            if m.group(1) in ("if", "case", "for", "while", "until", "select", "{"):
                stack.append(idx)
            elif stack:
                start = stack.pop()
                after = _SH_AFTER_BLOCK.match(flat, m.end())
                if after and (after.group(1) is None or after.group(1) not in _SH_TERMINAL):
                    kept.update(range(start, idx + 1))
    if exec_from is not None:
        kept.update(range(exec_from, len(flats)))
    views = [
        " " * len(line) if heredoc.get(idx) is False else shell_code(line, messages=idx not in kept)
        for idx, line in enumerate(sf.lines)
    ]
    return views, set(heredoc)


def shell_lines(sf: SourceFile) -> list:
    """sf の各行を shell_code に通したもの（_shell_structure）。ファイルごとに 1 回だけ作り、シェルのルールで分け合う。"""
    if "_shell_structure" not in sf.__dict__:
        sf.__dict__["_shell_structure"] = _shell_structure(sf)
    return sf.__dict__["_shell_structure"][0]


def shell_heredoc_lines(sf: SourceFile) -> set:
    """ヒアドキュメントの本文（と終わり）の行。0 から数える。"""
    shell_lines(sf)
    return sf.__dict__["_shell_structure"][1]


def shell_args(command: Optional[str] = None) -> str:
    """シェルのルールで、command のあとの引数を読み進める正規表現（shell_code を通した行に使う）。

    引用符の中の | ; & と、2>&1・&> の & は区切りと見ない。どの選び方も最初の 1〜2 文字で決まるので、
    組み合わせは増えない。command を渡すと次の command の手前で止める（同じ名前が並ぶ長い行で、
    当たり始めの位置ごとに行末まで読み直さないため）。
    """
    stop = r"(?!\b" + command + r"\b)" if command else ""
    return r"(?:" + stop + r"(?:[^\n|;&\"']|[<>]&|&>|\"[^\"\n]*\"|'[^'\n]*'))*"


@dataclass
class LineRule:
    id: str
    title: str
    severity: Severity
    category: str
    message: str
    remediation: str
    pattern: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    languages: tuple = ()
    path_globs: tuple = ()
    exclude_globs: tuple = ()
    unless: Optional[str] = None
    # 当たった部分（match.group(0)）だけに当てる除外。行全体に当たる unless と違い、同じ行のほかの当たりは見る。
    # pattern に入れないので、マスク（mask_in）は除外した値も伏せる
    value_unless: Optional[str] = None
    require_file: Optional[str] = None
    require_line: Optional[str] = None
    secret: bool = False
    secret_group: int = 0
    test_severity: Optional[Severity] = None
    tags: tuple = ()
    multiline: bool = False
    skip_comments: bool = True
    # シェルのルール。shell_code を通した行（コメントと、echo などで表示するだけの文字列を消したもの）で照合する。
    # unless・require_line と証拠は元の行
    shell_view: bool = False
    # 複数行のルールでも、証拠（と指紋）を当たり始めた行の全体にする（1 行のルールから複数行に変えても、指紋を変えないため）。
    # 同じ行の 2 つ目からの当たりは出さない
    whole_line_evidence: bool = False

    def __post_init__(self) -> None:
        self._pattern = re.compile(self.pattern)
        self._unless = re.compile(self.unless) if self.unless else None
        self._value_unless = re.compile(self.value_unless) if self.value_unless else None
        self._require_file = re.compile(self.require_file) if self.require_file else None
        self._require_line = re.compile(self.require_line) if self.require_line else None

    def applies(self, sf: SourceFile) -> bool:
        if not language_matches(sf, self.languages):
            return False
        if not matches_any(sf.relpath, self.path_globs):
            return False
        if self.exclude_globs and matches_any(sf.relpath, self.exclude_globs):
            return False
        if self._require_file and not self._require_file.search(sf.text):
            return False
        return True

    def evaluate(self, sf: SourceFile) -> Iterable[Finding]:
        severity = self.severity
        if self.test_severity is not None and sf.is_test_path():
            severity = self.test_severity

        language = language_of(sf.name)
        reported = set()
        for lineno, subject, _match in self._iter_matches(sf):
            # 複数行のルールは、当たった文字列ではなく、当たり始めた行でコメントかを見る
            line = sf.lines[lineno - 1] if self.multiline and lineno <= len(sf.lines) else subject
            # コメントに書いた秘密もリポジトリからは読めるので、秘密のルールはコメント行も見る
            if self.skip_comments and not self.secret and _is_comment(line, language):
                continue
            if self._require_line and not self._require_line.search(subject):
                continue
            if self._unless and self._unless.search(subject):
                continue
            if self.whole_line_evidence:
                if lineno in reported:
                    continue
                reported.add(lineno)

            evidence = _clip(redact(line if self.whole_line_evidence else subject))

            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=severity,
                category=self.category,
                message=self.message,
                remediation=self.remediation,
                location=Location(path=sf.relpath, line=lineno, snippet=evidence),
                cwe=self.cwe,
                owasp=self.owasp,
                evidence=evidence,
            )

    def _iter_matches(self, sf: SourceFile):
        if self.multiline:
            for match in self._pattern.finditer(sf.text):
                if self._excluded(match):
                    continue
                lineno = sf.text.count("\n", 0, match.start()) + 1
                yield lineno, match.group(0), match
            return
        for lineno, line in enumerate(sf.lines, 1):
            target = shell_lines(sf)[lineno - 1] if self.shell_view else line
            # 1 行に 1 件。value_unless で外した当たりの先に、外さない当たりがあればそれを使う
            match = next((m for m in self._pattern.finditer(target) if not self._excluded(m)), None)
            if match:
                yield lineno, line, match

    def _excluded(self, match) -> bool:
        return bool(self._value_unless and self._value_unless.search(match.group(0)))

    def mask_in(self, text: str) -> str:
        """text の中でこのルールに当たる値を、すべてマスクに置き換える。"""

        def replace(match) -> str:
            try:
                start, end = match.span(self.secret_group)
            except IndexError:
                start, end = match.span(0)
            if start == end:  # 値の無い当たり（PEM のヘッダ行だけ、など）
                return match.group(0)
            whole = match.group(0)
            s, e = start - match.start(), end - match.start()
            return whole[:s] + mask(whole[s:e]) + whole[e:]

        return self._pattern.sub(replace, text)


@dataclass
class FileRule:
    id: str
    title: str
    severity: Severity
    category: str
    message: str
    remediation: str
    check: Callable[[SourceFile], Iterable[tuple]]
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    languages: tuple = ()
    path_globs: tuple = ()
    exclude_globs: tuple = ()
    test_severity: Optional[Severity] = None

    def applies(self, sf: SourceFile) -> bool:
        if not language_matches(sf, self.languages):
            return False
        if not matches_any(sf.relpath, self.path_globs):
            return False
        if self.exclude_globs and matches_any(sf.relpath, self.exclude_globs):
            return False
        return True

    def evaluate(self, sf: SourceFile) -> Iterable[Finding]:
        severity = self.severity
        if self.test_severity is not None and sf.is_test_path():
            severity = self.test_severity
        for lineno, evidence in self.check(sf):
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=severity,
                category=self.category,
                message=self.message,
                remediation=self.remediation,
                location=Location(path=sf.relpath, line=lineno, snippet=_clip(redact(evidence))),
                cwe=self.cwe,
                owasp=self.owasp,
                evidence=redact(evidence).strip(),
            )
