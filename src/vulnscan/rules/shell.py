"""シェルスクリプトの、ファイル全体を見るルール（CFG-018: 空の変数で / 以下を消しうる rm -r）。

どの行も shell_lines（コメントと、echo などで表示するだけの文字列を消したもの）を読む。行の中の位置は元の行と同じ。

空でないと確かめた所は、迷いようのない形だけを数える（同じ行の && や ||、if [ -n ] の then の枝の中、
一番外側の行の頭の || exit や ${X:?}）。関数・if・case などの中の確かめは、どの枝・どの呼び出しで通るかを
行ごとの読み方では決められないので追わない（追うたびに、守られていない rm を見落とす形が見つかった）。
確かめたあとで値を入れ直すと（D=…・read D・local D・shift）、そこから先は守られていないと見る。
"""

from __future__ import annotations

import bisect
import math
import re
from typing import Iterable

from ..models import Severity, SourceFile
from .base import FileRule, shell_args, shell_construct_end, shell_flat, shell_heredoc_lines, shell_lines, shell_word_end

_NAME = r"([A-Za-z_]\w*|[1-9])"
# rm をコマンドの位置で呼んでいるもの（git rm・aws s3 rm のようなサブコマンドは外す）と、その引数。
# 前に置けるのは if・!・then、command・$SUDO・sudo -u user・doas、\rm（エイリアスを避ける書き方）など
_RM_COMMAND = re.compile(
    r"(?:^|[;&|({`!]|\b(?:then|do|else|if|while|until)\s)\s*"
    r"(?:(?:command|exec|xargs|time|nohup|\$\{?\w+\}?|(?:sudo|doas)(?:\s+-\S+(?:\s+(?![-\\/])[\w.-]+)?)*)\s+)*"
    r"\\?(?:/(?:usr/)?bin/)?rm\s(" + shell_args() + r")"
)
_RM_RECURSIVE = re.compile(r"(?:^|\s)(?:-[A-Za-z]*[rR][A-Za-z]*|--recursive)(?=\s|$)")
# 変数のすぐあとが / で終わる対象（"$DIR/"・"$DIR"/*・$DIR/・"$1/"*）。"${DIR:?}/" は当たらない
_RM_TARGET = re.compile(
    r"(?:^|(?<=\s))(?:\"\$\{?" + _NAME + r"\}?(?:/\"|\"/)|\$\{?" + _NAME + r"\}?/)\*?(?=[\s)]|$)"
)

# --- ファイルの形（ブロックの深さ・if の枝・関数）。どれも shell_flat を通した行（引用符・$(…) の中は空白）に使う
# if・case・ループ・関数や { … }・複数行の ( … ) の中。キーワードはコマンドの位置のものだけ数える（echo done は数えない）
_BLOCK_OPEN = re.compile(
    r"(?:^|[;&|(!]|\b(?:then|do|else)\s)\s*(?:if|case|for|while|until|select)\b|(?:^|\s)\{\s*$|\(\s*$"
)
_BLOCK_CLOSE = re.compile(r"(?:^|[;&|])\s*(?:fi|esac|done)\b|^\s*[})]")
_IF_KEYWORD = re.compile(r"(?:^|[;&|(!]|\b(?:then|do|else)\s)\s*(if|elif|else|fi)\b")
_BRACE_OPEN = re.compile(r"(?:^|\s)\{\s*$")
_BRACE_CLOSE = re.compile(r"^\s*\}")
_FUNCTION = re.compile(r"(?:^|[;&|])\s*(?:function\s+([\w.:-]+)(?:\s*\(\s*\))?|([\w.:-]+)\s*\(\s*\))")
# 条件つきで動く所・呼ばれないかもしれない所の始まり（これより後ろの確かめは、いつも通るとは限らない）。
# &&・||・if などのキーワード・( … )（exit はその中だけを終える）・関数の定義 name() と { … }
_CONDITIONAL = re.compile(
    r"&&|\|\||\b(?:if|then|else|elif|do|case|while|until|for|select)\b|\(\s*\)|(?<![$\w])\(|(?:^|(?<=[\s;&|]))\{(?=\s|$)"
)
# $1 などを入れ直すもの
_POSITIONAL_RESET = re.compile(r"(?:^|[;&|({]|\b(?:then|do|else)\s)\s*(?:shift|set\s+--)\b")

# --- 空にならない変数（1 行に単独で書いた代入 1 か所だけで、値が空にならないもの）
_LONE_ASSIGNMENT = re.compile(r"^\s*(?:(?:export|readonly|local|declare|typeset)\s+(?:-\w+\s+)*)?([A-Za-z_]\w*)=")
_LINE_REST = re.compile(r"\s*;?\s*")
# 代入（VAR=値 cmd・make PREFIX=…・if の中・A=1 B=2 も）
_ASSIGNED = re.compile(r"(?<![\w$.-])([A-Za-z_]\w*)\+?=(?!=)")
# 値を空にする・外から読み込むもの（= の無い名前）。export・readonly は値を変えないので数えない。
# 前置きの代入（IFS= read）の値は ( ; などで止める（( の位置ごとに行の終わりまで読み直さない）
_RESETS = re.compile(
    r"(?:^|[;&|({!]|\b(?:then|do|else|while|until|if)\s)\s*(?:[A-Za-z_]\w*=[^\s;&|()]*\s+)*"
    r"(unset|local|declare|typeset|read|mapfile|readarray|getopts|for|select)\s+([^;&|<>\n]*)"
)
_PRINTF_V = re.compile(r"\bprintf\s+-v\s+([A-Za-z_]\w*)")
# ほかのファイルを読み込む（どの変数も入れ直しうる）
_SOURCES = re.compile(r"(?:^|[;&|({!]|\b(?:then|do|else)\s)\s*(?:source|\.)\s+\S")
_BRACED = re.compile(r"\$\{((?:[^{}]|\{[^{}]*\})*)\}")
_OTHER_EXPANSION = re.compile(r"\$\((?:[^()]|\([^()]*\))*\)|`[^`]*`|\$(?:\w+|[@*#?$!-])")

# --- 空でないと確かめる書き方。単一引用符・$(…) の中を空白にした行（_Script.checks）に使う
_ASSERTED = re.compile(r"\$\{" + _NAME + r":(?:\?|=((?:[^{}]|\{[^{}]*\})*)\})")
_OPERAND_END = r"(?=[\s;&|)\]]|$)"
# -n・-d・-e は値が空なら偽（! -z も同じ）。[ ] と test は、引用符が無いと [ -n ] になっていつも真なので、引用符つきだけ。
# 変数そのものを確かめるもの（"$D/bin"・"${D:-x}" は D を確かめていない）
_NONEMPTY_TEST = re.compile(
    r"(?:\[\[\s+(?:-[nde]|!\s+-z)\s+\"?\$\{?" + _NAME + r"\}?\"?"
    r"|(?:\[|\btest)\s+(?:-[nde]|!\s+-z)\s+\"\$\{?" + _NAME + r"\}?\")" + _OPERAND_END
)
# -z は引用符が無くても、空なら [ -z ]（いつも真）になって向きが同じ
_EMPTY_TEST = re.compile(
    r"(?:\[\[\s+(?:-z|!\s+-[nde])\s+\"?\$\{?" + _NAME + r"\}?\"?"
    r"|(?:\[|\btest)\s+(?:-z\s+\"?\$\{?" + _NAME + r"\}?\"?|!\s+-[nde]\s+\"\$\{?" + _NAME + r"\}?\"))"
    + _OPERAND_END
)
# 確かめの終わり（[ ] の閉じかっこ。test は && || ; の手前）と、その中のほかの条件（-o・-a・&&・||）
_TEST_END = re.compile(r"\]\]?|&&|\|\||;")
_TEST_OTHER_CONDITION = re.compile(r"(?:^|\s)-[oa](?=\s)|&&|\|\|")
_CONNECTOR = re.compile(r"\s*(&&|\|\|)")
_THEN = re.compile(r"\bthen\b")
_IN_IF = re.compile(r"\b(el)?if\s+(!\s+)?$")
_SETS = re.compile(r"(?:^|[;&|]|\b(?:then|else)\s)\s*([A-Za-z_]\w*)=")
_BRACE_GROUP = re.compile(r"\s*\{\s*$")
_BACKGROUND = re.compile(r"(?<![&>])&(?![&>])")
_BRANCH_END = re.compile(r"\b(?:else|elif|fi)\b")
_CHECK_SPECIAL = re.compile(r"\\|'|\"|`|\$\(|\$'")
# 確かめた所から、続きを探す長さ（[ -z "$X" ] が何千も並ぶ行で、位置ごとに行末まで探さない）
_LOOKAHEAD = 200
# 行末の \ で続けた if の条件を読む行の数
_CONTINUATION_LINES = 20


def _never_empty(word: str) -> bool:
    """代入の値（引用符つきの 1 語）が、空や / にならないか。

    $…・$(…)・`…` の外に、/ と . 以外の固定の文字があるもの（"$ROOT/dist"）と、${X:-既定値}・${X:=既定値} の
    既定値がそうなっているもの・${X:?} は空にならない。$1・"$(pwd)"・"${1:-$DIR}"・"$PREFIX/" はなりうる。
    """
    for m in _BRACED.finditer(word):
        op = re.match(r"(?:\w+|[@*#?$!-]):([-=?])(.*)", m.group(1), re.S)
        if op and (op.group(1) == "?" or _never_empty(op.group(2))):
            return True
    rest = _OTHER_EXPANSION.sub("", _BRACED.sub("", word))
    return bool(re.sub(r"[\"'\s/.]", "", rest))


def _value_never_empty(code: str, pos: int) -> bool:
    return _never_empty(code[pos : shell_word_end(code, pos)])


def _reset_names(code: str) -> set:
    """read・unset・local・for・printf -v などで、値を外から読み込む・空にする名前。"""
    names = set(_PRINTF_V.findall(code))
    for m in _RESETS.finditer(code):
        keyword, words = m.group(1), m.group(2).split()
        if keyword in ("for", "select"):
            words = words[:1]
        skip = False
        for word in words:
            if skip:
                skip = False
            elif word.startswith("-"):
                # read -p prompt・-d delim・-t 5 などは、次の語がオプションの値
                skip = keyword == "read" and word[-1] in "pdtnNui"
            elif re.fullmatch(r"[A-Za-z_]\w*", word):
                names.add(word)
    return names


def _blank_for_checks(code: str) -> str:
    """確かめを探す行。単一引用符・$'…'・$(…)・`…` の中を空白にする（同じ長さ）。

    ssh host '[ -n "$D" ] || exit' や sed 's/${D:?}/x/' は、この変数を確かめていない。二重引用符の中（[ -n "$D" ]）は残す。
    """
    out = list(code)
    i = 0
    while True:
        m = _CHECK_SPECIAL.search(code, i)
        if not m:
            break
        j, c = m.start(), m.group()
        if c == "\\":
            i = j + 2
            continue
        end = shell_construct_end(code, j)
        if c != '"':
            out[j + len(c) : end] = " " * (end - j - len(c))
        i = end + 1
    return "".join(out)


class _Script:
    """ファイル全体を 1 回だけ読んで求めておくもの。どれも、要るときに初めて作るものもある。"""

    def __init__(self, sf: SourceFile) -> None:
        heredoc = shell_heredoc_lines(sf)
        # ヒアドキュメントの本文は、このシェルの代入・確かめ・if ではない
        self.code = [" " * len(code) if idx in heredoc else code for idx, code in enumerate(shell_lines(sf))]
        # 引用符・$(…) の中を空白にした骨組み（exit・if・代入を数える）と、確かめを探す行
        self.flat = [shell_flat(code) for code in self.code]
        self.checks = [_blank_for_checks(code) for code in self.code]
        # 各行の頭での、ブロックの深さ（最後に、ファイルの終わりの深さを足す）
        self.depth = [0]
        for flat in self.flat:
            opened = len(_BLOCK_OPEN.findall(flat)) - len(_BLOCK_CLOSE.findall(flat))
            self.depth.append(max(0, self.depth[-1] + opened))
        self._first_conditional, self._indent, self._continues = {}, {}, {}
        self._ifs = self._braces = self._exits = None
        self._functions()
        self._reassignments()

    def first_conditional(self, idx: int) -> float:
        if idx not in self._first_conditional:
            m = _CONDITIONAL.search(self.flat[idx])
            self._first_conditional[idx] = m.start() if m else math.inf
        return self._first_conditional[idx]

    def starts_line(self, idx: int, pos: int) -> bool:
        """pos が、行の頭（空白のあと）か。行の頭の空白は行ごとに 1 回だけ数える（if が並ぶ行で、位置ごとに数え直さない）。"""
        if idx not in self._indent:
            code = self.code[idx]
            self._indent[idx] = len(code) - len(code.lstrip())
        return self._indent[idx] == pos

    def unconditional(self, idx: int, pos: int) -> bool:
        """idx 行の pos が、一番外側で、前に条件の無い所か（その行を通れば、いつも通る）。"""
        return self.depth[idx] == 0 and self.first_conditional(idx) > pos

    def _functions(self) -> None:
        """関数の本体の行（function_of: 行 → いちばん内側の関数の定義の行、無ければ -1）と、exit する関数の名前。

        止めるものとして数えるのは exit と、同じファイルで、条件を挟まずに exit するように定義した関数（die() { …; exit 1; }）
        だけ。定義の無い die・usage は exit しないかもしれず、一番外側の return は bash ではエラーのまま先に進む。
        """
        self.function_of = [-1] * len(self.code)
        exiting = set()
        exit_statement = re.compile(r"(?:^|[;&|{(]|\b(?:then|else|do)\s)\s*exit(?![\w=-])")
        for idx, flat in enumerate(self.flat):
            m = _FUNCTION.search(flat)
            if not m:
                continue
            name = m.group(1) or m.group(2)
            body = flat[m.end() :]
            if self.depth[idx + 1] > self.depth[idx]:
                # 複数行の本体（name() { 改行 … }・name() (）。深さが戻るまで
                lines = [idx]
                j = idx + 1
                while j < len(self.code) and self.depth[j] > self.depth[idx]:
                    lines.append(j)
                    j += 1
                inner = self.depth[idx] + 1
                stops = any(
                    self.depth[k] == inner and (e := exit_statement.search(self.flat[k])) and e.start() < self.first_conditional(k)
                    for k in lines[1:]
                )
            else:
                # 1 行の本体（name() { …; exit 1; }）
                lines = [idx]
                start = body.find("{")
                text = body[start + 1 :] if start >= 0 else body
                conditional = _CONDITIONAL.search(text)
                e = exit_statement.search(text)
                stops = bool(e) and (not conditional or e.start() < conditional.start())
            for k in lines:
                self.function_of[k] = idx
            if stops:
                exiting.add(name)
        word = r"(?:exit" + "".join("|" + re.escape(name) for name in sorted(exiting)) + r")(?![\w=-])"
        # && や || のすぐあとの exit（{ exit 1; }・{ echo …; exit 1; } も）・文の頭の exit・枝の頭の exit
        self.exit_here = re.compile(r"\s*(?:\{(?:[^}]*?;)?\s*)?" + word)
        self.exit_statement = re.compile(r"(?:^|[;&|{(]|\b(?:then|else|do)\s)\s*" + word)
        self.exit_at = re.compile(r"(?:^|[;{(])\s*" + word)

    def _reassignments(self) -> None:
        """名前 → 値を入れ直す行（1 から、昇順）。代入・read・local・unset・for、$1 などは shift・set --。"""
        self.reassigned = {}
        for idx, flat in enumerate(self.flat):
            names = set(_ASSIGNED.findall(flat)) | _reset_names(flat)
            if _POSITIONAL_RESET.search(flat):
                names.update("123456789")
            for name in names:
                self.reassigned.setdefault(name, []).append(idx + 1)

    def until_reassigned(self, name: str, first: int, last: float) -> float:
        """first から last までの確かめを、その名前を入れ直す行の手前で切る。"""
        lines = self.reassigned.get(name, [])
        i = bisect.bisect_left(lines, first)
        return min(last, lines[i] - 1) if i < len(lines) else last

    def key(self, name: str, idx: int):
        """確かめの範囲を引く鍵。$1 などは関数ごとに別の値なので、関数の本体ごとに分ける。"""
        return (name, self.function_of[idx]) if name.isdigit() else name

    def if_branches(self) -> tuple:
        """if・elif の位置（行, 位置）→ then の枝の終わり（行, 位置）と、if を閉じる fi の行。行は 0 から数える。

        ファイルを 1 回だけ読む（if ごとに fi を探し直すと、if が並ぶファイルで行の数の 2 乗になる）。
        """
        if self._ifs is None:
            branch_end, fi_line, stack = {}, {}, []
            for idx, flat in enumerate(self.flat):
                for m in _IF_KEYWORD.finditer(flat):
                    word, here = m.group(1), (idx, m.start(1))
                    if word == "if":
                        stack.append({"keys": [here], "branch": here})
                        continue
                    if not stack:
                        continue
                    top = stack[-1]
                    if top["branch"] is not None:
                        branch_end[top["branch"]] = here
                    top["branch"] = here if word == "elif" else None
                    if word == "elif":
                        top["keys"].append(here)
                    elif word == "fi":
                        stack.pop()
                        fi_line.update(dict.fromkeys(top["keys"], idx))
            last = (len(self.code) - 1, None)
            for top in stack:
                if top["branch"] is not None:
                    branch_end[top["branch"]] = last
                fi_line.update(dict.fromkeys(top["keys"], last[0]))
            self._ifs = (branch_end, fi_line)
        return self._ifs

    def brace_end(self, idx: int) -> int:
        """行の終わりの { で始まる { … } を閉じる } の行。閉じなければ最後の行。"""
        if self._braces is None:
            self._braces, stack = {}, []
            for i, flat in enumerate(self.flat):
                if _BRACE_CLOSE.match(flat) and stack:
                    self._braces[stack.pop()] = i
                if _BRACE_OPEN.search(flat):
                    stack.append(i)
            self._braces.update(dict.fromkeys(stack, len(self.code) - 1))
        return self._braces.get(idx, idx)

    def exits_and_sets(self) -> tuple:
        """深さ → 条件より前に exit のある行、(名前, 深さ) → 条件より前に空でない値を入れる行。どれも昇順。"""
        if self._exits is None:
            exits, sets = {}, {}
            for idx, flat in enumerate(self.flat):
                depth, conditional = self.depth[idx], self.first_conditional(idx)
                m = self.exit_statement.search(flat)
                if m and m.start() < conditional:
                    exits.setdefault(depth, []).append(idx)
                for m in _SETS.finditer(flat):
                    if m.start() < conditional and _value_never_empty(self.code[idx], m.end()):
                        sets.setdefault((m.group(1), depth), []).append(idx)
            self._exits = (exits, sets)
        return self._exits

    def branch_stops(self, idx: int, start: int, end: tuple, name: str) -> bool:
        """一番外側の if [ -z "$X" ] の then の枝（idx 行の start から end まで）が、条件を挟まずに exit するか、
        X に空でない値を入れるか。"""
        end_line, end_pos = end
        if self._slice_stops(idx, start, end_pos if end_line == idx else None, name):
            return True
        if end_line == idx:
            return False
        exits, sets = self.exits_and_sets()
        for lines in (exits.get(1, []), sets.get((name, 1), [])):
            i = bisect.bisect_right(lines, idx)
            if i < len(lines) and lines[i] < end_line:
                return True
        return self._slice_stops(end_line, 0, end_pos, name)

    def _slice_stops(self, idx: int, start: int, stop, name: str) -> bool:
        text = self.flat[idx][start:stop]
        conditional = _CONDITIONAL.search(text)
        limit = conditional.start() if conditional else len(text)
        if self.exit_at.search(text, 0, limit):
            return True
        m = re.compile(r"(?:^|[;{(])\s*" + re.escape(name) + r"=").search(text, 0, limit)
        return bool(m) and _value_never_empty(self.code[idx], start + m.end())

    def condition(self, idx: int, start: int) -> str:
        """if の条件（idx 行の start から then まで）。then が無く、行末の \\ で続けた行はそれも読む。

        どの行も _LOOKAHEAD 文字までしか読まない（if が並ぶ長い行で、確かめのたびに行の残りを読み直さない）。
        """
        text, j = self.flat[idx][start : start + _LOOKAHEAD], idx
        then = _THEN.search(text)
        while not then and self.continues(j) and j + 1 < len(self.code) and j - idx < _CONTINUATION_LINES:
            j += 1
            text += "\n" + self.flat[j][:_LOOKAHEAD]
            then = _THEN.search(text)
        return text[: then.start()] if then else text

    def continues(self, idx: int) -> bool:
        """行末の \\ で、次の行に続いているか。"""
        if idx not in self._continues:
            self._continues[idx] = self.flat[idx].rstrip().endswith("\\")
        return self._continues[idx]


def _never_empty_variables(script: _Script) -> dict:
    """空にならない変数と、代入した行（1 から）。if・case・ループ・関数・{ … }・( … ) の外の 1 行に単独で書いた
    代入 1 か所だけで、値が空にならないもの。ほかの所で入れ直す（VAR=値 cmd・if の中・read・for）・空にする
    （unset・local VAR）変数は含めない。
    """
    lone, others = {}, set()
    for idx, code in enumerate(script.code):
        if not code.strip():
            continue
        flat = script.flat[idx]
        lone_name = None
        m = _LONE_ASSIGNMENT.match(code)
        if m and script.depth[idx] == 0:
            end = shell_word_end(code, m.end())
            if _LINE_REST.fullmatch(code[end:]):
                lone_name = m.group(1)
                lone.setdefault(lone_name, []).append((idx + 1, _never_empty(code[m.end() : end])))
        others.update(name for name in _ASSIGNED.findall(flat) if name != lone_name)
        others.update(name for name in _reset_names(flat) if name != lone_name)
    return {
        name: values[0][0]
        for name, values in lone.items()
        if len(values) == 1 and values[0][1] and name not in others
    }


def _checked_variables(script: _Script) -> tuple:
    """空でないと確かめている所。

    戻り値の ranges は 鍵（_Script.key）→ 守られている行の範囲（_merged の形。行は 1 から）、
    same_line は 行 → [(名前, 位置, つなぎ)]（同じ行のその位置より後ろの rm は、間の書き方しだいで守られている）。
    """
    explicit, same_line = {}, {}

    def guard(name: str, idx: int, first: int, last: float) -> None:
        # 確かめた行（idx）から見て、次に値を入れ直す行の手前まで
        last = script.until_reassigned(name, first, last)
        if first <= last:
            explicit.setdefault(script.key(name, idx), []).append((first, last))

    for idx, checks in enumerate(script.checks):
        lineno = idx + 1
        flat = script.flat[idx]
        # 一番外側の ${X:?}・${X:=値}（: "${X:?}"・X=${1:?}）。そこから最後まで
        for m in _ASSERTED.finditer(checks):
            if script.unconditional(idx, m.start()) and (m.group(2) is None or _never_empty(m.group(2))):
                guard(m.group(1), idx, lineno, math.inf)
        for test, nonempty in ((_NONEMPTY_TEST, True), (_EMPTY_TEST, False)):
            for m in test.finditer(checks):
                name = next(group for group in m.groups() if group)
                # [ -n "$D" -o … ] のように、ほかの条件を足したものは数えない
                close = _TEST_END.search(checks, m.end(), min(len(checks), m.end() + _LOOKAHEAD))
                inside_end = close.start() if close else m.end()
                if _TEST_OTHER_CONDITION.search(checks, m.end(), inside_end):
                    continue
                after_test = close.end() if close and close.group().startswith("]") else inside_end
                in_if = _IN_IF.search(checks, max(0, m.start() - 12), m.start())
                if in_if:
                    positive = nonempty != bool(in_if.group(2))
                    _check_in_if(script, idx, m, name, positive, in_if, guard, same_line)
                    continue
                conn = _CONNECTOR.match(checks, after_test)
                if not conn:
                    continue
                after = conn.end()
                kind = conn.group(1)
                if kind == "&&" and nonempty:
                    same_line.setdefault(lineno, []).append((name, after, "&&"))
                    if _BRACE_GROUP.fullmatch(flat, after):
                        # [ -n "$D" ] && { 改行 … } の中
                        guard(name, idx, lineno + 1, script.brace_end(idx))
                elif kind == "||" and not nonempty:
                    same_line.setdefault(lineno, []).append((name, after, "||"))
                elif script.unconditional(idx, m.start()):
                    # 一番外側の [ -n "$D" ] || exit・[ -z "$D" ] && exit・[ -z "$D" ] && D=値。次の行から
                    stops = bool(script.exit_here.match(flat, after, min(len(flat), after + _LOOKAHEAD)))
                    if stops or (kind == "&&" and _sets_never_empty(script.code[idx], after, name)):
                        guard(name, idx, lineno + 1, math.inf)
    return _merged(explicit), same_line


def _check_in_if(script: _Script, idx: int, m: re.Match, name: str, positive: bool, in_if, guard, same_line) -> None:
    """if [ … ] の中の確かめ。"""
    flat = script.flat[idx]
    then = _THEN.search(flat, m.end(), min(len(flat), m.end() + _LOOKAHEAD))
    condition = script.condition(idx, m.end())
    at_line_start = script.starts_line(idx, in_if.start())
    if positive:
        # if [ -n "$D" ] || …（D が空でも通る）は外す。守るのは then の枝だけ（else の枝では D が空）
        if re.search(r"\|\||\s-o\s", condition):
            return
        if then:
            same_line.setdefault(idx + 1, []).append((name, then.end(), "then"))
        if at_line_start:
            branch_end, _fi_line = script.if_branches()
            end_line = branch_end.get((idx, in_if.start()), (idx, None))[0]
            # then の枝の、if の行と else・elif・fi の行のあいだの行
            guard(name, idx, idx + 2, end_line)
        return
    # if [ -z "$D" ]; then exit; fi のあとから。一番外側で行の頭から書いた if だけ（elif・&& のあとの if・
    # ループの中の if は通らないことがある）。条件に && があるもの（D が空でも通らない）は外す
    if in_if.group(1) or not at_line_start or script.depth[idx] != 0 or re.search(r"&&|\s-a\s", condition):
        return
    branch_end, fi_line = script.if_branches()
    key = (idx, in_if.start())
    start = then.end() if then else len(flat)
    if script.branch_stops(idx, start, branch_end.get(key, (idx, None)), name):
        guard(name, idx, fi_line.get(key, idx) + 2, math.inf)


def _sets_never_empty(code: str, pos: int, name: str) -> bool:
    m = re.compile(r"\s*" + re.escape(name) + r"=").match(code, pos)
    return bool(m) and _value_never_empty(code, m.end())


def _merged(spans: dict) -> dict:
    """鍵 → (始まりの行の一覧, 終わりの行の一覧)。重なる範囲はまとめ、rm の行を二分探索で引けるようにする
    （rm ごとに範囲を全部見ると、確かめと rm が並ぶファイルで 2 乗になる）。"""
    merged = {}
    for key, items in spans.items():
        firsts, lasts = [], []
        for first, last in sorted(items):
            if lasts and first <= lasts[-1] + 1:
                lasts[-1] = max(lasts[-1], last)
            else:
                firsts.append(first)
                lasts.append(last)
        merged[key] = (firsts, lasts)
    return merged


def _same_line_guarded(code: str, pos: int, rm_at: int, kind: str) -> bool:
    """同じ行の確かめと rm の間で、守りが切れていないか。

    [ -n "$X" ] && … rm は ; と & と ||、[ -z "$X" ] || … rm は ; と & と &&、if [ -n "$X" ]; then … rm は
    else・elif・fi を挟まないこと。
    """
    between = code[pos:rm_at]
    if pos > rm_at:
        return False
    if kind == "then":
        return not _BRANCH_END.search(between)
    if ";" in between or _BACKGROUND.search(between):
        return False
    return ("||" if kind == "&&" else "&&") not in between


def _rm_with_empty_variable(sf: SourceFile) -> Iterable[tuple]:
    script = None
    for lineno, line in enumerate(sf.lines, 1):
        if "rm" not in line:
            continue
        code = shell_lines(sf)[lineno - 1]
        for command in _RM_COMMAND.finditer(code):
            args = command.group(1)
            if not _RM_RECURSIVE.search(args):
                continue
            if script is None:
                script = _Script(sf)
                never_empty = _never_empty_variables(script)
                ranges, same_line = _checked_variables(script)
                sources = [i + 1 for i, flat in enumerate(script.flat) if _SOURCES.search(flat)]
            names = [m.group(1) or m.group(2) for m in _RM_TARGET.finditer(args)]
            rm_at = command.start(1)

            def guarded(name: str) -> bool:
                assigned = never_empty.get(name)
                # 代入と rm の間で、ほかのファイルを読み込んでいないこと（. ./config.sh が入れ直しうる）
                if (
                    assigned is not None
                    and assigned < lineno
                    and bisect.bisect_left(sources, assigned) == bisect.bisect_left(sources, lineno)
                ):
                    return True
                firsts, lasts = ranges.get(script.key(name, lineno - 1), ((), ()))
                i = bisect.bisect_right(firsts, lineno) - 1
                if i >= 0 and lasts[i] >= lineno:
                    return True
                return any(
                    other == name and _same_line_guarded(code, pos, rm_at, kind)
                    for other, pos, kind in same_line.get(lineno, ())
                )

            if any(not guarded(name) for name in names):
                yield lineno, line.strip()
                break


FILE_RULES = [
    FileRule(
        id="CFG-018",
        title="空の変数で / 以下を消しうる rm -r",
        severity=Severity.LOW,
        category="hardening",
        message="変数が空か未設定だと \"$DIR/\"* が /* になり、ディスクの中身を消します。",
        remediation="\"${DIR:?}/\"* のように、空なら止まる形で書いてください。",
        check=_rm_with_empty_variable,
        languages=("shell",),
        # fish は if … end・and・or と書き方が違い、確かめを読めないので見ない
        exclude_globs=("*.fish",),
    ),
]
