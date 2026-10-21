"""端末で、矢印キーとスペースで項目を選ぶ一覧（--lang に値を付けないとき）。

標準ライブラリだけで作る。キーごとの決まり（PickerState・decode_key）と端末の入出力（read_key・pick）を分け、
決まりは端末なしでテストする。termios の無い環境（Windows など）では available() が False を返し、
呼ぶ側は番号を打つ形に戻る。
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass, field
from typing import Optional, TextIO

from .models import ScanError

UP, DOWN, TOGGLE, ALL, ENTER, CANCEL = "up", "down", "toggle", "all", "enter", "cancel"

_KEYS = {
    "k": UP,
    "j": DOWN,
    " ": TOGGLE,
    "a": ALL,
    "\r": ENTER,
    "\n": ENTER,
    "\x04": ENTER,  # Ctrl-D（番号を打つ形のときと同じく、そこで決める）
    "\x1b": CANCEL,
    "q": CANCEL,
}
# ESC [ と ESC O に続く終わりの文字。ほかの続き（F5 など）は何もしない
_ARROWS = {"A": UP, "B": DOWN}

HELP = "↑↓ で動かす・スペースで選ぶ・a ですべて・Enter で決める（何も選ばずに Enter ですべて）・q でやめる"


def decode_key(raw: str) -> str:
    """端末から読んだ 1 文字を、操作の名前にする。数字はそのまま返す（その番号の行を付け外しする）。"""
    return _KEYS.get(raw, raw)


def fit_width(text: str, columns: int) -> str:
    """端末の幅に収まるよう、表示の幅（全角は 2）で切る。折り返すと描き直しの戻り先がずれるため、1 桁あける。

    幅を 0 と報告する端末（疑似端末・一部の CI）は、幅が分からないものとして切らない。
    """
    if columns <= 1:
        return text
    used = 0
    for i, ch in enumerate(text):
        used += 2 if unicodedata.east_asian_width(ch) in "WF" else 1
        if used > columns - 1:
            return text[:i]
    return text


@dataclass
class PickerState:
    count: int
    cursor: int = 0
    checked: set = field(default_factory=set)

    def press(self, key: str) -> Optional[str]:
        """キーを 1 つ受け取る。決めたら "done"、やめたら "cancel"、続けるなら None。"""
        if key == UP:
            self.cursor = (self.cursor - 1) % self.count
        elif key == DOWN:
            self.cursor = (self.cursor + 1) % self.count
        elif key == TOGGLE:
            self.checked ^= {self.cursor}
        elif key == ALL:
            self.checked = set() if len(self.checked) == self.count else set(range(self.count))
        elif key.isdigit() and 1 <= int(key) <= self.count:
            self.cursor = int(key) - 1
            self.checked ^= {self.cursor}
        elif key == ENTER:
            return "done"
        elif key == CANCEL:
            return "cancel"
        return None

    def chosen(self) -> list:
        return sorted(self.checked)

    def lines(self, labels: list, active: bool = True) -> list:
        return [
            f"{'›' if active and i == self.cursor else ' '} [{'x' if i in self.checked else ' '}] {label}"
            for i, label in enumerate(labels)
        ]


def available(stdin: TextIO, out: TextIO) -> bool:
    """矢印キーで選べるか（入力と表示の両方が端末で、termios が使えるとき）。"""
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        import termios  # noqa: F401
    except ImportError:
        return False
    return stdin.isatty() and out.isatty()


def read_key(fd: int) -> str:
    """端末から 1 キーを読み、操作の名前にする。入力の終わりは CANCEL、知らない続き（F5 など）は ""。"""
    import select

    def ready() -> bool:
        return bool(select.select([fd], [], [], 0.05)[0])

    first = os.read(fd, 1)
    if not first:
        return CANCEL
    if first == b"\x1b":
        # 矢印キーは ESC [ A・ESC O A のように続けて届く。続きが来なければ ESC だけ（やめる）
        second = os.read(fd, 1) if ready() else b""
        if second == b"[":
            # CSI: 数字や ; のあと、0x40〜0x7E の終わりの文字まで読み切る（Ctrl+↑ は ESC [ 1 ; 5 A）
            final = b""
            while ready():
                ch = os.read(fd, 1)
                if not ch or 0x40 <= ch[0] <= 0x7E:
                    final = ch
                    break
            return _ARROWS.get(final.decode("ascii", "ignore"), "")
        if second == b"O":
            third = os.read(fd, 1) if ready() else b""
            return _ARROWS.get(third.decode("ascii", "ignore"), "")
        return CANCEL if not second else ""
    # UTF-8 の 1 文字を読み切ってから見る（日本語入力のスペース U+3000 は 3 バイト）。全角は NFKC で半角にする
    lead = first[0]
    size = 2 if lead >> 5 == 0b110 else 3 if lead >> 4 == 0b1110 else 4 if lead >> 3 == 0b11110 else 1
    raw = first
    while len(raw) < size:
        more = os.read(fd, size - len(raw))
        if not more:
            break
        raw += more
    return decode_key(unicodedata.normalize("NFKC", raw.decode("utf-8", "ignore")))


def _columns(out: TextIO) -> int:
    try:
        return os.get_terminal_size(out.fileno()).columns
    except (OSError, ValueError):
        return 80


def pick(title: str, labels: list, stdin: TextIO, out: TextIO) -> list:
    """一覧を出して選んでもらい、選んだ行の番号（0 から）を返す。何も選ばずに決めたら空。やめたら ScanError。"""
    import signal
    import termios
    import tty

    fd = stdin.fileno()
    saved = termios.tcgetattr(fd)
    state = PickerState(len(labels))

    def draw(first: bool, active: bool = True) -> None:
        if not first:
            out.write(f"\x1b[{len(labels)}A")
        width = _columns(out)
        for line in state.lines(labels, active):
            out.write(f"\r\x1b[2K{fit_width(line, width)}\n")
        out.flush()

    def interrupted(signum, frame):  # noqa: ARG001
        raise KeyboardInterrupt

    # kill・回線切れ・Ctrl-\ でも finally で端末を戻す。Ctrl-Z は一覧の間だけ効かなくする（止めると cbreak のまま残る）
    handlers = {sig: interrupted for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)}
    handlers[signal.SIGTSTP] = signal.SIG_IGN
    previous = {sig: signal.signal(sig, handler) for sig, handler in handlers.items()}
    try:
        # cbreak: 1 文字ずつ読み、打った文字は出さない。Ctrl-C はそのまま止める（KeyboardInterrupt）。
        # 一覧を出す前に切り替え、既定の TCSAFLUSH は使わない（一覧が出る間に打ったキーを捨ててしまう）
        tty.setcbreak(fd, termios.TCSANOW)
        # 先に打ったキーが cbreak の前に画面に出ていれば、その行を消してから描く
        out.write(f"\r\x1b[2K{title}\n{HELP}\n\x1b[?25l")
        draw(first=True)
        while True:
            result = state.press(read_key(fd))
            if result is None:
                draw(first=False)
                continue
            draw(first=False, active=False)
            if result == "cancel":
                raise ScanError("言語の選択をやめました。")
            return state.chosen()
    finally:
        # 戻す途中の Ctrl-C で、戻し損ねないようにする
        previous_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            out.write("\x1b[?25h")
            out.flush()
        except OSError:
            pass
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        except termios.error:
            pass
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        signal.signal(signal.SIGINT, previous_int)
