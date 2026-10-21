"""スキャン結果のデータモデル。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def coerce(cls, value: "Severity | int | str") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper()
        key = {"WARNING": "MEDIUM", "ERROR": "HIGH", "NONE": "INFO"}.get(key, key)
        if key not in cls.__members__:
            raise ValueError(f"不明な重要度: {value}")
        return cls[key]

    @property
    def label(self) -> str:
        return self.name.lower()


SEVERITY_JA = {
    Severity.CRITICAL: "緊急",
    Severity.HIGH: "高",
    Severity.MEDIUM: "中",
    Severity.LOW: "低",
    Severity.INFO: "情報",
}

# レポートや SARIF で使う英語ラベル
SEVERITY_EN = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

CATEGORY_JA = {
    "secret": "秘密情報の露出",
    "injection": "インジェクション",
    "xss": "クロスサイトスクリプティング",
    "crypto": "暗号・乱数",
    "auth": "認証・認可",
    "tls": "通信の安全性",
    "config": "設定ミス",
    "ci": "CI/CD",
    "dependency": "依存関係",
    "hardening": "セキュリティ強化",
}


class ScanError(Exception):
    """利用者に見せるエラー（指定の誤りなど）。CLI は終了コード 2 で返す。"""


def mask(value: str) -> str:
    """秘密情報をレポートに出さないためのマスク。短い値ほど見せる文字を減らす。

    20 文字以上のトークンは、種類が分かるよう先頭 4 文字（AKIA / ghp_ など）と末尾 2 文字を残す。
    """
    value = value.strip()
    if len(value) < 12:
        return "*" * max(len(value), 1)
    if len(value) < 20:
        return f"{value[:2]}…"
    return f"{value[:4]}…{value[-2:]}"


@dataclass
class Location:
    path: str
    line: int = 0
    column: int = 0
    snippet: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    remediation: str
    location: Location
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    evidence: str = ""
    fingerprint: str = ""
    suppressed: Optional[str] = None

    def compute_fingerprint(self, occurrence: int = 0) -> str:
        """行番号を含めないので、行が移動しても同じ指紋になる。

        同じファイルに同じ内容の行が複数あるときは、2 つ目以降に `occurrence` を混ぜて区別する
        （1 つ目は以前の版と同じ指紋のままにして、既存のベースラインを使えるようにする）。
        """
        normalized = re.sub(r"\s+", " ", self.evidence.strip())[:400]
        raw = f"{self.rule_id}\0{self.location.path}\0{normalized}"
        if occurrence:
            raw += f"\0{occurrence}"
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return self.fingerprint

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "title": self.title,
            "severity": SEVERITY_EN[self.severity],
            "category": self.category,
            "message": self.message,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "path": self.location.path,
            "line": self.location.line,
            "column": self.location.column,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
        }


@dataclass
class SourceFile:
    root: Path
    path: Path
    relpath: str
    text: str
    lines: list
    size: int
    tracked: bool
    mode: int

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()

    def is_test_path(self) -> bool:
        from .rules.base import TEST_PATH_RE

        return bool(TEST_PATH_RE.search(self.relpath))
