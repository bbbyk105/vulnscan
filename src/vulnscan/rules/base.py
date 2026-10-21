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
    "rust": {".rs"},
    "c": {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"},
    "objective-c": {".m", ".mm"},
    "elixir": {".ex", ".exs"},
    "lua": {".lua"},
    "perl": {".pl", ".pm"},
}

# 画面と --lang の番号の一覧に出す名前
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


def _is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(COMMENT_PREFIXES)


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
    require_file: Optional[str] = None
    require_line: Optional[str] = None
    secret: bool = False
    secret_group: int = 0
    test_severity: Optional[Severity] = None
    tags: tuple = ()
    multiline: bool = False
    skip_comments: bool = True

    def __post_init__(self) -> None:
        self._pattern = re.compile(self.pattern)
        self._unless = re.compile(self.unless) if self.unless else None
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

        for lineno, subject, _match in self._iter_matches(sf):
            # 複数行のルールは、当たった文字列ではなく、当たり始めた行でコメントかを見る
            line = sf.lines[lineno - 1] if self.multiline and lineno <= len(sf.lines) else subject
            # コメントに書いた秘密もリポジトリからは読めるので、秘密のルールはコメント行も見る
            if self.skip_comments and not self.secret and _is_comment(line):
                continue
            if self._require_line and not self._require_line.search(subject):
                continue
            if self._unless and self._unless.search(subject):
                continue

            evidence = _clip(redact(subject))

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
                lineno = sf.text.count("\n", 0, match.start()) + 1
                yield lineno, match.group(0), match
            return
        for lineno, line in enumerate(sf.lines, 1):
            match = self._pattern.search(line)
            if match:
                yield lineno, line, match

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

    def applies(self, sf: SourceFile) -> bool:
        if not language_matches(sf, self.languages):
            return False
        if not matches_any(sf.relpath, self.path_globs):
            return False
        if self.exclude_globs and matches_any(sf.relpath, self.exclude_globs):
            return False
        return True

    def evaluate(self, sf: SourceFile) -> Iterable[Finding]:
        for lineno, evidence in self.check(sf):
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                category=self.category,
                message=self.message,
                remediation=self.remediation,
                location=Location(path=sf.relpath, line=lineno, snippet=_clip(redact(evidence))),
                cwe=self.cwe,
                owasp=self.owasp,
                evidence=redact(evidence).strip(),
            )
