"""スキャン実行エンジン。

読み取り専用。対象ファイルの変更・外部への送信は一切しない。
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import ignore as ignore_mod
from .detect import detect_frameworks, language_summary
from .files import collect, load
from .models import Finding, Severity
from .rules import FILE_RULES, LINE_RULES, all_rule_meta
from .rules.base import CONFIG_LANGUAGES, language_of
from .rules.config import repo_checks
from .rules.deps import DEPENDENCY_FILES, LOCKFILES, OSV_LOCKFILES, dependency_findings


@dataclass
class ScanOptions:
    min_severity: Severity = Severity.LOW
    categories: tuple = ()
    exclude: tuple = ()
    ignore_file: Optional[Path] = None
    use_ignore: bool = True
    baseline: Optional[Path] = None
    max_file_bytes: int = 1_500_000
    deps: bool = False
    changed_only: bool = False
    languages: tuple = ()  # 空ならすべて。--lang で選んだ言語のキー
    # 番号で選ぶ一覧（--lang だけのとき）。スキャンと同じファイルの集まりの言語を受け取り、選んだキー（None ならすべて）を返す
    pick_languages: Optional[Callable[[list], Optional[list]]] = None
    base: Optional[str] = None
    reveal_secrets: bool = False


@dataclass
class ScanResult:
    root: Path
    findings: list = field(default_factory=list)
    suppressed: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    duration: float = 0.0
    lockfiles: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    # [{"language", "label", "files", "rules"}]。rules はその言語だけに効くルールの数（秘密のルールは全言語に効く）
    languages: list = field(default_factory=list)
    # [{"id", "label", "evidence"}]。--lang で絞っても、リポジトリ全体から見分ける
    frameworks: list = field(default_factory=list)

    @property
    def counts(self) -> Counter:
        return Counter(f.severity for f in self.findings)

    def count(self, severity: Severity) -> int:
        return self.counts.get(severity, 0)


def scan(root: Path, options: Optional[ScanOptions] = None) -> ScanResult:
    options = options or ScanOptions()
    started = time.monotonic()
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"対象が存在しません: {root}")

    fileset = collect(
        root,
        changed_only=options.changed_only,
        base=options.base,
        extra_excludes=options.exclude,
        dependency_names=DEPENDENCY_FILES,
    )

    frameworks = detect_frameworks(root, fileset.inventory) if root.is_dir() else []

    files = fileset.files
    selected = options.languages
    if options.pick_languages is not None:
        selected = tuple(options.pick_languages(language_summary(p.name for p in files)) or ())
    if selected:
        # 選ばなかった言語のコードのファイルだけを外す。言語の無いファイル（manifest・plist・.rules・.env・package.json）と
        # 設定の言語（YAML・Dockerfile）はいつも見る（Android・iOS・Firebase・.env のルールが当たるのはこれらのファイル）
        wanted = set(selected)
        files = [p for p in files if (lang := language_of(p.name)) is None or lang in wanted or lang in CONFIG_LANGUAGES]

    skipped: Counter = Counter()
    loaded = []
    total_bytes = 0

    for path in files:
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        result = load(path, root, rel in fileset.tracked, options.max_file_bytes)
        if result.file is None:
            skipped[result.reason or "unknown"] += 1
            continue
        loaded.append(result.file)
        total_bytes += result.file.size

    findings = []

    for sf in loaded:
        for rule in LINE_RULES:
            if rule.applies(sf):
                findings.extend(rule.evaluate(sf))
        for rule in FILE_RULES:
            if rule.applies(sf):
                findings.extend(rule.evaluate(sf))

    scanned = [sf.relpath for sf in loaded]
    findings.extend(repo_checks(root, fileset.tracked, scanned, fileset.git))
    findings.extend(dependency_findings(root, options.deps, fileset.dependency_files))

    if options.categories:
        wanted = set(options.categories)
        findings = [f for f in findings if f.category in wanted]

    findings = [f for f in findings if f.severity >= options.min_severity]

    # 同じファイルに同じ内容の行が複数あっても 1 件にまとめない。
    # 2 つ目以降は指紋を変えて、ベースラインに新しく増えた分を隠させない
    occurrences: Counter = Counter()
    for finding in findings:
        first = finding.compute_fingerprint()
        if occurrences[first]:
            finding.compute_fingerprint(occurrence=occurrences[first])
        occurrences[first] += 1
    unique = findings

    suppressed = []
    warnings = []

    if options.use_ignore:
        ignore_path = options.ignore_file or (root / ".vulnscanignore")
        entries, ignore_warnings = ignore_mod.load_ignore(ignore_path)
        warnings.extend(ignore_warnings)
        unique, ignored = ignore_mod.apply_ignore(unique, entries)
        suppressed.extend(ignored)

    if options.baseline:
        fingerprints = ignore_mod.load_baseline(options.baseline)
        unique, baselined = ignore_mod.apply_baseline(unique, fingerprints)
        suppressed.extend(baselined)

    unique.sort(key=lambda f: (-int(f.severity), f.location.path, f.location.line))

    languages = language_summary(sf.name for sf in loaded)

    stats = {
        "files_considered": len(files),
        "files_scanned": len(loaded),
        "files_skipped": sum(skipped.values()),
        "skipped_reasons": dict(skipped),
        "bytes": total_bytes,
        "git": fileset.git,
        "rules": len(all_rule_meta()),
        "deps_enabled": options.deps,
        "suppressed": len(suppressed),
    }

    return ScanResult(
        root=root,
        findings=unique,
        suppressed=suppressed,
        stats=stats,
        duration=time.monotonic() - started,
        lockfiles=[
            rel for rel in fileset.dependency_files if rel.rsplit("/", 1)[-1] in {*LOCKFILES, *OSV_LOCKFILES}
        ],
        warnings=warnings,
        languages=languages,
        frameworks=frameworks,
    )
