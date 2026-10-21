"""スキャン実行エンジン。

読み取り専用。対象ファイルの変更・外部への送信は一切しない。
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import ignore as ignore_mod
from .files import collect, load
from .models import Finding, Severity
from .rules import FILE_RULES, LINE_RULES, all_rule_meta, lockfiles_present
from .rules.config import repo_checks
from .rules.deps import dependency_findings


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
    )

    skipped: Counter = Counter()
    loaded = []
    total_bytes = 0

    for path in fileset.files:
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
    findings.extend(dependency_findings(root, options.deps))

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

    stats = {
        "files_considered": len(fileset.files),
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
        lockfiles=lockfiles_present(root),
        warnings=warnings,
    )
