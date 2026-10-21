"""抑制リスト（.vulnscanignore）とベースラインの読み書き。"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable, Optional

from .models import Finding

DATE_RE = re.compile(r"expires=(\d{4}-\d{2}-\d{2})")
BASELINE_VERSION = 1


@dataclass
class IgnoreEntry:
    rule: str
    glob: str
    reason: str = ""
    expires: Optional[date] = None

    def matches(self, finding: Finding) -> bool:
        if self.expires and self.expires < date.today():
            return False
        if not fnmatch.fnmatch(finding.rule_id, self.rule):
            return False
        path = finding.location.path
        return fnmatch.fnmatch(path, self.glob) or fnmatch.fnmatch(
            path.rsplit("/", 1)[-1], self.glob
        )


def load_ignore(path: Path) -> tuple:
    """(抑制の一覧, 警告) を返す。

    書き間違えた行は、期限なしの抑制として効いてしまわないよう使わずに、警告に出す。
    """
    entries, warnings = [], []
    if not path.is_file():
        return entries, warnings
    try:
        lines = path.read_text("utf-8", "replace").splitlines()
    except OSError:
        return entries, warnings

    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # 期限は理由（# のあと）に書かれていても読む
        expires = None
        if "expires=" in line:
            m = DATE_RE.search(line)
            try:
                expires = date.fromisoformat(m.group(1)) if m else None
            except ValueError:
                expires = None
            if expires is None:
                warnings.append(
                    f"{path.name}:{lineno} の expires= が YYYY-MM-DD の日付ではないため、この行の抑制は使いません"
                )
                continue
            line = DATE_RE.sub("", line).strip()

        reason = ""
        if "#" in line:
            line, reason = line.split("#", 1)
            reason = reason.strip()
            line = line.strip()

        parts = line.split()
        if not parts:
            continue
        if len(parts) > 2:
            warnings.append(f"{path.name}:{lineno} に余分な語があるため、この行の抑制は使いません: {line}")
            continue
        rule = parts[0]
        glob = parts[1] if len(parts) > 1 else "*"
        entries.append(IgnoreEntry(rule=rule, glob=glob, reason=reason, expires=expires))
    return entries, warnings


def apply_ignore(findings: Iterable[Finding], entries: list) -> tuple:
    kept, suppressed = [], []
    for finding in findings:
        hit = next((e for e in entries if e.matches(finding)), None)
        if hit is None:
            kept.append(finding)
        else:
            finding.suppressed = hit.reason or "vulnscanignore"
            suppressed.append(finding)
    return kept, suppressed


def load_baseline(path: Path) -> set:
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return set()
    if isinstance(data, dict) and data.get("version") == BASELINE_VERSION:
        return {
            item.get("fingerprint")
            for item in data.get("findings", [])
            if isinstance(item, dict) and item.get("fingerprint")
        }
    return set()


def write_baseline(path: Path, findings: list) -> None:
    payload = {
        "version": BASELINE_VERSION,
        "findings": [
            {
                "fingerprint": f.fingerprint,
                "rule": f.rule_id,
                "path": f.location.path,
                "line": f.location.line,
            }
            for f in findings
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", "utf-8")


def apply_baseline(findings: Iterable[Finding], fingerprints: set) -> tuple:
    if not fingerprints:
        return list(findings), []
    kept, suppressed = [], []
    for finding in findings:
        if finding.fingerprint in fingerprints:
            finding.suppressed = "baseline"
            suppressed.append(finding)
        else:
            kept.append(finding)
    return kept, suppressed
