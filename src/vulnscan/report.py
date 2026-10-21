"""レポート出力（text / Markdown / JSON / SARIF）。"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime
from pathlib import Path

from . import __version__
from .models import (
    CATEGORY_JA,
    SEVERITY_EN,
    SEVERITY_JA,
    Finding,
    Severity,
)

ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

ANSI = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[2m",
}
RESET = "\033[0m"
DIM = "\033[2m"


def _paint(text: str, severity: Severity, color: bool) -> str:
    if not color:
        return text
    return f"{ANSI[severity]}{text}{RESET}"


def _wrap(text: str, width: int, indent: str) -> str:
    return textwrap.fill(
        text,
        width=width,
        initial_indent=indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def _summary_line(result) -> str:
    parts = []
    for sev in ORDER:
        count = result.count(sev)
        if count:
            parts.append(f"{SEVERITY_JA[sev]} {count}")
    return " / ".join(parts) if parts else "0 件"


def render_text(result, *, color: bool = False, group_by: str = "severity") -> str:
    lines = []
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines.append(f"vulnscan {__version__} — {result.root}")
    lines.append(
        f"{stamp} · {result.stats['files_scanned']:,} ファイル · "
        f"{result.stats['rules']} ルール · {result.duration:.2f} 秒"
    )
    lines.append("")

    if not result.findings:
        lines.append("✓ 指定した条件では問題を検出しませんでした。")
        _append_footer(lines, result, color)
        return "\n".join(lines)

    lines.append(_paint(f"合計 {len(result.findings)} 件", Severity.HIGH, color) + f"（{_summary_line(result)}）")
    lines.append("")

    if group_by == "file":
        groups = {}
        for f in result.findings:
            groups.setdefault(f.location.path, []).append(f)
        ordered = sorted(groups.items())
    elif group_by == "rule":
        groups = {}
        for f in result.findings:
            groups.setdefault(f.rule_id, []).append(f)
        ordered = sorted(groups.items())
    else:
        ordered = [(sev, [f for f in result.findings if f.severity == sev]) for sev in ORDER]
        ordered = [(sev, items) for sev, items in ordered if items]
        groups = dict(ordered)

    for key, items in ordered:
        if not items:
            continue
        if group_by == "severity":
            header = f"■ {SEVERITY_JA[key]} ({len(items)})"
            lines.append(_paint(header, key, color))
        elif group_by == "file":
            lines.append(f"■ {key} ({len(items)})")
        else:
            lines.append(f"■ {items[0].rule_id} {items[0].title} ({len(items)})")
        lines.append("")

        for finding in items:
            lines.extend(_format_finding_text(finding, color, group_by))
        lines.append("")

    _append_footer(lines, result, color)
    return "\n".join(lines)


def _format_finding_text(finding: Finding, color: bool, group_by: str) -> list:
    lines = []
    if group_by != "rule":
        lines.append(
            f"  {finding.rule_id}  {finding.title}"
        )
        lines.append(f"    {finding.location.path}:{finding.location.line}")
    else:
        lines.append(f"    {finding.location.path}:{finding.location.line}")

    if finding.location.snippet:
        snippet = finding.location.snippet
        if len(snippet) > 160:
            snippet = snippet[:159] + "…"
        lines.append(f"    └ {snippet}")
    lines.append(_wrap(f"理由: {finding.message}", 100, "    "))
    lines.append(_wrap(f"修正: {finding.remediation}", 100, "    "))
    meta = [CATEGORY_JA.get(finding.category, finding.category)]
    if finding.cwe:
        meta.append(finding.cwe)
    if finding.owasp:
        meta.append(finding.owasp)
    lines.append(f"    {' / '.join(meta)}")
    lines.append("")
    return lines


def _append_footer(lines: list, result, color: bool) -> None:
    dim = DIM if color else ""
    reset = RESET if color else ""
    for warning in result.warnings:
        lines.append(f"注意: {warning}")
    if result.suppressed:
        lines.append(f"{dim}抑制: {len(result.suppressed)} 件（.vulnscanignore / baseline）{reset}")
    if result.lockfiles and not result.stats.get("deps_enabled"):
        lines.append(
            f"{dim}ヒント: {', '.join(result.lockfiles)} を検出しました。"
            f"既知CVEも調べるには `vulnscan scan --deps` を実行してください。{reset}"
        )
    if result.stats.get("files_skipped"):
        reasons = result.stats.get("skipped_reasons", {})
        detail = " / ".join(f"{k} {v}" for k, v in sorted(reasons.items()))
        lines.append(f"{dim}スキップ: {result.stats['files_skipped']} ファイル（{detail}）{reset}")


def render_markdown(result) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# セキュリティスキャン結果 — {result.root.name}",
        "",
        f"- 対象: `{result.root}`",
        f"- 実行: {stamp}",
        f"- ファイル: {result.stats['files_scanned']:,} / ルール: {result.stats['rules']}",
        f"- 結果: **{len(result.findings)} 件**（{_summary_line(result)}）",
        "",
    ]

    lines.extend(["## サマリー", "", "| 重大度 | 件数 |", "|---|---:|"])
    for sev in ORDER:
        lines.append(f"| {SEVERITY_JA[sev]} | {result.count(sev)} |")
    lines.append("")

    if result.warnings:
        lines.extend(["## 注意", ""])
        lines.extend(f"- {warning}" for warning in result.warnings)
        lines.append("")

    if not result.findings:
        lines.extend(["検出された問題はありません。", ""])
        return "\n".join(lines)

    for sev in ORDER:
        items = [f for f in result.findings if f.severity == sev]
        if not items:
            continue
        lines.extend([f"## {SEVERITY_JA[sev]}（{len(items)}）", ""])
        for finding in items:
            lines.extend(_format_finding_md(finding))
    return "\n".join(lines)


def _format_finding_md(finding: Finding) -> list:
    lines = [
        f"### `{finding.rule_id}` {finding.title}",
        "",
        f"- 場所: `{finding.location.path}:{finding.location.line}`",
        f"- 分類: {CATEGORY_JA.get(finding.category, finding.category)}",
    ]
    if finding.cwe:
        lines.append(f"- CWE: {finding.cwe}")
    if finding.owasp:
        lines.append(f"- OWASP: {finding.owasp}")
    lines.extend(["", f"**内容**: {finding.message}", "", f"**修正**: {finding.remediation}", ""])
    if finding.location.snippet:
        fence = "```"
        if fence in finding.location.snippet:
            fence = "~~~"
        lines.extend([fence, finding.location.snippet, fence, ""])
    return lines


def render_json(result) -> str:
    payload = {
        "tool": "vulnscan",
        "version": __version__,
        "root": str(result.root),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": round(result.duration, 3),
        "stats": result.stats,
        "summary": {SEVERITY_EN[sev]: result.count(sev) for sev in ORDER},
        "warnings": result.warnings,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_sarif(result) -> str:
    rules = {}
    for finding in result.findings:
        if finding.rule_id in rules:
            continue
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.message},
            "help": {"text": finding.remediation},
            "properties": {
                "category": finding.category,
                "cwe": finding.cwe,
                "security-severity": {
                    Severity.CRITICAL: "9.5",
                    Severity.HIGH: "8.0",
                    Severity.MEDIUM: "5.5",
                    Severity.LOW: "3.0",
                    Severity.INFO: "0.0",
                }[finding.severity],
            },
        }

    level = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    results = []
    for finding in result.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level[finding.severity],
                "message": {"text": f"{finding.title}: {finding.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.location.path},
                            "region": {"startLine": max(finding.location.line, 1)},
                        }
                    }
                ],
                "partialFingerprints": {"vulnscanFingerprint": finding.fingerprint},
            }
        )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulnscan",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render(result, fmt: str, *, color: bool = False, group_by: str = "severity") -> str:
    if fmt == "md":
        return render_markdown(result)
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_text(result, color=color, group_by=group_by)


def write_output(text: str, output: Path = None) -> None:
    if output is None:
        print(text)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text + "\n", "utf-8")
