"""依存パッケージの既知脆弱性チェック（オプトイン）。

`--deps` を付けたときだけ、各エコシステムの監査ツールを read-only で呼ぶ。
ネットワークアクセスが必要なので既定では無効。

監査ツールが無い・失敗した・出力を読めないときは「問題なし」にせず、
DEP-010 / DEP-011（高）として出す。`--fail-on high` の CI を、調べていないのに通さないため。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ..models import Finding, Location, Severity
from .base import redact

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

LOCKFILES = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "requirements.txt": "pip",
    "composer.lock": "composer",
}

TOOLS = {"npm": "npm", "pnpm": "pnpm", "yarn": "yarn", "pip": "pip-audit", "composer": "composer"}

INSTALL_HINTS = {"pip-audit": "`python3 -m pip install pip-audit`"}

# 監査ツールを呼ばない lockfile。見ていないことをレポートに出す
UNSUPPORTED_LOCKFILES = {
    "bun.lock": "bun",
    "bun.lockb": "bun",
    "poetry.lock": "Poetry",
    "uv.lock": "uv",
    "Pipfile.lock": "Pipenv",
    "Cargo.lock": "Cargo",
    "go.sum": "Go",
    "Gemfile.lock": "Bundler",
}


def _run(cmd: list, cwd: Path, env: Optional[dict] = None) -> tuple:
    """(stdout, うまくいかなかったときの説明) を返す。起動できなければ stdout は空。"""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            timeout=240,
            check=False,
            env={**os.environ, **env} if env else None,
        )
    except subprocess.TimeoutExpired:
        return "", "240 秒で終わりませんでした"
    except (OSError, subprocess.SubprocessError) as exc:
        return "", str(exc)
    out = proc.stdout.decode("utf-8", "replace").strip()
    err = proc.stderr.decode("utf-8", "replace").strip()
    lines = [line.strip() for line in (err or out).splitlines() if line.strip()]
    return out, (lines[-1][:200] if lines else f"終了コード {proc.returncode}")


def _json(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return None


def _finding(rule: str, title: str, sev: Severity, message: str, remediation: str, path: str, evidence: str) -> Finding:
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        category="dependency",
        message=message,
        remediation=remediation,
        location=Location(path=path, line=1, snippet=evidence),
        cwe="CWE-1104",
        owasp="A06:2021",
        evidence=evidence,
    )


def _missing(tool: str, path: str) -> Finding:
    hint = INSTALL_HINTS.get(tool, f"{tool} をインストール")
    return _finding(
        "DEP-010",
        f"{tool} が見つからないため依存を監査できません",
        Severity.HIGH,
        f"{path} の既知の脆弱性を調べるには {tool} が必要です。今回は確認できていません。",
        f"{hint}してから、もう一度 --deps を付けて実行してください。",
        path,
        f"{tool} not found",
    )


def _failed(tool: str, path: str, detail: str) -> Finding:
    return _finding(
        "DEP-011",
        f"{tool} による依存の監査ができませんでした",
        Severity.HIGH,
        f"{path} を {tool} で監査できず、既知の脆弱性は確認できていません（{redact(detail)}）。",
        "ネットワーク・レジストリの認証・ツールの版を確認し、手元で同じコマンドを流して原因を確かめてください。",
        path,
        f"{tool} failed",
    )


def _unsupported(path: str, ecosystem: str) -> Finding:
    return _finding(
        "DEP-012",
        f"{path} は --deps の対象外です",
        Severity.LOW,
        f"{path}（{ecosystem}）の既知の脆弱性は、vulnscan では調べていません。",
        "そのエコシステムの監査ツールを別に流してください（例: Cargo は cargo audit、Go は govulncheck、"
        "Ruby は bundler-audit）。",
        path,
        f"{path} unsupported",
    )


def _npm(root: Path, path: str) -> list:
    out, err = _run(["npm", "audit", "--json"], root)
    data = _json(out)
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), dict):
        # 失敗すると {"message": …, "error": …} が出る（npm 7 以降）
        detail = data.get("message") if isinstance(data, dict) else None
        return [_failed("npm audit", path, detail or err)]
    results = []
    for name, info in data["vulnerabilities"].items():
        if not isinstance(info, dict):
            continue
        sev = SEVERITY_MAP.get(str(info.get("severity", "")).lower(), Severity.MEDIUM)
        via = [v for v in info.get("via", []) if isinstance(v, dict)]
        titles_all = [v.get("title", "") for v in via if v.get("title")]
        titles = "; ".join(titles_all[:3])
        if len(titles_all) > 3:
            titles += f" ほか{len(titles_all) - 3}件"
        titles = titles or "既知の脆弱性"
        fix = info.get("fixAvailable")
        if isinstance(fix, dict):
            fix_text = f"{fix.get('name')} {fix.get('version')}"
        elif fix is True:
            fix_text = "npm audit fix で更新可能"
        else:
            fix_text = "修正版なし（代替を検討）"
        results.append(
            _finding(
                "DEP-001",
                f"依存パッケージ {name} に既知の脆弱性",
                sev,
                f"{name}（{info.get('range', '不明')}）: {titles}",
                f"修正版: {fix_text}。`npm audit fix` 後にテストしてください。",
                path,
                f"{name}@{info.get('range', '?')}",
            )
        )
    return results


def _pnpm(root: Path, path: str) -> list:
    out, err = _run(["pnpm", "audit", "--json"], root)
    data = _json(out)
    if not isinstance(data, dict) or not isinstance(data.get("advisories"), dict):
        # 失敗すると {"error": {"code": …, "message": …}} が出る
        error = data.get("error") if isinstance(data, dict) else None
        detail = error.get("message") if isinstance(error, dict) else None
        return [_failed("pnpm audit", path, detail or err)]
    results = []
    for item in data["advisories"].values():
        if not isinstance(item, dict):
            continue
        sev = SEVERITY_MAP.get(str(item.get("severity", "")).lower(), Severity.MEDIUM)
        results.append(
            _finding(
                "DEP-001",
                f"依存パッケージ {item.get('module_name', '?')} に既知の脆弱性",
                sev,
                item.get("title", "既知の脆弱性"),
                f"修正版: {item.get('patched_versions', '不明')}。",
                path,
                f"{item.get('module_name')}@{item.get('vulnerable_versions', '?')}",
            )
        )
    return results


def _yarn(root: Path, path: str) -> list:
    # YARN_IGNORE_PATH: リポジトリの .yarnrc の yarn-path（任意の JS）を実行しない
    out, err = _run(["yarn", "audit", "--json"], root, env={"YARN_IGNORE_PATH": "1"})
    events = [e for e in map(_json, out.splitlines()) if isinstance(e, dict)]
    # 最後まで終わると auditSummary が出る。Yarn 2 以降には `yarn audit` が無く、これが出ない
    if not any(e.get("type") == "auditSummary" for e in events):
        return [_failed("yarn audit", path, err)]
    results = []
    for event in events:
        if event.get("type") != "auditAdvisory":
            continue
        adv = (event.get("data") or {}).get("advisory") or {}
        sev = SEVERITY_MAP.get(str(adv.get("severity", "")).lower(), Severity.MEDIUM)
        results.append(
            _finding(
                "DEP-001",
                f"依存パッケージ {adv.get('module_name', '?')} に既知の脆弱性",
                sev,
                adv.get("title", "既知の脆弱性"),
                f"修正版: {adv.get('patched_versions', '不明')}。",
                path,
                f"{adv.get('module_name')}@{adv.get('vulnerable_versions', '?')}",
            )
        )
    return results


def _pip(root: Path, path: str) -> list:
    out, err = _run(["pip-audit", "-r", path, "-f", "json", "--progress-spinner", "off"], root)
    data = _json(out)
    # 2.x は {"dependencies": [...], "fixes": [...]}、古い版は依存の配列
    deps = data.get("dependencies") if isinstance(data, dict) else data
    if not isinstance(deps, list):
        return [_failed("pip-audit", path, err)]
    results = []
    for pkg in deps:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name", "?")
        version = pkg.get("version", "?")
        for vuln in pkg.get("vulns", []) or []:
            if not isinstance(vuln, dict):
                continue
            fix = ", ".join(vuln.get("fix_versions", []) or []) or "修正版なし"
            results.append(
                _finding(
                    "DEP-001",
                    f"依存パッケージ {name} に既知の脆弱性",
                    Severity.HIGH,
                    f"{name} {version}: {vuln.get('id', '脆弱性')} {vuln.get('description', '')}".strip(),
                    f"修正版: {fix}。",
                    path,
                    f"{name}=={version}",
                )
            )
    return results


def _composer(root: Path, path: str) -> list:
    # --locked: vendor/ が無くても composer.lock を見る（無いと "No packages - skipping audit." で何もしない）
    # --no-plugins: vendor/ にあるプラグイン（任意の PHP）を読み込まない
    out, err = _run(
        ["composer", "audit", "--locked", "--format=json", "--no-interaction", "--no-plugins"], root
    )
    data = _json(out)
    if not isinstance(data, dict) or "advisories" not in data:
        if not out and "No packages" in err:  # lock に依存が 1 つも無い
            return []
        return [_failed("composer audit", path, err)]
    advisories = data["advisories"]
    if not isinstance(advisories, dict):  # 0 件のときは [] になる
        advisories = {}
    results = []
    for package, items in advisories.items():
        for item in items or []:
            if not isinstance(item, dict):
                continue
            results.append(
                _finding(
                    "DEP-001",
                    f"依存パッケージ {package} に既知の脆弱性",
                    Severity.HIGH,
                    f"{item.get('title', '既知の脆弱性')}（{item.get('cve', item.get('advisoryId', ''))}）",
                    f"影響: {item.get('affectedVersions', '不明')}。composer update を検討してください。",
                    path,
                    f"{package}",
                )
            )
    return results


def dependency_findings(root: Path, enabled: bool) -> list:
    if not enabled:
        return []

    results = []
    runner = {"npm": _npm, "pnpm": _pnpm, "yarn": _yarn, "pip": _pip, "composer": _composer}
    for name, kind in LOCKFILES.items():
        if not (root / name).is_file():
            continue
        tool = TOOLS[kind]
        if not shutil.which(tool):
            results.append(_missing(tool, name))
            continue
        results.extend(runner[kind](root, name))
    for name, ecosystem in UNSUPPORTED_LOCKFILES.items():
        if (root / name).is_file():
            results.append(_unsupported(name, ecosystem))
    return results
