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
from typing import Iterable, Optional

from ..models import Finding, Location, Severity
from .base import TEST_PATH_RE, redact

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

INSTALL_HINTS = {
    "pip-audit": "`python3 -m pip install pip-audit`",
    "osv-scanner": "`brew install osv-scanner` などで osv-scanner をインストール",
}

# OSV-Scanner（google/osv-scanner）で見る lockfile。lockfile を読むだけで、プロジェクトのコードは動かさない
OSV_LOCKFILES = {
    "pubspec.lock": "Dart",
    "go.mod": "Go",
    "Cargo.lock": "Rust",
    "Gemfile.lock": "Ruby",
    "gems.locked": "Ruby",
    "poetry.lock": "Poetry",
    "Pipfile.lock": "Pipenv",
    "uv.lock": "uv",
    "pdm.lock": "PDM",
    "bun.lock": "bun",
    "mix.lock": "Elixir",
    "gradle.lockfile": "Gradle",
}

# どのツールでも見ない lockfile。見ていないことをレポートに出す
UNSUPPORTED_LOCKFILES = {"bun.lockb": "bun（バイナリの形式）"}

DEPENDENCY_FILES = frozenset({*LOCKFILES, *OSV_LOCKFILES, *UNSUPPORTED_LOCKFILES})


def _run(cmd: list, cwd: Path, env: Optional[dict] = None) -> tuple:
    """(stdout, うまくいかなかったときの説明, 終了コード) を返す。起動できなければ stdout は空で、終了コードは None。"""
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
        return "", "240 秒で終わりませんでした", None
    except (OSError, subprocess.SubprocessError) as exc:
        return "", str(exc), None
    out = proc.stdout.decode("utf-8", "replace").strip()
    err = proc.stderr.decode("utf-8", "replace").strip()
    lines = [line.strip() for line in (err or out).splitlines() if line.strip()]
    return out, (lines[-1][:200] if lines else f"終了コード {proc.returncode}"), proc.returncode


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
        f"{path} は --deps で調べていません",
        Severity.LOW,
        f"{path}（{ecosystem}）の既知の脆弱性は、vulnscan では調べていません。",
        "テキストの形式の bun.lock に移すと、osv-scanner で調べられます。",
        path,
        f"{path} unsupported",
    )


def _cvss_severity(score) -> Severity:
    """OSV-Scanner の groups[].max_severity（CVSS の点数の文字列）を重要度にする。無ければ中。"""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return Severity.MEDIUM
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if value > 0 else Severity.MEDIUM


def _npm(cwd: Path, path: str) -> list:
    out, err, _ = _run(["npm", "audit", "--json"], cwd)
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


def _pnpm(cwd: Path, path: str) -> list:
    out, err, _ = _run(["pnpm", "audit", "--json"], cwd)
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


def _yarn(cwd: Path, path: str) -> list:
    # YARN_IGNORE_PATH: リポジトリの .yarnrc の yarn-path（任意の JS）を実行しない
    out, err, _ = _run(["yarn", "audit", "--json"], cwd, env={"YARN_IGNORE_PATH": "1"})
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


def _pip(cwd: Path, path: str) -> list:
    out, err, _ = _run(["pip-audit", "-r", Path(path).name, "-f", "json", "--progress-spinner", "off"], cwd)
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


def _composer(cwd: Path, path: str) -> list:
    # --locked: vendor/ が無くても composer.lock を見る（無いと "No packages - skipping audit." で何もしない）
    # --no-plugins: vendor/ にあるプラグイン（任意の PHP）を読み込まない
    out, err, _ = _run(
        ["composer", "audit", "--locked", "--format=json", "--no-interaction", "--no-plugins"], cwd
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


def _osv(root: Path, paths: list) -> list:
    """OSV-Scanner は、lockfile を -L で並べて 1 回で呼ぶ。結果の source.path で、どの lockfile のものかに戻す。"""
    args = ["osv-scanner", "scan", "source"]
    for rel in paths:
        args += ["-L", rel]
    # --no-call-analysis=go: go.mod でコンパイラを呼ぶ解析をしない（lockfile を読むだけにする）
    args += ["--format=json", "--no-call-analysis=go"]
    out, err, code = _run(args, root)
    if code == 128:  # パッケージが 1 つも無い
        return []
    data = _json(out)
    if code not in (0, 1) or not isinstance(data, dict) or not isinstance(data.get("results", []), list):
        return [_failed("osv-scanner", rel, err) for rel in paths]

    resolved_root = root.resolve()

    def rel_of(source_path) -> str:
        try:
            return Path(source_path).resolve().relative_to(resolved_root).as_posix()
        except (TypeError, ValueError, OSError):
            return paths[0] if len(paths) == 1 else str(source_path)

    results = []
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        path = rel_of((result.get("source") or {}).get("path"))
        for pkg in result.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            info = pkg.get("package") or {}
            name = info.get("name", "?")
            version = info.get("version", "?")
            ecosystem = info.get("ecosystem", "")
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or [] if isinstance(v, dict)}
            # groups は、別名（GHSA と CVE など）で同じ脆弱性をまとめたもの
            groups = pkg.get("groups") or [{"ids": [vid]} for vid in vulns]
            for group in groups:
                ids = group.get("ids") or ["?"]
                primary = ids[0]
                names = list(dict.fromkeys([primary, *(a for a in group.get("aliases") or [] if a.startswith("CVE-"))]))
                summary = (vulns.get(primary) or {}).get("summary", "")
                results.append(
                    _finding(
                        "DEP-001",
                        f"依存パッケージ {name} に既知の脆弱性",
                        _cvss_severity(group.get("max_severity")),
                        f"{name} {version}（{ecosystem}）: {', '.join(names)} {summary}".strip(),
                        f"https://osv.dev/vulnerability/{primary} で修正版を確かめて、更新してください。",
                        path,
                        f"{name}@{version} {primary}",
                    )
                )
    return results


def dependency_findings(root: Path, enabled: bool, dependency_files: Iterable[str] = ()) -> list:
    """dependency_files は root からの相対パス。npm などは lockfile のあるフォルダで、osv-scanner はまとめて 1 回で動かす。"""
    if not enabled:
        return []

    results = []
    runner = {"npm": _npm, "pnpm": _pnpm, "yarn": _yarn, "pip": _pip, "composer": _composer}
    osv_paths = []
    for rel in dependency_files:
        name = rel.rsplit("/", 1)[-1]
        if name in LOCKFILES:
            tool = TOOLS[LOCKFILES[name]]
            if not shutil.which(tool):
                results.append(_missing(tool, rel))
                continue
            results.extend(runner[LOCKFILES[name]]((root / rel).parent, rel))
        elif name in OSV_LOCKFILES:
            osv_paths.append(rel)
        elif name in UNSUPPORTED_LOCKFILES:
            results.append(_unsupported(rel, UNSUPPORTED_LOCKFILES[name]))

    if osv_paths:
        if shutil.which("osv-scanner"):
            results.extend(_osv(root, osv_paths))
        else:
            results.extend(_missing("osv-scanner", rel) for rel in osv_paths)

    # テスト・フィクスチャの lockfile は配られないので、わざと古い版を入れていても CI を止めない
    for finding in results:
        if TEST_PATH_RE.search(finding.location.path) and finding.severity > Severity.LOW:
            finding.severity = Severity.LOW
    return results
