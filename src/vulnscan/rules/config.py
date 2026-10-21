"""設定・ファイル配置のチェック。

行単位のルールで表せないもの（.env の追跡状況、Dockerfile、GitHub Actions、
package.json のバージョン指定など）をここにまとめる。
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from ..models import Finding, Location, Severity, SourceFile
from .base import FileRule, LineRule

# クライアントに露出する接頭辞。ここに秘密情報を置くと全員に配られる。
PUBLIC_ENV_PREFIX = r"(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|EXPO_PUBLIC_)"


def _read_lines(path: Path) -> list:
    try:
        return path.read_text("utf-8", "replace").splitlines()
    except OSError:
        return []


def _dockerfile_without_user(sf: SourceFile) -> Iterable[tuple]:
    for line in sf.lines:
        if re.match(r"(?i)^\s*USER\s+\S+", line):
            return
    yield 1, "Dockerfile に USER 命令がありません（root で実行されます）"


def _workflow_run_blocks(lines: list) -> Iterable[tuple]:
    """GitHub Actions の `run:` の中身を (行番号, テキスト) で返す。"""
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", line)
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        rest = m.group(2).strip()
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            block = []
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                stripped = nxt.strip()
                if stripped and (len(nxt) - len(nxt.lstrip())) <= indent:
                    break
                block.append(nxt)
                j += 1
            yield i + 1, "\n".join(block)
            i = j
        else:
            yield i + 1, rest
            i += 1


GHA_EXPRESSION = re.compile(r"\$\{\{\s*([^}]*?)\s*\}\}")

GHA_UNTRUSTED = re.compile(
    r"^github\.(?:"
    r"event\.(?:issue|comment|pull_request|review|discussion|head_commit|commits?)"
    r"|head_ref"
    r")\b"
)

# 番号や SHA など、PR を出す人が自由な文字列を入れられない値
GHA_SAFE_FIELD = re.compile(
    r"\.(?:number|id|node_id|sha|draft|merged|additions|deletions|changed_files|created_at|updated_at)$"
)


def _gha_script_injection(sf: SourceFile) -> Iterable[tuple]:
    for lineno, block in _workflow_run_blocks(sf.lines):
        for m in GHA_EXPRESSION.finditer(block):
            expr = m.group(1)
            if GHA_UNTRUSTED.search(expr) and not GHA_SAFE_FIELD.search(expr):
                yield lineno, f"run ブロックに未信頼の式が入っています: {m.group(0)}"
                break


def _gha_pull_request_target(sf: SourceFile) -> Iterable[tuple]:
    text = sf.text
    if "pull_request_target" not in text:
        return
    if "github.event.pull_request.head" not in text:
        return
    lineno = next(
        (i for i, line in enumerate(sf.lines, 1) if "pull_request_target" in line), 1
    )
    yield lineno, "pull_request_target で PR の head を checkout しています"


def _package_json_unpinned(sf: SourceFile) -> Iterable[tuple]:
    try:
        data = json.loads(sf.text)
    except (ValueError, TypeError):
        return
    if not isinstance(data, dict):
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            if version in ("latest", "*", "x", ""):
                lineno = next(
                    (i for i, line in enumerate(sf.lines, 1) if f'"{name}"' in line), 1
                )
                yield lineno, f"{name}: {version!r}"


FILE_RULES = [
    FileRule(
        id="CFG-010",
        title="Dockerfile に USER 指定がありません",
        severity=Severity.LOW,
        category="config",
        message="コンテナが root で動くと、侵害時の影響がホスト全体に広がります。",
        remediation="専用ユーザーを作成し、USER 命令で切り替えてください。",
        check=_dockerfile_without_user,
        languages=("docker",),
        cwe="CWE-250",
    ),
    FileRule(
        id="CI-001",
        title="GitHub Actions のスクリプトインジェクション",
        severity=Severity.HIGH,
        category="ci",
        message="Issue や PR のタイトルなど未信頼の値を run: に直接埋めると、"
        "ワークフロー上で任意コマンドを実行されます。",
        remediation="値を env: で受け取り、$TITLE のようにシェル変数として参照してください。",
        check=_gha_script_injection,
        path_globs=(".github/workflows/*.yml", ".github/workflows/*.yaml"),
        cwe="CWE-78",
    ),
    FileRule(
        id="CI-002",
        title="pull_request_target での未信頼コード checkout",
        severity=Severity.HIGH,
        category="ci",
        message="pull_request_target は秘密情報にアクセスできる状態で、PR のコードを実行してしまいます。",
        remediation="pull_request を使うか、checkout する ref を信頼済みのものに限定してください。",
        check=_gha_pull_request_target,
        path_globs=(".github/workflows/*.yml", ".github/workflows/*.yaml"),
        cwe="CWE-829",
    ),
    FileRule(
        id="DEP-002",
        title="依存パッケージのバージョンが固定されていません",
        severity=Severity.LOW,
        category="dependency",
        message="latest / * 指定は、意図しない更新やサプライチェーン攻撃のリスクを高めます。",
        remediation="動作確認したバージョンに固定し、lockfile をコミットしてください。",
        check=_package_json_unpinned,
        path_globs=("package.json",),
        cwe="CWE-1104",
    ),
]


ENV_PUBLIC_SECRET = re.compile(
    r"^\s*" + PUBLIC_ENV_PREFIX + r"[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|SERVICE_ROLE|API_KEY)[A-Z0-9_]*\s*=",
    re.IGNORECASE,
)

ENV_FILENAMES = (
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.prod",
    ".env.staging",
)

ENV_PLACEHOLDERS = {"", "changeme", "your_key_here", "xxx", "todo", "example"}


def _git_ignored(root: Path, relpath: str) -> Optional[bool]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-q", relpath],
            capture_output=True,
            timeout=30,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None


# リポジトリ全体を見るチェックの説明（`vulnscan rules` / `explain` もここを読む）
REPO_RULES = {
    "FILE-001": {
        "title": ".env ファイルが git にコミットされています",
        "severity": Severity.CRITICAL,
        "category": "secret",
        "message": "環境変数ファイルがリポジトリに含まれており、履歴からも秘密情報が読めます。",
        "remediation": "ファイルを git から外し、値をローテーションしてください。"
        ".gitignore に .env* を追加し、.env.example だけをコミットします。",
        "cwe": "CWE-538",
        "owasp": "A05:2021",
    },
    "FILE-002": {
        "title": ".env が .gitignore で除外されていません",
        "severity": Severity.MEDIUM,
        "category": "secret",
        "message": "今は未追跡でも、git add . で秘密情報がコミットされる危険があります。",
        "remediation": ".gitignore に .env と .env.local などを追加してください。",
        "cwe": "CWE-538",
        "owasp": None,
    },
    "FILE-003": {
        "title": "クライアントに露出する環境変数に秘密情報",
        "severity": Severity.HIGH,
        "category": "secret",
        "message": "NEXT_PUBLIC_ / VITE_ などの接頭辞が付いた値は、ビルドされてブラウザに配信されます。",
        "remediation": "秘密情報は接頭辞なしのサーバー側変数に移し、API 経由で必要な分だけ返してください。",
        "cwe": "CWE-798",
        "owasp": None,
    },
}


def _repo_finding(rule_id: str, path: str, line: int, snippet: str, evidence: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        location=Location(path=path, line=line, snippet=snippet),
        evidence=evidence,
        **REPO_RULES[rule_id],
    )


def _env_files(root: Path, tracked: set, scanned: Iterable[str]) -> list:
    """確認する .env ファイル（root からの相対パス）。

    直下のものは .gitignore で除外されていても読む（NEXT_PUBLIC_ の確認のため）。
    サブフォルダ（monorepo の apps/web/.env など）は、git に入っているものと走査対象のもの。
    """
    names = {name for name in ENV_FILENAMES if (root / name).is_file()}
    names.update(rel for rel in (*tracked, *scanned) if rel.rsplit("/", 1)[-1] in ENV_FILENAMES)
    return sorted(names)


def repo_checks(root: Path, tracked: set, scanned: Iterable[str], is_git: bool) -> list:
    """リポジトリ全体を見ないと判断できないチェック。"""
    findings = []

    for rel in _env_files(root, tracked, scanned):
        path = root / rel
        if not path.is_file():
            continue

        if rel in tracked:
            findings.append(_repo_finding("FILE-001", rel, 1, f"{rel}（追跡対象）", f"{rel} tracked"))
        elif is_git and _git_ignored(root, rel) is False:
            findings.append(
                _repo_finding("FILE-002", ".gitignore", 1, f"{rel} が無視されていません", f"{rel} not ignored")
            )

        for lineno, line in enumerate(_read_lines(path), 1):
            if not ENV_PUBLIC_SECRET.search(line):
                continue
            value = line.split("=", 1)[1].strip().strip("\"'") if "=" in line else ""
            if value.lower() in ENV_PLACEHOLDERS:
                continue
            masked = line.split("=", 1)[0] + "=***"
            findings.append(_repo_finding("FILE-003", rel, lineno, masked, masked))

    return findings
