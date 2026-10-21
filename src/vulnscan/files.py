"""対象ファイルの列挙と読み込み。

git リポジトリなら `git ls-files` を使うので .gitignore を尊重する。
そうでなければディレクトリを歩き、既知のビルド/依存ディレクトリだけ除外する。
"""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from .models import ScanError, SourceFile

# 走っている vulnscan 自身のフォルダ（src/vulnscan/files.py の 2 つ上）。
# README の CI 例のようにリポジトリの中に置いたとき、ルールの正規表現やテストの文字列に反応しないよう見ない
TOOL_ROOT = Path(__file__).resolve().parents[2]

# 中身を走査する意味がない／巨大なディレクトリ
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    "vendor",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".vercel",
    ".netlify",
    "dist",
    "build",
    "out",
    "coverage",
    ".nyc_output",
    ".cache",
    ".parcel-cache",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "venv",
    ".venv",
    "site-packages",
    "Pods",
    "DerivedData",
    ".gradle",
    ".idea",
    ".pnpm-store",
    ".yarn",
    ".obsidian",
    ".claude",
    ".codex",
    ".cursor",
    "target",
    "obj",
}

# 内容走査をスキップするファイル名（依存ロックは --deps 側で扱う）
SKIPPED_FILENAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
    "composer.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "gems.locked",
    "pubspec.lock",
    "uv.lock",
    "pdm.lock",
    "bun.lock",
    "mix.lock",
    "gradle.lockfile",
}

SKIPPED_SUFFIXES = (".min.js", ".min.css", ".map")


@dataclass
class FileSet:
    files: list = field(default_factory=list)
    tracked: set = field(default_factory=set)
    skipped_dirs: int = 0
    git: bool = False
    # 依存の lockfile（root からの相対パス）。中身は走査しないが、--deps で監査する
    dependency_files: list = field(default_factory=list)
    # リポジトリ全体のファイル（root からの相対パス）。--changed / --base のときも全体（フレームワークの見分けに使う）
    inventory: list = field(default_factory=list)


def _run_git(root: Path, args: list) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace")


def _split_z(output: Optional[str]) -> list:
    if not output:
        return []
    return [p for p in output.split("\0") if p]


def _in_excluded_dir(relpath: str) -> bool:
    return any(
        part in EXCLUDED_DIRS or part.startswith(("dist-", "build-", "out-")) for part in relpath.split("/")[:-1]
    )


def _is_excluded(relpath: str) -> bool:
    if _in_excluded_dir(relpath):
        return True
    name = relpath.rsplit("/", 1)[-1]
    if name in SKIPPED_FILENAMES:
        return True
    return name.endswith(SKIPPED_SUFFIXES)


def _changed_names(root: Path, base: Optional[str]) -> list:
    # --relative: root がリポジトリの中のフォルダでも、root からの相対パスで、その中だけを返す
    diff = ["diff", "--name-only", "-z", "--relative", "--diff-filter=d"]
    names = _split_z(_run_git(root, [*diff, "HEAD", "--"]))  # コミットしていない変更
    if base:
        out = _run_git(root, [*diff, f"{base}...HEAD", "--"])
        if out is None:
            raise ScanError(
                f"--base {base} との差分を取れません。ブランチ名と、CI の checkout の fetch-depth（0 にする）を確認してください。"
            )
        names += _split_z(out)
    names += _split_z(_run_git(root, ["ls-files", "-z", "--others", "--exclude-standard"]))
    return list(dict.fromkeys(names))


def _tool_prefix(root: Path) -> Optional[str]:
    """vulnscan 自身が root の中（root そのものではない）にあれば、その相対パス + "/"。"""
    if TOOL_ROOT == root:
        return None
    try:
        return TOOL_ROOT.relative_to(root).as_posix() + "/"
    except ValueError:
        return None


def collect(
    root: Path,
    *,
    changed_only: bool = False,
    base: Optional[str] = None,
    extra_excludes: Iterable[str] = (),
    dependency_names: Iterable[str] = (),
) -> FileSet:
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"対象が存在しません: {root}")

    if root.is_file():
        rel = root.name
        return FileSet(files=[root], tracked={rel}, git=False)

    # root/.git の有無ではなく、リポジトリの中かで判断する（repo/src を指定しても .gitignore を効かせる）
    is_git = (_run_git(root, ["rev-parse", "--is-inside-work-tree"]) or "").strip() == "true"
    if base and not is_git:
        raise ScanError("git リポジトリではないので --base は使えません。")
    excludes = list(extra_excludes)
    tool_prefix = _tool_prefix(root)
    dependency_names = set(dependency_names)

    def is_candidate(rel: str) -> bool:
        return (
            not (tool_prefix and rel.startswith(tool_prefix))
            and not any(_glob_match(rel, pat) for pat in excludes)
            and not (root / rel).is_symlink()
            and (root / rel).is_file()
        )

    def is_dependency_file(rel: str) -> bool:
        return rel.rsplit("/", 1)[-1] in dependency_names and not _in_excluded_dir(rel) and is_candidate(rel)

    def scannable(names: Iterable[str]) -> list:
        return [n for n in names if n and not _is_excluded(n) and is_candidate(n)]

    if is_git:
        all_names = _split_z(_run_git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"]))
        names = _changed_names(root, base) if changed_only or base else all_names
        tracked = set(_split_z(_run_git(root, ["ls-files", "-z", "--cached"])))
        # 依存は、--changed / --base でも全部の lockfile を見る（新しく公開された脆弱性は lockfile を変えなくても出る）。
        # .gitignore で除外した lockfile も、手元に入っている依存を表すので見る
        ignored_lockfiles = (
            _split_z(
                _run_git(
                    root,
                    ["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--"]
                    + [f":(glob)**/{name}" for name in sorted(dependency_names)],
                )
            )
            if dependency_names
            else []
        )
        dependency_files = sorted(rel for rel in {*all_names, *ignored_lockfiles} if is_dependency_file(rel))
        paths = [root / name for name in scannable(names)]
        inventory = scannable(all_names)
        return FileSet(
            files=paths, tracked=tracked, git=True, dependency_files=dependency_files, inventory=inventory
        )

    paths = []
    dependency_files = []
    skipped = 0
    for dirpath, dirnames, filenames in os.walk(root):
        kept = []
        for d in dirnames:
            if d in EXCLUDED_DIRS or d.startswith((".vulnscan", "dist-", "build-", "out-")):
                skipped += 1
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if is_dependency_file(rel):
                dependency_files.append(rel)
            if _is_excluded(rel) or not is_candidate(rel):
                continue
            paths.append(full)
    return FileSet(
        files=paths,
        tracked=set(),
        skipped_dirs=skipped,
        git=False,
        dependency_files=sorted(dependency_files),
        inventory=[p.relative_to(root).as_posix() for p in paths],
    )


def _glob_match(path: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path.rsplit("/", 1)[-1], pattern)


@dataclass
class LoadResult:
    file: Optional[SourceFile] = None
    reason: Optional[str] = None


def load(path: Path, root: Path, tracked: bool, max_bytes: int) -> LoadResult:
    try:
        st = path.stat()
    except OSError:
        return LoadResult(reason="unreadable")
    if not stat.S_ISREG(st.st_mode):
        return LoadResult(reason="not_regular")
    if st.st_size > max_bytes:
        return LoadResult(reason="too_large")
    if st.st_size == 0:
        return LoadResult(reason="empty")
    try:
        raw = path.read_bytes()
    except OSError:
        return LoadResult(reason="unreadable")
    if b"\x00" in raw[:8192]:
        return LoadResult(reason="binary")
    text = raw.decode("utf-8", "replace")
    rel = path.relative_to(root).as_posix() if path != root else path.name
    return LoadResult(
        file=SourceFile(
            root=root,
            path=path,
            relpath=rel,
            text=text,
            lines=text.splitlines(),
            size=st.st_size,
            tracked=tracked,
            mode=st.st_mode,
        )
    )
