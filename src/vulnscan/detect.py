"""言語とフレームワークの自動の見分けと、--lang の選び方。

言語はファイル名（拡張子）で、フレームワークは目印のファイル（package.json の依存、pubspec.yaml、
requirements.txt、firebase.json など）で決める。どちらも中身を変えず、ネットワークも使わない。
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .files import collect
from .models import ScanError
from .rules import FILE_RULES, LINE_RULES
from .rules.base import LANGUAGE_ALIASES, LANGUAGE_LABELS, NON_CODE_LANGUAGES, language_of


@dataclass(frozen=True)
class Framework:
    id: str
    label: str
    npm: tuple = ()  # package.json の dependencies / devDependencies の名前
    python: tuple = ()  # requirements*.txt・pyproject.toml・Pipfile に出る名前
    files: tuple = ()  # このファイル（パスの末尾）があれば
    text: tuple = ()  # (ファイル名, 中身に当たる正規表現)


FRAMEWORKS = (
    Framework("nextjs", "Next.js", npm=("next", "vinext")),
    Framework("expo", "Expo/React Native", npm=("expo", "react-native")),
    Framework("express", "Express", npm=("express",)),
    Framework("hono", "Hono", npm=("hono",)),
    Framework(
        "supabase",
        "Supabase",
        npm=("@supabase/supabase-js", "@supabase/ssr"),
        python=("supabase",),
        files=("supabase/config.toml",),
    ),
    Framework(
        "firebase",
        "Firebase",
        npm=("firebase", "firebase-admin", "firebase-functions"),
        files=("firebase.json", "firestore.rules", "storage.rules", "google-services.json", "GoogleService-Info.plist"),
        text=(("pubspec.yaml", r"(?m)^\s+firebase_\w+\s*:"),),
    ),
    Framework("flutter", "Flutter", text=(("pubspec.yaml", r"sdk:\s*flutter"),)),
    Framework(
        "cloudflare",
        "Cloudflare Workers",
        npm=("wrangler", "@cloudflare/vite-plugin", "@opennextjs/cloudflare"),
        files=("wrangler.toml", "wrangler.json", "wrangler.jsonc", "cloudflare.config.ts"),
    ),
    Framework("django", "Django", python=("django",), files=("manage.py",)),
    Framework("fastapi", "FastAPI", python=("fastapi",)),
    Framework("flask", "Flask", python=("flask",)),
    Framework("rails", "Rails", text=(("Gemfile", r"""gem\s+['"]rails['"]"""),)),
    Framework("laravel", "Laravel", text=(("composer.json", r'"laravel/framework"'),)),
)

PYTHON_DEPENDENCY_FILES = re.compile(r"(?:^|/)(?:requirements[^/]*\.txt|pyproject\.toml|Pipfile)$")


def _read(path: Path) -> str:
    try:
        return path.read_text("utf-8", "replace")
    except OSError:
        return ""


def _npm_dependencies(text: str) -> set:
    try:
        data = json.loads(text)
    except ValueError:
        return set()
    if not isinstance(data, dict):
        return set()
    names = set()
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict):
            names.update(deps)
    return names


def _python_mentions(text: str, name: str) -> bool:
    # "fastapi==0.1"・"Django>=5"・["flask"] は当たり、"flask-cors" は当たらない
    return re.search(rf"(?im)(?:^|[\s\"'\[,]){re.escape(name)}(?=\s*(?:\[|[<>=!~;,\"']|$))", text) is not None


def detect_frameworks(root: Path, relpaths: Iterable[str]) -> list:
    """[{"id", "label", "evidence"}]。evidence は見分けた目印のファイル。"""
    relpaths = sorted(relpaths)
    contents: dict = {}

    def text_of(rel: str) -> str:
        if rel not in contents:
            contents[rel] = _read(root / rel)
        return contents[rel]

    package_jsons = [rel for rel in relpaths if rel.rsplit("/", 1)[-1] == "package.json"]
    npm_deps = {rel: _npm_dependencies(text_of(rel)) for rel in package_jsons}
    python_files = [rel for rel in relpaths if PYTHON_DEPENDENCY_FILES.search(rel)]

    found = []
    for fw in FRAMEWORKS:
        evidence: Optional[str] = None
        for rel, deps in npm_deps.items():
            if deps.intersection(fw.npm):
                evidence = rel
                break
        if evidence is None and fw.python:
            evidence = next(
                (rel for rel in python_files if any(_python_mentions(text_of(rel), n) for n in fw.python)), None
            )
        if evidence is None and fw.files:
            evidence = next(
                (rel for rel in relpaths if any(rel == f or rel.endswith("/" + f) for f in fw.files)), None
            )
        if evidence is None:
            for name, pattern in fw.text:
                evidence = next(
                    (
                        rel
                        for rel in relpaths
                        if rel.rsplit("/", 1)[-1] == name and re.search(pattern, text_of(rel))
                    ),
                    None,
                )
                if evidence:
                    break
        if evidence:
            found.append({"id": fw.id, "label": fw.label, "evidence": evidence})
    return found


def language_summary(names: Iterable[str]) -> list:
    """[{"language", "label", "files", "rules"}]。rules はその言語だけに効くルールの数（秘密のルールは全言語に効く）。"""
    file_counts = Counter(language_of(name) for name in names)
    rule_counts = Counter(lang for rule in [*LINE_RULES, *FILE_RULES] for lang in rule.languages)
    return [
        {"language": lang, "label": LANGUAGE_LABELS.get(lang, lang), "files": n, "rules": rule_counts[lang]}
        for lang, n in file_counts.most_common()
        if lang and lang not in NON_CODE_LANGUAGES
    ]


def detect(root: Path) -> dict:
    """スキャンせずに、言語とフレームワークだけを見分ける（`vulnscan detect` と、番号で選ぶ一覧）。"""
    root = root.resolve()
    if root.is_file():
        return {"root": str(root), "languages": language_summary([root.name]), "frameworks": []}
    fileset = collect(root)
    return {
        "root": str(root),
        "languages": language_summary(rel.rsplit("/", 1)[-1] for rel in fileset.inventory),
        "frameworks": detect_frameworks(root, fileset.inventory),
    }


def _alias_table() -> dict:
    table = {}
    for lang, aliases in LANGUAGE_ALIASES.items():
        for name in (lang, *aliases, LANGUAGE_LABELS.get(lang, lang)):
            table[name.lower()] = lang
    table["javascript/typescript"] = "javascript"
    return table


def parse_languages(spec: str) -> list:
    """"js,py" のような指定を、言語のキーの一覧にする。"""
    table = _alias_table()
    chosen = []
    for token in (t.strip().lower() for t in spec.split(",")):
        if not token:
            continue
        if token not in table:
            names = ", ".join(sorted({aliases[0] for aliases in LANGUAGE_ALIASES.values()}))
            raise ScanError(f"知らない言語です: {token}。使える名前: {names}")
        if table[token] not in chosen:
            chosen.append(table[token])
    if not chosen:
        raise ScanError("--lang に言語を指定してください（例: --lang js,py）。")
    return chosen


def choose_languages(detected: list, answer: str) -> Optional[list]:
    """番号で選ぶ一覧への答え（"1,3"・"py"・空）を、言語のキーの一覧にする。空なら None（絞らない。--lang を付けないときと同じ）。"""
    if not answer.strip():
        return None
    chosen = []
    for token in (t.strip() for t in answer.split(",")):
        if not token:
            continue
        if token.isdigit():
            index = int(token)
            if not 1 <= index <= len(detected):
                raise ScanError(f"{token} は一覧にありません（1〜{len(detected)}）。")
            keys = [detected[index - 1]["language"]]
        else:
            keys = parse_languages(token)
        chosen.extend(k for k in keys if k not in chosen)
    return chosen
