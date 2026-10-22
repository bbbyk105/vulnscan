"""言語とフレームワークの自動の見分けと、--lang の選び方。

言語はファイル名（拡張子）で、フレームワークは目印のファイル（package.json・go.mod の依存、pubspec.yaml、
requirements.txt、firebase.json など）で決める。どちらも中身を変えず、ネットワークも使わない。
フレームワークには、チェックリストで読む所が決まるもの（Stripe・MCP などのライブラリ、AWS・Terraform などの基盤）も含める。
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Iterable, Optional

from .files import collect

try:
    import tomllib
except ImportError:  # Python 3.9・3.10。pyproject.toml・Pipfile は 0.3.0 までと同じ読み方（_python_mentions）で見る
    tomllib = None
from .models import ScanError
from .rules import FILE_RULES, LINE_RULES
from .rules.base import LANGUAGE_ALIASES, LANGUAGE_LABELS, NON_CODE_LANGUAGES, language_of


@dataclass(frozen=True)
class Framework:
    id: str
    label: str
    npm: tuple = ()  # package.json の dependencies / devDependencies の名前。"/" で終わるものはその scope の全部（"@clerk/"）
    python: tuple = ()  # requirements・pyproject.toml・Pipfile で依存に書く名前。"-" で終わるものはその一族（"langchain-"）
    go: tuple = ()  # go.mod で直接 require しているモジュール（"/v2" などの下も含む。indirect は数えない）
    files: tuple = ()  # このファイル（パスの末尾）があれば。"*" を含むものはファイル名との照合（"*.tf"）
    # (ファイル名か "*.csproj" の形, 中身に当たる正規表現か、全部が当たるべき正規表現を並べたもの)。
    # "/" を含む形はパス全体と照合する（"*sites-available/*"）。
    # 中身は、コメントアウトした行を外した先頭だけを見る
    text: tuple = ()


def _gem(name: str) -> str:
    return rf"""(?m)^[ \t]*gem[ \t]+['"]{re.escape(name)}['"]"""


def _crate(name: str) -> str:
    # Cargo.toml の `axum = "0.8"`・`axum = { … }`・`axum.workspace = true`・`[dependencies.axum]`
    escaped = re.escape(name)
    return rf"(?m)^[ \t]*(?:{escaped}[ \t]*(?:=|\.)|\[[^\]\n]*dependencies\.{escaped}[ \t]*\])"


# apiVersion と、Kubernetes の kind の両方がある YAML（GitHub Actions や Backstage の kind: Component は当たらない）
_K8S_KINDS = (
    "Deployment|StatefulSet|DaemonSet|ReplicaSet|Pod|Job|CronJob|Service|Ingress|IngressClass|NetworkPolicy|Secret|"
    "ConfigMap|ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|Namespace|PersistentVolume|"
    "PersistentVolumeClaim|StorageClass|HorizontalPodAutoscaler|PodDisruptionBudget|ResourceQuota|LimitRange|"
    "PriorityClass|CustomResourceDefinition|Gateway|HTTPRoute|List"
)
# 正規表現を並べたものは、全部が当たったら（先読みの .*? で 1 文字ずつ先を見ないように、別々に探す）
_K8S_MANIFEST = (
    r"(?m)^apiVersion:[ \t]",
    rf"(?m)^kind:[ \t]*([\"']?)(?:{_K8S_KINDS})\1[ \t]*(?:#[^\n]*)?$",
)
# nginx の指令は ; で終わる（TOML・INI の `server_name = "…"` は当たらない）
_NGINX_CONF = (
    r"(?m)(?:^|[{;])[ \t]*(?:(?:listen|server_name)[ \t]+[^=;{}\s][^=;{}\n]*;|proxy_pass[ \t]+[^;{}\s][^;{}\n]*;"
    r"|location[ \t]+[^{};\s][^{};\n]*\{)"
)
# SAM の Transform は 1 行でも、一覧（Transform:\n  - AWS::Serverless-…）でも
_CLOUDFORMATION = r"(?m)^(?:AWSTemplateFormatVersion:|Transform:[ \t]*(?:\n[ \t]*-[ \t]*)?[\"']?AWS::Serverless)"
_SPRING_GRADLE = r"org\.springframework\.boot|libs\.(?:plugins\.)?spring\.boot\b"
_ASPNET = (
    r"""(?:Sdk|Name)\s*=\s*["']Microsoft\.NET\.Sdk\.Web(?:/[^"']*)?["']"""
    r"""|Include\s*=\s*["']Microsoft\.AspNetCore\.(?:App|All)["']"""
)


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
        text=(("pubspec.yaml", r"(?m)^[ \t]+firebase_\w+[ \t]*:"),),
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
    Framework("rails", "Rails", text=(("Gemfile", _gem("rails")),)),
    Framework("laravel", "Laravel", text=(("composer.json", r'"laravel/framework"'),)),
    Framework(
        "wordpress",
        "WordPress",
        files=("wp-config.php", "wp-config-sample.php", "wp-load.php"),
        text=(
            ("readme.txt", r"(?m)^(?:Stable tag|Requires at least):"),  # プラグインの readme
            ("style.css", r"(?m)^[ \t]*(?:\*[ \t]*)?Theme Name:"),  # テーマ
            ("composer.json", r'"type"\s*:\s*"wordpress-(?:plugin|theme|muplugin)"|"(?:johnpbloch|roots)/wordpress"'),
        ),
    ),
    Framework("nestjs", "NestJS", npm=("@nestjs/core",)),
    Framework("fastify", "Fastify", npm=("fastify",)),
    Framework("koa", "Koa", npm=("koa",)),
    Framework("gin", "Gin", go=("github.com/gin-gonic/gin",)),
    Framework("echo", "Echo", go=("github.com/labstack/echo",)),
    Framework("fiber", "Fiber", go=("github.com/gofiber/fiber",)),
    Framework("chi", "chi", go=("github.com/go-chi/chi",)),
    Framework(
        "spring",
        "Spring Boot",
        text=(
            ("pom.xml", r"<groupId>\s*org\.springframework\.boot\s*</groupId>"),
            ("build.gradle", _SPRING_GRADLE),
            ("build.gradle.kts", _SPRING_GRADLE),
            ("libs.versions.toml", r"org\.springframework\.boot"),
        ),
    ),
    Framework(
        "aspnet",
        "ASP.NET Core",
        # Web の SDK か、ASP.NET Core の共有フレームワーク（SignalR のクライアント・テスト・Blazor WASM のパッケージは数えない）
        text=(("*.csproj", _ASPNET), ("*.fsproj", _ASPNET), ("*.vbproj", _ASPNET)),
    ),
    Framework("axum", "Axum", text=(("Cargo.toml", _crate("axum")),)),
    Framework("actix", "Actix Web", text=(("Cargo.toml", _crate("actix-web")),)),
    Framework("phoenix", "Phoenix", text=(("mix.exs", r"\{\s*:phoenix\s*,"),)),
    Framework(
        "aws",
        "AWS",
        npm=("@aws-sdk/", "aws-sdk", "aws-cdk-lib", "aws-amplify", "@aws-amplify/backend", "serverless"),
        python=("boto3", "aws-cdk-lib", "chalice"),
        go=("github.com/aws/aws-sdk-go-v2", "github.com/aws/aws-sdk-go", "github.com/aws/aws-lambda-go"),
        files=("serverless.yml", "serverless.yaml", "cdk.json", "samconfig.toml", "amplify/backend.ts"),
        text=(
            ("*.yaml", _CLOUDFORMATION),
            ("*.yml", _CLOUDFORMATION),
            ("*.template.json", r'"AWSTemplateFormatVersion"'),
            ("template.json", r'"AWSTemplateFormatVersion"'),
        ),
    ),
    Framework("better-auth", "Better Auth", npm=("better-auth",)),
    Framework("authjs", "Auth.js", npm=("next-auth", "@auth/")),
    Framework("clerk", "Clerk", npm=("@clerk/",)),
    Framework("prisma", "Prisma", npm=("prisma", "@prisma/client")),
    Framework("drizzle", "Drizzle", npm=("drizzle-orm",)),
    Framework(
        "stripe",
        "Stripe",
        npm=("stripe", "@stripe/"),
        python=("stripe",),
        go=("github.com/stripe/stripe-go",),
        text=(("Gemfile", _gem("stripe")), ("composer.json", r'"stripe/stripe-php"')),
    ),
    Framework(
        "graphql",
        "GraphQL",
        # graphql・@apollo/client だけ（GraphQL を呼ぶ画面）は数えない。サーバーを作るものだけ
        npm=(
            "@apollo/server",
            "apollo-server",
            "apollo-server-express",
            "graphql-yoga",
            "@nestjs/graphql",
            "type-graphql",
            "mercurius",
            "graphql-http",
            "express-graphql",
            "@pothos/core",
        ),
        python=("strawberry-graphql", "strawberry-graphql-django", "graphene", "graphene-django", "ariadne"),
        go=("github.com/99designs/gqlgen", "github.com/graph-gophers/graphql-go"),
        text=(("Gemfile", _gem("graphql")),),
    ),
    Framework("trpc", "tRPC", npm=("@trpc/server",)),
    Framework(
        "mcp",
        "MCP",
        npm=("@modelcontextprotocol/sdk", "fastmcp", "mcp-handler"),
        python=("mcp", "fastmcp"),
        go=("github.com/modelcontextprotocol/go-sdk", "github.com/mark3labs/mcp-go"),
    ),
    Framework(
        "llm",
        "LLM の API",
        npm=(
            "openai",
            "@anthropic-ai/sdk",
            "@anthropic-ai/claude-agent-sdk",
            "@openai/agents",
            "ai",
            "@ai-sdk/",
            "@google/genai",
            "@google/generative-ai",
            "langchain",
            "@langchain/",
            "@mistralai/mistralai",
            "groq-sdk",
            "ollama",
        ),
        python=(
            "openai",
            "openai-agents",
            "anthropic",
            "claude-agent-sdk",
            "langchain",
            "langchain-",  # "-" で終わるものはその一族（langchain-openai など）
            "llama-index",
            "llama-index-",
            "pydantic-ai",
            "pydantic-ai-",
            "google-genai",
            "google-generativeai",
            "litellm",
            "mistralai",
            "groq",
            "ollama",
        ),
        go=("github.com/openai/openai-go", "github.com/anthropics/anthropic-sdk-go", "github.com/sashabaranov/go-openai"),
    ),
    Framework(
        "docker-compose",
        "Docker Compose",
        files=("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml", "compose.*.yml", "compose.*.yaml"),
    ),
    Framework(
        "kubernetes",
        "Kubernetes",
        files=("Chart.yaml", "kustomization.yaml", "kustomization.yml"),
        text=(("*.yaml", _K8S_MANIFEST), ("*.yml", _K8S_MANIFEST)),
    ),
    Framework("terraform", "Terraform", files=("*.tf",)),
    Framework(
        "nginx",
        "nginx",
        files=("nginx.conf",),
        # sites-available/ のサイトの名前のファイルと、公式のイメージの templates/*.conf.template
        text=(
            ("*.conf", _NGINX_CONF),
            ("*.conf.template", _NGINX_CONF),
            ("*sites-available/*", _NGINX_CONF),
            ("*sites-enabled/*", _NGINX_CONF),
        ),
    ),
)

PYTHON_DEPENDENCY_FILES = re.compile(
    r"(?:^|/)(?:requirements[^/]*\.(?:txt|in)|requirements/(?![Rr][Ee][Aa][Dd][Mm][Ee])[^/]+\.(?:txt|in)|pyproject\.toml|Pipfile)$"
)

# text の目印は先頭だけを読む（*.yaml などは数が多いので、大きなデータのファイルで遅く・重くならないように）。
# 依存を書く manifest は、スキャンと同じ 1.5MB まで読む（親の pom.xml の BOM や workspace の依存は後ろにあることがある）
_MARKER_READ_LIMIT = 32768
_MANIFEST_READ_LIMIT = 1_500_000
_MANIFESTS = (
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "libs.versions.toml",
    "Cargo.toml",
    "composer.json",
    "mix.exs",
    "pubspec.yaml",
)


def _read_limit(basename: str) -> int:
    manifest = basename in _MANIFESTS or basename.endswith((".csproj", ".fsproj", ".vbproj"))
    return _MANIFEST_READ_LIMIT if manifest else _MARKER_READ_LIMIT


def _read(path: Path, limit: Optional[int] = None) -> str:
    """BOM を外し、改行を \n にそろえて読む（CRLF や CR だけの改行でも、正規表現の ^・$ が効くように）。"""
    try:
        with path.open("rb") as handle:
            data = handle.read() if limit is None else handle.read(limit)
    except OSError:
        return ""
    return re.sub(r"\r\n?", "\n", data.decode("utf-8-sig", "replace"))


# Gradle は行の頭から始まるコメントだけを外す（`exclude '**/*.tmp'` の /* は文字列の中）
_C_COMMENT_START = re.compile(r"^[ \t]*(/\*|//)", re.M)


def _strip_xml_comments(text: str) -> str:
    parts = []
    position = 0
    while True:
        start = text.find("<!--", position)
        if start < 0:
            return "".join(parts) + text[position:]
        parts.append(text[position:start])
        end = text.find("-->", start + 4)
        if end < 0:  # 閉じないコメントは、最後までコメント
            return "".join(parts)
        position = end + 3


def _strip_c_comments(text: str) -> str:
    parts = []
    position = 0
    while True:
        match = _C_COMMENT_START.search(text, position)
        if not match:
            return "".join(parts) + text[position:]
        parts.append(text[position : match.start(1)])
        if match.group(1) == "//":
            end = text.find("\n", match.end())
            position = len(text) if end < 0 else end
        else:
            end = text.find("*/", match.end())
            if end < 0:
                return "".join(parts)
            position = end + 2


def _strip_hash_comment(line: str) -> str:
    """引用符の外で、行の頭か空白の後ろの # から後ろ（コメント）を外す。"""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _without_comments(basename: str, text: str) -> str:
    """目印の中身から、コメントを外す（`# {:phoenix, …}` は依存ではない）。"""
    if basename.endswith((".csproj", ".fsproj", ".vbproj", ".xml")):
        return _strip_xml_comments(text)
    if basename.startswith("build.gradle"):
        return _strip_c_comments(text)
    if basename.endswith((".json", ".css", ".txt")):  # テーマの見出しは /* … */ の中にある
        return text
    if "#" not in text:
        return text
    return "\n".join(_strip_hash_comment(line) if "#" in line else line for line in text.split("\n"))


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


def _npm_matches(deps: set, names: tuple) -> bool:
    return any(dep == name or (name.endswith("/") and dep.startswith(name)) for dep in deps for name in names)


def _go_requires(text: str) -> set:
    """go.mod で直接 require しているモジュール（// indirect の付いたものは除く）。"""
    modules = set()
    in_block = False
    for line in text.splitlines():
        code, _, comment = line.partition("//")
        words = code.split()
        if in_block:
            if words[:1] == [")"]:
                in_block = False
                continue
        elif words[:1] == ["require"]:
            words = words[1:]
            if words == ["("]:
                in_block = True
                continue
        else:
            continue
        if len(words) >= 2 and "indirect" not in comment:
            modules.add(words[0].strip('"`'))
    return modules


def _go_matches(modules: set, names: tuple) -> bool:
    return any(module == name or module.startswith(name + "/") for module in modules for name in names)


def _is_pattern(name: str) -> bool:
    return any(ch in name for ch in "*?[")


class _Paths:
    """目印を探すための、パスの索引（ファイル名ごと・拡張子ごと）。パスの数 × 目印の数だけ照合し直さないように。"""

    def __init__(self, relpaths: list) -> None:
        self.relpaths = relpaths  # 並べたもの（evidence は最初に見つかったもの）
        self.by_name: dict = {}
        self.by_suffix: dict = {}
        for rel in relpaths:
            name = rel.rsplit("/", 1)[-1]
            self.by_name.setdefault(name, []).append(rel)
            if "." in name:
                self.by_suffix.setdefault(name[name.rfind(".") :], []).append(rel)

    def find(self, name: str) -> list:
        """name（ファイル名・"*.tf" の形・"supabase/config.toml" の形・"*sites-available/*" の形）に当たるパス。"""
        if "/" in name and _is_pattern(name):
            literal = max(re.split(r"[*?\[\]]", name), key=len)
            return [rel for rel in self.relpaths if literal in rel and fnmatchcase(rel, name)]
        if "/" in name:
            base = name.rsplit("/", 1)[-1]
            return [rel for rel in self.by_name.get(base, []) if rel == name or rel.endswith("/" + name)]
        if not _is_pattern(name):
            return self.by_name.get(name, [])
        suffix = name[name.rfind(".") :] if "." in name else ""
        pool = self.by_suffix.get(suffix, []) if suffix and not _is_pattern(suffix) else self.relpaths
        return [rel for rel in pool if fnmatchcase(rel.rsplit("/", 1)[-1], name)]


def _normalize_python_name(name: str) -> str:
    # pip は大文字小文字と - _ . を区別しない（PEP 503）
    return re.sub(r"[-_.]+", "-", name).lower()


def _python_matches(deps: set, names: tuple) -> bool:
    # "-" で終わる名前は、その名前で始まる一族（"langchain-" は langchain-openai など）
    wanted = [_normalize_python_name(n) for n in names]
    return any(dep == name or (name.endswith("-") and dep.startswith(name)) for dep in deps for name in wanted)


def _python_mentions(text: str, name: str) -> bool:
    """0.3.0 までの読み方: 名前が依存の形（後ろに版の指定・引用符・行の終わり）で出てくるか。TOML を読めないときに使う。

    "fastapi==0.1"・"Django>=5"・["flask"] は当たり、"flask-cors" は当たらない。キーワードや説明に出てくる名前にも当たる。
    """
    family = "[A-Za-z0-9._-]*" if name.endswith("-") else ""
    pattern = rf"(?im)(?:^|[\s\"'\[,]){re.escape(name)}{family}(?=[ \t]*(?:\[|[<>=!~;,\"']|$))"
    return re.search(pattern, text) is not None


# requirements の 1 行。名前の後ろは、extras・版の指定・環境の条件・URL だけ（`openai is not used` のような文は当たらない）
_REQUIREMENT_LINE = re.compile(r"[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*(?:\[[^\]\n]*\][ \t]*)?(?:[<>=!~;@]|\\?$)")
_REQUIREMENT_COMMENT = re.compile(r"(?:^|\s)#.*$")  # 前に空白の無い # は URL の一部（git+https://…#egg=…）
# 依存を書くキー（dependencies・optional-dependencies・dev-dependencies・pypi-dependencies・extra-dependencies・
# dependency-groups・requires・requires-extra・tox の deps）
_DEPENDENCY_KEY = re.compile(r"(?:.*[-_])?dependencies|dependency-groups|requires(?:-extra)?|deps")
# 値が「グループの名前 → 依存の一覧」になるキー（キーそのものは依存の名前ではない）
_GROUP_KEYS = {"optional-dependencies", "dependency-groups", "requires-extra"}
# 依存を書くキーの名前でも、実行に使う依存ではない場所: ビルドの道具・uv の版の制約・hatch のビルド・setuptools の dynamic（ファイルの指定）
_NOT_DEPENDENCIES = re.compile(
    r"build-system(?:\x1f.*)?|.*\x1f(?:constraint|override)-dependencies|tool\x1fhatch\x1fbuild(?:\x1f.*)?"
    r"|tool\x1fsetuptools\x1fdynamic(?:\x1f.*)?"
)
_PIPFILE_OTHER_TABLES = {"source", "requires", "scripts", "pipenv"}


def _requirement_names(items: list) -> set:
    names = set()
    for item in items:
        match = _REQUIREMENT_LINE.match(item) if isinstance(item, str) else None
        if match:
            names.add(match.group(1))
    return names


def _names_in(key: str, value) -> set:
    """依存を書くキーの値から、依存の名前を取り出す。"""
    if isinstance(value, list):  # ["fastapi>=0.1", …]
        return _requirement_names(value)
    if not isinstance(value, dict):
        return set()
    names = set()
    for name, item in value.items():
        if isinstance(item, list) and (key in _GROUP_KEYS or all(isinstance(x, str) for x in item)):
            names |= _requirement_names(item)  # optional-dependencies・dependency-groups の ai = [...]
        elif key not in _GROUP_KEYS:
            names.add(name)  # Poetry・pixi の fastapi = "^1"・{ version = … }・[{ … }, { … }]
    return names


def _tox_ini_dependencies(ini: str) -> set:
    """[tool.tox] の legacy_tox_ini（tox.ini の中身の文字列）の deps。"""
    names = set()
    in_deps = False
    for line in ini.splitlines():
        key = re.match(r"[ \t]*deps[ \t]*=(.*)$", line)
        if key:
            in_deps, line = True, key.group(1)
        elif not (in_deps and line[:1] in (" ", "\t")):
            in_deps = False
            continue
        match = _REQUIREMENT_LINE.match(line)
        if match:
            names.add(match.group(1))
    return names


def _toml_dependencies(data: dict, pipfile: bool) -> set:
    if pipfile:  # [packages]・[dev-packages] と、自分で付けた区分の表
        return {
            name
            for key, table in data.items()
            if key not in _PIPFILE_OTHER_TABLES and isinstance(table, dict)
            for name in table
        }
    names = set()
    stack = [((), data)]
    while stack:
        path, table = stack.pop()
        for key, value in table.items():
            here = path + (key,)
            joined = "\x1f".join(here)
            if _NOT_DEPENDENCIES.fullmatch(joined):
                continue
            if _DEPENDENCY_KEY.fullmatch(key) and (key != "deps" or here[:2] == ("tool", "tox")):
                names |= _names_in(key, value)
            if here == ("tool", "tox", "legacy_tox_ini") and isinstance(value, str):
                names |= _tox_ini_dependencies(value)
            if isinstance(value, dict):
                stack.append((here, value))
            elif isinstance(value, list):
                stack.extend((here, item) for item in value if isinstance(item, dict))
    return names


def _python_dependencies(rel: str, text: str) -> Optional[set]:
    """requirements・pyproject.toml・Pipfile で依存に書いた名前（PEP 503 でそろえたもの）。

    キーワード・説明・コメントに出てくる名前は数えない（keywords = ["openai"] は依存ではない）。
    TOML を読めないとき（tomllib の無い Python・壊れたファイル）は None を返し、0.3.0 までの読み方に任せる。
    """
    if rel.endswith((".toml", "Pipfile")):
        if tomllib is None:
            return None
        try:
            data = tomllib.loads(text)
        except (ValueError, RecursionError):  # 壊れたファイル・入れ子の深すぎるファイル
            return None
        names = _toml_dependencies(data, pipfile=rel.endswith("Pipfile"))
    else:
        names = set()
        for line in text.splitlines():
            match = _REQUIREMENT_LINE.match(_REQUIREMENT_COMMENT.sub("", line))
            if match:
                names.add(match.group(1))
    return {_normalize_python_name(n) for n in names}


def _text_markers(root: Path, paths: _Paths, frameworks: list) -> dict:
    """text の目印（中身の正規表現）を当てる。{(フレームワークの番号, text の番号): evidence}。

    1 つのファイルを読むのは 1 回だけにする（*.yaml は aws と kubernetes、pubspec.yaml は firebase と flutter が見る）。
    """
    wanted: dict = {}  # rel -> [(key, pattern)]
    for i, fw in frameworks:
        for j, (name, pattern) in enumerate(fw.text):
            compiled = [re.compile(p) for p in ((pattern,) if isinstance(pattern, str) else pattern)]
            for rel in paths.find(name):
                wanted.setdefault(rel, []).append(((i, j), compiled))
    hits: dict = {}
    first: dict = {}  # フレームワークの番号 -> いちばん先に当たった text の番号（それより後ろの目印は要らない）
    for rel in sorted(wanted):  # 並べた順に見るので、最初に当たったものが evidence
        pending = [
            (key, pattern) for key, pattern in wanted[rel] if key not in hits and key[1] < first.get(key[0], len(FRAMEWORKS))
        ]
        if not pending:
            continue
        basename = rel.rsplit("/", 1)[-1]
        text = _without_comments(basename, _read(root / rel, _read_limit(basename)))
        for key, patterns in pending:
            if all(pattern.search(text) for pattern in patterns):
                hits[key] = rel
                first[key[0]] = min(key[1], first.get(key[0], key[1]))
    return hits


def detect_frameworks(root: Path, relpaths: Iterable[str]) -> list:
    """[{"id", "label", "evidence"}]。evidence は見分けた目印のファイル。"""
    paths = _Paths(sorted(relpaths))
    npm_deps = {rel: _npm_dependencies(_read(root / rel)) for rel in paths.find("package.json")}
    go_mods = {rel: _go_requires(_read(root / rel)) for rel in paths.find("go.mod")}
    python_files = {rel: _read(root / rel) for rel in paths.relpaths if PYTHON_DEPENDENCY_FILES.search(rel)}
    python_deps = {rel: _python_dependencies(rel, text) for rel, text in python_files.items()}

    def uses_python(rel: str, names: tuple) -> bool:
        deps = python_deps[rel]
        if deps is None:
            return any(_python_mentions(python_files[rel], name) for name in names)
        return _python_matches(deps, names)

    evidence: dict = {}
    for i, fw in enumerate(FRAMEWORKS):
        found: Optional[str] = None
        if fw.npm:
            found = next((rel for rel, deps in npm_deps.items() if _npm_matches(deps, fw.npm)), None)
        if found is None and fw.go:
            found = next((rel for rel, modules in go_mods.items() if _go_matches(modules, fw.go)), None)
        if found is None and fw.python:
            found = next((rel for rel in python_deps if uses_python(rel, fw.python)), None)
        if found is None and fw.files:
            found = min((rel for name in fw.files for rel in paths.find(name)), default=None)
        if found is not None:
            evidence[i] = found
    hits = _text_markers(root, paths, [(i, fw) for i, fw in enumerate(FRAMEWORKS) if i not in evidence])
    for (i, j), rel in sorted(hits.items()):
        evidence.setdefault(i, rel)  # text の目印は、書いた順に先のものを使う
    return [
        {"id": fw.id, "label": fw.label, "evidence": evidence[i]} for i, fw in enumerate(FRAMEWORKS) if i in evidence
    ]


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
    """スキャンせずに、言語とフレームワークだけを見分ける（`vulnscan detect` と、言語を選ぶ一覧）。"""
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
    """番号を打つ形（termios の無い環境で使う）への答え（"1,3"・"py"・空）を、言語のキーの一覧にする。空なら None（絞らない。--lang を付けないときと同じ）。"""
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
