"""バックエンド・サービス・インフラの見分けと、見分けたものからチェックリストの節への道筋。"""

from __future__ import annotations

import json
import re
import time
import unittest
from unittest import mock

from test_vulnscan import ROOT, RepoCase

from vulnscan import detect as detect_module
from vulnscan.detect import FRAMEWORKS, detect


requires_tomllib = unittest.skipIf(
    detect_module.tomllib is None,
    "tomllib の無い Python（3.9・3.10）では、pyproject.toml・Pipfile を以前と同じ読み方（名前が依存の形で出てくるか）で見る",
)


class Case(RepoCase):
    def ids(self) -> set:
        return {item["id"] for item in detect(self.root)["frameworks"]}


class BackendDetectionTests(Case):
    def test_go_modules_from_go_mod(self) -> None:
        self.write(
            {
                "backend/go.mod": (
                    "module example.com/api\n\ngo 1.22\n\n"
                    "require github.com/gofiber/fiber/v2 v2.52.0\n\n"
                    "require (\n"
                    "\tgithub.com/gin-gonic/gin v1.10.0\n"
                    "\tgithub.com/aws/aws-sdk-go-v2/service/s3 v1.95.0 // indirect\n"
                    ")\n"
                ),
            }
        )
        # indirect の依存は、このモジュールが直接使っているものではないので数えない
        self.assertEqual(self.ids(), {"fiber", "gin"})

    def test_jvm_dotnet_rust_and_elixir_manifests(self) -> None:
        self.write(
            {
                "api/pom.xml": "<project><parent><groupId>org.springframework.boot</groupId></parent></project>\n",
                "web/Web.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web">\n</Project>\n',
                "svc/Cargo.toml": '[package]\nname = "svc"\n\n[dependencies]\naxum = "0.8"\nactix-web = { version = "4" }\n',
                "chat/mix.exs": "defp deps do\n  [\n    {:phoenix, \"~> 1.7\"},\n    {:phoenix_live_view, \"~> 1.0\"}\n  ]\nend\n",
            }
        )
        self.assertEqual(self.ids(), {"spring", "aspnet", "axum", "actix", "phoenix"})

    def test_phoenix_plugins_alone_are_not_phoenix(self) -> None:
        self.write({"mix.exs": "defp deps do\n  [{:phoenix_pubsub, \"~> 2.1\"}]\nend\n"})
        self.assertEqual(self.ids(), set())

    def test_gradle_kotlin_dsl(self) -> None:
        self.write({"build.gradle.kts": 'plugins {\n    id("org.springframework.boot") version "3.3.0"\n}\n'})
        self.assertEqual(self.ids(), {"spring"})

    def test_console_dotnet_project_is_not_aspnet(self) -> None:
        self.write({"Tool.csproj": '<Project Sdk="Microsoft.NET.Sdk">\n</Project>\n'})
        self.assertEqual(self.ids(), set())

    def test_node_servers(self) -> None:
        self.write(
            {
                "api/package.json": json.dumps({"dependencies": {"@nestjs/core": "11", "fastify": "5"}}),
                "legacy/package.json": json.dumps({"dependencies": {"koa": "2"}}),
            }
        )
        self.assertEqual(self.ids(), {"nestjs", "fastify", "koa"})


class ServiceDetectionTests(Case):
    def test_js_libraries_with_scoped_names(self) -> None:
        self.write(
            {
                "package.json": json.dumps(
                    {
                        "dependencies": {
                            "@clerk/nextjs": "6",
                            "better-auth": "1",
                            "@trpc/server": "11",
                            "@modelcontextprotocol/sdk": "1",
                            "@ai-sdk/anthropic": "2",
                            "stripe": "18",
                            "drizzle-orm": "0.45",
                            "@aws-sdk/client-s3": "3",
                        },
                        "devDependencies": {"prisma": "6", "@apollo/server": "4"},
                    }
                ),
            }
        )
        self.assertEqual(
            self.ids(),
            {"clerk", "better-auth", "trpc", "mcp", "llm", "stripe", "drizzle", "aws", "prisma", "graphql"},
        )

    def test_graphql_client_is_not_a_server(self) -> None:
        # graphql と Apollo Client だけなら、GraphQL を使う画面であって、GraphQL のサーバーではない
        self.write({"package.json": json.dumps({"dependencies": {"graphql": "16", "@apollo/client": "3"}})})
        self.assertEqual(self.ids(), set())

    def test_python_services(self) -> None:
        self.write({"worker/requirements.txt": "boto3==1.35\nanthropic>=0.40\nmcp[cli]\nstripe\nstrawberry-graphql\n"})
        self.assertEqual(self.ids(), {"aws", "llm", "mcp", "stripe", "graphql"})

    def test_ruby_php_and_go_services(self) -> None:
        self.write(
            {
                "Gemfile": "gem 'rails', '~> 8.0'\ngem \"stripe\"\ngem 'graphql'\n",
                "composer.json": json.dumps({"require": {"laravel/framework": "^12.0", "stripe/stripe-php": "^16"}}),
                "go.mod": "module x\n\nrequire github.com/stripe/stripe-go/v82 v82.0.0\n",
            }
        )
        self.assertEqual(self.ids(), {"rails", "laravel", "stripe", "graphql"})

    def test_wordpress_sites_plugins_and_themes(self) -> None:
        self.write({"site/wp-config-sample.php": "<?php\n"})
        self.assertEqual(self.ids(), {"wordpress"})
        self.write({"site/wp-config-sample.php": "", "plugin/readme.txt": "=== My Plugin ===\nStable tag: 1.2.0\n"})
        (self.root / "site/wp-config-sample.php").unlink()
        self.assertEqual(self.ids(), {"wordpress"})
        (self.root / "plugin/readme.txt").unlink()
        self.write({"theme/style.css": "/*\nTheme Name: Example\n*/\n"})
        self.assertEqual(self.ids(), {"wordpress"})

    def test_ordinary_readme_and_css_are_not_wordpress(self) -> None:
        self.write({"readme.txt": "How to build\n", "style.css": "body { margin: 0 }\n"})
        self.assertEqual(self.ids(), set())

    def test_aws_from_infrastructure_files(self) -> None:
        self.write({"template.yaml": "Transform: AWS::Serverless-2016-10-31\nResources: {}\n"})
        self.assertEqual(self.ids(), {"aws"})


class InfrastructureDetectionTests(Case):
    def test_compose_terraform_kubernetes_and_nginx(self) -> None:
        self.write(
            {
                "docker-compose.yml": "services:\n  db:\n    image: postgres\n",
                "infra/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
                "k8s/api.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n",
                "deploy/nginx/default.conf": "server {\n  listen 80;\n  location / {\n    proxy_pass http://app;\n  }\n}\n",
            }
        )
        self.assertEqual(self.ids(), {"docker-compose", "terraform", "kubernetes", "nginx"})

    def test_other_yaml_is_not_kubernetes(self) -> None:
        self.write(
            {
                ".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
                "catalog-info.yaml": "apiVersion: backstage.io/v1alpha1\nkind: Component\n",
                "app.conf": "[server]\nport = 80\n",
            }
        )
        self.assertEqual(self.ids(), set())

    def test_compose_override_files(self) -> None:
        self.write({"compose.override.yaml": "services: {}\n"})
        self.assertEqual(self.ids(), {"docker-compose"})


class ReviewFindingsTests(Case):
    # /code-review の指摘（2026-10-22）

    def test_crlf_and_bom_markers(self) -> None:
        # Windows の checkout（CRLF）と BOM 付きのファイルでも見分ける
        (self.root / "k8s").mkdir()
        (self.root / "k8s/a.yaml").write_bytes(b"\xef\xbb\xbfapiVersion: apps/v1\r\nkind: Deployment\r\n")
        (self.root / "go.mod").write_bytes(b"module x\r\n\r\nrequire github.com/gin-gonic/gin v1.10.0\r\n")
        (self.root / "package.json").write_bytes(b'\xef\xbb\xbf{"dependencies": {"fastify": "5"}}')
        self.assertEqual(self.ids(), {"kubernetes", "gin", "fastify"})

    def test_kubernetes_kinds_quotes_and_comments(self) -> None:
        for body in (
            "apiVersion: v1\nkind: Secret\n",
            "apiVersion: v1\nkind: Service\n---\napiVersion: batch/v1\nkind: Job\n",
            'apiVersion: apps/v1\nkind: "Deployment"\n',
            "apiVersion: apps/v1\nkind: Deployment  # api\n",
        ):
            with self.subTest(body=body):
                self.write({"k8s/a.yaml": body})
                self.assertEqual(self.ids(), {"kubernetes"})

    def test_glob_markers_read_only_a_prefix(self) -> None:
        # *.yaml などは全部を読むので、大きなデータの YAML を丸ごと読んで持ち続けない
        self.write({"locales/ja.yml": "ja:\n" + "  key: value\n" * 200_000, "package.json": "{}"})
        with mock.patch.object(detect_module, "_read", wraps=detect_module._read) as spy:
            detect(self.root)
        limits = {call.args[0].name: call.args[1] if len(call.args) > 1 else call.kwargs.get("limit") for call in spy.call_args_list}
        self.assertIsNotNone(limits["ja.yml"])
        self.assertLessEqual(limits["ja.yml"], 65536)
        self.assertIsNone(limits["package.json"])  # 依存の一覧は全部を読む

    def test_commented_gem_is_not_rails(self) -> None:
        self.write({"Gemfile": "source 'https://rubygems.org'\n# gem 'rails'\ngem 'sinatra'\n"})
        self.assertEqual(self.ids(), set())

    @requires_tomllib
    def test_python_names_only_in_dependencies(self) -> None:
        # キーワード・説明・コメントにある名前は、依存ではない
        self.write(
            {
                "pyproject.toml": (
                    '[project]\nname = "tool"\ndescription = "A small CLI for Stripe"\n'
                    'keywords = ["mcp", "openai", "stripe"]\ndependencies = [\n  "httpx>=0.27",\n]\n'
                ),
                "requirements.txt": "# TODO: replace with openai\nrequests\n",
            }
        )
        self.assertEqual(self.ids(), set())

    def test_python_dependency_sections(self) -> None:
        self.write(
            {
                "a/pyproject.toml": '[project]\nname = "a"\ndependencies = [\n  "fastapi[standard]>=0.115",\n]\n',
                "b/pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.12"\nstripe = "^11.0"\n',
                "c/pyproject.toml": '[project.optional-dependencies]\nai = ["anthropic>=0.40"]\n',
                "d/Pipfile": '[packages]\nboto3 = "*"\n',
            }
        )
        self.assertEqual(self.ids(), {"fastapi", "stripe", "llm", "aws"})

    @requires_tomllib
    def test_python_extras_do_not_end_the_array(self) -> None:
        # "fastapi[standard]" の ] で配列が終わったと読んで、後ろの依存を落とさない
        self.write(
            {
                "pyproject.toml": (
                    '[project]\nname = "a"\ndependencies = [\n  "fastapi[standard]>=0.115",  # web\n'
                    '  "anthropic==0.40",\n  "mcp @ git+https://example.com/mcp.git#egg=mcp",\n]\n'
                ),
            }
        )
        self.assertEqual(self.ids(), {"fastapi", "llm", "mcp"})

    def test_python_names_are_normalized(self) -> None:
        # pip は - と _ と . を同じに扱う（PEP 503）
        self.write({"requirements.txt": "llama_index==0.10\nLangChain_Core\n"})
        self.assertEqual(self.ids(), {"llm"})

    def test_graphql_integration_packages(self) -> None:
        self.write({"requirements.txt": "Django==5.1\ngraphene-django==3.2\n"})
        self.assertEqual(self.ids(), {"django", "graphql"})

    def test_cargo_dependency_tables(self) -> None:
        self.write({"Cargo.toml": '[package]\nname = "svc"\n\n[dependencies.axum]\nversion = "0.8"\n'})
        self.assertEqual(self.ids(), {"axum"})

    def test_nginx_file_names_and_other_conf(self) -> None:
        server = "server {\n  listen 80;\n  location / {\n    proxy_pass http://app;\n  }\n}\n"
        self.write({"deploy/nginx/sites-available/default": server})
        self.assertEqual(self.ids(), {"nginx"})
        (self.root / "deploy/nginx/sites-available/default").unlink()
        self.write({"nginx/templates/default.conf.template": server})
        self.assertEqual(self.ids(), {"nginx"})
        (self.root / "nginx/templates/default.conf.template").unlink()
        # Play・Akka の HOCON（application.conf）の `location {` は nginx ではない
        self.write({"conf/application.conf": "location {\n  default = \"tokyo\"\n}\n"})
        self.assertEqual(self.ids(), set())


class SecondReviewTests(Case):
    # 2 回目の /code-review の指摘（2026-10-22）

    def test_commented_out_markers(self) -> None:
        for name, body in (
            ("mix.exs", 'defp deps do\n  [\n    # {:phoenix, "~> 1.7"},\n    {:plug_cowboy, "~> 2.0"}\n  ]\nend\n'),
            ("build.gradle", "plugins { id 'java' }\n// org.springframework.boot plugin removed\n"),
            ("Web.csproj", '<Project Sdk="Microsoft.NET.Sdk">\n  <!-- <PackageReference Include="Microsoft.AspNetCore.Mvc" /> -->\n</Project>\n'),
        ):
            with self.subTest(name=name):
                self.write({name: body})
                self.assertEqual(self.ids(), set())
                (self.root / name).unlink()

    def test_requirements_folders_and_pip_tools(self) -> None:
        self.write({"manage.py": "", "requirements/base.txt": "stripe\n", "requirements.in": "openai\n"})
        self.assertEqual(self.ids(), {"django", "stripe", "llm"})

    @requires_tomllib
    def test_poetry_expanded_tables_and_pdm(self) -> None:
        self.write(
            {
                "a/pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.12"\n\n[tool.poetry.dependencies.fastapi]\nversion = "^0.115"\n',
                "b/pyproject.toml": '[tool.poetry.dependencies]\nstripe.version = "^11"\n',
                "c/pyproject.toml": '[tool.pdm.dev-dependencies]\nai = ["openai"]\n',
            }
        )
        self.assertEqual(self.ids(), {"fastapi", "stripe", "llm"})

    @requires_tomllib
    def test_toml_comments_and_multiline_strings(self) -> None:
        self.write(
            {
                "a/pyproject.toml": '[project]\ndependencies = [\n  "httpx",# x ]\n  "stripe",\n]\n',
                "b/pyproject.toml": '[project]\nname = "b"\nreadme.text = """\n[tool.poetry.dependencies]\nopenai = 1\n"""\n',
            }
        )
        self.assertEqual(self.ids(), {"stripe"})

    def test_nginx_site_names_and_other_server_name(self) -> None:
        self.write({"nginx/sites-available/example.com": "server {\n  listen 80;\n  server_name example.com;\n}\n"})
        self.assertEqual(self.ids(), {"nginx"})
        (self.root / "nginx/sites-available/example.com").unlink()
        self.write({"telegraf.conf": '[[inputs.x509_cert]]\n  server_name = "example.org"\n'})
        self.assertEqual(self.ids(), set())

    def test_cloudformation_templates(self) -> None:
        self.write({"infra/stack.yaml": "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n"})
        self.assertEqual(self.ids(), {"aws"})

    def test_more_kubernetes_kinds(self) -> None:
        for kind in ("PodDisruptionBudget", "CustomResourceDefinition", "HTTPRoute"):
            with self.subTest(kind=kind):
                self.write({"k8s/a.yaml": f"apiVersion: x/v1\nkind: {kind}\n"})
                self.assertEqual(self.ids(), {"kubernetes"})

    def test_carriage_return_only_line_endings(self) -> None:
        (self.root / "Gemfile").write_bytes(b"source 'https://rubygems.org'\rgem 'rails'\r")
        self.assertEqual(self.ids(), {"rails"})

    def test_text_markers_read_only_a_prefix(self) -> None:
        self.write({"theme/style.css": "/*\nTheme Name: X\n*/\n" + "a { color: red }\n" * 100_000})
        with mock.patch.object(detect_module, "_read", wraps=detect_module._read) as spy:
            self.assertEqual(self.ids(), {"wordpress"})
        limits = [call.args[1] if len(call.args) > 1 else call.kwargs.get("limit") for call in spy.call_args_list if call.args[0].name == "style.css"]
        self.assertTrue(limits and all(limit is not None and limit <= 65536 for limit in limits))

    def test_many_paths_do_not_rematch_every_marker(self) -> None:
        # パスの数 × 目印の数だけ照合し直さない（20 万パスで 10 倍遅くなっていた）
        relpaths = [f"src/pkg{i // 100}/file{i}.ts" for i in range(20_000)]
        with mock.patch.object(detect_module, "fnmatchcase", wraps=detect_module.fnmatchcase) as fnmatch_spy:
            with mock.patch.object(detect_module, "_is_pattern", wraps=detect_module._is_pattern) as pattern_spy:
                detect_module.detect_frameworks(self.root, relpaths)
        self.assertLess(fnmatch_spy.call_count, 1_000)
        self.assertLess(pattern_spy.call_count, 1_000)

    def test_every_kind_of_marker(self) -> None:
        # 目印ごとに 1 つずつ（名前の書き間違いに気づくように）
        cases = [
            ({"go.mod": "module x\nrequire github.com/labstack/echo/v4 v4.12.0\n"}, "echo"),
            ({"go.mod": "module x\nrequire github.com/go-chi/chi/v5 v5.1.0\n"}, "chi"),
            ({"go.mod": "module x\nrequire github.com/aws/aws-lambda-go v1.47.0\n"}, "aws"),
            ({"go.mod": "module x\nrequire github.com/mark3labs/mcp-go v0.20.0\n"}, "mcp"),
            ({"go.mod": "module x\nrequire github.com/openai/openai-go v1.0.0\n"}, "llm"),
            ({"go.mod": "module x\nrequire github.com/99designs/gqlgen v0.17.0\n"}, "graphql"),
            ({"package.json": json.dumps({"dependencies": {"next-auth": "5"}})}, "authjs"),
            ({"package.json": json.dumps({"dependencies": {"@auth/core": "0.37"}})}, "authjs"),
            ({"package.json": json.dumps({"dependencies": {"koa": "2"}})}, "koa"),
            ({"charts/api/Chart.yaml": "apiVersion: v2\nname: api\n"}, "kubernetes"),
            ({"k8s/kustomization.yaml": "resources: []\n"}, "kubernetes"),
            ({"composer.json": json.dumps({"type": "wordpress-plugin"})}, "wordpress"),
            ({"build.gradle": "plugins {\n  id 'org.springframework.boot' version '3.3.0'\n}\n"}, "spring"),
            ({"Api.csproj": '<Project Sdk="Microsoft.NET.Sdk">\n  <FrameworkReference Include="Microsoft.AspNetCore.App" />\n</Project>\n'}, "aspnet"),
            ({"serverless.yml": "service: api\n"}, "aws"),
            ({"cdk.json": "{}\n"}, "aws"),
            ({"amplify/backend.ts": "export {}\n"}, "aws"),
            ({"infra/network.tf": "variable \"x\" {}\n"}, "terraform"),
            ({"nginx.conf": "events {}\n"}, "nginx"),
            ({"docker-compose.prod.yaml": "services: {}\n"}, "docker-compose"),
        ]
        for files, expected in cases:
            with self.subTest(expected=expected, files=list(files)):
                case = Case("ids")
                case.setUp()
                try:
                    case.write(files)
                    self.assertEqual(case.ids(), {expected})
                finally:
                    case.tearDown()


class ThirdReviewTests(Case):
    # 3 回目の /code-review の指摘（2026-10-22）

    @requires_tomllib
    def test_other_pyproject_dependency_forms(self) -> None:
        # main の読み方では見分けていた書き方（pixi・インライン表・hatch・引用符付きのドット付きキー）
        for body, expected in (
            ('[tool.pixi.pypi-dependencies]\nfastapi = "*"\n', "fastapi"),
            ('[project]\noptional-dependencies = { ai = ["fastapi"] }\n', "fastapi"),
            ('[tool.hatch.envs.default]\nextra-dependencies = ["flask"]\n', "flask"),
            ('[tool.poetry.dependencies]\n"flask".version = "^3"\n', "flask"),
            ('[project]\n# see """x\ndependencies = ["django"]\n', "django"),
        ):
            with self.subTest(body=body):
                self.write({"pyproject.toml": body})
                self.assertEqual(self.ids(), {expected})

    def test_gradle_strings_that_look_like_comments(self) -> None:
        self.write(
            {
                "build.gradle": (
                    "exclude '**/*.tmp'\nimplementation 'org.springframework.boot:spring-boot-starter-web'\n"
                    "include '**/Test*'\n"
                ),
            }
        )
        self.assertEqual(self.ids(), {"spring"})

    def test_requirements_prose_is_not_a_dependency(self) -> None:
        self.write({"requirements/README.txt": "openai is not used here\n"})
        self.assertEqual(self.ids(), set())

    def test_trailing_comments_in_markers(self) -> None:
        self.write({"mix.exs": 'defp deps do\n  [{:plug, "~> 1.0"}] # {:phoenix, "~> 1.7"}\nend\n'})
        self.assertEqual(self.ids(), set())

    def test_python_package_families(self) -> None:
        for name in ("langchain-openai", "llama-index-core", "openai-agents", "pydantic-ai"):
            with self.subTest(name=name):
                self.write({"requirements.txt": f"{name}==1.0\n"})
                self.assertEqual(self.ids(), {"llm"})

    def test_each_marker_file_is_read_once(self) -> None:
        # *.yaml は aws と kubernetes、pubspec.yaml は firebase・flutter などで、同じファイルを何度も読んでいた
        self.write({f"cfg/{i}.yaml": "a: 1\n" for i in range(20)})
        self.write({"app/pubspec.yaml": "name: app\n", "Gemfile": "gem 'sinatra'\n"})
        with mock.patch.object(detect_module, "_read", wraps=detect_module._read) as spy:
            detect(self.root)
        reads = [call.args[0].name for call in spy.call_args_list]
        self.assertEqual(sorted(name for name in set(reads) if reads.count(name) > 1), [])
        self.assertEqual(reads.count("pubspec.yaml"), 1)
        self.assertEqual(reads.count("Gemfile"), 1)


class AdversarialMarkerTests(Case):
    # 目印の正規表現が、長い行・空行だらけのファイルで、長さの 2 乗の時間にならないこと
    # （直す前は go.mod が 78 秒、Cargo.toml が 7 秒、Gemfile が 4 秒、nginx が 2 秒かかった）
    def test_markers_scale_linearly(self) -> None:
        cases = {
            "go.mod": "require (\n" * 50_000,
            "Cargo.toml": "\n" * 32_000,
            "Gemfile": "\n" * 32_000,
            "app/pubspec.yaml": "\n" * 32_000,
            "nginx/a.conf": "listen" + " " * 32_000,
            "Web.csproj": "<!--" * 8_000,
            "build.gradle": "/*\n" * 10_000,
            "pyproject.toml": "[project]\n" + " a" * 200_000 + "\n",
            "requirements.txt": "a" * 300_000 + " b\n",
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                case = Case("ids")
                case.setUp()
                try:
                    case.write({name: body})
                    started = time.monotonic()
                    case.ids()
                    self.assertLess(time.monotonic() - started, 1.0)
                finally:
                    case.tearDown()


class FourthReviewTests(Case):
    # 4 回目の /code-review の指摘（2026-10-22）

    def test_every_text_marker_is_linear(self) -> None:
        # 手書きの一覧ではなく、すべての text の目印を、空白・改行だらけの入力で測る（style.css の ^\s*\*?\s* が 3 乗だった）
        size = 32_768
        inputs = ["\n" * size, " " * size, " \n\t" * (size // 3), "a" * size, "#" * size, "*\n" * (size // 2)]
        for fw in FRAMEWORKS:
            for name, pattern in fw.text:
                for compiled in [re.compile(p) for p in ((pattern,) if isinstance(pattern, str) else pattern)]:
                    for text in inputs:
                        with self.subTest(framework=fw.id, marker=name, text=repr(text[:4])):
                            started = time.monotonic()
                            compiled.search(text)
                            self.assertLess(time.monotonic() - started, 0.5)

    @requires_tomllib
    def test_more_pyproject_dependency_forms(self) -> None:
        for body, expected in (
            ('[dependency-groups]\nserver = ["fastapi>=0.1"]\n', {"fastapi"}),
            ('[tool.flit.metadata.requires-extra]\nai = ["openai"]\n', {"llm"}),
            ('[tool.tox.env_run_base]\ndeps = ["fastapi"]\n', {"fastapi"}),
            ('[tool.poetry.dependencies]\nfastapi = [\n  {version = "<0.100", python = "<3.8"},\n  {version = "^0.115", python = ">=3.8"},\n]\n', {"fastapi"}),
            ('[tool.poetry.dependencies]\nfastapi = [{version = "^0.1"}]\n', {"fastapi"}),
            ('[project]\ndescription = "Use \'\'\' for blocks"\ndependencies = ["fastapi"]\n', {"fastapi"}),
            ('[project]\noptional-dependencies = { web = ["fastapi[standard]", "openai"] }\n', {"fastapi", "llm"}),
            ('[tool.hatch.envs.test]\nmatrix.python.dependencies = [\n  { value = "x", if = ["3.12"] },\n  "openai",\n]\n', {"llm"}),
            ("[project]\ndependencies = {\n" + "[" * 1000 + "\n", set()),
        ):
            with self.subTest(body=body[:60]):
                self.write({"pyproject.toml": body})
                self.assertEqual(self.ids(), expected)

    @requires_tomllib
    def test_pipfile_custom_categories(self) -> None:
        self.write({"Pipfile": '[[source]]\nurl = "https://pypi.org/simple"\n\n[server]\nfastapi = "*"\n'})
        self.assertEqual(self.ids(), {"fastapi"})

    def test_invalid_toml_falls_back_to_mentions(self) -> None:
        # 読めない TOML は、main と同じ読み方（名前が依存の形で出てくるか）に戻す
        self.write({"pyproject.toml": '[project\ndependencies = ["fastapi>=0.1"]\n'})
        self.assertEqual(self.ids(), {"fastapi"})

    def test_without_tomllib_falls_back_to_mentions(self) -> None:
        # Python 3.9・3.10（tomllib が無い）でも、main と同じように見分ける
        self.write({"pyproject.toml": '[project]\ndependencies = ["fastapi>=0.1", "langchain-openai"]\n'})
        with mock.patch.object(detect_module, "tomllib", None):
            self.assertEqual(self.ids(), {"fastapi", "llm"})

    def test_aspnet_client_packages_are_not_servers(self) -> None:
        for reference in ("Microsoft.AspNetCore.SignalR.Client", "Microsoft.AspNetCore.Mvc.Testing", "Microsoft.AspNetCore.Components.WebAssembly"):
            with self.subTest(reference=reference):
                self.write({"App.csproj": f'<Project Sdk="Microsoft.NET.Sdk">\n  <PackageReference Include="{reference}" />\n</Project>\n'})
                self.assertEqual(self.ids(), set())
        self.write({"Lib.csproj": '<Project Sdk="Microsoft.NET.Sdk">\n  <FrameworkReference Include="Microsoft.AspNetCore.App" />\n</Project>\n'})
        (self.root / "App.csproj").unlink()
        self.assertEqual(self.ids(), {"aspnet"})

    def test_manifests_are_read_in_full(self) -> None:
        # 名前の決まった manifest（pom.xml など）は、main と同じく全部を読む
        padding = "<!-- " + "x" * 40_000 + " -->\n"
        self.write({"pom.xml": "<project>\n" + padding + "<parent><groupId>org.springframework.boot</groupId></parent></project>\n"})
        self.assertEqual(self.ids(), {"spring"})


class FifthReviewTests(Case):
    # 5 回目の /code-review の指摘（2026-10-22）

    def test_deeply_nested_toml_does_not_stop_the_scan(self) -> None:
        # tomllib は入れ子が深いと RecursionError を投げ、detect と scan が止まっていた
        self.write({"pyproject.toml": "x = " + "[" * 500 + "]" * 500 + "\n", "a.py": "1\n"})
        self.assertEqual(self.ids(), set())
        self.scan()

    @requires_tomllib
    def test_group_names_are_not_packages(self) -> None:
        for body in (
            "[project.optional-dependencies]\nopenai = []\n",
            '[dependency-groups]\nmcp = [{include-group = "base"}]\nbase = ["httpx"]\n',
            '[tool.setuptools.dynamic.optional-dependencies]\nstripe = {file = ["requirements-stripe.txt"]}\n',
        ):
            with self.subTest(body=body):
                self.write({"pyproject.toml": body})
                self.assertEqual(self.ids(), set())

    @requires_tomllib
    def test_keys_that_are_not_runtime_dependencies(self) -> None:
        for body in (
            '[build-system]\nrequires = ["setuptools", "fastapi"]\n',
            '[tool.uv]\nconstraint-dependencies = ["openai<2"]\noverride-dependencies = ["stripe==1"]\n',
            '[tool.poe.tasks.release]\ndeps = ["stripe"]\n',
            '[tool.hatch.build.hooks.custom]\ndependencies = ["openai"]\n',
        ):
            with self.subTest(body=body):
                self.write({"pyproject.toml": body})
                self.assertEqual(self.ids(), set())

    @requires_tomllib
    def test_poetry_legacy_dev_dependencies(self) -> None:
        # Poetry の古い書き方は名前 → 版（PDM の dev-dependencies はグループ → 一覧）
        self.write({"pyproject.toml": '[tool.poetry.dev-dependencies]\nfastapi = "^0.115"\n'})
        self.assertEqual(self.ids(), {"fastapi"})

    @requires_tomllib
    def test_legacy_tox_ini_in_pyproject(self) -> None:
        self.write({"pyproject.toml": '[tool.tox]\nlegacy_tox_ini = """\n[testenv]\ndeps =\n    fastapi\n    pytest\n"""\n'})
        self.assertEqual(self.ids(), {"fastapi"})

    def test_requirements_readme_and_prose(self) -> None:
        for body in ("Stripe, OpenAI and Django are optional here.\n", "Django (see docs) is not installed\n"):
            with self.subTest(body=body):
                self.write({"requirements/README.txt": body, "requirements/notes.txt": body})
                self.assertEqual(self.ids(), set())

    def test_gradle_version_catalogs(self) -> None:
        self.write({"build.gradle.kts": "plugins {\n    alias(libs.plugins.spring.boot)\n}\n"})
        self.assertEqual(self.ids(), {"spring"})
        (self.root / "build.gradle.kts").unlink()
        self.write({"gradle/libs.versions.toml": '[plugins]\nspring-boot = { id = "org.springframework.boot", version = "3.3.0" }\n'})
        self.assertEqual(self.ids(), {"spring"})

    def test_nginx_query_strings_and_one_line_blocks(self) -> None:
        self.write({"site.conf": "upstream app { server 127.0.0.1:3000; }\nlocation_only = 1\n  proxy_pass http://app/api?token=abc;\n"})
        self.assertEqual(self.ids(), {"nginx"})
        (self.root / "site.conf").unlink()
        self.write({"one.conf": "server { listen 80; server_name a; }\n"})
        self.assertEqual(self.ids(), {"nginx"})

    def test_aspnet_sdk_forms(self) -> None:
        for name, body in (
            ("App.csproj", "<Project Sdk='Microsoft.NET.Sdk.Web'>\n</Project>\n"),
            ("App.csproj", '<Project Sdk="Microsoft.NET.Sdk.Web/8.0.0">\n</Project>\n'),
            ("App.fsproj", '<Project Sdk="Microsoft.NET.Sdk.Web">\n</Project>\n'),
        ):
            with self.subTest(name=name, body=body):
                for old in self.root.glob("App.*proj"):
                    old.unlink()
                self.write({name: body})
                self.assertEqual(self.ids(), {"aspnet"})

    def test_sam_transform_in_list_form(self) -> None:
        self.write({"template.yaml": "Transform:\n  - AWS::Serverless-2016-10-31\nResources: {}\n"})
        self.assertEqual(self.ids(), {"aws"})

    def test_quoted_go_module_paths(self) -> None:
        self.write({"go.mod": 'module x\n\nrequire "github.com/gin-gonic/gin" v1.10.0\n'})
        self.assertEqual(self.ids(), {"gin"})

    def test_later_markers_are_skipped_after_an_earlier_hit(self) -> None:
        # nginx が *.conf で見つかったら、後ろの目印（*.conf.template）のファイルは読まない（先の目印の evidence が勝つので）
        self.write({"nginx/a.conf": "server {\n  listen 80;\n}\n"})
        self.write({f"nginx/templates/{i}.conf.template": "server {\n  listen 80;\n}\n" for i in range(20)})
        with mock.patch.object(detect_module, "_read", wraps=detect_module._read) as spy:
            self.assertEqual(self.ids(), {"nginx"})
        self.assertEqual([call.args[0].name for call in spy.call_args_list if call.args[0].name.endswith(".template")], [])


class PythonWithoutTomllibTests(Case):
    # tomllib の無い Python（3.9・3.10）の道。以前と同じ読み方で、見分けを落とさないこと
    def test_dependencies_are_still_found(self) -> None:
        self.write(
            {
                "a/pyproject.toml": '[project]\ndependencies = ["fastapi[standard]>=0.115"]\n',
                "b/pyproject.toml": '[tool.poetry.dependencies]\nstripe = "^11"\n',
                "c/Pipfile": '[packages]\nboto3 = "*"\n',
                "requirements.txt": "langchain-openai==0.3\n",
            }
        )
        with mock.patch.object(detect_module, "tomllib", None):
            self.assertEqual(self.ids(), {"fastapi", "stripe", "aws", "llm"})


class SkillRoutingTests(unittest.TestCase):
    def test_every_framework_has_a_checklist_section(self) -> None:
        # vulnscan detect で見分けたものは、SKILL.md の表でチェックリストのどの節を読むかが決まっていること
        skill = (ROOT / "skills/vulnscan/SKILL.md").read_text("utf-8")
        checklists = (ROOT / "skills/vulnscan/references/checklists.md").read_text("utf-8")
        headings = [line[3:] for line in checklists.splitlines() if line.startswith("## ")]
        known = {fw.id for fw in FRAMEWORKS}
        routed = {}
        for line in skill.splitlines():
            row = re.match(r"\s*\|\s*((?:`[\w.-]+`・?)+)\s*\|\s*([^|]+?)\s*\|\s*$", line)
            if row and row.group(2) != "節":  # 表の見出しの行
                for framework_id in re.findall(r"`([\w.-]+)`", row.group(1)):
                    routed[framework_id] = row.group(2)
        self.assertEqual(sorted(known - set(routed)), [])
        # 表にあるのに vulnscan が出さない id（名前を変えた・消したのに残った行、書き間違い）
        self.assertEqual(sorted(set(routed) - known), [])
        no_section = {fid: name for fid, name in routed.items() if not any(h.startswith(name) for h in headings)}
        self.assertEqual(no_section, {})


if __name__ == "__main__":
    unittest.main()
