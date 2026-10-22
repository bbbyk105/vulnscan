"""Rails・Laravel・Spring・C#・Rust と、Compose・Kubernetes・nginx の設定のルール。"""

from __future__ import annotations

import re
import time
import unittest
from collections import Counter
from types import SimpleNamespace

from test_vulnscan import ROOT, RepoCase

from vulnscan.rules import FILE_RULES, LINE_RULES, get_rule
from vulnscan.rules.base import LANGUAGE_LABELS, FileRule


class Case(RepoCase):
    def lines_of(self, rule_id: str) -> set:
        return {(f.location.path, f.location.line) for f in self.scan().findings if f.rule_id == rule_id}

    def severity_of(self, rule_id: str) -> set:
        return {f.severity.label for f in self.scan().findings if f.rule_id == rule_id}


class RubyRuleTests(Case):
    def test_sql_with_interpolated_values(self) -> None:
        self.write(
            {
                "app/models/user.rb": "User.where(\"name = '#{params[:name]}'\")\n"
                'User.where("id = #{params[:id]}")\n'
                "Post.find_by_sql(\"SELECT * FROM posts WHERE title LIKE '%#{q}%'\")\n"
                'User.where("name = ?", params[:name])\n'
                "User.where(name: params[:name])\n"
                'User.where("#{table}.deleted_at IS NULL")\n'
                'User.where("id = #{params[:id].to_i}")\n'
                "User.where(\"status = 'active' AND role = ?\", role)\n"
                "conn.execute(\"UPDATE users SET name = '\" + name + \"'\")\n"
                "User.where(\"status = 'active'\").where(\"id = #{id}\")\n"
                "User.where \"email = '#{email}'\"\n"
                "# User.where(\"id = #{id}\")\n"
            }
        )
        self.assertEqual(
            self.lines_of("INJ-018"),
            {("app/models/user.rb", n) for n in (1, 2, 3, 9, 10, 11)},
        )

    def test_sql_in_specs_is_low(self) -> None:
        self.write({"spec/models/user_spec.rb": 'User.where("id = #{user.id}")\n'})
        self.assertEqual(self.severity_of("INJ-018"), {"low"})

    def test_permit_all(self) -> None:
        self.write(
            {
                "app/controllers/users_controller.rb": "User.update(params.require(:user).permit!)\n"
                "attrs = params.permit!\n"
                "User.update(params.require(:user).permit(:name, :email))\n"
                "# params.permit!\n"
            }
        )
        self.assertEqual(
            self.lines_of("AUTH-009"),
            {("app/controllers/users_controller.rb", 1), ("app/controllers/users_controller.rb", 2)},
        )


class PhpRuleTests(Case):
    def test_sql_with_interpolated_or_joined_values(self) -> None:
        self.write(
            {
                "app/Http/Controllers/UserController.php": "<?php\n"
                "$users = DB::select(\"SELECT * FROM users WHERE name = '$name'\");\n"
                'User::whereRaw("price > $min")->get();\n'
                "User::whereRaw('price > ' . $min)->get();\n"
                "User::whereRaw('price > ?', [$min])->get();\n"
                "DB::select('select * from users where id = ?', [$id]);\n"
                '$pdo->query("SELECT * FROM users WHERE id = " . $id);\n'
                "$page = $request->query('page');\n"
                '$wpdb->get_results("SELECT * FROM $wpdb->posts WHERE post_author = {$author}");\n'
                '$wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE ID = %d", $id));\n'
                "mysqli_query($conn, \"SELECT * FROM users WHERE email = '\" . $email . \"'\");\n"
                'User::orderByRaw("$column $direction");\n'
            }
        )
        path = "app/Http/Controllers/UserController.php"
        self.assertEqual(self.lines_of("INJ-019"), {(path, n) for n in (2, 3, 4, 7, 9, 11)})

    def test_mass_assignment_unguarded(self) -> None:
        self.write(
            {
                "app/Models/Post.php": "<?php\nclass Post extends Model {\n    protected $guarded = [];\n}\n",
                "app/Models/User.php": "<?php\nclass User extends Model {\n    protected $guarded = ['id'];\n}\n",
                "app/Providers/AppServiceProvider.php": "<?php\nModel::unguard();\n",
                "database/seeders/DatabaseSeeder.php": "<?php\nModel::unguard();\n",
            }
        )
        self.assertEqual(
            self.lines_of("AUTH-010"),
            {("app/Models/Post.php", 3), ("app/Providers/AppServiceProvider.php", 2)},
        )

    def test_blade_unescaped_output(self) -> None:
        self.write(
            {
                "resources/views/post.blade.php": "<h1>{{ $post->title }}</h1>\n"
                "<div>{!! $post->body !!}</div>\n"
                "{!! csrf_field() !!}\n",
                "app/Support/Markdown.php": "<?php\n$tpl = '{!! $html !!}';\n",
            }
        )
        self.assertEqual(self.lines_of("XSS-007"), {("resources/views/post.blade.php", 2)})


class JavaRuleTests(Case):
    def test_sql_with_joined_values(self) -> None:
        self.write(
            {
                "src/main/java/com/example/UserDao.java": "stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n"
                'jdbcTemplate.query("SELECT * FROM users WHERE id = " + id, mapper);\n'
                'em.createQuery("SELECT u FROM User u WHERE u.name = :name");\n'
                'jdbcTemplate.query("SELECT * FROM " + table + " WHERE id = ?", mapper, id);\n'
                "stmt.executeQuery(\"SELECT * FROM users WHERE status = 'active' AND id = ?\");\n",
                "src/main/kotlin/com/example/Repo.kt": "jdbc.queryForList(\"SELECT * FROM users WHERE email = '$email'\")\n"
                'jdbc.queryForList("SELECT * FROM users WHERE id = ${user.id}")\n'
                'jdbc.queryForList("SELECT * FROM users WHERE id = ?", id)\n',
            }
        )
        self.assertEqual(
            self.lines_of("INJ-020"),
            {
                ("src/main/java/com/example/UserDao.java", 1),
                ("src/main/java/com/example/UserDao.java", 2),
                ("src/main/kotlin/com/example/Repo.kt", 1),
                ("src/main/kotlin/com/example/Repo.kt", 2),
            },
        )

    def test_unsafe_deserialization(self) -> None:
        self.write(
            {
                "src/main/java/com/example/Load.java": "ObjectInputStream in = new ObjectInputStream(socket.getInputStream());\n"
                "Object o = new XMLDecoder(input).readObject();\n"
                "var safe = new ValidatingObjectInputStream(input);\n"
                "private void readObject(ObjectInputStream in) throws IOException {}\n",
                "src/main/kotlin/com/example/Load.kt": "val o = ObjectInputStream(bytes.inputStream()).use { it.readObject() }\n"
                "class SafeInput(input: InputStream) : ObjectInputStream(input) {\n",
            }
        )
        self.assertEqual(
            self.lines_of("INJ-023"),
            {
                ("src/main/java/com/example/Load.java", 1),
                ("src/main/java/com/example/Load.java", 2),
                ("src/main/kotlin/com/example/Load.kt", 1),
            },
        )


class CSharpRuleTests(Case):
    def test_sql_with_interpolated_or_joined_values(self) -> None:
        self.write(
            {
                "Data/UserRepository.cs": "var a = db.Users.FromSqlRaw($\"SELECT * FROM Users WHERE Name = '{name}'\").ToList();\n"
                'var b = db.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = {0}", name).ToList();\n'
                'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, conn);\n'
                'cmd.CommandText = $"DELETE FROM Users WHERE Id = {id}";\n'
                'var c = conn.Query<User>("SELECT * FROM Users WHERE Id = @Id", new { Id = id });\n'
                "var d = conn.Query<User>($\"SELECT * FROM Users WHERE Email = '{email}'\");\n"
                'db.Database.ExecuteSqlRaw(string.Format("DELETE FROM Users WHERE Id = {0}", id));\n'
                'var e = db.Users.FromSql($"SELECT * FROM Users WHERE Id = {id}");\n'
                'var f = conn.Query<User>($"SELECT * FROM {table} WHERE Id = @id", new { id });\n'
            }
        )
        self.assertEqual(self.lines_of("INJ-021"), {("Data/UserRepository.cs", n) for n in (1, 3, 4, 6, 7)})

    def test_dangerous_serializers(self) -> None:
        self.write(
            {
                "Services/Cache.cs": "using System.Runtime.Serialization.Formatters.Binary;\n"
                "var formatter = new BinaryFormatter();\n"
                "BinaryFormatter bf = new();\n"
                "var s = new NetDataContractSerializer();\n"
                "// new BinaryFormatter()\n"
                "var ok = new DataContractSerializer(typeof(User));\n"
                "var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n"
                "    TypeNameHandling = TypeNameHandling.Auto,\n"
                "    TypeNameHandling = TypeNameHandling.None,\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-024"), {("Services/Cache.cs", n) for n in (2, 3, 4)})
        self.assertEqual(self.lines_of("INJ-025"), {("Services/Cache.cs", n) for n in (7, 8)})

    def test_certificate_checks_turned_off(self) -> None:
        self.write(
            {
                "Http/Client.cs": "handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;\n"
                "ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true;\n"
                "handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;\n"
                "handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => e == SslPolicyErrors.None;\n"
                "ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };\n"
                "var ssl = new SslStream(stream, false, new RemoteCertificateValidationCallback((s, c, ch, e) => true));\n"
            }
        )
        self.assertEqual(self.lines_of("TLS-012"), {("Http/Client.cs", n) for n in (1, 2, 3, 5, 6)})

    def test_csharp_has_rules(self) -> None:
        self.write({"Program.cs": "var app = builder.Build();\n"})
        (lang,) = [item for item in self.scan().languages if item["language"] == "csharp"]
        self.assertEqual(lang["rules"], 4)


class RustRuleTests(Case):
    def test_sql_built_with_format(self) -> None:
        self.write(
            {
                "src/db.rs": "sqlx::query(&format!(\"SELECT * FROM users WHERE name = '{}'\", name))\n"
                'sqlx::query_as::<_, User>(&format!("SELECT * FROM users WHERE id = {id}"))\n'
                'sqlx::query("SELECT * FROM users WHERE id = $1").bind(id)\n'
                'diesel::sql_query(format!("SELECT * FROM {} WHERE id = $1", table))\n'
                "conn.execute(&format!(\"DELETE FROM t WHERE name = '{}'\", n), [])?;\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-022"), {("src/db.rs", 1), ("src/db.rs", 2), ("src/db.rs", 5)})

    def test_certificate_checks_turned_off(self) -> None:
        self.write(
            {
                "src/http.rs": "let c = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;\n"
                "let c = builder.danger_accept_invalid_hostnames(true);\n"
                "let c = builder.danger_accept_invalid_certs(false);\n"
            }
        )
        self.assertEqual(self.lines_of("TLS-013"), {("src/http.rs", 1), ("src/http.rs", 2)})

    def test_rust_has_rules(self) -> None:
        self.write({"src/main.rs": "fn main() {}\n"})
        (lang,) = [item for item in self.scan().languages if item["language"] == "rust"]
        self.assertEqual(lang["rules"], 2)


class CsrfRuleTests(Case):
    def test_spring_security(self) -> None:
        self.write(
            {
                "src/main/java/com/example/SecurityConfig.java": "http.csrf().disable();\n"
                "http.csrf(AbstractHttpConfigurer::disable)\n"
                "    .csrf(csrf -> csrf.disable())\n"
                '    .csrf(csrf -> csrf.ignoringRequestMatchers("/webhooks/**"))\n',
                "src/main/kotlin/com/example/SecurityConfig.kt": "http {\n    csrf { disable() }\n}\n"
                "http.csrf { it.disable() }\n",
            }
        )
        self.assertEqual(
            self.lines_of("AUTH-005"),
            {
                ("src/main/java/com/example/SecurityConfig.java", 1),
                ("src/main/java/com/example/SecurityConfig.java", 2),
                ("src/main/java/com/example/SecurityConfig.java", 3),
                ("src/main/kotlin/com/example/SecurityConfig.kt", 2),
                ("src/main/kotlin/com/example/SecurityConfig.kt", 4),
            },
        )

    def test_rails(self) -> None:
        setting = "  config.action_controller.allow_forgery_protection = false\n"
        self.write(
            {
                "app/controllers/webhooks_controller.rb": "skip_before_action :verify_authenticity_token, only: :create\n"
                "skip_forgery_protection\n"
                "protect_from_forgery with: :exception\n",
                "config/environments/production.rb": setting,
                # Rails の generator が作る test.rb には、はじめからこの行がある
                "config/environments/test.rb": setting,
            }
        )
        self.assertEqual(
            self.lines_of("AUTH-005"),
            {
                ("app/controllers/webhooks_controller.rb", 1),
                ("app/controllers/webhooks_controller.rb", 2),
                ("config/environments/production.rb", 1),
            },
        )

    def test_existing_forms_still_found(self) -> None:
        self.write({"app.js": "app.use(lusca({ csrf: false }))\n", "views.py": "@csrf_exempt\ndef hook(request): pass\n"})
        self.assertEqual(self.lines_of("AUTH-005"), {("app.js", 1), ("views.py", 1)})


class InfrastructureRuleTests(Case):
    def test_actuator_exposes_everything(self) -> None:
        self.write(
            {
                "src/main/resources/application.properties": "management.endpoints.web.exposure.include=*\n",
                "src/main/resources/application-prod.properties": "management.endpoints.web.exposure.include=health,info\n",
                "src/main/resources/application.yml": "management:\n  endpoints:\n    web:\n      exposure:\n"
                '        include: "*"\n',
                "docker-compose.yml": "services:\n  api:\n    environment:\n      - MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=*\n",
                ".github/workflows/ci.yml": "jobs:\n  t:\n    strategy:\n      matrix:\n        include: '*'\n",
            }
        )
        self.assertEqual(
            self.lines_of("CFG-019"),
            {
                ("src/main/resources/application.properties", 1),
                ("src/main/resources/application.yml", 5),
                ("docker-compose.yml", 4),
            },
        )

    def test_actuator_in_test_resources_is_low(self) -> None:
        self.write({"src/test/resources/application.properties": "management.endpoints.web.exposure.include=*\n"})
        self.assertEqual(self.severity_of("CFG-019"), {"low"})

    def test_docker_socket_mount(self) -> None:
        self.write(
            {
                "docker-compose.yml": "services:\n  traefik:\n    volumes:\n"
                "      - /var/run/docker.sock:/var/run/docker.sock:ro\n"
                "      - ./data:/data\n"
                '      - "~/.docker/run/docker.sock:/var/run/docker.sock"\n'
                "  app:\n    environment:\n      - DOCKER_HOST=unix:///var/run/docker.sock\n"
                "    # - /var/run/docker.sock:/var/run/docker.sock\n",
                "k8s/agent.yaml": "volumes:\n  - name: sock\n    hostPath:\n      path: /var/run/docker.sock\n",
            }
        )
        # Kubernetes は hostPath: の下の path: だけを見るので、hostPath: の行で出す（2 回目のレビューで Ansible の path: を外した）
        self.assertEqual(
            self.lines_of("CFG-020"),
            {("docker-compose.yml", 4), ("docker-compose.yml", 6), ("k8s/agent.yaml", 3)},
        )

    def test_host_namespaces(self) -> None:
        self.write(
            {
                "compose.yaml": "services:\n  a:\n    network_mode: host\n  b:\n    network_mode: bridge\n"
                '  c:\n    pid: "host"\n',
                "k8s/pod.yaml": "spec:\n  hostNetwork: true\n  hostPID: true\n  hostIPC: false\n",
            }
        )
        self.assertEqual(
            self.lines_of("CFG-021"),
            {("compose.yaml", 3), ("compose.yaml", 7), ("k8s/pod.yaml", 2), ("k8s/pod.yaml", 3)},
        )

    def test_nginx_alias_without_matching_slash(self) -> None:
        self.write(
            {
                "nginx/default.conf": "server {\n"
                "    location /static {\n"
                "        alias /srv/app/static/;\n"
                "    }\n"
                "    location /media/ {\n"
                "        alias /srv/app/media/;\n"
                "    }\n"
                "    location /files {\n"
                "        alias /srv/app/files;\n"
                "    }\n"
                "    location = /favicon.ico { alias /srv/app/static/favicon.ico; }\n"
                "    location ~ ^/img/(.*)$ { alias /srv/img/$1; }\n"
                "    location /assets { alias /srv/assets/; }\n"
                "}\n"
            }
        )
        self.assertEqual(self.lines_of("CFG-022"), {("nginx/default.conf", 2), ("nginx/default.conf", 13)})


class OpenSourceRepoTests(Case):
    # 公開のリポジトリ（BookStack・chatwoot・mastodon・jellyfin）で走らせて当たった、外の値が入らない書き方

    def test_safe_blade_output(self) -> None:
        self.write(
            {
                "resources/views/a.blade.php": "{!! method_field('PATCH') !!}\n"
                "{!! $books->links() !!}\n"
                "{!! $books->render() !!}\n"
                "<p>{!! trans('settings.app_logo_desc') !!}</p>\n"
                "{!! __('auth.failed') !!}\n"
                "{!! nl2br(e(trans('entities.tags_explain'))) !!}\n"
                "{!! nl2br(htmlentities(session()->get('success'))) !!}\n"
                "{!! trans('entities.meta_owned_name', ['user' => $user->name]) !!}\n"
                "{!! $page->html !!}\n"
            }
        )
        # 3 行目の render() は、Markdown などを HTML にするものにも使う名前なので、2 回目のレビューで外さないように変えた
        self.assertEqual(
            self.lines_of("XSS-007"),
            {("resources/views/a.blade.php", 3), ("resources/views/a.blade.php", 8), ("resources/views/a.blade.php", 9)},
        )

    def test_sql_in_migrations(self) -> None:
        self.write(
            {
                "db/migrate/20261014_enable_push.rb": 'batch.update_all("#{column} = #{column} | #{bit}")\n',
                "db/post_migrate/20240603_change_scope.rb": "Doorkeeper::Application.where(\"scopes LIKE '%#{old_scope}%'\")\n",
                "database/migrations/2017_04_20_add_counts.php": "<?php\nDB::statement(\"UPDATE t SET c = '{$x}'\");\n",
                "Jellyfin.Server/Migrations/Routines/Check.cs": "cmd.CommandText = $\"SELECT 1 FROM t WHERE name = '{column}'\";\n",
                "src/main/java/db/migration/V2__Fill.java": "stmt.execute(\"UPDATE t SET a = '\" + value + \"'\");\n",
            }
        )
        self.assertEqual(
            {f.rule_id for f in self.scan().findings} & {"INJ-018", "INJ-019", "INJ-020", "INJ-021"},
            set(),
        )

    def test_ruby_constants_are_not_values(self) -> None:
        self.write(
            {
                "lib/optimizer.rb": "ActiveRecord::Base.connection.execute(\"SET work_mem = '#{WORK_MEM}MB'\")\n"
                "ActiveRecord::Base.connection.execute(\"SET work_mem = '#{mem}MB'\")\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-018"), {("lib/optimizer.rb", 2)})

    def test_permit_all_in_specs_is_low(self) -> None:
        self.write({"spec/services/filter_service_spec.rb": "params = ActionController::Parameters.new(payload).permit!\n"})
        self.assertEqual(self.severity_of("AUTH-009"), {"low"})


class FirstReviewTests(Case):
    # 1 回目の /code-review の指摘（2026-10-22）

    def test_rails_calls_without_receiver(self) -> None:
        self.write(
            {
                "app/models/post.rb": "scope :titled, ->(q) { where(\"title LIKE '%#{q}%'\") }\n"
                "def self.search(q) where(\"title = '#{q}'\") end\n"
                'find_by_sql("SELECT * FROM posts WHERE id = #{id}")\n'
                "respond_to?(:where)\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-018"), {("app/models/post.rb", n) for n in (1, 2, 3)})

    def test_value_joined_after_a_table_name(self) -> None:
        self.write(
            {
                "Dao.java": 'stmt.executeQuery("SELECT * FROM " + TABLE + " WHERE id = " + id);\n',
                "Repo.cs": 'var cmd = new SqlCommand("SELECT * FROM " + table + " WHERE Id = " + id, conn);\n',
                "repo.php": "<?php\n$pdo->query('SELECT * FROM ' . $table . ' WHERE id = ' . $id);\n",
                "repo.rb": "conn.execute(\"SELECT * FROM \" + table + \" WHERE name = '\" + name + \"'\")\n",
            }
        )
        ids = {(f.rule_id, f.location.path) for f in self.scan().findings}
        self.assertTrue(
            {("INJ-020", "Dao.java"), ("INJ-021", "Repo.cs"), ("INJ-019", "repo.php"), ("INJ-018", "repo.rb")} <= ids
        )

    def test_only_real_quoting_helpers_are_safe(self) -> None:
        self.write(
            {
                "app/models/post.rb": "Post.where(\"title LIKE '%#{sanitize_sql_like(params[:q])}%'\")\n"
                "Quote.where(\"title = '#{@quote.title}'\")\n"
                "Quote.where(\"title = '#{params[:quote]}'\")\n"
                'Post.where("title = #{ActiveRecord::Base.connection.quote(params[:q])}")\n'
                "Post.where(\"title = '#{connection.quote_string(params[:q])}'\")\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-018"), {("app/models/post.rb", n) for n in (1, 2, 3)})

    def test_qualified_column_after_a_comparison(self) -> None:
        self.write(
            {
                "app/models/post.rb": 'Post.joins("INNER JOIN comments ON comments.post_id = #{table_name}.id")\n'
                "Post.where(\"file = '#{name}.txt'\")\n",
                "inc/query.php": '<?php\n$wpdb->get_results("SELECT * FROM {$wpdb->posts} JOIN {$wpdb->postmeta} '
                'ON {$wpdb->posts}.ID = {$wpdb->postmeta}.post_id WHERE meta_key = %s");\n',
                "Repo.cs": 'var u = conn.Query<User>($"SELECT * FROM Orders o JOIN Users u ON o.UserId = {schema}.Users.Id");\n',
            }
        )
        found = {(f.rule_id, f.location.path, f.location.line) for f in self.scan().findings if f.rule_id.startswith("INJ")}
        self.assertEqual(found, {("INJ-018", "app/models/post.rb", 2)})

    def test_csharp_callback_with_body_on_next_lines(self) -> None:
        self.write(
            {
                "Http/Client.cs": "handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>\n"
                "{\n"
                "    return true;\n"
                "};\n"
            }
        )
        self.assertEqual(self.lines_of("TLS-012"), {("Http/Client.cs", 1)})

    def test_more_csrf_forms(self) -> None:
        self.write(
            {
                "SecurityConfig.kt": "http {\n    csrf {\n        disable()\n    }\n}\n"
                "http.csrf { csrf -> csrf.disable() }\n",
                "SecurityConfig.java": "http.csrf(csrf -> { csrf.disable(); });\n",
                "app/controllers/hooks_controller.rb": "skip_before_action(:verify_authenticity_token)\n",
            }
        )
        self.assertEqual(
            self.lines_of("AUTH-005"),
            {
                ("SecurityConfig.kt", 2),
                ("SecurityConfig.kt", 6),
                ("SecurityConfig.java", 1),
                ("app/controllers/hooks_controller.rb", 1),
            },
        )

    def test_csrf_off_in_tests_and_docs(self) -> None:
        self.write(
            {
                "spec/rails_helper.rb": "ActionController::Base.allow_forgery_protection = false\n",
                "src/test/java/com/example/TestSecurityConfig.java": "http.csrf(AbstractHttpConfigurer::disable);\n",
                "README.md": "Use `skip_forgery_protection` for webhooks.\n",
            }
        )
        findings = [f for f in self.scan().findings if f.rule_id == "AUTH-005"]
        self.assertEqual({f.location.path for f in findings}, {"spec/rails_helper.rb", "src/test/java/com/example/TestSecurityConfig.java"})
        self.assertEqual({f.severity.label for f in findings}, {"low"})

    def test_actuator_only_for_web_exposure(self) -> None:
        self.write(
            {
                "src/main/resources/application.yml": "management:\n  endpoints:\n    jmx:\n      exposure:\n"
                '        include: "*"\n',
                "deploy/values.yaml": "# exposure checks\nmatrix:\n  include: '*'\n",
                "src/main/resources/application-prod.yml": "management:\n  endpoints:\n    web:\n      exposure:\n"
                "        exclude: env\n        include:\n          - \"*\"\n",
                "src/main/resources/application-dev.yml": "management.endpoints.web.exposure.include: '*'\n",
            }
        )
        self.assertEqual(
            self.lines_of("CFG-019"),
            {("src/main/resources/application-prod.yml", 7), ("src/main/resources/application-dev.yml", 1)},
        )

    def test_more_php_connections(self) -> None:
        self.write(
            {
                "src/Repo.php": "<?php\nmysqli_query($this->db, \"SELECT * FROM users WHERE email = '$email'\");\n"
                "pg_query(\"SELECT * FROM users WHERE email = '$email'\");\n"
                "$this->wpdb->get_results(\"SELECT * FROM t WHERE a = '$a'\");\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-019"), {("src/Repo.php", n) for n in (2, 3, 4)})

    def test_tuple_type_arguments(self) -> None:
        self.write(
            {
                "src/db.rs": "sqlx::query_as::<Postgres, (i64,)>(&format!(\"SELECT id FROM t WHERE name = '{n}'\"))\n",
                "Repo.cs": "var r = await connection.QueryAsync<(int Id, string Name)>($\"SELECT * FROM t WHERE Name = '{name}'\");\n",
            }
        )
        self.assertEqual(self.lines_of("INJ-022"), {("src/db.rs", 1)})
        self.assertEqual(self.lines_of("INJ-021"), {("Repo.cs", 1)})

    def test_nginx_comments_nested_blocks_and_quotes(self) -> None:
        self.write(
            {
                "nginx/site.conf": "location /static {\n"
                "    # alias /old/static/;\n"
                "    alias /srv/static;\n"
                "}\n"
                "location /media {\n"
                "    if ($x) { return 403; }\n"
                "    alias /srv/media/;\n"
                "}\n"
                'location /dl { alias "/srv/dl/"; }\n',
                "nginx/README.md": "location /static { alias /srv/static/; }\n",
            }
        )
        self.assertEqual(self.lines_of("CFG-022"), {("nginx/site.conf", 5), ("nginx/site.conf", 9)})

    def test_deserialization_forms(self) -> None:
        self.write(
            {
                "Load.java": "ObjectInputStream ois = new ObjectInputStream(in); // read class data\n"
                "Object o = new java.io.ObjectInputStream(in).readObject();\n"
                "XMLDecoder d = new java.beans.XMLDecoder(in);\n"
                "ObjectInputStream f = new ObjectInputStream(in) {\n",
                "Load.kt": "val o = java.io.ObjectInputStream(input).readObject()\n"
                "class SafeInput(input: InputStream) :\n"
                "    ObjectInputStream(input) {\n"
                "val s = object : ObjectInputStream(input) {\n",
            }
        )
        # 4 行目の無名の継承（Java の new …(in) { と Kotlin の object : …(input) {）は、2 回目のレビューで見るように変えた
        self.assertEqual(
            self.lines_of("INJ-023"),
            {("Load.java", 1), ("Load.java", 2), ("Load.java", 3), ("Load.java", 4), ("Load.kt", 1), ("Load.kt", 4)},
        )

    def test_escaped_then_joined_blade_output(self) -> None:
        self.write({"resources/views/a.blade.php": "{!! e($a) . $b !!}\n{!! e($a) !!}\n"})
        self.assertEqual(self.lines_of("XSS-007"), {("resources/views/a.blade.php", 1)})

    def test_update_method_is_not_sql(self) -> None:
        self.write(
            {
                "Notes.java": 'this.update("Saved: name = " + name);\n'
                "jdbcTemplate.update(\"UPDATE users SET name = '\" + name + \"'\");\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-020"), {("Notes.java", 2)})


class SecondReviewTests(Case):
    # 2 回目の /code-review の指摘（2026-10-22）

    def test_escaping_helpers_that_do_not_protect(self) -> None:
        self.write(
            {
                "app/models/post.rb": "Post.where(\"title = '#{sanitize_sql(params[:q])}'\")\n"
                'Post.where("id = #{connection.quote_string(params[:id])}")\n'
                'Post.where("id = #{sanitize_sql_for_conditions(params[:id])}")\n'
                "Post.where(\"title = '#{connection.quote_string(params[:q])}'\")\n"
                'Post.where("id = #{sanitize_sql_array(["?", params[:id]])}")\n'
            }
        )
        self.assertEqual(self.lines_of("INJ-018"), {("app/models/post.rb", n) for n in (1, 2, 3)})

    def test_anonymous_subclasses_and_elvis_still_create_streams(self) -> None:
        self.write(
            {
                "Load.java": "ObjectInputStream f = new ObjectInputStream(in) {\n",
                "Load.kt": "val s = object : ObjectInputStream(input) {\n"
                "val t = cached ?: ObjectInputStream(input)\n"
                "class SafeInput(input: InputStream) : ObjectInputStream(input) {\n"
                "class Other(input: InputStream) :\n"
                "    ObjectInputStream(input) {\n",
            }
        )
        self.assertEqual(self.lines_of("INJ-023"), {("Load.java", 1), ("Load.kt", 1), ("Load.kt", 2)})

    def test_shell_execute_in_deploy_scripts(self) -> None:
        self.write(
            {
                "config/deploy.rb": 'execute "cd #{current_path} && RAILS_ENV=#{fetch(:rails_env)} bundle exec rake db:seed"\n'
                "execute \"echo '#{msg}' >> /tmp/log\"\n",
                "lib/helpers.rb": "exec_query('SELECT reltuples FROM pg_class WHERE relname = ' + \"'#{name}'\")\n"
                "connection.exec_query(\"SELECT * FROM t WHERE a = '#{a}'\")\n",
            }
        )
        self.assertEqual(self.lines_of("INJ-018"), {("lib/helpers.rb", 2)})

    def test_sql_words_outside_or_in_prose(self) -> None:
        self.write(
            {
                "Notes.java": 'notes.update("Saved: name = " + name, values);\n'
                'progress.update("Imported from CSV: count = " + n);\n'
                'uri.query("from=" + start + "&to=" + end);\n'
                'em.createQuery("FROM User u WHERE u.name = \'" + name + "\'");\n',
                "Log.cs": 'logger.Execute($"Imported from CSV: count = {n}");\n',
                "src/log.rs": 'client.execute(&format!("echo from = {}", x));\n',
            }
        )
        found = {(f.rule_id, f.location.path, f.location.line) for f in self.scan().findings if f.rule_id.startswith("INJ")}
        self.assertEqual(found, {("INJ-020", "Notes.java", 4)})

    def test_android_where_clauses(self) -> None:
        self.write(
            {
                "app/src/main/java/Store.java": 'db.update("users", values, "id = " + id, null);\n'
                "db.query(\"users\", cols, \"name = '\" + name + \"'\", null, null, null, null);\n"
                'db.delete("users", "id = " + id, null);\n'
                'db.delete("users", "id = ?", new String[]{id});\n',
                "app/src/main/java/Store.kt": "db.query(\"users\", null, \"name = '$name'\", null, null, null, null)\n",
            }
        )
        self.assertEqual(
            self.lines_of("INJ-020"),
            {("app/src/main/java/Store.java", n) for n in (1, 2, 3)} | {("app/src/main/java/Store.kt", 1)},
        )

    def test_blade_render_and_pagination_chains(self) -> None:
        self.write(
            {
                "resources/views/a.blade.php": "{!! $markdown->render() !!}\n"
                "{!! $users->withQueryString()->links() !!}\n"
                "{!! $users->appends(['q' => $q])->links() !!}\n"
                "{!! $users->appends(request()->query())->links() !!}\n"
            }
        )
        self.assertEqual(self.lines_of("XSS-007"), {("resources/views/a.blade.php", 1)})

    def test_skip_before_action_with_several_names(self) -> None:
        self.write(
            {
                "app/controllers/a_controller.rb": "skip_before_action :authenticate_user!, :verify_authenticity_token\n"
                "skip_before_filter :verify_authenticity_token\n"
            }
        )
        self.assertEqual(self.lines_of("AUTH-005"), {("app/controllers/a_controller.rb", 1), ("app/controllers/a_controller.rb", 2)})

    def test_csharp_initializer_and_named_argument(self) -> None:
        self.write(
            {
                "Repo.cs": 'using var cmd = new NpgsqlCommand { Connection = conn, CommandText = $"SELECT * FROM T WHERE Id = {id}" };\n'
                'conn.Execute(sql: "DELETE FROM U WHERE Id = " + id);\n'
                "    [JsonProperty(ItemTypeNameHandling = TypeNameHandling.Auto)]\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-021"), {("Repo.cs", 1), ("Repo.cs", 2)})
        self.assertEqual(self.lines_of("INJ-025"), {("Repo.cs", 3)})

    def test_php_casts_and_quoting(self) -> None:
        self.write(
            {
                "src/Repo.php": "<?php\n"
                '$pdo->query("SELECT * FROM t WHERE a = " . $pdo->quote($a));\n'
                '$pdo->query("SELECT * FROM t WHERE id = " . (int) $id);\n'
                '$wpdb->get_row("SELECT * FROM t WHERE id = " . absint($id));\n'
                "$wpdb->query(\"DELETE FROM t WHERE a = '\" . esc_sql($a) . \"'\");\n"
                "mysqli_query($c, \"SELECT * FROM t WHERE a = '\" . mysqli_real_escape_string($c, $a) . \"'\");\n"
                '$wpdb->query("DELETE FROM t WHERE id = " . esc_sql($id));\n'
            }
        )
        # 最後の行は、引用符の外なので esc_sql では守れない
        self.assertEqual(self.lines_of("INJ-019"), {("src/Repo.php", 7)})

    def test_docker_socket_outside_containers(self) -> None:
        self.write(
            {
                "ansible/tasks.yml": "- wait_for:\n    path: /var/run/docker.sock\n"
                "- file:\n    path: /var/run/docker.sock\n    mode: \"0660\"\n",
                "k8s/agent.yaml": "volumes:\n  - name: sock\n    hostPath:\n      type: Socket\n      path: /var/run/docker.sock\n",
            }
        )
        self.assertEqual(self.lines_of("CFG-020"), {("k8s/agent.yaml", 3)})

    def test_scala_interpolation(self) -> None:
        self.write({"src/main/scala/Repo.scala": 'stmt.executeQuery(s"SELECT * FROM t WHERE id = $id")\n'})
        self.assertEqual(self.lines_of("INJ-020"), {("src/main/scala/Repo.scala", 1)})

    def test_rust_migrations(self) -> None:
        self.write({"db/migration/src/m1.rs": "conn.execute(&format!(\"UPDATE t SET a = '{}'\", v), [])?;\n"})
        self.assertEqual(self.lines_of("INJ-022"), set())


class ThirdReviewTests(Case):
    # 3 回目の /code-review の指摘（2026-10-22）。この直しはレビューにかけていない

    def test_csrf_evidence_is_the_whole_line(self) -> None:
        # 前の版と同じ証拠（行全体）にして、指紋を変えない（ベースラインで外した指摘がまた出ないように）
        line = "app.use(lusca({ csrf: false, xframe: 'SAMEORIGIN' }))"
        self.write({"app.js": line + "\n", "SecurityConfig.kt": "http {\n    csrf {\n        disable()\n    }\n}\n"})
        evidence = {f.location.path: f.evidence for f in self.scan().findings if f.rule_id == "AUTH-005"}
        self.assertEqual(evidence, {"app.js": line, "SecurityConfig.kt": "csrf {"})

    def test_quote_inside_sql_quotes_is_not_safe(self) -> None:
        self.write(
            {
                "app/models/post.rb": "Post.where(\"title = '#{connection.quote(params[:q])}'\")\n"
                "Post.where(\"title LIKE '%#{connection.quote(q)}%'\")\n"
                'Post.where("title = #{connection.quote(params[:q])}")\n',
                "src/Repo.php": "<?php\n$pdo->query(\"SELECT * FROM t WHERE a = '\" . $pdo->quote($a) . \"'\");\n"
                '$q->whereRaw("a = ".$this->db->escape($a));\n'
                '$pdo->query("SELECT * FROM t WHERE a = " . DB::getPdo()->quote($a));\n',
            }
        )
        self.assertEqual(self.lines_of("INJ-018"), {("app/models/post.rb", 1), ("app/models/post.rb", 2)})
        self.assertEqual(self.lines_of("INJ-019"), {("src/Repo.php", 2)})

    def test_android_where_clause_needs_a_database_receiver(self) -> None:
        self.write(
            {
                "app/src/main/java/Progress.java": 'progress.update("import", "count = " + n);\n'
                'tracker.query("users", "count = " + n);\n',
                "app/src/main/java/State.kt": 'state.update("ui", "loading = ${isLoading}")\n',
                "app/src/main/java/Store.java": 'db.update(TABLE_USERS, values, "id = " + id, null);\n'
                'db.delete(UserContract.TABLE, "id = " + id, null);\n'
                "db.query(\"users\", new String[]{\"id\"}, \"name = '\" + name + \"'\", null, null, null, null);\n",
                "app/src/main/java/Store.kt": 'writableDatabase.update(UserTable.NAME, values, "id = $id", null)\n',
            }
        )
        self.assertEqual(
            self.lines_of("INJ-020"),
            {("app/src/main/java/Store.java", n) for n in (1, 2, 3)} | {("app/src/main/java/Store.kt", 1)},
        )

    def test_value_after_a_closed_quote(self) -> None:
        self.write(
            {
                "src/Repo.php": "<?php\n$wpdb->query(\"DELETE FROM t WHERE a = '\" . esc_sql($a) . \"' AND b = '\" . $b . \"'\");\n",
            }
        )
        self.assertEqual(self.lines_of("INJ-019"), {("src/Repo.php", 2)})

    def test_folders_that_only_end_with_migrations(self) -> None:
        self.write(
            {
                "src/Services/DataMigrations/ImportService.cs": "var c = new SqlCommand(\"SELECT * FROM T WHERE Name = '\" + name + \"'\", conn);\n",
                "src/main/java/com/app/UserMigrations/Copy.java": 'stmt.executeQuery("SELECT * FROM t WHERE a = " + a);\n',
            }
        )
        self.assertEqual(self.lines_of("INJ-021"), {("src/Services/DataMigrations/ImportService.cs", 1)})
        self.assertEqual(self.lines_of("INJ-020"), {("src/main/java/com/app/UserMigrations/Copy.java", 1)})

    def test_kotlin_class_headers_on_several_lines(self) -> None:
        self.write(
            {
                "Load.kt": "class SafeObjectInputStream(\n    input: InputStream,\n) : ObjectInputStream(input) {\n"
                "class B(input: InputStream) :\n    ObjectInputStream(input)\n"
            }
        )
        self.assertEqual(self.lines_of("INJ-023"), set())

    def test_actuator_in_jvm_options_indexes_and_kubernetes_env(self) -> None:
        self.write(
            {
                ".env": "JAVA_OPTS=-Dmanagement.endpoints.web.exposure.include=*\n",
                "src/main/resources/application.properties": "management.endpoints.web.exposure.include[0]=*\n",
                "k8s/deploy.yaml": "env:\n  - name: MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE\n    value: \"*\"\n"
                "  - name: OTHER\n    value: \"*\"\n",
            }
        )
        self.assertEqual(
            self.lines_of("CFG-019"),
            {(".env", 1), ("src/main/resources/application.properties", 1), ("k8s/deploy.yaml", 3)},
        )

    def test_to_i_must_wrap_the_whole_value(self) -> None:
        self.write(
            {
                "app/models/user.rb": 'User.where("a = #{params[:a].presence || DEFAULT.to_i}")\n'
                "User.where([\"name = '#{params[:name]}'\"])\n"
                'User.where("a = #{params[:a].to_i}")\n'
            }
        )
        self.assertEqual(self.lines_of("INJ-018"), {("app/models/user.rb", 1), ("app/models/user.rb", 2)})


NEW_RULES = {
    "INJ-018": ('.where("', '.where "', ".execute(", '.where(["'),
    "INJ-019": (
        'DB::select("',
        "whereRaw('",
        '$wpdb->query("',
        'mysqli_query($c, "',
        '->query("SELECT ',
        '$wpdb->query("DELETE FROM t WHERE a = \'" . esc_sql($a) . "',
        'whereRaw("a = ".$this->db->',
    ),
    "INJ-020": ('executeQuery("', 'query("', 'db.update("t", values, "', 'db.delete(T, "', 'mDb.query(T, new String[]{"id"}, "'),
    "INJ-021": (
        'FromSqlRaw($"',
        '.Query<User>("',
        'new SqlCommand("',
        ".CommandText = ",
        'ExecuteSqlRaw(string.Format("',
        ".Query<",
        'conn.Execute(sql: "SELECT ',
        '{ CommandText = $"SELECT ',
    ),
    "INJ-022": ('query(&format!("', "query_as::<"),
    "INJ-023": ("new ObjectInputStream(",),
    "INJ-024": ("new BinaryFormatter",),
    "INJ-025": ("TypeNameHandling = ",),
    "AUTH-005": (".csrf(", "csrf {", "skip_before_action ", "skip_before_action :a, "),
    "AUTH-009": (".permit!",),
    "AUTH-010": ("$guarded = [",),
    "XSS-007": ("{!!",),
    "TLS-012": ("ServerCertificateCustomValidationCallback = (",),
    "TLS-013": (".danger_accept_invalid_certs(",),
    "CFG-019": (
        "management.endpoints.web.exposure.include=",
        "management:\n  endpoints:\n    web:\n      exposure:\n        include:",
        "- ",
        "- name: MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE\n  value: ",
    ),
    "CFG-020": ("- ", "source: ", "hostPath:\n  ", "hostPath: {"),
    "CFG-021": ("network_mode: ",),
    "CFG-022": ("location /a {", "location "),
}


def _timed(run, text: str, times: int = 1) -> float:
    """いちばん速かった回の時間（伸び方を比べるときは、ほかの処理の揺れで落ちないよう 3 回流す）。"""
    best = float("inf")
    for _ in range(times):
        started = time.monotonic()
        run(text)
        best = min(best, time.monotonic() - started)
    return best


class NewRulePerformanceTests(unittest.TestCase):
    def test_new_rules_are_linear(self) -> None:
        # 当たりそうで当たらない長い行で、どのルールも長さの 2 乗の時間にならないこと
        # （書いた直後は、TLS-012 が空白の続く行で、INJ-022 が query_as::< の並ぶ行で 2 乗だった）。
        # 15 ミリ秒を超えた入力は 4 倍の長さでも流し、時間が 10 倍を超えて伸びないことを見る
        # （CFG-022 のコメントの読み飛ばしは、4 万文字では 0.04 秒で、16 万文字で 0.6 秒になった）
        fragments = ["'", '"', " ", "= ", "#{", "${", "{", "$a", "'a'", "''", " like ", "\\", "(", " + ", " . ", "\n", "a"]
        fragments += ["<a", "::<", "->", "}", "#{a.to_i", "= #{", "= {$", "= ${", "= {", "= $a[", "= {0"]
        size = 40_000
        for rule_id, prefixes in NEW_RULES.items():
            rule = get_rule(rule_id)
            if isinstance(rule, FileRule):  # CFG-019 は行を読む関数
                runs = [lambda text, rule=rule: list(rule.check(SimpleNamespace(text=text, lines=text.split("\n"))))]
            else:
                patterns = [p for p in (rule._pattern, rule._unless, rule._require_line, rule._value_unless) if p]
                runs = [lambda text, pattern=pattern: list(pattern.finditer(text)) for pattern in patterns]
            for prefix in prefixes:
                for fragment in fragments:
                    makers = (
                        lambda n, prefix=prefix, fragment=fragment: prefix + fragment * (n // len(fragment)),
                        lambda n, prefix=prefix, fragment=fragment: (prefix + fragment) * (n // len(prefix + fragment)),
                    )
                    for make in makers:
                        for run in runs:
                            with self.subTest(rule=rule_id, prefix=prefix, fragment=fragment):
                                took = _timed(run, make(size))
                                self.assertLess(took, 0.5)
                                if took > 0.015 and _timed(run, make(size * 4)) > took * 10 + 0.05:
                                    # 揺れかもしれないので、3 回ずつ流し直して比べる
                                    took = _timed(run, make(size), 3)
                                    self.assertLess(_timed(run, make(size * 4), 3), took * 10 + 0.05)


class ReadmeRuleCountTests(unittest.TestCase):
    def test_language_tables_match_the_rules(self) -> None:
        # README の「言語 | ルール」の表の数が、言語ごとのルールの数とずれないこと（YAML・Dockerfile は最後の行にまとめてある）
        counts = Counter(lang for rule in [*LINE_RULES, *FILE_RULES] for lang in rule.languages)
        expected = {lang: n for lang, n in counts.items() if lang not in {"yaml", "docker"}}
        by_label = {label: lang for lang, label in LANGUAGE_LABELS.items()}
        for readme, shell_label in (("README.ja.md", "シェル"), ("README.md", "Shell")):
            rows = re.findall(r"(?m)^\| ([^|\n]+?) \| (\d+) \|", (ROOT / readme).read_text("utf-8"))
            labels = {**by_label, shell_label: "shell"}
            found = {labels[label]: int(n) for label, n in rows if label in labels}
            with self.subTest(readme=readme):
                self.assertEqual(found, expected)


if __name__ == "__main__":
    unittest.main()
