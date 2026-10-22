**English** | [日本語](rules.ja.md)

# Rule details

How some rules decide what to report. For the list of rules, run `./vulnscan rules`; for one rule, `./vulnscan explain <ID>`.

## SEC-013: hard-coded passwords and API keys

**What it reports**: names that end with `password`, `secret`, `secret_key`, `api_key`, `access_token` and the like (including `SMTP_PASSWORD`, `dbPassword` and `'X-Api-Key'`) assigned an ASCII value without spaces, in quotes or backticks. Values with spaces are skipped so that UI text is not reported.

- Assignments: `=`, `:` and Go's `:=`; `=>` only after a quoted name or a Ruby symbol (not arrow functions).
- `.env`-style files are left to SEC-016, which also reads commented-out lines, trailing comments and `_PWD`.
- Translation files (JSON, YAML, PHP and the like under `lang/`, `locales/`, `i18n/` and similar folders) are not scanned.

**Values not treated as secrets** (other values on the same line are still checked):

| Kind | Examples |
|---|---|
| References | `process.env`, `${…}`, a whole value of `"$VAR"` |
| Placeholders | `changeme`, `your-…`, `<…>`, `__…`, `xxxxxx` |
| Addresses | URLs (unless they contain `user:pass@`), `env()`, lowercase paths |
| Names, not values | i18n keys (`auth.password.label`), uppercase identifiers made of letters and `_`, camelCase or `/`-separated values that name a credential (`'newPassword'`, `'auth/RESET_PASSWORD'`) |
| Words | values made only of lowercase words (`"local-test-key"`); letters-only values on names with a prefix (`"showPassword": "Anzeigen"`) |
| Other formats | Laravel validation rules, bcrypt hashes |
| Public values | Turnstile's test secret, RevenueCat public keys |
| Reported elsewhere | tokens that SEC-002 and SEC-005 to SEC-011 already report (so they are not counted twice) |

As a result, weak passwords made only of lowercase words (`"my-super-secret"`) and letters-only passwords on names with a prefix (`DB_PASSWORD = "topsecret"`) are not reported. The same value is reported when the name is exactly `password`.

Values that are not treated as secrets are still masked in the evidence of other findings. When the masking changes, other findings on that line get a new fingerprint once; regenerate your baseline if you use one.

## INJ-009: SQL built in JavaScript/TypeScript

**Calls it looks at**: `query`, `execute` and `raw`, and the sqlite3, better-sqlite3 and Prisma calls `all`, `get`, `run`, `each`, `exec`, `prepare`, `$queryRawUnsafe` and `$executeRawUnsafe` (with TypeScript type arguments such as `<User[]>` too). The sqlite3, better-sqlite3 and Prisma calls are only checked when the string starts with an SQL verb, so `router.get(...)` and caches are not reported.

**It only reports where a value is joined**:

- inside SQL `'…'` (including `\'`)
- `${}` or concatenation right after `=`, `<`, `>`, `LIKE`, `ILIKE`, `GLOB` or `REGEXP`
- `"…"` only right after a comparison, because Postgres also uses it for identifiers

For concatenation it checks every string in `"…" + expression + "…"`, and stops at an expression that contains quotes. It also looks inside nested templates (`` ${cond ? `AND id = ${id}` : ''} ``).

**Not reported**: building column lists, `WHERE` clauses or `IN (?, ?)` while binding the values (the same rule as Go's INJ-014). Column names, table names and sort order taken from input (`SET ${field}=?`, `ORDER BY ${sort}`) and values in positions without quotes or operators (`LIMIT ${n}`) are not reported either; read them in review. Findings in test files are low.

## Shell scripts

These rules read `.sh`, `.bash`, `.zsh` and `.fish` files, one line at a time. They do not read scripts without an extension (even with a `#!/bin/sh` line), `RUN` lines in a Dockerfile or `run:` blocks in GitHub Actions. A command continued on the next line with `\` is not joined (CFG-018 does join an `if` condition), and fish's `\'` inside single quotes is not handled.

Before matching, each line drops what the shell does not run:

- comments: a `#` at the start of a word, and the rest of the line (`$#`, `${x#…}` and `#` inside a URL are kept)
- text in quotes passed to commands that only print it: `echo`, `printf`, `print`, `say`, `usage`, `die`, `fail`, `abort`, `fatal`, `log`, `info`, `warn`, `warning`, `error`, `err`, `debug`, `msg`, `note`, `notice`, `success`, and those words with `log_`, `print_`, `echo_` before or `_msg` after them (`log_info`, `print_error`, `warn_msg`). Helpers that run their arguments, such as `log_exec`, are not on the list. A `$(…)` inside that text runs, so it is kept. Printing to the terminal includes `>&2` and `> /dev/null`.
- heredoc bodies passed to commands that read them as data (`cat <<EOF`). Bodies passed to `sh`, `bash`, `zsh`, `ssh`, `su`, `python`, `perl`, `ruby`, `node` or `php` are read as commands.

The text is kept when the output does more than print. That covers writing it to a file (`echo "StrictHostKeyChecking no" >> "$SSH_CONFIG"`), piping it to another command (`echo "…" | sh`, `| sudo tee`) or capturing it with `$(…)`. It also covers groups whose output goes to a file or a pipe (`{ …; } >> cfg`, `for …; done >> cfg`, `if …; fi | sh`, over several lines too), and every line after `exec >> file`. Quotes passed to other commands are read as is (`STATUS="$(curl -sk …)"`, `git -c "http.sslVerify=false"`).

- **INJ-016 (medium), running a downloaded script**: `curl` or `wget` piped into `sh`, `bash`, `zsh`, `python`, `perl`, `ruby`, `node`, `php` or fish's `source`. This includes `/bin/bash`, `/usr/bin/env -i bash`, `sudo`, `doas`, `|&`, `2>&1`, and other commands in between (`| gunzip | sh`, `| tr -d '\r' | bash`, `| sudo tee x | bash`). Also reported: `bash <(curl …)`, `bash -s stable < <(curl …)`, `bash <<< "$(curl …)"`, `source <(curl …)`, `bash -c "$(curl …)"`, `bash -e -c "$(curl …)"`, `eval "$(curl …)"`, and the same with backticks. Not reported:
  - an interpreter given a script, or `-c`, `-e`, `-r` (also after other options, as in `bash -e -c`), because it then reads the download as data (`python3 -c 'import json…'`, `bash ./parse.sh`)
  - saving to a file and running it later
- **INJ-017 (medium), `eval` and `sh -c` on arguments**: only when an argument is passed as is (`eval "$@"`, `eval $1`, `bash -c "$1"`, `eval "$1=$2"`, `eval "$1=\"$2\""`). Not reported:
  - `eval "$(ssh-agent -s)"`, and `eval` on other variables
  - `eval "$1=\$value"`, which passes the value by name
  - arguments in single quotes (`eval '$@'`), whose values are not read again as commands
- **TLS-010 (high), certificate checks turned off**: `curl -k` or `--insecure` (also inside `-sk`), `wget --no-check-certificate`, `pip --trusted-host`, git's `http.sslVerify` set to `false`, `no`, `off` or `0` (in any case, also per URL as `http.<url>.sslVerify`), `GIT_SSL_NO_VERIFY=` (git skips the checks whatever the value) and `strict-ssl false` for npm, yarn and pnpm. A `curl` or `wget` whose URLs all point to `localhost`, `127.0.0.1`, `0.0.0.0` or `[::1]`, with no variable, `$(…)` or backticks in its arguments (quoted ones included), is skipped. These do not count as local: hosts that only start with those names (`localhost.example`), and URLs where the name is the user part (`localhost:pw@example.com` connects to example.com). Findings in test files are low.
- **TLS-011 (medium), SSH host keys not checked**: `StrictHostKeyChecking=no`, `off` or `false` (also written `-oStrictHostKeyChecking=no`). `accept-new` is not reported.
- **CFG-017 (medium), files anyone can write**: modes that let other users write (`777`, `666`, `66`, `2777`, `"777"`, `o+w`, `a+w`) given to `chmod`, `mkdir -m`, `mkdir --mode=` or `install -m`, and `umask 000`. Not reported: modes with the sticky bit such as `1777` (shared folders like `/tmp`), `g+w`, `+w`, and symbolic modes that also take write away from others (`a+rw,o-w`).
- **CFG-018 (low), `rm -r` that can delete `/`**: a variable followed only by `/` or `/*` (`"$DIR/"*`, `"$DIR"/`, `$1/`), which becomes `/` when the variable is empty. It reads `rm` at the start of a command, including after `if`, `!`, `sudo -E`, `sudo -u user`, `doas`, `$SUDO` and `\rm`. Not reported:
  - `"${DIR:?}/"*`, and paths that go on after the variable (`"$DIR/build"`)
  - `rm` used as a subcommand (`git rm`, `aws s3 rm`)
  - variables checked before the `rm` in a way that stops it when empty. Only forms that leave no doubt are counted. The check must test the variable itself (`"$DIR/bin"` and `"${DIR:-x}"` do not count), with no other condition in the same test (`-o`, `-a`, `&&` or `||` inside the brackets). With `[ ]` and `test`, `-n`, `-d` and `-e` need quotes: `[ -n $DIR ]` becomes `[ -n ]` when DIR is empty, which is always true. Checks inside a string passed to another command (`ssh host '[ -n "$D" ] || exit'`) or inside `$(…)` do not count. The forms counted:
    - on the same line: `[ -n "$DIR" ] && rm …` or `[ -z "$DIR" ] || rm …`, with no `;`, `&`, or `||` after `&&` (`&&` after `||`) in between; or `if [ -n "$DIR" ]; then … rm …` before any `else`, `elif` or `fi`
    - inside a block: `rm` on the lines of the `then` branch of an `if [ -n "$DIR" ]` (or `-d`) that starts its line, with no `||` in the condition (lines continued with `\` included); or inside `[ -n "$DIR" ] && {` … `}`
    - for the rest of the file, but only when written at the top level (not inside a function, `if`, `case`, loop, `( … )` or `{ … }`, multi-line ones included) with nothing conditional before it on its line:
      - `${DIR:?}` or `${DIR:=default}` (`: "${DIR:?}"`, `DIR=${1:?}`)
      - `[ -n "$DIR" ] || exit`, `[ -z "$DIR" ] && exit` (also `{ …; exit 1; }`), or `[ -z "$DIR" ] && DIR=<value>`
      - `if [ -z "$DIR" ]` at the start of its line (not `elif`, no `&&` in the condition) whose `then` branch runs `exit` or sets `DIR` to a value that cannot be empty, outside any nested condition

    `exit` may also be a function defined in the same file that exits without a condition (`die() { echo "$*" >&2; exit 1; }`). A `die`, `fail` or `usage` with no such definition in the file does not count, since it may not exit. `return` does not count either: at the top level of a script, bash reports an error and carries on.

    A check protects only until the variable is set again (`DIR=…`, `read DIR`, `local DIR`, `unset DIR`, `for DIR in`; `shift` and `set --` for `$1`). A top-level check on `$1` does not cover functions, whose `$1` is their own argument. Checks inside functions and other blocks are not followed, so a function that checks and then deletes is reported (low). Write the check into the `rm` itself as `"${DIR:?}/"*`.
  - variables that cannot be empty when the `rm` runs. Such a variable is set once before the `rm`, on a line of its own, to a value that cannot be empty. The value has fixed text other than `/` and `.` (`OUT="$ROOT/dist"`, not `"$PREFIX/"`), or a default of that kind (`${X:-default}`). That line is outside `if`, `case`, loops, functions, `( … )`, `{ … }` and heredocs. Nothing else in the file sets the variable, reads it in (`read`, `IFS= read`, `for`, `select`, `printf -v`) or clears it (`unset`, `local`). No other file is sourced (`.` or `source`) between the assignment and the `rm`.

  CFG-018 does not read `.fish` files, whose `if … end`, `and` and `or` it cannot follow.

## `--deps`: dependency audits

| Lockfiles | Audited with |
|---|---|
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (Yarn 1), `requirements.txt`, `composer.lock` | their own audit tools |
| `pubspec.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `bun.lock` and others | `osv-scanner` |
| `bun.lockb` | none; reported as not checked (DEP-012, low) |

- Lockfiles in subfolders and lockfiles excluded by `.gitignore` are audited too; `--exclude` applies. Findings for lockfiles in test folders are low.
- A missing audit tool (DEP-010) or a failed audit (DEP-011) is reported as high, so a project that was not checked never passes. This includes a missing `osv-scanner`.
- The handling of `osv-scanner`'s output follows its official documentation and has not yet been checked against real output.

## `.env` files

The `.env` at the root is read even when it is gitignored, to check exposure such as `NEXT_PUBLIC_` (its contents are never sent anywhere). `.env` files in subfolders are read only when they are committed or not excluded by `.gitignore`.
