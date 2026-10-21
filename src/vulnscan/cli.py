"""コマンドラインインターフェース。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .detect import choose_languages, detect, parse_languages
from .engine import ScanOptions, scan
from .models import CATEGORY_JA, SEVERITY_JA, ScanError, Severity
from .report import language_scope, render, write_output
from .rules import all_rule_meta, describe
from .rules.base import set_reveal_secrets

FAIL_ON = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="ローカルコードの脆弱性を自分で見つける静的解析ツール（読み取り専用）",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # 省略形は受け付けない（--base を --baseline の省略と取り違えるなど、指定と違う動きになるため）
    p = sub.add_parser("scan", help="ディレクトリまたはファイルをスキャンする", allow_abbrev=False)
    p.add_argument("path", nargs="?", default=".", help="対象（既定: カレントディレクトリ）")
    p.add_argument("--format", choices=["text", "md", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="出力ファイル（未指定なら標準出力）")
    p.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="low")
    p.add_argument("--category", action="append", choices=sorted(CATEGORY_JA), help="カテゴリで絞り込む（複数可）")
    p.add_argument(
        "--lang",
        nargs="?",
        const="",
        metavar="LANGS",
        help="この言語のファイルだけを見る（例: --lang js,py。値を付けなければ、見つかった言語から番号で選ぶ）",
    )
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="除外するパス（複数可）")
    p.add_argument("--max-file-size", type=int, default=1500, metavar="KB", help="走査するファイルの上限サイズ")
    p.add_argument("--deps", action="store_true", help="依存パッケージの既知CVEも検査する（ネットワーク使用）")
    p.add_argument("--changed", action="store_true", help="git のコミットしていない変更ファイルだけを対象にする")
    p.add_argument(
        "--base",
        metavar="REF",
        help="REF からの変更（PR の差分）だけを対象にする。--changed を含む（例: --base origin/main）",
    )
    p.add_argument("--baseline", type=Path, help="既知の指摘を抑制するベースラインJSON")
    p.add_argument("--ignore-file", type=Path, help=".vulnscanignore の場所を指定")
    p.add_argument("--no-ignore", action="store_true", help=".vulnscanignore を使わない")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="high")
    p.add_argument("--group-by", choices=["severity", "file", "rule"], default="severity")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--reveal-secrets", action="store_true", help="秘密情報をマスクせずに表示する（取扱注意）")

    r = sub.add_parser("rules", help="利用できるルールの一覧")
    r.add_argument("--json", action="store_true")
    r.add_argument("--category", choices=sorted(CATEGORY_JA))

    d = sub.add_parser("detect", help="言語とフレームワークを見分ける（スキャンはしない）")
    d.add_argument("path", nargs="?", default=".")
    d.add_argument("--json", action="store_true")

    e = sub.add_parser("explain", help="ルールの詳細を表示する")
    e.add_argument("rule_id")

    b = sub.add_parser("baseline", help="現在の指摘をベースラインとして保存する", allow_abbrev=False)
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("-o", "--output", default=".vulnscan-baseline.json")

    return parser


NEEDS_LANG_VALUE = "--lang に言語を指定してください（例: --lang js,py）。番号で選ぶのは、端末で実行したときだけです。"


def ask_languages(detected: list):
    """スキャンと同じファイルの集まりで見つかった言語を番号つきで出し、選んでもらう。

    一覧と問いは stderr に出す（stdout はレポート用）。返すのは選んだ言語のキーか、None（すべて）。
    """
    if not detected:
        raise ScanError("言語のファイルが見つかりませんでした。")
    print("見る言語を選んでください（番号か名前をカンマ区切りで。空のまま Enter ですべて）:", file=sys.stderr)
    for i, item in enumerate(detected, 1):
        print(f"  {i}) {item['label']}  {item['files']} ファイル  {language_scope(item)}", file=sys.stderr)
    print("> ", end="", file=sys.stderr, flush=True)
    return choose_languages(detected, sys.stdin.readline())


def resolve_lang(args) -> tuple:
    """(言語のキー, 番号で選ぶか) を返す。`scan --lang <フォルダ>` はフォルダを対象にして番号で選ぶ。"""
    if args.lang is None:
        return (), False
    if not args.lang:
        return (), True
    try:
        return tuple(parse_languages(args.lang)), False
    except ScanError:
        # --lang は値を省けるので、後ろに書いたフォルダを値として受け取ってしまう。言語の名前でなく、
        # 存在するパスで、対象のパスを書いていないなら、それを対象にする
        if args.path == "." and Path(args.lang).exists():
            args.path = args.lang
            return (), True
        raise


def cmd_scan(args) -> int:
    languages, ask = resolve_lang(args)
    if ask and not sys.stdin.isatty():
        raise ScanError(NEEDS_LANG_VALUE)
    path = Path(args.path)
    options = ScanOptions(
        min_severity=Severity.coerce(args.min_severity),
        categories=tuple(args.category or ()),
        exclude=tuple(args.exclude),
        ignore_file=args.ignore_file,
        use_ignore=not args.no_ignore,
        baseline=args.baseline,
        max_file_bytes=args.max_file_size * 1024,
        deps=args.deps,
        changed_only=args.changed,
        base=args.base,
        languages=languages,
        pick_languages=ask_languages if ask else None,
        reveal_secrets=args.reveal_secrets,
    )
    set_reveal_secrets(args.reveal_secrets)

    result = scan(path, options)
    color = not args.no_color and args.output is None and sys.stdout.isatty()
    text = render(result, args.format, color=color, group_by=args.group_by)

    output = Path(args.output) if args.output else None
    if output is not None and str(output) == "-":
        output = None
    write_output(text, output)

    if args.fail_on == "never":
        return 0
    threshold = FAIL_ON[args.fail_on]
    return 1 if any(f.severity >= threshold for f in result.findings) else 0


def cmd_rules(args) -> int:
    meta = all_rule_meta()
    if args.category:
        meta = [m for m in meta if m["category"] == args.category]
    if args.json:
        print(json.dumps(meta, ensure_ascii=False, indent=2))
        return 0
    for item in meta:
        sev = Severity.coerce(item["severity"])
        print(f"{item['id']:<10} {SEVERITY_JA[sev]:<2} {item['title']}")
    print(f"\n{len(meta)} ルール")
    return 0


def cmd_explain(args) -> int:
    info = describe(args.rule_id)
    if info is None:
        print(f"ルールが見つかりません: {args.rule_id}", file=sys.stderr)
        return 2
    print(f"{info['id']}  {info['title']}")
    print(f"重要度: {SEVERITY_JA[Severity.coerce(info['severity'])]} / 分類: {CATEGORY_JA.get(info['category'], info['category'])}")
    if info.get("cwe"):
        print(f"CWE: {info['cwe']}  OWASP: {info.get('owasp') or '-'}")
    print(f"\n内容:\n  {info['message']}")
    print(f"\n修正:\n  {info['remediation']}")
    return 0


def cmd_baseline(args) -> int:
    options = ScanOptions(min_severity=Severity.INFO, use_ignore=True, deps=False)
    result = scan(Path(args.path), options)
    output = Path(args.output)
    from .ignore import write_baseline as save_baseline

    save_baseline(output, result.findings)
    print(f"{len(result.findings)} 件をベースラインに保存しました: {output}")
    print("次回から `vulnscan scan --baseline " + str(output) + "` で既知の指摘を除外できます。")
    return 0


def cmd_detect(args) -> int:
    info = detect(Path(args.path))
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0
    print("言語:")
    for item in info["languages"]:
        print(f"  {item['label']}  {item['files']} ファイル  {language_scope(item)}")
    if not info["languages"]:
        print("  （見つかりませんでした）")
    print("フレームワーク:")
    for item in info["frameworks"]:
        print(f"  {item['label']}（{item['evidence']}）")
    if not info["frameworks"]:
        print("  （見つかりませんでした）")
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "rules":
            return cmd_rules(args)
        if args.command == "detect":
            return cmd_detect(args)
        if args.command == "explain":
            return cmd_explain(args)
        if args.command == "baseline":
            return cmd_baseline(args)
    except (FileNotFoundError, ScanError) as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("中断しました。", file=sys.stderr)
        return 130
    except Exception as exc:  # 終了コード 1（指摘あり）と区別するため 2 で返す
        print(f"エラー: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 2
