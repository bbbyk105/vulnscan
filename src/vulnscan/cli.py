"""コマンドラインインターフェース。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .engine import ScanOptions, scan
from .models import CATEGORY_JA, SEVERITY_JA, ScanError, Severity
from .report import render, write_output
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

    e = sub.add_parser("explain", help="ルールの詳細を表示する")
    e.add_argument("rule_id")

    b = sub.add_parser("baseline", help="現在の指摘をベースラインとして保存する", allow_abbrev=False)
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("-o", "--output", default=".vulnscan-baseline.json")

    return parser


def cmd_scan(args) -> int:
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


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "rules":
            return cmd_rules(args)
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
