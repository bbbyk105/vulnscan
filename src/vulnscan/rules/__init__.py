"""ルールの登録とメタ情報。"""

from __future__ import annotations

from typing import Optional

from . import code, config, deps, secrets, shell
from .base import FileRule, LineRule

LINE_RULES = [*secrets.RULES, *code.RULES]
FILE_RULES = [*config.FILE_RULES, *shell.FILE_RULES]

_RULE_INDEX = {rule.id: rule for rule in [*LINE_RULES, *FILE_RULES]}

DEP_RULES_META = [
    {
        "id": "DEP-001",
        "title": "依存パッケージの既知の脆弱性",
        "severity": "high",
        "category": "dependency",
        "message": "lockfile を監査ツールで検査し、既知の脆弱性を報告します。",
        "remediation": "修正版に更新し、テストを実行してください。",
    },
    {
        "id": "DEP-010",
        "title": "依存監査ツールが見つからない",
        "severity": "high",
        "category": "dependency",
        "message": "--deps を付けたのに、lockfile に対応する監査ツール（npm / pnpm / yarn / pip-audit / composer / osv-scanner）"
        "が無く、既知の脆弱性を確認できていません。",
        "remediation": "ツールをインストールしてから、もう一度 --deps を付けて実行してください。",
    },
    {
        "id": "DEP-011",
        "title": "依存の監査に失敗",
        "severity": "high",
        "category": "dependency",
        "message": "監査ツールがエラーで終わったか、出力を読めませんでした。既知の脆弱性は確認できていません。",
        "remediation": "ネットワーク・レジストリの認証・ツールの版を確認し、手元で同じコマンドを流してください。",
    },
    {
        "id": "DEP-012",
        "title": "--deps の対象外の lockfile",
        "severity": "low",
        "category": "dependency",
        "message": "どのツールでも見られない lockfile（バイナリの形式の bun.lockb）です。",
        "remediation": "テキストの形式の bun.lock に移すと、osv-scanner で調べられます。",
    },
]


def _rule_meta(rule) -> dict:
    return {
        "id": rule.id,
        "title": rule.title,
        "severity": rule.severity.label,
        "category": rule.category,
        "message": rule.message,
        "remediation": rule.remediation,
        "cwe": rule.cwe,
        "owasp": rule.owasp,
    }


def _repo_rules_meta() -> list:
    return [
        {"id": rule_id, **meta, "severity": meta["severity"].label}
        for rule_id, meta in config.REPO_RULES.items()
    ]


def get_rule(rule_id: str):
    return _RULE_INDEX.get(rule_id)


def describe(rule_id: str) -> Optional[dict]:
    rule = _RULE_INDEX.get(rule_id)
    if rule is not None:
        return _rule_meta(rule)
    for meta in [*_repo_rules_meta(), *DEP_RULES_META]:
        if meta["id"] == rule_id:
            return dict(meta)
    return None


def all_rule_meta() -> list:
    meta = [_rule_meta(rule) for rule in [*LINE_RULES, *FILE_RULES]]
    meta.extend(_repo_rules_meta())
    meta.extend(DEP_RULES_META)
    return meta
