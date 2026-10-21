"""文書（Markdown）の書き方の決まり。"""

from __future__ import annotations

import re
import subprocess
import unittest

from test_vulnscan import ROOT

# 地の文に書いた <N>・<c>・<base> のようなものは、GitHub が HTML のタグとして消したり崩したりする
_TAG = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>")
# わざと使ってよいタグ（README の折りたたみ）
_ALLOWED = {"details", "summary"}


def html_like_tags(text: str) -> list:
    """コードの枠（``` か ~~~ の間）とインラインのコード（`…`）の外にある、HTML のタグの形の文字列。"""
    hits = []
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        outside_code = re.sub(r"(`+)(.+?)\1", "", line)
        for tag in _TAG.findall(outside_code):
            name = re.match(r"</?([A-Za-z0-9-]+)", tag).group(1).lower()
            if name not in _ALLOWED:
                hits.append((lineno, tag))
    return hits


class MarkdownTests(unittest.TestCase):
    def test_placeholders_outside_code_are_not_html_tags(self) -> None:
        # SKILL.md の「- <N> は流した…」が、GitHub では「は流した…」と表示されていた（2026-10-22）
        # git に入っている文書と、まだ入れていない新しい文書だけを見る（.gitignore した .venv やレポートは見ない）
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.md"],
            capture_output=True,
            check=True,
        ).stdout.decode()
        found = []
        for rel in sorted(p for p in listed.split("\0") if p):
            path = ROOT / rel
            if path.exists():
                found.extend((rel, lineno, tag) for lineno, tag in html_like_tags(path.read_text("utf-8")))
        self.assertEqual(found, [])

    def test_code_and_allowed_tags_are_ignored(self) -> None:
        text = "```\n- <N> 件\n```\n`<base>` と ``<a>`` は書ける\n<details>\n<summary>例</summary>\n</details>\n- <c> は消える\n"
        self.assertEqual(html_like_tags(text), [(8, "<c>")])

    def test_self_closing_tags_and_tilde_fences(self) -> None:
        # /code-review の指摘: <N/> は GitHub で消えるのに見逃し、~~~ の枠の中を地の文として見ていた
        text = "~~~\n- <N> 件\n~~~\n- <N/> と <br/> は消える\n"
        self.assertEqual(html_like_tags(text), [(4, "<N/>"), (4, "<br/>")])


if __name__ == "__main__":
    unittest.main()
