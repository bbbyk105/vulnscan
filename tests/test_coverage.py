"""言語ごとの対象範囲（どの言語のファイルを、いくつのルールで見たか）の表示。"""

from __future__ import annotations

import json
import unittest

from test_vulnscan import RepoCase

from vulnscan.report import render_json, render_markdown, render_text


class CoverageTests(RepoCase):
    def languages(self, result) -> dict:
        return {item["language"]: item for item in result.languages}

    def test_languages_are_counted_with_their_rules(self) -> None:
        self.write(
            {
                "web/a.ts": "1\n",
                "web/b.tsx": "1\n",
                "tool.py": "1\n",
                "ios/Runner/AppDelegate.swift": "import UIKit\n",
                "ios/Runner/SceneDelegate.swift": "import UIKit\n",
            }
        )
        langs = self.languages(self.scan())
        self.assertEqual(langs["javascript"]["files"], 2)
        self.assertGreater(langs["javascript"]["rules"], 0)
        self.assertEqual(langs["python"]["files"], 1)
        self.assertEqual(langs["swift"], {"language": "swift", "label": "Swift", "files": 2, "rules": 0})

    def test_data_files_are_not_listed(self) -> None:
        self.write({"package.json": "{}\n", "drizzle/0001.sql": "select 1;\n", "Makefile": "a:\n"})
        self.assertEqual(self.scan().languages, [])

    def test_reports_show_languages_without_rules(self) -> None:
        self.write({"AppDelegate.swift": "import UIKit\n", "a.ts": "1\n"})
        result = self.scan()
        text = render_text(result)
        self.assertIn("Swift 1", text)
        self.assertIn("言語のルールなし", text)
        self.assertIn("言語のルールなし", render_markdown(result))
        data = json.loads(render_json(result))
        self.assertEqual(data["schema_version"], 1)
        self.assertIn("swift", {item["language"] for item in data["languages"]})


if __name__ == "__main__":
    unittest.main()
