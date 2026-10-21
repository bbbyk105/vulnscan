"""版の番号が、書いてある所でそろっているか（上げるときの直し忘れを止める）。"""

from __future__ import annotations

import re
import unittest

from test_vulnscan import ROOT

from vulnscan import __version__


class VersionTests(unittest.TestCase):
    def test_pyproject_and_readmes_match_the_package(self) -> None:
        pyproject = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
        self.assertEqual(pyproject, __version__)
        for name in ("README.md", "README.ja.md"):
            shown = re.findall(r"^vulnscan (\d+\.\d+\.\d+) — ", (ROOT / name).read_text(), re.M)
            self.assertEqual(shown, [__version__], name)


if __name__ == "__main__":
    unittest.main()
