from pathlib import Path
import tempfile
import unittest

from platform_build import build_assets


class PlatformBuildTest(unittest.TestCase):
    def test_support_entry_survives_public_asset_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build_assets(root)
            page = (root / "index.html").read_text()
            support_url = "https://support.coinexo.top/?project=leakssr"
            header = page.split('<header class="topbar">', 1)[1].split("</header>", 1)[0]
            footer = page.split('<footer class="app-footer">', 1)[1].split("</footer>", 1)[0]
            self.assertIn(support_url, header)
            self.assertIn(support_url, footer)
            self.assertIn("支持项目", header)
            self.assertIn('data-lucide="heart"', header)

    def test_build_only_public_assets_and_preserve_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "health.json").write_text('{"stale": true}')
            build_assets(root)
            self.assertEqual((root / "health.json").read_text(), '{"stale": true}')
            self.assertIn("LeakSSR", (root / "index.html").read_text())
            self.assertTrue((root / "vendor/lucide.min.js").is_file())
            self.assertTrue((root / "source.js").is_file())
            self.assertFalse((root / "login.html").exists())
            self.assertFalse((root / "key_manager.html").exists())
            self.assertFalse((root / "data").exists())
