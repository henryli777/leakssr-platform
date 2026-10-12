from pathlib import Path
import tempfile
import unittest

from platform_build import build_assets


class PlatformBuildTest(unittest.TestCase):
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

