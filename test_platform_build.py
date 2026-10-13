from pathlib import Path
import tempfile
import unittest

from platform_build import build_assets


class PlatformBuildTest(unittest.TestCase):
    def test_every_public_page_keeps_support_entries_after_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build_assets(root)
            support_url = "https://support.coinexo.top/?project=leakssr"
            pages = sorted(root.glob("*.html"))
            self.assertEqual({page.name for page in pages}, {"index.html", "source.html", "404.html"})
            for page in pages:
                with self.subTest(page=page.name):
                    content = page.read_text()
                    header = content.split('<header class="topbar">', 1)[1].split("</header>", 1)[0]
                    footer = content.split('<footer class="app-footer">', 1)[1].split("</footer>", 1)[0]
                    self.assertIn(support_url, header)
                    self.assertIn(support_url, footer)
                    self.assertIn("支持项目", header)
                    self.assertIn('data-lucide="heart"', header)
                    sidebar = content.split('<nav class="main-nav">', 1)[1].split("</nav>", 1)[0]
                    mobile = content.split('<nav class="mobile-nav"', 1)[1].split("</nav>", 1)[0]
                    for navigation in (sidebar, mobile):
                        self.assertIn(support_url, navigation)
                        self.assertIn("支持项目", navigation)
                        self.assertIn('data-lucide="heart"', navigation)
                        self.assertIn('target="_blank" rel="noopener noreferrer"', navigation)
                        self.assertEqual(navigation.count("<a "), 5)

    def test_nginx_preserves_not_found_status_with_public_error_page(self):
        config = (Path(__file__).parent / "deploy/nginx-static.conf").read_text()
        self.assertIn("error_page 404 /404.html;", config)
        self.assertNotIn("error_page 404 =200", config)

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
