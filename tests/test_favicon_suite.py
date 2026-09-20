"""
TRACEGATE — FAVICON VERIFICATION SUITE
======================================
Verifies:
1. GET /favicon.ico returns 200 OK and image/x-icon.
2. GET /static/img/favicon-32x32.png returns 200 OK and image/png.
3. GET /static/img/favicon-16x16.png returns 200 OK and image/png.
4. GET /static/img/apple-touch-icon.png returns 200 OK and image/png.
5. index.html head contains correct favicon link elements.
6. Existing page titles are preserved.
"""

import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app import app

BASE_DIR = Path(__file__).resolve().parent.parent
HTML_PATH = BASE_DIR / "frontend" / "index.html"

with open(HTML_PATH, "r", encoding="utf-8") as f:
    HTML_CONTENT = f.read()


class TestFaviconSuite(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_favicon_ico_endpoint(self):
        """Root /favicon.ico must return 200 OK with valid icon media type"""
        res = self.client.get("/favicon.ico")
        self.assertEqual(res.status_code, 200)
        self.assertIn("image/", res.headers.get("content-type", ""))
        self.assertGreater(len(res.content), 0)

    def test_static_png_favicons(self):
        """Standard 16x16 and 32x32 favicons must be available statically"""
        res32 = self.client.get("/static/img/favicon-32x32.png")
        self.assertEqual(res32.status_code, 200)
        self.assertEqual(res32.headers.get("content-type"), "image/png")

        res16 = self.client.get("/static/img/favicon-16x16.png")
        self.assertEqual(res16.status_code, 200)
        self.assertEqual(res16.headers.get("content-type"), "image/png")

        res_apple = self.client.get("/static/img/apple-touch-icon.png")
        self.assertEqual(res_apple.status_code, 200)
        self.assertEqual(res_apple.headers.get("content-type"), "image/png")

    def test_index_html_head_favicon_links(self):
        """frontend/index.html head must contain favicon link elements"""
        self.assertIn('<link rel="icon" type="image/x-icon" href="/favicon.ico">', HTML_CONTENT)
        self.assertIn('<link rel="icon" type="image/png" sizes="32x32" href="/static/img/favicon-32x32.png">', HTML_CONTENT)
        self.assertIn('<link rel="icon" type="image/png" sizes="16x16" href="/static/img/favicon-16x16.png">', HTML_CONTENT)
        self.assertIn('<link rel="apple-touch-icon" sizes="180x180" href="/static/img/apple-touch-icon.png">', HTML_CONTENT)
        self.assertIn('<link rel="shortcut icon" href="/favicon.ico">', HTML_CONTENT)

    def test_page_title_preserved(self):
        """Document title must remain unchanged"""
        self.assertIn("<title>Tracegate — Premium Cybersecurity Learning & VAPT Platform</title>", HTML_CONTENT)


if __name__ == "__main__":
    unittest.main()
