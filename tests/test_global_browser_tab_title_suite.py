"""
Tracegate Global Browser Tab Title Test Suite
Verifies:
1. Single source of truth: index.html defines <title>Tracegate — Premium Platform</title>.
2. Zero dynamic title overrides: app.js contains 0 occurrences of `document.title =`.
3. No stale route-specific titles (e.g. 'Sign In — Tracegate', 'Create Account — Tracegate', etc.).
4. Visible in-app UI headings remain 100% intact.
5. Favicon tags and assets remain untouched.
"""

import unittest
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INDEX_HTML_PATH = BASE_DIR / "frontend" / "index.html"
APP_JS_PATH = BASE_DIR / "frontend" / "js" / "app.js"

class TestGlobalBrowserTabTitleSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(INDEX_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html_content = f.read()
        with open(APP_JS_PATH, "r", encoding="utf-8") as f:
            cls.js_content = f.read()

    def test_single_global_document_title_in_index_html(self):
        """index.html must have exactly <title>Tracegate — Premium Platform</title>"""
        m = re.search(r"<title>(.*?)</title>", self.html_content, re.IGNORECASE)
        self.assertIsNotNone(m, "No <title> tag found in frontend/index.html")
        self.assertEqual(m.group(1).strip(), "Tracegate — Premium Platform")

    def test_zero_document_title_assignments_in_app_js(self):
        """app.js must not contain any document.title assignments that could overwrite the global title"""
        matches = re.findall(r"document\.title\s*=", self.js_content)
        self.assertEqual(
            len(matches),
            0,
            f"Found dynamic document.title assignments in app.js: {matches}"
        )

    def test_no_page_specific_title_strings_in_app_js(self):
        """Verify former page-specific title override strings are completely absent from app.js"""
        disallowed_titles = [
            "Sign In — Tracegate",
            "Create Account — Tracegate",
            "Reset Password — Tracegate",
            "Tracegate Capabilities — AI-Assisted Cybersecurity Testing",
            "How Tracegate Works — End-to-End VAPT Lifecycle",
            "Who It's For — Tracegate Cybersecurity Platform",
            "Security Pillars — Tracegate VAPT Platform",
        ]
        for title in disallowed_titles:
            self.assertNotIn(
                title,
                self.js_content,
                f"Page-specific title string '{title}' was found in frontend/js/app.js"
            )

    def test_visible_ui_headings_preserved(self):
        """Visible UI headings must remain intact and must not be altered by browser tab title fix"""
        self.assertIn("Sign in to Tracegate", self.html_content)
        self.assertIn("Project Workspace", self.html_content)
        self.assertIn("Professional VAPT Audit Report Generator", self.html_content)
        self.assertIn("Checklist Generation", self.html_content)
        self.assertIn("Confirmed Findings", self.html_content)

    def test_favicon_links_preserved(self):
        """Favicon links must remain completely intact in index.html head"""
        self.assertIn('<link rel="icon" type="image/x-icon" href="/favicon.ico">', self.html_content)
        self.assertIn('<link rel="icon" type="image/png" sizes="32x32" href="/static/img/favicon-32x32.png">', self.html_content)
        self.assertIn('<link rel="icon" type="image/png" sizes="16x16" href="/static/img/favicon-16x16.png">', self.html_content)
        self.assertIn('<link rel="apple-touch-icon" sizes="180x180" href="/static/img/apple-touch-icon.png">', self.html_content)
        self.assertIn('<link rel="shortcut icon" href="/favicon.ico">', self.html_content)

if __name__ == "__main__":
    unittest.main()
