"""
Tests for ``allianceauth_oidc.templatetags.oidc_tags``.

The render-time scheme guard exists because the model's URLValidator
runs only on ``full_clean()`` — every other write path (bulk_create,
loaddata, raw save) bypasses it. Closing the loop at render time means
no matter how a hostile URL got into the database, the browser never
sees a ``javascript:`` or ``data:`` ``src``.
"""

from django.template import Context, Template
from django.test import SimpleTestCase

from allianceauth_oidc.templatetags.oidc_tags import safe_image_url


class TestSafeImageUrlFilter(SimpleTestCase):
    def test_passes_http_url_through(self) -> None:
        self.assertEqual(
            "http://example.com/x.png",
            safe_image_url("http://example.com/x.png"),
        )

    def test_passes_https_url_through(self) -> None:
        self.assertEqual(
            "https://example.com/x.png",
            safe_image_url("https://example.com/x.png"),
        )

    def test_strips_javascript_scheme(self) -> None:
        """
        ``javascript:alert(1)`` is the canonical XSS payload for an
        ``<img src>``; the filter must replace it with an empty string
        so the resulting tag has ``src=""`` instead of executable code.
        """
        self.assertEqual("", safe_image_url("javascript:alert(1)"))

    def test_strips_data_url(self) -> None:
        """
        ``data:image/svg+xml;base64,...`` can ship an SVG with embedded
        ``<script>`` in some browser/version combos. Block at render.
        """
        self.assertEqual(
            "",
            safe_image_url("data:image/svg+xml;base64,PHN2Zy8+"),
        )

    def test_strips_ftp_scheme(self) -> None:
        self.assertEqual("", safe_image_url("ftp://example.com/x.png"))

    def test_handles_empty_and_none(self) -> None:
        self.assertEqual("", safe_image_url(""))
        self.assertEqual("", safe_image_url(None))

    def test_handles_non_string(self) -> None:
        """
        A model field may, in theory, hand the template something
        that ``str()`` would coerce — the filter must not trust
        ``__str__`` to be safe and instead return empty.
        """
        self.assertEqual("", safe_image_url(12345))
        self.assertEqual("", safe_image_url(object()))

    def test_filter_is_registered_for_template_use(self) -> None:
        """
        End-to-end: ``{% load oidc_tags %}`` + ``|safe_image_url``
        must work in a real template context.
        """
        tpl = Template(
            '{% load oidc_tags %}<img src="{{ url|safe_image_url }}">'
        )
        rendered_safe = tpl.render(Context({"url": "https://x.test/p.png"}))
        self.assertIn('src="https://x.test/p.png"', rendered_safe)

        rendered_blocked = tpl.render(Context({"url": "javascript:alert(1)"}))
        self.assertIn('src=""', rendered_blocked)
        self.assertNotIn("javascript:", rendered_blocked)
