"""Regressions taken from real scan reports of production sites.

Each test below corresponds to a finding that a previous build reported and
that a human had to dismiss. They are the definition of "working" for the
filter chain.
"""
from __future__ import annotations

import unittest

from scanner.core.context import ScanContext
from scanner.core.detector.detector_services import Detector
from scanner.core.models import Asset
from tests.helpers import has_title, scan_html, scan_text


def _run(content, url="https://example.com/app.js", kind="js", headers=None,
         detectors=None, target="https://example.com/"):
    context = ScanContext.for_url(target)
    detector = Detector(context, enabled=detectors)
    asset = Asset(url=url, content=content, status=200, headers=headers or {}, kind=kind)
    detector.scan(asset)
    detector.finalize(asset)
    return context.results


class NextJsBundleReport(unittest.TestCase):
    """From a Next.js e-commerce scan."""

    ROUTE_TABLE = (
        't.create_user="user/create_user",t.reset_password="user/reset_password",'
        't.validate_email_token="user/validate_email_token",'
        't.change_password="user/change_password",t.check_password="user/check_password";'
    )
    I18N = (
        'const es={min_password:"Debe tener al menos 8 caracteres",'
        'required_password:"La contraseña es obligatoria",'
        'required_match_password:"Las contraseñas deben coincidir"};'
    )

    def test_api_route_constants_are_not_credentials(self):
        findings = scan_text(self.ROUTE_TABLE)
        self.assertFalse(has_title(findings, "credential"))

    def test_api_route_constants_become_endpoints(self):
        results = _run(self.ROUTE_TABLE, detectors=["endpoints"])
        routes = {e.url for e in results.endpoints if e.scope == "relative"}
        self.assertIn("user/reset_password", routes)
        self.assertIn("user/change_password", routes)

    def test_accented_i18n_messages_are_not_credentials(self):
        findings = scan_text(self.I18N)
        self.assertFalse(
            has_title(findings, "credential"),
            "Spanish validation messages must not read as key material",
        )

    def test_mime_types_do_not_enter_the_route_table(self):
        results = _run(
            self.ROUTE_TABLE + 'a.type="text/html";b.type="image/png";c.type="application/json";',
            detectors=["endpoints"],
        )
        routes = {e.url for e in results.endpoints if e.scope == "relative"}
        self.assertNotIn("text/html", routes)
        self.assertNotIn("image/png", routes)

    def test_third_party_server_header_is_not_the_sites_stack(self):
        results = _run(
            "<html></html>",
            url="https://www.googletagmanager.com/gtm.js",
            kind="html",
            headers={"Server": "Google Tag Manager"},
            detectors=["technology"],
            target="https://example.com/",
        )
        self.assertNotIn("Google Tag Manager", results.technologies)

    def test_own_origin_server_header_is_still_recorded(self):
        results = _run(
            "<html></html>",
            url="https://example.com/",
            kind="html",
            headers={"Server": "nginx/1.18.0"},
            detectors=["technology"],
        )
        self.assertIn("nginx", results.technologies)
        self.assertEqual(results.technologies["nginx"].version, "1.18.0")


class WordPressBundleReport(unittest.TestCase):
    """From a WordPress news site scan."""

    def test_minified_parser_code_is_not_a_credential(self):
        # A raw regex paired the opening quote of one string with the closing
        # quote of another and captured 400 characters of a jison parser.
        minified = (
            'a.token="+d);switch($[0]){case 1:n.push(d),r.push(this.lexer.yytext),'
            'i.push(this.lexer.yylloc),n.push($[1]),d=null"'
        )
        findings = scan_text(minified)
        self.assertFalse(has_title(findings, "credential"))

    def test_theme_enumeration_is_reported_once(self):
        context = ScanContext.for_url("https://example.com/")
        detector = Detector(context, enabled=["technology"])
        main = Asset(
            url="https://example.com/",
            content='<link href="/wp-content/themes/advantage-theme/style.css?ver=2.1">',
            status=200, kind="html",
        )
        detector.scan(main)
        detector.scan(Asset(
            url="https://example.com/a.js",
            content='"/wp-content/themes/advantage-theme-child/app.js"',
            status=200, kind="js",
        ))
        detector.finalize(main)

        summaries = [f for f in context.results.findings if "themes enumerated" in f.title]
        self.assertEqual(len(summaries), 1, "one aggregate finding, not one per file")
        self.assertIn("advantage-theme", summaries[0].value)
        self.assertIn("advantage-theme-child", summaries[0].value)

    def test_wp_json_routes_resolve_under_the_namespace(self):
        results = _run(
            '{"routes":{"/wp/v2/users":{},"/tangible/v1/token":{}}}',
            url="https://example.com/wp-json/",
            kind="json",
            detectors=["endpoints"],
        )
        urls = {e.url for e in results.endpoints}
        self.assertIn("https://example.com/wp-json/wp/v2/users", urls)
        self.assertNotIn("https://example.com/wp/v2/users", urls)

    def test_case_variant_technologies_are_merged(self):
        results = _run(
            "<html></html>",
            url="https://example.com/",
            kind="html",
            headers={"Server": "cloudflare", "CF-Ray": "abc-XYZ"},
            detectors=["technology"],
        )
        names = {n.lower() for n in results.technologies}
        self.assertEqual(
            len([n for n in names if n == "cloudflare"]), 1,
            "`cloudflare` and `Cloudflare` are one product",
        )


if __name__ == "__main__":
    unittest.main()


class DesignTokenNoise(unittest.TestCase):
    """Chakra-style design tokens are shaped exactly like API routes."""

    def test_style_tokens_do_not_enter_the_route_table(self):
        results = _run(
            'a="bg.emphasized/60",b="blue.500/40",c="fg.muted/80",'
            'd="cart/update_cart",e="banner/get_banners",f="campaign/active";',
            detectors=["endpoints"],
        )
        routes = {e.url for e in results.endpoints if e.scope == "relative"}
        self.assertNotIn("bg.emphasized/60", routes)
        self.assertNotIn("blue.500/40", routes)
        self.assertIn("cart/update_cart", routes)
        self.assertIn("banner/get_banners", routes)
