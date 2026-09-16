"""Regression tests for the false positives this scanner used to report.

Every case here was produced by an earlier version of the scanner against a real
site. They are the reason the filter chain exists, so they must keep passing.
"""
from __future__ import annotations

import unittest

from tests.helpers import has_title, scan_html, scan_text


class SecretFalsePositives(unittest.TestCase):
    def test_fetch_credentials_option_is_not_a_secret(self):
        findings = scan_text('fetch(url, {credentials:"same-origin", mode:"cors"});')
        self.assertFalse(has_title(findings, "credential"), "fetch options must not be reported")

    def test_placeholder_echoing_the_key_is_ignored(self):
        findings = scan_text('const cfg = {api_key:"apikey", password:"password"};')
        self.assertFalse(has_title(findings, "credential"))
        self.assertFalse(has_title(findings, "password"))

    def test_env_template_is_not_a_secret(self):
        findings = scan_text('const key = "${NEXT_PUBLIC_API_KEY}"; const t = "{{ token }}";')
        self.assertFalse(has_title(findings, "credential"))

    def test_masked_values_are_ignored(self):
        findings = scan_text('token: "****************", secret: "xxxxxxxxxxxxxxxx"')
        self.assertFalse(has_title(findings, "credential"))

    def test_short_low_entropy_values_are_ignored(self):
        findings = scan_text('const secret = "abcabcabcabc"; const token = "aaaaaaaaaaaaaaa";')
        self.assertFalse(has_title(findings, "credential"))

    def test_base64_that_is_not_a_jwt_is_ignored(self):
        # `eyJ`-prefixed base64 that does not decode to a JWT header.
        findings = scan_text('const blob = "eyJub3RhdG9rZW4iZmFrZQ.eyJzdGlsbG5vdGFqd3Q.zzz";')
        self.assertFalse(has_title(findings, "JSON Web Token"))

    def test_webpack_hashes_are_not_secrets(self):
        findings = scan_text('const token = "a3f5c9e1b2d4f6a8c0e2b4d6f8a0c2e4";')
        self.assertFalse(has_title(findings, "credential"))


class SQLFalsePositives(unittest.TestCase):
    def test_marketing_copy_is_not_sql(self):
        html = """
        <html><body>
          <h2>Select a plan from our catalogue</h2>
          <p>Update your profile and set a new password whenever you want.</p>
          <p>Delete from your cart the items you no longer need.</p>
        </body></html>
        """
        findings = scan_html(html)
        self.assertFalse(has_title(findings, "SQL"), "prose must never be reported as SQL")

    def test_spanish_copy_is_not_sql(self):
        html = "<p>Seleccione un producto de nuestra tienda</p><div>Insert into the box</div>"
        findings = scan_html(html)
        self.assertFalse(has_title(findings, "SQL"))

    def test_html_template_string_is_not_sql(self):
        findings = scan_text(
            'const tpl = "<ul><li>Select an option from the list below</li></ul>";'
        )
        self.assertFalse(has_title(findings, "SQL"))

    def test_incomplete_statement_is_not_sql(self):
        # No clause, no parameter, no terminator: not enough to call it a query.
        findings = scan_text('const label = "select icon from set";')
        self.assertFalse(has_title(findings, "SQL"))

    def test_sql_inside_a_comment_is_ignored(self):
        findings = scan_text('// SELECT * FROM users WHERE id = 1;\nconst x = 1;')
        self.assertFalse(has_title(findings, "SQL"))

    def test_css_selector_text_is_not_sql(self):
        findings = scan_text('const css = "select.form-control { color: red }";')
        self.assertFalse(has_title(findings, "SQL"))


class RoleFalsePositives(unittest.TestCase):
    def test_aria_roles_are_ignored(self):
        html = '<div role="button"></div><nav role="navigation"></nav><div role="dialog"></div>'
        findings = scan_html(html)
        self.assertFalse(has_title(findings, "role"), "ARIA roles are not application roles")

    def test_mime_types_are_not_permissions(self):
        findings = scan_text('const types = ["image.read", "application.view"];')
        self.assertFalse(has_title(findings, "Permission identifier"))


class TechnologyFalsePositives(unittest.TestCase):
    def test_vendor_bundle_secrets_are_not_noise(self):
        findings = scan_text(
            'var x = {token: "aaaa"};',
            url="https://example.com/vendor/jquery-3.6.0.min.js",
        )
        self.assertFalse(has_title(findings, "credential"))


if __name__ == "__main__":
    unittest.main()


class RealWorldFalsePositives(unittest.TestCase):
    """Cases captured from live scans of production sites."""

    def test_escaped_json_url_is_not_a_credential(self):
        # wordpress.org ships this inside an inline JSON blob. Escaped slashes
        # used to hide the fact that the value is a URL, not key material.
        findings = scan_text(
            r'{"endpoints":{"authorization":"https:\/\/wordpress.org\/wp-admin\/authorize.php"}}'
        )
        self.assertFalse(has_title(findings, "credential"))

    def test_js_property_access_is_not_an_internal_host(self):
        # `navigator.language` and `node.localName` contain ".lan" / ".local".
        findings = scan_text(
            "const d = e.toLocaleDateString(window.navigator.language);"
            "if (p.localName == v) { return c.localName; }"
        )
        self.assertFalse(has_title(findings, "Internal"))

    def test_xml_namespaces_are_not_insecure_endpoints(self):
        findings = scan_text(
            'const NS = "http://www.w3.org/2000/svg";'
            'const M = "http://www.w3.org/1998/Math/MathML";'
        )
        self.assertFalse(has_title(findings, "Insecure HTTP"))

    def test_real_internal_host_is_still_reported(self):
        findings = scan_text('const api = "https://billing.internal:8443/v1";')
        self.assertTrue(has_title(findings, "Internal"))

    def test_real_insecure_endpoint_is_still_reported(self):
        findings = scan_text('const api = "http://api.example.com/v1/orders";')
        self.assertTrue(has_title(findings, "Insecure HTTP"))

    def test_generator_meta_splits_name_and_version(self):
        from scanner.core.context import ScanContext
        from scanner.core.detector.detector_services import Detector
        from scanner.core.models import Asset

        for content, name, version in (
            ('<meta name="generator" content="WordPress 6.2.1">', "WordPress", "6.2.1"),
            ('<meta name="generator" content="WordPress 7.2-alpha-63632">', "WordPress", "7.2-alpha-63632"),
            ('<meta name="generator" content="Drupal 10 (https://drupal.org)">', "Drupal", "10"),
        ):
            with self.subTest(content=content):
                context = ScanContext.for_url("https://example.com/")
                detector = Detector(context, enabled=["technology"])
                detector.scan(Asset(url="https://example.com/", content=content,
                                    status=200, kind="html"))
                self.assertIn(name, context.results.technologies)
                if version:
                    self.assertEqual(context.results.technologies[name].version, version)

    def test_substring_keyword_is_not_a_role(self):
        # React's modifier map `{Control: "ctrlKey"}` used to match because
        # "Control" contains "rol".
        findings = scan_text('const m = {Alt:"altKey", Control:"ctrlKey", Shift:"shiftKey"};')
        self.assertFalse(has_title(findings, "role"))

    def test_framework_global_is_not_an_open_redirect(self):
        findings = scan_text("window.location.href = window.next.__pendingUrl.toString();")
        self.assertFalse(has_title(findings, "Open redirect"))

    def test_real_open_redirect_is_still_reported(self):
        findings = scan_text('location.href = params.redirectUrl;')
        self.assertTrue(has_title(findings, "Open redirect"))

    def test_uppercase_role_constants_are_still_catalogued(self):
        findings = scan_text('const APP_ROLES = ["admin", "editor", "viewer"];')
        self.assertTrue(has_title(findings, "catalogue"))

    def test_truncated_template_url_is_cleaned(self):
        from scanner.core.context import ScanContext
        from scanner.core.detector.detector_services import Detector
        from scanner.core.models import Asset

        context = ScanContext.for_url("https://example.com/")
        detector = Detector(context, enabled=["endpoints"])
        detector.scan(Asset(
            url="https://example.com/app.js",
            content='fetch(`https://vitals.example.com/v2/vitals?dsn=${a}`);',
            status=200, kind="js",
        ))
        for endpoint in context.results.endpoints:
            self.assertNotIn("${", endpoint.url)

    def test_real_domains_containing_env_words_are_not_staging(self):
        findings = scan_text(
            'const a = "https://dev.to/t/vue";'
            'const b = "https://developer.mozilla.org/en-US/docs";'
            'const c = "https://testing-library.com/docs";'
        )
        self.assertFalse(has_title(findings, "Staging"))

    def test_real_staging_host_is_still_reported(self):
        findings = scan_text('const api = "https://staging.example.com/api/v1";')
        self.assertTrue(has_title(findings, "Staging"))

    def test_hyphenated_staging_host_is_reported(self):
        findings = scan_text('const api = "https://api-dev.example.com/v1";')
        self.assertTrue(has_title(findings, "Staging"))
