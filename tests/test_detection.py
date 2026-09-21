"""True-positive tests: the things the scanner must never miss."""
from __future__ import annotations

import unittest

from scanner.core.models import Severity
from tests.fixtures import (
    AWS_ACCESS_KEY_ID,
    DATABASE_URL,
    GENERIC_SECRET,
    GITHUB_PAT,
    GOOGLE_API_KEY,
    JWT_ADMIN,
    SLACK_BOT_TOKEN,
    STRIPE_PUBLISHABLE_KEY,
    STRIPE_SECRET_KEY,
)
from tests.helpers import has_title, scan_html, scan_text, titles


def _find(findings, fragment):
    for finding in findings:
        if fragment.lower() in finding.title.lower():
            return finding
    return None


class SecretDetection(unittest.TestCase):
    def test_aws_access_key(self):
        findings = scan_text('const k = "{}";'.format(AWS_ACCESS_KEY_ID))
        finding = _find(findings, "AWS Access Key")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_stripe_secret_key_is_critical_but_publishable_is_info(self):
        findings = scan_text(
            'const a = "{}"; const b = "{}";'.format(
                STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY
            )
        )
        secret = _find(findings, "Stripe Secret Key")
        publishable = _find(findings, "Stripe Publishable Key")
        self.assertIsNotNone(secret)
        self.assertEqual(secret.severity, Severity.CRITICAL)
        self.assertIsNotNone(publishable)
        self.assertEqual(publishable.severity, Severity.INFO)

    def test_google_api_key(self):
        findings = scan_text('key: "{}"'.format(GOOGLE_API_KEY))
        self.assertTrue(has_title(findings, "Google API Key"))

    def test_real_jwt_is_decoded_and_roles_extracted(self):
        findings = scan_text('const t = "{}";'.format(JWT_ADMIN))
        finding = _find(findings, "JSON Web Token")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, Severity.CRITICAL, "admin role must escalate severity")
        self.assertIn("claims", finding.evidence)

    def test_database_connection_string(self):
        findings = scan_text('const url = "{}";'.format(DATABASE_URL))
        finding = _find(findings, "Database Connection String")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_private_key_block(self):
        findings = scan_text('const k = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE...";')
        self.assertTrue(has_title(findings, "Private Key"))

    def test_high_entropy_generic_credential(self):
        findings = scan_text('const clientSecret = "{}";'.format(GENERIC_SECRET))
        self.assertTrue(has_title(findings, "credential"))

    def test_github_and_slack_tokens(self):
        findings = scan_text(
            'a="{}"; b="{}";'.format(GITHUB_PAT, SLACK_BOT_TOKEN)
        )
        self.assertTrue(has_title(findings, "GitHub Token"))
        self.assertTrue(has_title(findings, "Slack Token"))


class SQLDetection(unittest.TestCase):
    def test_raw_select_with_clause(self):
        findings = scan_text(
            'const q = "SELECT id, email FROM users WHERE active = 1 ORDER BY id";'
        )
        finding = _find(findings, "Raw SQL")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_template_literal_interpolation_is_injection(self):
        findings = scan_text(
            'const q = `SELECT * FROM orders WHERE user_id = ${userId} LIMIT 10`;'
        )
        finding = _find(findings, "SQL injection")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertIn("sqli", finding.tags)

    def test_string_concatenation_is_injection(self):
        findings = scan_text(
            'var q = "SELECT * FROM accounts WHERE name = \'" + name + "\'";'
        )
        self.assertTrue(has_title(findings, "SQL"))

    def test_insert_update_delete(self):
        for query in (
            'const a = "INSERT INTO logs (msg, level) VALUES (?, ?)";',
            'const b = "UPDATE users SET role = ? WHERE id = ?";',
            'const c = "DELETE FROM sessions WHERE expires_at < NOW()";',
        ):
            with self.subTest(query=query):
                self.assertTrue(has_title(scan_text(query), "SQL"), query)

    def test_sql_in_inline_script_of_html_page(self):
        html = """
        <html><body>
          <p>Select a plan from our catalogue</p>
          <script>
            const q = "SELECT password_hash FROM users WHERE email = '" + email + "'";
          </script>
        </body></html>
        """
        findings = scan_html(html)
        self.assertTrue(has_title(findings, "SQL"), "inline script SQL must be found")

    def test_prisma_in_frontend(self):
        findings = scan_text("const users = await prisma.user.findMany({where:{id}});")
        self.assertTrue(has_title(findings, "Prisma"))


class AccessControlDetection(unittest.TestCase):
    def test_role_array_is_catalogued(self):
        findings = scan_text('const ROLES = ["admin", "editor", "viewer"];')
        finding = _find(findings, "catalogue")
        self.assertIsNotNone(finding)
        self.assertIn("admin", finding.value)

    def test_privileged_role_name(self):
        findings = scan_text('const userRole = "super_admin";')
        self.assertTrue(has_title(findings, "Privileged role"))

    def test_permission_strings(self):
        findings = scan_text('can("invoice.delete") && can("user.manage")')
        self.assertTrue(has_title(findings, "Permission identifier"))

    def test_client_side_authorization_check(self):
        findings = scan_text('if (user.isAdmin) { showAdminPanel(); }')
        self.assertTrue(
            has_title(findings, "Client-side authorization")
            or has_title(findings, "permission check")
        )

    def test_auth_bypass_flag(self):
        findings = scan_text("const config = { skipAuth: true };")
        self.assertTrue(has_title(findings, "bypass"))

    def test_role_constants(self):
        findings = scan_text('const R = "ROLE_SUPER_ADMIN";')
        self.assertTrue(has_title(findings, "role"))


class VulnerabilityDetection(unittest.TestCase):
    def test_dom_xss_with_taint_source_escalates(self):
        tainted = scan_text("el.innerHTML = location.hash.substring(1);")
        clean = scan_text("el.innerHTML = renderTemplate(data);")
        tainted_finding = _find(tainted, "innerHTML")
        clean_finding = _find(clean, "innerHTML")
        self.assertIsNotNone(tainted_finding)
        self.assertIsNotNone(clean_finding)
        self.assertGreater(
            Severity.weight(tainted_finding.severity),
            Severity.weight(clean_finding.severity),
            "a tainted sink must outrank an untainted one",
        )

    def test_internal_host_reference(self):
        findings = scan_text('const api = "http://10.0.5.23:8080/internal";')
        self.assertTrue(has_title(findings, "Internal"))

    def test_client_side_password_comparison(self):
        findings = scan_text('if (password === "Sup3rS3cret!") login();')
        self.assertTrue(has_title(findings, "password comparison"))

    def test_credentials_in_web_storage(self):
        findings = scan_text('localStorage.setItem("access_token", token);')
        self.assertTrue(has_title(findings, "Web Storage"))

    def test_tls_verification_disabled(self):
        findings = scan_text("const agent = new https.Agent({rejectUnauthorized: false});")
        self.assertTrue(has_title(findings, "TLS verification"))


class TechnologyDetection(unittest.TestCase):
    def test_wordpress_plugin_enumeration_with_versions(self):
        html = """
        <link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css?ver=5.7.2">
        <script src="/wp-content/plugins/woocommerce/assets/js/frontend.js?ver=8.1.0"></script>
        <link href="/wp-content/themes/astra/style.css?ver=4.1.0">
        """
        findings = scan_html(html)
        self.assertTrue(has_title(findings, "WordPress plugins enumerated"))
        finding = _find(findings, "WordPress plugins enumerated")
        self.assertIn("contact-form-7", finding.value)
        self.assertIn("5.7.2", finding.value)

    def test_outdated_jquery_is_flagged(self):
        findings = scan_text('jQuery.fn.jquery = "3.4.1";', kind="js")
        self.assertTrue(has_title(findings, "Outdated component"))

    def test_server_version_header_disclosure(self):
        findings = scan_html("<html></html>", headers={"Server": "nginx/1.18.0"})
        self.assertTrue(has_title(findings, "version disclosed"))

    def test_framework_fingerprints(self):
        from scanner.core.context import ScanContext
        from scanner.core.detector.detector_services import Detector
        from scanner.core.models import Asset

        cases = {
            'window.__NUXT__={};': "Nuxt",
            '<div id="__next"></div><script src="/_next/static/chunks/main.js"></script>': "Next.js",
            'Vue.version = "3.2.47";': "Vue.js",
            '<div ng-version="15.1.0"></div>': "Angular",
            '<link href="/wp-content/themes/x/style.css">': "WordPress",
        }
        for content, expected in cases.items():
            with self.subTest(expected=expected):
                context = ScanContext.for_url("https://example.com/")
                detector = Detector(context, enabled=["technology"])
                detector.scan(Asset(url="https://example.com/", content=content,
                                    status=200, kind="html"))
                self.assertIn(expected, context.results.technologies)


class EndpointDetection(unittest.TestCase):
    def test_fetch_call_with_method(self):
        from scanner.core.context import ScanContext
        from scanner.core.detector.detector_services import Detector
        from scanner.core.models import Asset

        content = """
        fetch("/api/v1/users", {method: "POST", body: b});
        axios.delete("/api/v1/users/42");
        const ws = "wss://realtime.example.com/socket";
        """
        context = ScanContext.for_url("https://example.com/")
        detector = Detector(context, enabled=["endpoints"])
        detector.scan(Asset(url="https://example.com/app.js", content=content,
                            status=200, kind="js"))

        pairs = {(e.method, e.url) for e in context.results.endpoints}
        self.assertIn(("POST", "https://example.com/api/v1/users"), pairs)
        self.assertIn(("DELETE", "https://example.com/api/v1/users/42"), pairs)
        self.assertTrue(any(e.kind == "websocket" for e in context.results.endpoints))

    def test_third_party_services_are_identified(self):
        from scanner.core.context import ScanContext
        from scanner.core.detector.detector_services import Detector
        from scanner.core.models import Asset

        content = (
            '<script src="https://www.googletagmanager.com/gtm.js"></script>'
            '<script src="https://js.stripe.com/v3/"></script>'
            '<script src="https://browser.sentry-cdn.com/x.js"></script>'
        )
        context = ScanContext.for_url("https://example.com/")
        detector = Detector(context, enabled=["technology"])
        detector.scan(Asset(url="https://example.com/", content=content, status=200, kind="html"))

        names = set(context.results.services.keys())
        self.assertIn("Google Tag Manager", names)
        self.assertIn("Stripe", names)


class HeaderDetection(unittest.TestCase):
    def test_missing_security_headers(self):
        findings = scan_html("<html></html>", headers={"Content-Type": "text/html"})
        self.assertTrue(has_title(findings, "Content-Security-Policy"))
        self.assertTrue(has_title(findings, "Strict-Transport-Security"))

    def test_dangerous_cors(self):
        findings = scan_html(
            "<html></html>",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        self.assertTrue(has_title(findings, "Dangerous CORS"))

    def test_insecure_session_cookie(self):
        findings = scan_html("<html></html>", headers={"Set-Cookie": "sessionid=abc; Path=/"})
        self.assertTrue(has_title(findings, "missing"))


if __name__ == "__main__":
    unittest.main()
