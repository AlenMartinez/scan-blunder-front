"""Technology, framework, library and third-party service fingerprints."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class TechRule:
    name: str
    pattern: "re.Pattern"
    category: str = "framework"
    #: regex group holding the version, if the pattern can capture one
    version_group: Optional[int] = None
    evidence: str = ""


# --------------------------------------------------------------------------- #
# Markup / bundle fingerprints (run against HTML and JS content)
# --------------------------------------------------------------------------- #

CONTENT_RULES: List[TechRule] = [
    # --- meta generator, the most reliable source of a version ---------------
    TechRule("Generator", re.compile(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.I), "cms", 1, "meta generator"),

    # --- React family --------------------------------------------------------
    TechRule("React", re.compile(r"React\.version\s*=\s*[\"']([\d][\w.\-]*)[\"']"), "framework", 1, "React.version"),
    TechRule("React", re.compile(r"\"react\"\s*:\s*\"[\^~]?([\d][\w.\-]*)\""), "framework", 1, "package manifest"),
    TechRule("React", re.compile(r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom"), "framework", None, "react runtime marker"),
    TechRule("Next.js", re.compile(r"\"next\"\s*:\s*\"[\^~]?([\d][\w.\-]*)\""), "framework", 1, "package manifest"),
    TechRule("Next.js", re.compile(r"/_next/static/|__NEXT_DATA__|next/dist/client"), "framework", None, "/_next/ assets"),
    TechRule("Gatsby", re.compile(r"___gatsby|/page-data/|gatsby-browser"), "framework", None, "gatsby runtime"),
    TechRule("Remix", re.compile(r"__remixContext|__remixRouteModules"), "framework", None, "remix runtime"),
    TechRule("Create React App", re.compile(r"/static/js/main\.[0-9a-f]{8}\.(?:chunk\.)?js"), "framework", None, "CRA bundle layout"),
    TechRule("Preact", re.compile(r"\bpreact\b.{0,40}?version[\"']?\s*[:=]\s*[\"']([\d][\w.\-]*)"), "framework", 1, "preact"),

    # --- Vue family ----------------------------------------------------------
    TechRule("Vue.js", re.compile(r"Vue\.version\s*=\s*[\"']([\d][\w.\-]*)[\"']"), "framework", 1, "Vue.version"),
    TechRule("Vue.js", re.compile(r"\"vue\"\s*:\s*\"[\^~]?([\d][\w.\-]*)\""), "framework", 1, "package manifest"),
    TechRule("Vue.js", re.compile(r"__VUE_DEVTOOLS_GLOBAL_HOOK__|data-v-[0-9a-f]{8}|\bv-(?:if|for|bind|model)="), "framework", None, "vue runtime marker"),
    TechRule("Nuxt", re.compile(r"window\.__NUXT__|/_nuxt/"), "framework", None, "nuxt runtime"),

    # --- Angular -------------------------------------------------------------
    TechRule("Angular", re.compile(r"ng-version=\"([\d][\w.\-]*)\""), "framework", 1, "ng-version"),
    TechRule("Angular", re.compile(r"\bng-app\b|angular\.module\(|__zone_symbol__|platformBrowserDynamic"), "framework", None, "angular runtime"),
    TechRule("AngularJS", re.compile(r"angular\.version\s*=\s*\{[^}]*full\s*:\s*[\"']([\d][\w.\-]*)[\"']"), "framework", 1, "angular.version"),

    # --- other JS frameworks -------------------------------------------------
    TechRule("Svelte", re.compile(r"\bsvelte-[0-9a-z]{6}\b|__svelte|SvelteComponent"), "framework", None, "svelte marker"),
    TechRule("SvelteKit", re.compile(r"__sveltekit_|/_app/immutable/"), "framework", None, "sveltekit assets"),
    TechRule("Solid.js", re.compile(r"_\$createComponent|solid-js"), "framework", None, "solid runtime"),
    TechRule("Alpine.js", re.compile(r"\bx-data=|Alpine\.version\s*=\s*[\"']([\d][\w.\-]*)"), "framework", 1, "alpine"),
    TechRule("htmx", re.compile(r"\bhx-(?:get|post|target|swap)=|htmx\.org/(\d[\w.]*)"), "framework", 1, "htmx"),
    TechRule("Ember.js", re.compile(r"Ember\.VERSION\s*=\s*[\"']([\d][\w.\-]*)"), "framework", 1, "Ember.VERSION"),
    TechRule("Backbone.js", re.compile(r"Backbone\.VERSION\s*=\s*[\"']([\d][\w.\-]*)"), "framework", 1, "Backbone.VERSION"),
    TechRule("Astro", re.compile(r"astro-island|/_astro/"), "framework", None, "astro assets"),

    # --- libraries -----------------------------------------------------------
    TechRule("jQuery", re.compile(r"jQuery\.fn\.jquery\s*=\s*[\"']([\d][\w.\-]*)[\"']"), "library", 1, "jQuery.fn.jquery"),
    TechRule("jQuery", re.compile(r"/jquery[.\-]?([\d]+\.[\d.]+)(?:\.min)?\.js"), "library", 1, "filename"),
    TechRule("jQuery UI", re.compile(r"jquery-ui[.\-]?([\d]+\.[\d.]+)?"), "library", 1, "filename"),
    TechRule("Bootstrap", re.compile(r"bootstrap(?:\.min)?\.(?:css|js)[^\"']*?[?&]?v?e?r?=?([\d]+\.[\d.]+)?"), "library", 1, "filename"),
    TechRule("Bootstrap", re.compile(r"/\*!\s*Bootstrap\s+v([\d][\w.\-]*)"), "library", 1, "banner"),
    TechRule("Tailwind CSS", re.compile(r"tailwindcss|\bclass=\"[^\"]*\b(?:flex|grid)\s+(?:items-center|justify-between)\b"), "library", None, "tailwind classes"),
    TechRule("Lodash", re.compile(r"lodash[.\-]?([\d]+\.[\d.]+)?(?:\.min)?\.js|VERSION\s*=\s*[\"']([\d.]+)[\"'][^;]{0,40}lodash"), "library", 1, "lodash"),
    TechRule("Moment.js", re.compile(r"moment(?:\.min)?\.js|moment\.version\s*=\s*[\"']([\d.]+)"), "library", 1, "moment"),
    TechRule("Axios", re.compile(r"axios[/@]?([\d]+\.[\d.]+)?(?:/dist)?/axios|\baxios\.(?:get|post|create)\b"), "library", 1, "axios"),
    TechRule("D3.js", re.compile(r"d3(?:\.min)?\.js|d3\.version\s*=\s*[\"']([\d.]+)"), "library", 1, "d3"),
    TechRule("Three.js", re.compile(r"THREE\.REVISION\s*=\s*[\"']?([\d]+)"), "library", 1, "THREE.REVISION"),
    TechRule("GSAP", re.compile(r"gsap[/@]?([\d]+\.[\d.]+)?|GreenSock"), "library", 1, "gsap"),
    TechRule("Swiper", re.compile(r"swiper(?:-bundle)?(?:\.min)?\.(?:js|css)"), "library", None, "swiper"),
    TechRule("Webpack", re.compile(r"webpackJsonp|__webpack_require__|webpackChunk"), "bundler", None, "webpack runtime"),
    TechRule("Vite", re.compile(r"/assets/index-[\w]{8}\.js|__vite__|vite/modulepreload"), "bundler", None, "vite assets"),
    TechRule("Parcel", re.compile(r"parcelRequire"), "bundler", None, "parcel runtime"),

    # --- CMS / platforms -----------------------------------------------------
    TechRule("WordPress", re.compile(r"/wp-content/|/wp-includes/|wp-json|wpemoji"), "cms", None, "wp paths"),
    TechRule("WooCommerce", re.compile(r"/plugins/woocommerce/|woocommerce-page|wc-ajax"), "cms", None, "woocommerce"),
    TechRule("Drupal", re.compile(r"/sites/(?:default|all)/(?:files|modules|themes)/|Drupal\.settings|drupal\.js"), "cms", None, "drupal paths"),
    TechRule("Joomla", re.compile(r"/media/jui/|/components/com_|joomla"), "cms", None, "joomla paths"),
    TechRule("Magento", re.compile(r"/static/version\d+/frontend/|Magento_|mage/cookies"), "cms", None, "magento paths"),
    TechRule("Shopify", re.compile(r"cdn\.shopify\.com|Shopify\.theme|/s/files/\d+/"), "cms", None, "shopify assets"),
    TechRule("Wix", re.compile(r"static\.parastorage\.com|wix-?code"), "cms", None, "wix assets"),
    TechRule("Squarespace", re.compile(r"static1\.squarespace\.com|Static\.SQUARESPACE_CONTEXT"), "cms", None, "squarespace"),
    TechRule("Webflow", re.compile(r"webflow\.js|data-wf-page"), "cms", None, "webflow"),
    TechRule("Laravel", re.compile(r"laravel_session|csrf-token\"\s+content|/vendor/laravel/"), "backend", None, "laravel marker"),
    TechRule("Django", re.compile(r"csrfmiddlewaretoken|__admin_media_prefix__|/static/admin/"), "backend", None, "django marker"),
    TechRule("Ruby on Rails", re.compile(r"csrf-param|data-turbolinks|/assets/application-[0-9a-f]{32}"), "backend", None, "rails marker"),
    TechRule("ASP.NET", re.compile(r"__VIEWSTATE|__EVENTVALIDATION|\.aspx\b"), "backend", None, "asp.net marker"),
    TechRule("PHP", re.compile(r"PHPSESSID|\.php(?:\?|\"|')"), "backend", None, "php marker"),
]

#: `?ver=x.y.z` style cache busters, the classic way to version WordPress assets.
ASSET_VERSION_RE = re.compile(r"[?&](?:ver|version|v)=([0-9]+(?:\.[0-9]+){1,3})")

#: Library banners left in minified bundles: `/*! jQuery v3.6.0 | ...`
BANNER_VERSION_RE = re.compile(
    r"/\*!?\s*(?:\*\s*)?([A-Za-z][\w.\-]{1,30})(?:\.js)?\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
)

#: WordPress plugin / theme enumeration.
WP_PLUGIN_RE = re.compile(r"/wp-content/plugins/([\w\-.]+)/[^\"'\s)]*")
WP_THEME_RE = re.compile(r"/wp-content/themes/([\w\-.]+)/[^\"'\s)]*")

# --------------------------------------------------------------------------- #
# Response header / cookie fingerprints
# --------------------------------------------------------------------------- #

HEADER_RULES: List[Tuple[str, str, str]] = [
    # (header name, technology, category)
    ("server", "", "server"),
    ("x-powered-by", "", "backend"),
    ("x-aspnet-version", "ASP.NET", "backend"),
    ("x-aspnetmvc-version", "ASP.NET MVC", "backend"),
    ("x-generator", "", "cms"),
    ("x-drupal-cache", "Drupal", "cms"),
    ("x-drupal-dynamic-cache", "Drupal", "cms"),
    ("x-shopify-stage", "Shopify", "cms"),
    ("x-shopid", "Shopify", "cms"),
    ("x-vercel-id", "Vercel", "hosting"),
    ("x-vercel-cache", "Vercel", "hosting"),
    ("x-nextjs-cache", "Next.js", "framework"),
    ("x-nf-request-id", "Netlify", "hosting"),
    ("cf-ray", "Cloudflare", "cdn"),
    ("x-amz-cf-id", "AWS CloudFront", "cdn"),
    ("x-amz-request-id", "AWS S3", "hosting"),
    ("x-served-by", "Fastly", "cdn"),
    ("x-github-request-id", "GitHub Pages", "hosting"),
    ("x-litespeed-cache", "LiteSpeed", "server"),
    ("x-varnish", "Varnish", "cdn"),
    ("x-envoy-upstream-service-time", "Envoy", "proxy"),
    ("x-kong-upstream-latency", "Kong Gateway", "proxy"),
]

COOKIE_RULES: List[Tuple["re.Pattern", str, str]] = [
    (re.compile(r"(?i)^PHPSESSID"), "PHP", "backend"),
    (re.compile(r"(?i)^JSESSIONID"), "Java / Servlet", "backend"),
    (re.compile(r"(?i)^ASP\.NET_SessionId"), "ASP.NET", "backend"),
    (re.compile(r"(?i)^laravel_session"), "Laravel", "backend"),
    (re.compile(r"(?i)^XSRF-TOKEN"), "Laravel/Angular CSRF", "backend"),
    (re.compile(r"(?i)^(?:csrftoken|sessionid)$"), "Django", "backend"),
    (re.compile(r"(?i)^connect\.sid"), "Express.js", "backend"),
    (re.compile(r"(?i)^_session_id"), "Ruby on Rails", "backend"),
    (re.compile(r"(?i)^wordpress_|^wp-settings"), "WordPress", "cms"),
    (re.compile(r"(?i)^_shopify_"), "Shopify", "cms"),
    (re.compile(r"(?i)^AWSALB|^AWSELB"), "AWS Load Balancer", "hosting"),
    (re.compile(r"(?i)^__cf"), "Cloudflare", "cdn"),
    (re.compile(r"(?i)^SERVERID|^BIGipServer"), "F5 BIG-IP", "proxy"),
]

# --------------------------------------------------------------------------- #
# Third-party services, identified by the hosts the page talks to
# --------------------------------------------------------------------------- #

SERVICE_HOSTS: Dict[str, Tuple[str, str]] = {
    # host fragment -> (service name, category)
    "google-analytics.com": ("Google Analytics", "analytics"),
    "googletagmanager.com": ("Google Tag Manager", "analytics"),
    "analytics.google.com": ("Google Analytics", "analytics"),
    "doubleclick.net": ("Google DoubleClick", "advertising"),
    "googlesyndication.com": ("Google AdSense", "advertising"),
    "googleadservices.com": ("Google Ads", "advertising"),
    "googleapis.com": ("Google APIs", "cloud"),
    "gstatic.com": ("Google Static", "cdn"),
    "fonts.googleapis.com": ("Google Fonts", "cdn"),
    "recaptcha.net": ("Google reCAPTCHA", "security"),
    "facebook.net": ("Meta Pixel", "analytics"),
    "facebook.com": ("Facebook", "social"),
    "connect.facebook.net": ("Meta Pixel", "analytics"),
    "hotjar.com": ("Hotjar", "analytics"),
    "clarity.ms": ("Microsoft Clarity", "analytics"),
    "mixpanel.com": ("Mixpanel", "analytics"),
    "segment.com": ("Segment", "analytics"),
    "segment.io": ("Segment", "analytics"),
    "amplitude.com": ("Amplitude", "analytics"),
    "matomo": ("Matomo", "analytics"),
    "plausible.io": ("Plausible", "analytics"),
    "posthog.com": ("PostHog", "analytics"),
    "sentry.io": ("Sentry", "monitoring"),
    "bugsnag.com": ("Bugsnag", "monitoring"),
    "newrelic.com": ("New Relic", "monitoring"),
    "datadoghq.com": ("Datadog", "monitoring"),
    "logrocket.com": ("LogRocket", "monitoring"),
    "intercom.io": ("Intercom", "support"),
    "intercomcdn.com": ("Intercom", "support"),
    "zendesk.com": ("Zendesk", "support"),
    "crisp.chat": ("Crisp", "support"),
    "tawk.to": ("Tawk.to", "support"),
    "drift.com": ("Drift", "support"),
    "hubspot.com": ("HubSpot", "marketing"),
    "hs-scripts.com": ("HubSpot", "marketing"),
    "mailchimp.com": ("Mailchimp", "marketing"),
    "klaviyo.com": ("Klaviyo", "marketing"),
    "stripe.com": ("Stripe", "payments"),
    "paypal.com": ("PayPal", "payments"),
    "mercadopago": ("Mercado Pago", "payments"),
    "braintreegateway.com": ("Braintree", "payments"),
    "adyen.com": ("Adyen", "payments"),
    "squareup.com": ("Square", "payments"),
    "firebaseio.com": ("Firebase RTDB", "backend"),
    "firebaseapp.com": ("Firebase Hosting", "backend"),
    "firebasedatabase.app": ("Firebase RTDB", "backend"),
    "supabase.co": ("Supabase", "backend"),
    "supabase.in": ("Supabase", "backend"),
    "amazonaws.com": ("Amazon AWS", "cloud"),
    "cloudfront.net": ("AWS CloudFront", "cdn"),
    "azurewebsites.net": ("Azure App Service", "cloud"),
    "azureedge.net": ("Azure CDN", "cdn"),
    "cloudflare.com": ("Cloudflare", "cdn"),
    "cloudflareinsights.com": ("Cloudflare Analytics", "analytics"),
    "jsdelivr.net": ("jsDelivr CDN", "cdn"),
    "cdnjs.cloudflare.com": ("cdnjs", "cdn"),
    "unpkg.com": ("unpkg CDN", "cdn"),
    "bootstrapcdn.com": ("BootstrapCDN", "cdn"),
    "cloudinary.com": ("Cloudinary", "media"),
    "imgix.net": ("Imgix", "media"),
    "vimeo.com": ("Vimeo", "media"),
    "youtube.com": ("YouTube", "media"),
    "ytimg.com": ("YouTube", "media"),
    "algolia.net": ("Algolia", "search"),
    "algolianet.com": ("Algolia", "search"),
    "typeform.com": ("Typeform", "forms"),
    "auth0.com": ("Auth0", "identity"),
    "okta.com": ("Okta", "identity"),
    "clerk.accounts.dev": ("Clerk", "identity"),
    "onelogin.com": ("OneLogin", "identity"),
    "cognito-idp": ("AWS Cognito", "identity"),
    "twilio.com": ("Twilio", "communications"),
    "pusher.com": ("Pusher", "realtime"),
    "pusherapp.com": ("Pusher", "realtime"),
    "ably.io": ("Ably", "realtime"),
    "contentful.com": ("Contentful", "cms"),
    "sanity.io": ("Sanity", "cms"),
    "strapi": ("Strapi", "cms"),
    "shopify.com": ("Shopify", "ecommerce"),
    "vercel.app": ("Vercel", "hosting"),
    "netlify.app": ("Netlify", "hosting"),
    "herokuapp.com": ("Heroku", "hosting"),
    "railway.app": ("Railway", "hosting"),
    "render.com": ("Render", "hosting"),
    "fly.dev": ("Fly.io", "hosting"),
}

#: Files worth requesting directly: they routinely leak stack and configuration.
SENSITIVE_PATHS: List[Tuple[str, str, str]] = [
    # (path, label, severity)
    ("/.env", "Environment file (.env)", "CRITICAL"),
    ("/.env.local", "Environment file (.env.local)", "CRITICAL"),
    ("/.env.production", "Environment file (.env.production)", "CRITICAL"),
    ("/.git/config", "Exposed .git repository", "CRITICAL"),
    ("/.git/HEAD", "Exposed .git repository", "CRITICAL"),
    ("/.svn/entries", "Exposed .svn repository", "HIGH"),
    ("/.DS_Store", "macOS .DS_Store directory listing", "LOW"),
    ("/package.json", "package.json (dependency inventory)", "LOW"),
    ("/composer.json", "composer.json (dependency inventory)", "LOW"),
    ("/composer.lock", "composer.lock (exact versions)", "LOW"),
    ("/yarn.lock", "yarn.lock (exact versions)", "LOW"),
    ("/webpack.config.js", "Build configuration exposed", "MEDIUM"),
    ("/config.json", "Application configuration exposed", "HIGH"),
    ("/appsettings.json", "ASP.NET configuration exposed", "CRITICAL"),
    ("/wp-config.php.bak", "WordPress config backup", "CRITICAL"),
    ("/.htaccess", "Apache configuration exposed", "MEDIUM"),
    ("/server-status", "Apache server-status exposed", "MEDIUM"),
    ("/phpinfo.php", "phpinfo() exposed", "HIGH"),
    ("/robots.txt", "robots.txt", "INFO"),
    ("/sitemap.xml", "sitemap.xml", "INFO"),
    ("/security.txt", "security.txt", "INFO"),
    ("/.well-known/security.txt", "security.txt", "INFO"),
    ("/swagger.json", "Swagger/OpenAPI specification", "MEDIUM"),
    ("/openapi.json", "OpenAPI specification", "MEDIUM"),
    ("/api-docs", "API documentation exposed", "MEDIUM"),
    ("/graphql", "GraphQL endpoint", "INFO"),
    ("/wp-json/wp/v2/users", "WordPress user enumeration", "MEDIUM"),
    ("/.well-known/apple-app-site-association", "App association file", "INFO"),
    ("/debug", "Debug endpoint", "MEDIUM"),
    ("/actuator/health", "Spring Boot Actuator exposed", "MEDIUM"),
    ("/actuator/env", "Spring Boot Actuator env exposed", "CRITICAL"),
]

#: Security headers we expect on a modern site.
SECURITY_HEADERS: List[Tuple[str, str, str, str]] = [
    # (header, severity, detail, remediation)
    (
        "content-security-policy",
        "MEDIUM",
        "No Content-Security-Policy. The browser has no restriction on where scripts may come from.",
        "Add a CSP starting from `default-src 'self'` and tighten script-src.",
    ),
    (
        "strict-transport-security",
        "MEDIUM",
        "No HSTS header, so a first request can be downgraded to HTTP.",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    ),
    (
        "x-frame-options",
        "LOW",
        "No X-Frame-Options / frame-ancestors, so the page can be framed (clickjacking).",
        "Send `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    ),
    (
        "x-content-type-options",
        "LOW",
        "No X-Content-Type-Options, so browsers may MIME-sniff responses.",
        "Send `X-Content-Type-Options: nosniff`.",
    ),
    (
        "referrer-policy",
        "LOW",
        "No Referrer-Policy; full URLs may leak to third parties.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
    (
        "permissions-policy",
        "INFO",
        "No Permissions-Policy to restrict powerful browser features.",
        "Send a Permissions-Policy disabling unused features (camera, geolocation...).",
    ),
]
