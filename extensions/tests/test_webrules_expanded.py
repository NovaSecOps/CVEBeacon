"""Synthetic, passive evidence checks for the expanded web rule set."""

from datetime import datetime, timezone

import pytest

from cvebeacon.identity import normalize_asset
from cvebeacon.models import Asset
from cvebeacon_extensions.web import (
    Allowlist,
    Endpoint,
    WebAsset,
    _FetchSuccess,
    _Response,
    _observe,
)
from cvebeacon_extensions import webrules
from cvebeacon_extensions.webrules import Resource, detect, page_from

MAX_CDN_DETECTIONS = getattr(webrules, "MAX_CDN_DETECTIONS", 128)


def _page(kind, text):
    if kind == "header":
        name, value = text.split(":", 1)
        return page_from({name: [value.strip()]}, "")
    if kind == "cookie":
        return page_from({"set-cookie": [text + "=value; Path=/"]}, "")
    if kind == "url":
        return page_from({}, f'<script src="{text}"></script>')
    if kind == "style-url":
        return page_from({}, f'<link rel="stylesheet" href="{text}">')
    if kind == "meta":
        return page_from({}, f'<meta name="generator" content="{text}">')
    if kind in {"script", "style", "manifest", "robots"}:
        extension = "js" if kind == "script" else "css"
        return page_from({}, "", resources=(Resource(f"https://example.invalid/{extension}.{extension}", kind, text),))
    return page_from({}, text)


# Each case exercises one rule. Existing URL rules are also checked for their
# newly required display and npm identities.
RULE_CASES = (
    ("angular", "html", '<app-root ng-version="17.3.8"></app-root>', '<div data-version="17.3.8">', "Angular", "@angular/core", "17.3.8"),
    ("angular-core", "script", 'const pkg="@angular/core@17.3.8";', 'const build="17.3.8";', "Angular", "@angular/core", "17.3.8"),
    ("angularjs-markup", "html", '<div ng-app="demo">', '<div app-name="demo">', "AngularJS", "angular", ""),
    ("angularjs-script", "script", '/*! AngularJS v1.8.3 */', '/*! AngularJS compatible build 2026 */', "AngularJS", "angular", "1.8.3"),
    ("nextjs", "html", '<script id="__NEXT_DATA__">{}</script>', '<script id="NEXT_DATA">{}</script>', "Next.js", "next", ""),
    ("gatsby-markup", "html", '<div id="___gatsby"></div>', '<div id="gatsby"></div>', "Gatsby", "gatsby", ""),
    ("nuxt", "html", '<div id="__nuxt"></div>', '<div id="nuxt"></div>', "Nuxt", "nuxt", ""),
    ("react", "url", "https://static.example.invalid/react.production.min.js", "https://static.example.invalid/reactive.js", "React", "react", ""),
    ("react-script", "script", '/*! @license React v18.2.0 */', '/*! @license React build 2026.2 */', "React", "react", "18.2.0"),
    ("react-markup", "html", '<div data-reactroot="">', '<div data-reactive="">', "React", "react", ""),
    ("vue", "url", "https://static.example.invalid/vue.global.prod.js", "https://static.example.invalid/vue-router.global.js", "Vue.js", "vue", ""),
    ("vue-script", "script", '/*! Vue.js v3.5.13 */', '/*! Vue compatible build 2026 */', "Vue.js", "vue", "3.5.13"),
    ("vue-markup", "html", '<div data-v-app="">', '<div data-view-app="">', "Vue.js", "vue", ""),
    ("ember-script", "script", 'Ember.VERSION = "5.12.0";', 'const buildVersion = "5.12.0";', "Ember", "ember-source", "5.12.0"),
    ("ember-markup", "html", '<div class="ember-view">', '<div class="ember-like">', "Ember", "ember-source", ""),
    ("backbone-script", "script", 'Backbone.VERSION = "1.6.1";', 'const BackboneCompat = "1.6.1";', "Backbone.js", "backbone", "1.6.1"),
    ("alpine-markup", "html", '<div x-data="{}">', '<div data-x-data="{}">', "Alpine.js", "alpinejs", ""),
    ("alpine-script", "script", 'Alpine.version = "3.14.8";', 'Alpine.build = "3.14.8";', "Alpine.js", "alpinejs", "3.14.8"),
    ("htmx-markup", "html", '<button hx-get="/items">', '<button data-hx-get="/items">', "htmx", "htmx.org", ""),
    ("htmx-script", "script", 'htmx.version = "2.0.4";', 'htmx.build = "2.0.4";', "htmx", "htmx.org", "2.0.4"),
    ("jquery", "url", "https://static.example.invalid/jquery-3.7.1.min.js", "https://static.example.invalid/jquery-plugin.js", "jQuery", "jquery", "3.7.1"),
    ("jquery-script", "script", '/*! jQuery v3.7.1 | OpenJS Foundation */', '/*! jQuery compatible build 2026 */', "jQuery", "jquery", "3.7.1"),
    ("jquery-ui-script", "script", '/*! jQuery UI - v1.14.1 - 2024-09-26 */', '/*! jQuery UI extensions */', "jQuery UI", "jquery-ui", "1.14.1"),
    ("jquery-migrate-script", "script", 'JQMIGRATE: Migrate is installed, version 3.4.1', 'JQMIGRATE: Migrate compatible build 2026', "jQuery Migrate", "jquery-migrate", "3.4.1"),
    ("lodash-script", "script", 'lodash 4.17.21', 'loadsheaf 4.17.21', "Lodash", "lodash", "4.17.21"),
    ("underscore-script", "script", 'Underscore.js 1.13.7\n// https://underscorejs.org', 'Underscore-compatible build 1.13.7', "Underscore.js", "underscore", "1.13.7"),
    ("moment-script", "script", '//! moment.js version : 2.30.1', '//! moment.js compatibility layer', "Moment.js", "moment", "2.30.1"),
    ("axios-script", "script", '/*! Axios v1.7.9 | (c) OpenJS Foundation */', '/*! Axios-compatible build v1.7.9 */', "Axios", "axios", "1.7.9"),
    ("chartjs-script", "script", '/*! Chart.js v4.4.7 */', '/*! Chart-compatible build v4.4.7 */', "Chart.js", "chart.js", "4.4.7"),
    ("d3-script", "script", 'd3.version = "7.9.0";', 'd3.compatibility = "7.9.0";', "D3", "d3", "7.9.0"),
    ("swiper-script", "script", '/*! Swiper 11.1.15 */', '/*! Swiper compatible build 11.1.15 */', "Swiper", "swiper", "11.1.15"),
    ("select2-script", "script", '/*! Select2 4.1.0-rc.0 */', '/*! Select2-compatible build 4.1.0 */', "Select2", "select2", "4.1.0-rc.0"),
    ("datatables-script", "script", '/*! DataTables 2.2.1 */', '/*! DataTables-compatible build 2.2.1 */', "DataTables", "datatables.net", "2.2.1"),
    ("modernizr-script", "script", 'Modernizr._version = "3.13.0";', 'Modernizr.build = "3.13.0";', "Modernizr", "modernizr", "3.13.0"),
    ("requirejs-script", "script", '/*! RequireJS 2.3.7 */', '/*! RequireJS-compatible build 2.3.7 */', "RequireJS", "requirejs", "2.3.7"),
    ("handlebars-script", "script", 'Handlebars.VERSION = "4.7.8";', 'Handlebars.build = "4.7.8";', "Handlebars", "handlebars", "4.7.8"),
    ("rxjs-script", "script", 'rxjs@7.8.1', 'rxjs-compatible-build@7.8.1', "RxJS", "rxjs", "7.8.1"),
    ("core-js", "script", "__core-js_shared__.versions.push({ version: '3.40.0', mode: 'global', copyright: 'Core-js' });", "const build = '3.40.0';", "core-js", "core-js", "3.40.0"),
    ("zonejs-script", "script", '/*! zone.js v0.15.0 */', '/*! zone.js compatible build 0.15.0 */', "zone.js", "zone.js", "0.15.0"),
    ("webpack-runtime", "script", 'self.webpackChunk_app = self.webpackChunk_app || [];', 'self.webpackChunked_app = [];', "webpack", "webpack", ""),
    ("tslib", "url", "https://static.example.invalid/tslib/tslib.es6.js", "https://static.example.invalid/my-tslib.js", "tslib", "tslib", ""),
    ("typescript", "url", "https://static.example.invalid/typescript@5.7.2/browser.js", "https://static.example.invalid/typescript-helper.js", "TypeScript", "typescript", "5.7.2"),
    ("popper-script", "script", '/*! @popperjs/core v2.11.8 */', '/*! popper-compatible build v2.11.8 */', "Popper", "@popperjs/core", "2.11.8"),
    ("bootstrap", "url", "https://static.example.invalid/bootstrap-5.3.3.min.css", "https://static.example.invalid/bootstrapper-5.3.3.css", "Bootstrap", "bootstrap", "5.3.3"),
    ("bootstrap-script", "script", '/*! Bootstrap v5.3.3 */', '/*! Bootstrap-compatible build v5.3.3 */', "Bootstrap", "bootstrap", "5.3.3"),
    ("bootstrap-style", "style", '/*! Bootstrap v5.3.3 | https://getbootstrap.com/ */', '/*! Bootstrap-like stylesheet v5.3.3 */', "Bootstrap", "bootstrap", "5.3.3"),
    ("font-awesome-style", "style", '/*! Font Awesome Free 6.7.2 by @fontawesome */', '/*! Font Awesome compatible icons 6.7.2 */', "Font Awesome", "@fortawesome/fontawesome-free", "6.7.2"),
    ("tailwind-style", "style", '/*! tailwindcss v3.4.17 | MIT License */', '/*! tailwind-compatible utilities v3.4.17 */', "Tailwind CSS", "tailwindcss", "3.4.17"),
    ("bulma-style", "style", '/*! Bulma v1.0.2 | https://bulma.io */', '/*! Bulma-compatible styles v1.0.2 */', "Bulma", "bulma", "1.0.2"),
    ("foundation-style", "style", '/*! Foundation for Sites 6.8.1 */', '/*! Foundation-like styles 6.8.1 */', "Foundation", "foundation-sites", "6.8.1"),
    ("animate-style", "style", '/*! animate.css - Version 4.1.1 */', '/*! animate-compatible styles 4.1.1 */', "Animate.css", "animate.css", "4.1.1"),
    ("font-awesome-url", "style-url", "https://cdn.example.invalid/font-awesome/6.7.2/css/all.min.css", "https://cdn.example.invalid/font-like/6.7.2/css/all.css", "Font Awesome", "@fortawesome/fontawesome-free", ""),
    ("tailwind-url", "style-url", "https://cdn.example.invalid/tailwindcss/3.4.17/tailwind.min.css", "https://cdn.example.invalid/tailwind-like/3.4.17/app.css", "Tailwind CSS", "tailwindcss", ""),
    ("symfony-header", "header", "X-Debug-Token: abc123", "X-Debug-Token-Status: 200", "Symfony", "", ""),
    ("symfony-cookie", "cookie", "_symfony_session", "symfony_sessionish", "Symfony", "", ""),
    ("codeigniter-header", "header", "X-Powered-By: CodeIgniter", "X-Powered-By: CodeIgniter-compatible", "CodeIgniter", "", ""),
    ("codeigniter-cookie", "cookie", "ci_session", "ci_session_backup", "CodeIgniter", "", ""),
    ("django-cookie", "cookie", "csrftoken", "csrf-token", "Django", "", ""),
    ("rails-header", "header", "X-Runtime: 0.123", "X-Runtime-Name: rails", "Ruby on Rails", "", ""),
    ("livewire-markup", "html", '<div wire:id="abc123">', '<div data-wire-id="abc123">', "Livewire", "", ""),
    ("inertia-markup", "html", '<div id="app" data-page="{&quot;component&quot;:&quot;Home&quot;}">', '<div data-page-name="Home">', "Inertia.js", "@inertiajs/core", ""),
    ("wordpress-robots", "robots", "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php", "User-agent: *\nDisallow: /admin/", "WordPress", "", ""),
    ("drupal-robots", "robots", "Disallow: /core/\nDisallow: /modules/\nDisallow: /profiles/", "Disallow: /core-files/", "Drupal", "", ""),
    ("joomla-robots", "robots", "Disallow: /administrator/", "Disallow: /admin/", "Joomla", "", ""),
    ("angular-manifest", "manifest", '{"serviceworker":{"src":"/ngsw-worker.js"}}', '{"serviceworker":{"src":"/worker.js"}}', "Angular", "@angular/core", ""),
    ("google-maps", "url", "https://maps.googleapis.com/maps/api/js?key=TEST", "https://maps.example.invalid/api/js", "Google Maps", "", ""),
    ("google-fonts", "style-url", "https://fonts.googleapis.com/css?family=Inter", "https://fonts.example.invalid/css?family=Inter", "Google Font API", "", ""),
    ("google-analytics", "url", "https://www.google-analytics.com/analytics.js", "https://analytics.example.invalid/analytics.js", "Google Analytics", "", ""),
    ("google-tag-manager", "url", "https://www.googletagmanager.com/gtm.js?id=GTM-TEST", "https://tagmanager.example.invalid/gtm.js", "Google Tag Manager", "", ""),
    ("google-recaptcha", "url", "https://www.google.com/recaptcha/api.js", "https://captcha.example.invalid/recaptcha/api.js", "Google reCAPTCHA", "", ""),
    ("hcaptcha", "url", "https://js.hcaptcha.com/1/api.js", "https://captcha.example.invalid/1/api.js", "hCaptcha", "", ""),
    ("cloudflare-turnstile", "url", "https://challenges.cloudflare.com/turnstile/v0/api.js", "https://challenges.example.invalid/turnstile/v0/api.js", "Cloudflare Turnstile", "", ""),
    ("cloudflare-web-analytics", "url", "https://static.cloudflareinsights.com/beacon.min.js", "https://static.example.invalid/beacon.min.js", "Cloudflare Web Analytics", "", ""),
    ("facebook-pixel", "url", "https://connect.facebook.net/en_US/fbevents.js", "https://connect.example.invalid/en_US/fbevents.js", "Facebook Pixel", "", ""),
    ("hotjar", "url", "https://static.hotjar.com/c/hotjar-123.js", "https://static.example.invalid/c/hotjar-123.js", "Hotjar", "", ""),
    ("microsoft-clarity", "url", "https://www.clarity.ms/tag/abc123", "https://clarity.example.invalid/tag/abc123", "Microsoft Clarity", "", ""),
    ("matomo", "url", "https://stats.example.invalid/matomo.js", "https://stats.example.invalid/analytics.js", "Matomo", "", ""),
    ("stripe-js", "url", "https://js.stripe.com/v3/", "https://js.example.invalid/v3/", "Stripe.js", "@stripe/stripe-js", ""),
    ("paypal", "url", "https://www.paypal.com/sdk/js?client-id=TEST", "https://www.paypal.example.invalid/sdk/js", "PayPal", "", ""),
    ("sentry-browser", "url", "https://browser.sentry-cdn.com/7.120.3/bundle.min.js", "https://browser.example.invalid/7.120.3/bundle.min.js", "Sentry", "@sentry/browser", "7.120.3"),
    ("intercom", "url", "https://widget.intercom.io/widget/abc123", "https://widget.example.invalid/widget/abc123", "Intercom", "@intercom/messenger-js-sdk", ""),
    ("zendesk", "url", "https://static.zdassets.com/ekr/snippet.js?key=TEST", "https://static.example.invalid/ekr/snippet.js", "Zendesk", "", ""),
)


@pytest.mark.parametrize("key,kind,positive,negative,name,package,version", RULE_CASES)
def test_rule_has_narrow_positive_negative_and_identity(key, kind, positive, negative,
                                                        name, package, version):
    rule = next(rule for rule in webrules.RULES
                if rule.key.removeprefix("expanded-") == key)
    matched = detect(_page(kind, positive))
    found = next((item for item in matched if item.name == name), None)
    assert found is not None, key
    assert not any(item.name == name for item in detect(_page(kind, negative))), key
    if package:
        assert (found.ecosystem, found.package) == ("npm", package), key
    if version:
        assert found.versions == (version,), key


def test_all_new_rules_have_positive_and_negative_cases():
    from cvebeacon_extensions.webrules import RULES

    case_keys = {case[0] for case in RULE_CASES}
    case_keys -= {"angular", "nextjs", "nuxt", "react", "vue", "jquery", "bootstrap"}
    required = {rule.key.removeprefix("expanded-") for rule in RULES
                if rule.key.startswith("expanded-")}
    assert required == case_keys


@pytest.mark.parametrize("url,package,version", [
    ("https://cdn.jsdelivr.net/npm/core-js@3.40.0/es/index.js", "core-js", "3.40.0"),
    ("https://unpkg.com/@scope/widget@2.4.1/dist/widget.js", "@scope/widget", "2.4.1"),
    ("https://cdn.jsdelivr.net/npm/@angular/core@17.3.8/fesm2022/core.mjs", "@angular/core", "17.3.8"),
    ("https://unpkg.com/@popperjs/core@2.11.8/dist/umd/popper.min.js", "@popperjs/core", "2.11.8"),
])
def test_jsdelivr_and_unpkg_keep_npm_names_and_versions(url, package, version):
    detections = detect(page_from({}, f'<script src="{url}"></script>'))
    found = next(item for item in detections if item.ecosystem == "npm" and item.package == package)
    assert found.versions == (version,)
    assert "url" in found.evidence_types


def test_cdnjs_maps_known_packages_and_leaves_unknown_libraries_unidentified():
    html = (
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>'
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/unknown-widget/2.4.1/widget.js"></script>'
    )
    detections = detect(page_from({}, html))
    jquery = next(item for item in detections if item.name == "jQuery")
    review = next(item for item in detections if item.name == "Unidentified cdnjs library")
    assert (jquery.ecosystem, jquery.package, jquery.versions) == ("npm", "jquery", ("3.7.1",))
    assert (review.vendor, review.product, review.ecosystem, review.package, review.versions) == (
        "cdnjs", "", "", "", (),
    )
    assert review.evidence[0].source == "page"


def test_cdn_detection_count_is_bounded():
    links = "".join(
        f'<script src="https://cdn.jsdelivr.net/npm/unknown-package-{index}@1.2.3/index.js"></script>'
        for index in range(MAX_CDN_DETECTIONS + 20)
    )
    detections = detect(page_from({}, links))
    assert 0 < len(detections) <= MAX_CDN_DETECTIONS


def test_versions_are_read_from_the_product_banner_only():
    page = _page("script", '/*! Chart.js v4.4.7 */ /*! unrelated compiler v99.88.77 */')
    chart = next(item for item in detect(page) if item.name == "Chart.js")
    assert chart.versions == ("4.4.7",)
    page = _page("script", '/*! Chart.js library */ /*! unrelated v99.88.77 */')
    chart = next(item for item in detect(page) if item.name == "Chart.js")
    assert chart.versions == ()


@pytest.mark.parametrize("kind,text,expected,source", [
    ("cookie", "laravel_session", "PHP", "Laravel"),
    ("html", '<app-root ng-version="17.3.8">', "TypeScript", "Angular"),
    ("meta", "WordPress 6.7.1", "PHP", "WordPress"),
    ("meta", "Drupal 10.3.6", "PHP", "Drupal"),
    ("meta", "Joomla! 5.2.1", "PHP", "Joomla"),
    ("header", "X-Magento-Tags: cat_c", "PHP", "Magento"),
    ("meta", "PrestaShop 8.2.1", "PHP", "PrestaShop"),
    ("meta", "TYPO3 CMS 13.4.1", "PHP", "TYPO3"),
    ("cookie", "phpmyadmin", "PHP", "phpMyAdmin"),
    ("header", "X-Debug-Token: abc123", "PHP", "Symfony"),
    ("cookie", "ci_session", "PHP", "CodeIgniter"),
    ("html", '<script id="__NEXT_DATA__">{}</script>', "React", "Next.js"),
    ("html", '<div id="___gatsby"></div>', "React", "Gatsby"),
    ("html", '<div id="__nuxt"></div>', "Vue.js", "Nuxt"),
    ("header", "X-Powered-By: Express", "Node.js", "Express"),
    ("html", '<div wire:id="abc123">', "Laravel", "Livewire"),
])
def test_required_technology_implications(kind, text, expected, source):
    item = next(item for item in detect(_page(kind, text)) if item.name == expected)
    assert item.versions == ()
    assert item.confidence == "low"
    assert item.evidence_types == ("implied",)
    assert item.implied_by == (source,)


def test_implications_merge_with_direct_evidence_and_keep_versions():
    page = page_from(
        {"x-powered-by": ["PHP/8.3.1"], "set-cookie": ["laravel_session=token; Path=/"]},
        '<app-root ng-version="17.3.8"></app-root>',
    )
    php = next(item for item in detect(page) if item.name == "PHP")
    assert php.versions == ("8.3.1",)
    assert "header" in php.evidence_types and "implied" not in php.evidence_types
    assert php.implied_by == ("Laravel",)
    typescript = next(item for item in detect(page) if item.name == "TypeScript")
    assert typescript.evidence_types == ("implied",) and typescript.implied_by == ("Angular",)


def test_direct_detections_record_matched_excerpt_and_source():
    page = page_from({}, '<app-root ng-version="17.3.8"></app-root>')
    angular = next(item for item in detect(page) if item.name == "Angular")
    evidence = next(item for item in angular.evidence if item.kind == "html")
    assert evidence.source == "page"
    assert evidence.excerpt == 'ng-version="17.3.8'
    assert len(evidence.excerpt) <= 160


def test_direct_react_evidence_merges_with_nextjs_implication():
    page = page_from({}, '<script id="__NEXT_DATA__">{}</script><div data-reactroot="">')
    react = next(item for item in detect(page) if item.name == "React")
    assert react.ecosystem == "npm" and react.package == "react"
    assert "html" in react.evidence_types and react.implied_by == ("Next.js",)


def test_npm_rows_from_web_row_builder_normalize():
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    asset = WebAsset(Endpoint("https", "example.invalid", 443, "/"), "Test", now, None, True, 0, False)
    allowlist = Allowlist("Acme", None, (asset,))

    class Fetcher:
        @staticmethod
        def _clock():
            return 0.0

        @staticmethod
        def fetch(*args, **kwargs):
            body = b'<script src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"></script>'
            return _FetchSuccess(_Response(200, {"content-type": ("text/html",)}, body), (), now)

    result = _observe(asset, allowlist, Fetcher(), run_deadline=10.0)
    row = next(row for row in result.rows if row["ecosystem"] == "npm")
    normalized = normalize_asset(Asset(
        asset_id=row["asset_id"], vendor=row["vendor"], product=row["product"],
        version=row["version"], system_id=row["system_id"], ecosystem=row["ecosystem"],
        purl=row["purl"], cpe=row["cpe"],
    ))
    assert normalized.purl == "pkg:npm/react@18.2.0"
    assert normalized.cpe == ""


def test_angular_example_with_resources_and_laravel_cookie():
    html = (
        '<app-root ng-version="17.3.8"></app-root>'
        '<script src="https://maps.googleapis.com/maps/api/js?key=TEST"></script>'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter">'
    )
    resources = (
        Resource("https://example.invalid/runtime.js", "script", "self.webpackChunk_app = [];"),
        Resource("https://example.invalid/polyfills.js", "script", "/*! zone.js v0.15.0 */ __core-js_shared__.versions.push({ version: '3.40.0', copyright: 'Core-js' });"),
        Resource("https://example.invalid/main.js", "script", 'const core="@angular/core@17.3.8";'),
        Resource("https://example.invalid/styles.css", "style", "/*! Bootstrap v5.3.3 */"),
    )
    detections = detect(page_from({"set-cookie": ["laravel_session=value; Path=/"]}, html, resources))
    names = {item.name for item in detections}
    assert {"Angular", "TypeScript", "zone.js", "core-js", "webpack", "Bootstrap",
            "Google Maps", "Google Font API", "Laravel", "PHP"} <= names


def test_detection_over_16mb_in_24_resources_finishes_under_two_seconds():
    padding = "x" * (16 * 1024 * 1024 // 24 - 64)
    resources = tuple(
        Resource(f"https://example.invalid/{index}.js", "script",
                 padding + ("/*! Chart.js v4.4.7 */" if index == 23 else ""))
        for index in range(24)
    )
    import time

    started = time.perf_counter()
    detections = detect(page_from({}, "", resources))
    elapsed = time.perf_counter() - started
    assert any(item.name == "Chart.js" for item in detections)
    assert elapsed < 2.0
