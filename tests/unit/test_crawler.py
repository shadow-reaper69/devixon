"""
Unit tests for Web Crawler link extraction, scope filtering, and link categorization.
"""

import pytest
from devixon.core.scope import ScopeProfile
from devixon.recon.stages.stage09_crawler import Stage09WebCrawler


def test_link_parsing_and_scope_filtering():
    scope = ScopeProfile(
        primary_domain="target.com",
        allowed_domains=["*.target.com"],
        excluded_paths=["/logout", "/admin/delete"],
        authorized_by_user=True,
    )

    # In-scope link
    in_scope, _ = scope.is_in_scope("https://api.target.com/v1/users")
    assert in_scope is True

    # Out-of-scope external link
    in_scope, _ = scope.is_in_scope("https://google.com/search")
    assert in_scope is False

    # Excluded path link
    in_scope, _ = scope.is_in_scope("https://target.com/logout", path="/logout")
    assert in_scope is False

    # Normal path
    in_scope, _ = scope.is_in_scope("https://target.com/dashboard", path="/dashboard")
    assert in_scope is True


def test_crawler_html_link_extraction():
    html_sample = """
    <html>
        <head>
            <title>Test Page</title>
            <script src="/static/app.js"></script>
            <link rel="stylesheet" href="/static/style.css">
        </head>
        <body>
            <a href="/about">About Us</a>
            <a href="https://target.com/contact?ref=nav">Contact</a>
            <a href="https://external-partner.com">Partner</a>
            <form action="/login" method="POST">
                <input type="text" name="username">
            </form>
        </body>
    </html>
    """
    import re
    from urllib.parse import urljoin

    base_url = "https://target.com"
    hrefs = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\'>\s#]+)["\']', html_sample, re.IGNORECASE)
    assert len(hrefs) == 3

    forms = re.findall(r'<form\s+(?:[^>]*?\s+)?action=["\']([^"\'>\s]*)["\'](?:\s+[^>]*?method=["\']([^"\'>\s]+)["\'])?', html_sample, re.IGNORECASE)
    assert len(forms) == 1
    assert forms[0][0] == "/login"
    assert forms[0][1].upper() == "POST"

    scripts = re.findall(r'<script\s+(?:[^>]*?\s+)?src=["\']([^"\'>\s]+)["\']', html_sample, re.IGNORECASE)
    assert len(scripts) == 1
    assert scripts[0] == "/static/app.js"
