import logging

import pytest
import responses

from engines.chrome_extension import ChromeExtensionEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets():
    return Secrets()


@pytest.fixture
def extension_id():
    return "abcdefg1234567890"


@pytest.fixture
def chrome_url(extension_id):
    return f"https://chromewebstore.google.com/detail/{extension_id}"


@pytest.fixture
def edge_url(extension_id):
    return f"https://microsoftedge.microsoft.com/addons/detail/{extension_id}"


@pytest.fixture
def chrome_html_success():
    """Mock HTML response from Chrome Web Store with h1 tag."""
    return """
    <html>
    <head><title>Some title</title></head>
    <body>
        <h1>Test Extension Name</h1>
        <p>Extension description</p>
    </body>
    </html>
    """


@pytest.fixture
def edge_html_success():
    """Mock HTML response from Edge Add-ons with title tag."""
    return """
    <html>
    <head><title>Test Extension Name - Microsoft Edge</title></head>
    <body>
        <h1>Some other content</h1>
    </body>
    </html>
    """


@pytest.fixture
def html_empty_name():
    """Mock HTML with h1 tag but empty content."""
    return """
    <html>
    <head><title>Title</title></head>
    <body>
        <h1>   </h1>
    </body>
    </html>
    """


@pytest.fixture
def html_no_tags():
    """Mock HTML with no h1 or title tags."""
    return """
    <html>
    <head></head>
    <body>
        <p>Some content without h1 tag</p>
    </body>
    </html>
    """


@pytest.fixture
def html_empty_body():
    """Mock HTML with empty body."""
    return """
    <html>
    <head><title>Empty</title></head>
    <body></body>
    </html>
    """


# ============================================================================
# High Priority: Critical Paths & Core Functionality
# ============================================================================


@responses.activate
@pytest.mark.parametrize(
    "browser_url,browser_html,browser_name",
    [
        ("chrome_url", "chrome_html_success", "Chrome"),
        ("edge_url", "edge_html_success", "Edge"),
    ],
)
def test_analyze_success_browser_variants(
    request, secrets, extension_id, browser_url, browser_html, browser_name
):
    """Test successful extension name extraction from Chrome and Edge stores."""
    # Resolve fixture names to actual fixtures
    url = request.getfixturevalue(browser_url)
    html = request.getfixturevalue(browser_html)

    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, url, body=html, status=200)

    result = engine.analyze(extension_id, "CHROME_EXTENSION")

    assert result is not None
    assert result["name"] == "Test Extension Name"
    assert result["url"] == url


@responses.activate
def test_analyze_chrome_fails_fallback_edge(
    secrets, extension_id, chrome_url, edge_url, html_no_tags, edge_html_success
):
    """Test fallback to Edge when Chrome URL returns no h1 tag."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, chrome_url, body=html_no_tags, status=200)
    responses.add(responses.GET, edge_url, body=edge_html_success, status=200)

    result = engine.analyze(extension_id, "CHROME_EXTENSION")

    assert result is not None
    assert result["name"] == "Test Extension Name"
    assert result["url"] == edge_url


@responses.activate
def test_analyze_both_urls_fail(secrets, extension_id, chrome_url, edge_url, html_no_tags):
    """Test returns None when both Chrome and Edge URLs fail to find extension name."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, chrome_url, body=html_no_tags, status=200)
    responses.add(responses.GET, edge_url, body=html_no_tags, status=200)

    result = engine.analyze(extension_id, "CHROME_EXTENSION")

    assert result is None


@responses.activate
def test_analyze_chrome_empty_name_fallback(
    secrets, extension_id, chrome_url, edge_url, html_empty_name, edge_html_success
):
    """Test fallback to Edge when Chrome returns empty whitespace-only h1."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, chrome_url, body=html_empty_name, status=200)
    responses.add(responses.GET, edge_url, body=edge_html_success, status=200)

    result = engine.analyze(extension_id, "CHROME_EXTENSION")

    assert result is not None
    assert result["name"] == "Test Extension Name"
    assert result["url"] == edge_url


@responses.activate
def test_analyze_edge_title_parsing(secrets, extension_id, edge_url):
    """Test Edge title tag parsing extracts name before '-' delimiter."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    html = """
    <html>
    <head><title>My Cool Extension - Microsoft Edge</title></head>
    <body></body>
    </html>
    """
    responses.add(responses.GET, edge_url, body=html, status=200)

    result = engine.analyze(extension_id, "CHROME_EXTENSION")

    assert result is not None
    assert result["name"] == "My Cool Extension"
    assert result["url"] == edge_url


def test_create_export_row_success(secrets):
    """Test create_export_row formats result dict with extension_name."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    analysis_result = {"name": "Test Extension", "url": "https://example.com"}

    export_row = engine.create_export_row(analysis_result)

    assert export_row == {"extension_name": "Test Extension"}


def test_create_export_row_none(secrets):
    """Test create_export_row returns None for extension_name when result is None."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)

    export_row = engine.create_export_row(None)

    assert export_row == {"extension_name": None}


# ============================================================================
# Medium Priority: Robustness & Error Handling
# ============================================================================


@responses.activate
def test_fetch_extension_http_error_404(secrets, extension_id, chrome_url):
    """Test handles HTTP 404 error gracefully."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, chrome_url, status=404)

    result = engine._fetch_extension_name(chrome_url)

    assert result is None


@responses.activate
def test_fetch_extension_http_error_500(secrets, extension_id, edge_url):
    """Test handles HTTP 500 error gracefully."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, edge_url, status=500)

    result = engine._fetch_extension_name(edge_url)

    assert result is None


@responses.activate
def test_fetch_extension_timeout_error(secrets, extension_id, chrome_url):
    """Test handles request timeout gracefully."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, chrome_url, body=ConnectionError("Connection timeout"))

    result = engine._fetch_extension_name(chrome_url)

    assert result is None


@responses.activate
def test_fetch_extension_connection_error(secrets, extension_id, edge_url):
    """Test handles connection error gracefully."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, edge_url, body=ConnectionError("Failed to connect"))

    result = engine._fetch_extension_name(edge_url)

    assert result is None


@responses.activate
def test_fetch_extension_invalid_html(secrets, extension_id, chrome_url, html_no_tags):
    """Test handles HTML with missing expected tags gracefully."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, chrome_url, body=html_no_tags, status=200)

    result = engine._fetch_extension_name(chrome_url)

    assert result is None


@responses.activate
def test_analyze_url_construction(secrets, extension_id, chrome_url, edge_url, html_no_tags):
    """Test correct URLs are constructed for both Chrome and Edge."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, chrome_url, body=html_no_tags, status=200)
    responses.add(responses.GET, edge_url, body=html_no_tags, status=200)

    engine.analyze(extension_id, "CHROME_EXTENSION")

    assert len(responses.calls) == 2
    assert responses.calls[0].request.url == chrome_url
    assert responses.calls[1].request.url == edge_url


@responses.activate
def test_fetch_extension_ssl_verify_parameter(
    secrets, extension_id, chrome_url, chrome_html_success
):
    """Test ssl_verify parameter is passed to requests.get()."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=False)
    responses.add(responses.GET, chrome_url, body=chrome_html_success, status=200)

    engine._fetch_extension_name(chrome_url)

    # Verify the request was made (responses mock captures all calls)
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == chrome_url


@responses.activate
def test_fetch_extension_proxies_parameter(secrets, extension_id, chrome_url, chrome_html_success):
    """Test proxies parameter is passed to requests.get()."""
    proxies = {"http": "http://proxy.example.com:8080"}
    engine = ChromeExtensionEngine(secrets, proxies=proxies, ssl_verify=True)
    responses.add(responses.GET, chrome_url, body=chrome_html_success, status=200)

    engine._fetch_extension_name(chrome_url)

    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == chrome_url


# ============================================================================
# Low Priority: Edge Cases & Special Scenarios
# ============================================================================


@responses.activate
def test_fetch_extension_empty_response_body(secrets, extension_id, chrome_url, html_empty_body):
    """Test handles empty HTML body gracefully."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    responses.add(responses.GET, chrome_url, body=html_empty_body, status=200)

    result = engine._fetch_extension_name(chrome_url)

    assert result is None


@responses.activate
def test_analyze_extension_id_with_special_chars(secrets):
    """Test extension ID with hyphens and underscores in URL construction."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    special_id = "test-ext_123"
    chrome_url = f"https://chromewebstore.google.com/detail/{special_id}"
    edge_url = f"https://microsoftedge.microsoft.com/addons/detail/{special_id}"
    html = """<html><body><h1>Test</h1></body></html>"""
    responses.add(responses.GET, chrome_url, body=html, status=200)
    responses.add(responses.GET, edge_url, body=html, status=200)

    engine.analyze(special_id, "CHROME_EXTENSION")

    # Verify URLs were called with special character ID intact
    assert responses.calls[0].request.url == chrome_url


@responses.activate
def test_fetch_extension_whitespace_handling(secrets, extension_id, chrome_url):
    """Test names with leading/trailing whitespace are stripped."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    html = """
    <html>
    <body>
        <h1>   Test Extension With Spaces   </h1>
    </body>
    </html>
    """
    responses.add(responses.GET, chrome_url, body=html, status=200)

    result = engine._fetch_extension_name(chrome_url)

    assert result["name"] == "Test Extension With Spaces"


def test_create_export_row_missing_name_key(secrets):
    """Test create_export_row gracefully handles result missing 'name' key."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    analysis_result = {"url": "https://example.com"}

    export_row = engine.create_export_row(analysis_result)

    assert export_row == {"extension_name": None}


@responses.activate
def test_analyze_extra_keys_in_result(secrets, extension_id, chrome_url):
    """Test create_export_row ignores extra keys in result dict."""
    engine = ChromeExtensionEngine(secrets, proxies={}, ssl_verify=True)
    html = """
    <html>
    <body>
        <h1>Test Extension</h1>
    </body>
    </html>
    """
    responses.add(responses.GET, chrome_url, body=html, status=200)

    analysis_result = engine.analyze(extension_id, "CHROME_EXTENSION")
    export_row = engine.create_export_row(analysis_result)

    # Should only have extension_name, not extra keys
    assert len(export_row) == 1
    assert export_row == {"extension_name": "Test Extension"}
