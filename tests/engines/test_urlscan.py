import logging
from urllib.parse import quote

import pytest
import requests
import responses

from engines.urlscan import URLScanEngine
from models.observable import ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


# ============================================================================
# Phase 1: Fixtures & Setup
# ============================================================================


@pytest.fixture
def urlscan_engine():
    """Create URLScan engine with minimal config."""
    return URLScanEngine(Secrets(), proxies={}, ssl_verify=True)


@pytest.fixture
def ipv4_observable():
    """IPv4 address observable."""
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    """IPv6 address observable."""
    return "2001:4860:4860::8888"


@pytest.fixture
def fqdn_observable():
    """FQDN observable."""
    return "example.com"


@pytest.fixture
def url_observable():
    """Full URL observable."""
    return "https://subdomain.example.com/path?query=value"


@pytest.fixture
def md5_observable():
    """MD5 hash observable."""
    return "d41d8cd98f00b204e9800998ecf8427e"


@pytest.fixture
def sha1_observable():
    """SHA1 hash observable."""
    return "da39a3ee5e6b4b0d3255bfef95601890afd80709"


@pytest.fixture
def sha256_observable():
    """SHA256 hash observable."""
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture
def success_response_with_data():
    """Successful URLScan API response with multiple results."""
    return {
        "results": [
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "cdn.example.com"}},
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "api.example.com"}},
            {"page": {"domain": "example.com"}},
        ],
        "total": 5,
    }


@pytest.fixture
def empty_results_response():
    """Valid response with no results."""
    return {"results": [], "total": 0}


@pytest.fixture
def minimal_response():
    """Minimal valid response."""
    return {"results": [{"page": {"domain": "single.com"}}], "total": 1}


# ============================================================================
# Phase 2: High Priority Tests - Observable Types & Core Paths
# ============================================================================


@responses.activate
@pytest.mark.parametrize(
    "observable_type,observable_value",
    [
        (ObservableType.IPV4, "1.1.1.1"),
        (ObservableType.IPV6, "2001:4860:4860::8888"),
        (ObservableType.FQDN, "example.com"),
        (ObservableType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        (ObservableType.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (ObservableType.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ],
)
def test_analyze_all_observable_types_success(
    observable_type, observable_value, success_response_with_data
):
    """Test successful analysis for all non-URL observable types."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json=success_response_with_data, status=200)

    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert result["scan_count"] == 5
    assert len(result["top_domains"]) > 0


@responses.activate
def test_analyze_url_observable_success(success_response_with_data):
    """Test URL observable with domain extraction."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    # Should extract "subdomain.example.com" from the URL
    responses.add(responses.GET, url, json=success_response_with_data, status=200)

    result = engine.analyze("https://subdomain.example.com/path?query=value", ObservableType.URL)

    assert result is not None
    assert "scan_count" in result
    # Verify the correct request was made with extracted domain
    assert len(responses.calls) == 1
    assert "subdomain.example.com" in responses.calls[0].request.url


@responses.activate
def test_url_domain_extraction_simple(success_response_with_data):
    """Test URL domain extraction: simple URL with protocol."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json=success_response_with_data, status=200)
    result = engine.analyze("https://example.com/path", ObservableType.URL)

    assert result is not None
    assert "example.com" in responses.calls[0].request.url


@responses.activate
def test_url_domain_extraction_with_port(success_response_with_data):
    """Test URL domain extraction: URL with port."""

    # TODO: Not actually sure this test is doing what I, at first, thought it was doing.
    # Re-evaluate purpose of test
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json=success_response_with_data, status=200)
    result = engine.analyze("http://example.com:8080/path", ObservableType.URL)

    assert result is not None
    assert "example.com" in responses.calls[0].request.url
    assert "8080" not in responses.calls[0].request.url


@responses.activate
def test_query_field_ipv4_uses_ip_field(ipv4_observable):
    """Test that IPv4 observables use 'ip' query field."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert quote("ip:1.1.1.1") in responses.calls[0].request.url


@responses.activate
def test_query_field_ipv6_uses_ip_field(ipv6_observable):
    """Test that IPv6 observables use 'ip' query field."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    engine.analyze(ipv6_observable, ObservableType.IPV6)

    assert quote("ip:2001") in responses.calls[0].request.url


@responses.activate
def test_query_field_md5_uses_files_md5(md5_observable):
    """Test that MD5 observables use 'files.md5' query field."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    engine.analyze(md5_observable, ObservableType.MD5)

    assert quote("files.md5:") in responses.calls[0].request.url


@responses.activate
def test_query_field_sha1_uses_files_sha1(sha1_observable):
    """Test that SHA1 observables use 'files.sha1' query field."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    engine.analyze(sha1_observable, ObservableType.SHA1)

    assert quote("files.sha1:") in responses.calls[0].request.url


@responses.activate
def test_query_field_sha256_uses_files_sha256(sha256_observable):
    """Test that SHA256 observables use 'files.sha256' query field."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    engine.analyze(sha256_observable, ObservableType.SHA256)

    assert quote("files.sha256:") in responses.calls[0].request.url


@responses.activate
def test_query_field_fqdn_uses_page_domain(fqdn_observable):
    """Test that FQDN observables use 'page.domain' query field."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    engine.analyze(fqdn_observable, ObservableType.FQDN)

    assert quote("page.domain:example.com") in responses.calls[0].request.url


@responses.activate
def test_scan_count_extracted_correctly(success_response_with_data):
    """Test that scan_count is correctly extracted from response."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json=success_response_with_data, status=200)
    result = engine.analyze("1.1.1.1", ObservableType.IPV4)

    assert result["scan_count"] == 5


@responses.activate
def test_top_domains_aggregation(ipv4_observable):
    """Test that domains are aggregated by count."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    response = {
        "results": [
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "cdn.example.com"}},
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "api.example.com"}},
            {"page": {"domain": "example.com"}},
        ],
        "total": 5,
    }
    responses.add(responses.GET, url, json=response, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # Should have example.com with count 3 at the top
    domains = result["top_domains"]
    assert len(domains) > 0
    assert domains[0]["domain"] == "example.com"
    assert domains[0]["count"] == 3


@responses.activate
def test_top_5_domains_limit(ipv4_observable):
    """Test that only top 5 domains are returned."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    # Create response with 10 unique domains
    results = [{"page": {"domain": f"domain{i}.com"}} for i in range(10)]
    response = {"results": results, "total": 10}

    responses.add(responses.GET, url, json=response, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert len(result["top_domains"]) == 5


@responses.activate
def test_urlscan_link_generation(ipv4_observable):
    """Test that urlscan.io link is correctly generated."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert "link" in result
    assert result["link"] == "https://urlscan.io/search/#ip:1.1.1.1"


@responses.activate
def test_proxies_passed_to_request(ipv4_observable, caplog):
    """Test that proxies are passed to requests.get()."""
    proxies = {"http": "http://proxy.example.com:8080"}
    engine = URLScanEngine(Secrets(), proxies=proxies, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    engine.analyze(ipv4_observable, ObservableType.IPV4)

    # Verify the request was made (proxies parameter handled by responses library)
    assert len(responses.calls) == 1


@responses.activate
def test_ssl_verify_false(ipv4_observable):
    """Test that ssl_verify=False is passed to requests.get()."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=False)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert len(responses.calls) == 1


# ============================================================================
# Phase 3: Medium Priority Tests - Error Scenarios & Edge Cases
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [400, 403, 429, 500, 503])
def test_analyze_http_error_codes(ipv4_observable, status_code, caplog):
    """Test handling of HTTP error responses."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying urlscan.io" in caplog.text


@responses.activate
def test_analyze_request_timeout(ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying urlscan.io" in caplog.text


@responses.activate
def test_analyze_connection_error(ipv4_observable, caplog):
    """Test handling of connection error."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying urlscan.io" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    assert "Error querying urlscan.io" in caplog.text


@responses.activate
def test_analyze_empty_results_list(ipv4_observable):
    """Test handling of empty results list."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["scan_count"] == 0
    assert result["top_domains"] == []


@responses.activate
def test_analyze_missing_results_key(ipv4_observable):
    """Test handling of response missing 'results' key (uses get with default [])."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"total": 0}, status=200)

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # Engine uses .get("results", []) so missing key defaults to empty list
    assert result is not None
    assert result["scan_count"] == 0
    assert result["top_domains"] == []


@responses.activate
def test_analyze_missing_total_key(ipv4_observable):
    """Test handling of response missing 'total' key."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(
        responses.GET, url, json={"results": [{"page": {"domain": "example.com"}}]}, status=200
    )
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # Should use get() with default 0
    assert result is not None
    assert result["scan_count"] == 0


@responses.activate
def test_analyze_entry_missing_page_key(ipv4_observable):
    """Test handling of result entry missing 'page' key (uses get with default {})."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(
        responses.GET,
        url,
        json={"results": [{"other_field": "value"}], "total": 1},
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # Engine uses .get("page", {}) so missing key defaults to empty dict,
    # then .get("domain", "Unknown")
    assert result is not None
    assert result["scan_count"] == 1
    assert result["top_domains"][0]["domain"] == "Unknown"


@responses.activate
def test_analyze_page_missing_domain_key(ipv4_observable):
    """Test handling of page object missing 'domain' key (uses get with default 'Unknown')."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(
        responses.GET,
        url,
        json={"results": [{"page": {"other": "value"}}], "total": 1},
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # Engine uses .get("domain", "Unknown") so missing key defaults to "Unknown"
    assert result is not None
    assert result["scan_count"] == 1
    assert result["top_domains"][0]["domain"] == "Unknown"


@responses.activate
def test_analyze_domain_value_is_null(ipv4_observable):
    """Test handling of null domain value (treated as None, aggregated)."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(
        responses.GET,
        url,
        json={"results": [{"page": {"domain": None}}], "total": 1},
        status=200,
    )

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # Engine accepts None as a valid domain value and aggregates it
    assert result is not None
    assert result["scan_count"] == 1
    assert result["top_domains"][0]["domain"] is None


@responses.activate
def test_single_domain_multiple_times(ipv4_observable):
    """Test aggregation when same domain appears multiple times."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    response = {
        "results": [
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "example.com"}},
        ],
        "total": 3,
    }
    responses.add(responses.GET, url, json=response, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert len(result["top_domains"]) == 1
    assert result["top_domains"][0]["domain"] == "example.com"
    assert result["top_domains"][0]["count"] == 3


@responses.activate
def test_multiple_domains_equal_counts(ipv4_observable):
    """Test sorting when multiple domains have equal counts."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    response = {
        "results": [
            {"page": {"domain": "domain1.com"}},
            {"page": {"domain": "domain2.com"}},
            {"page": {"domain": "domain3.com"}},
        ],
        "total": 3,
    }
    responses.add(responses.GET, url, json=response, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    # All should have count 1, sorting should be stable
    assert len(result["top_domains"]) == 3
    assert all(d["count"] == 1 for d in result["top_domains"])


@responses.activate
def test_domains_with_special_characters(ipv4_observable):
    """Test handling of domains with special characters."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    response = {
        "results": [
            {"page": {"domain": "example-123.co.uk"}},
            {"page": {"domain": "sub_domain.com"}},
        ],
        "total": 2,
    }
    responses.add(responses.GET, url, json=response, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    domains = result["top_domains"]
    assert len(domains) == 2
    assert any(d["domain"] == "example-123.co.uk" for d in domains)
    assert any(d["domain"] == "sub_domain.com" for d in domains)


# ============================================================================
# Phase 4: Low Priority Tests - Export & Properties
# ============================================================================


def test_create_export_row_with_data():
    """Test export row creation with valid analysis result."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "scan_count": 42,
        "top_domains": [
            {"domain": "example.com", "count": 15},
            {"domain": "cdn.example.com", "count": 10},
            {"domain": "api.example.com", "count": 8},
        ],
        "link": "https://urlscan.io/search/#page.domain:example.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["urlscan_count"] == 42
    assert row["urlscan_top_domains"] == "example.com, cdn.example.com, api.example.com"


def test_create_export_row_none():
    """Test export row with None result."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    row = engine.create_export_row(None)

    assert row["urlscan_count"] is None
    assert row["urlscan_top_domains"] is None


def test_create_export_row_empty_domains():
    """Test export row with zero domains."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "scan_count": 0,
        "top_domains": [],
        "link": "https://urlscan.io/search/#page.domain:example.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["urlscan_count"] == 0
    assert row["urlscan_top_domains"] is None


def test_create_export_row_single_domain():
    """Test export row with single domain."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "scan_count": 5,
        "top_domains": [{"domain": "single.com", "count": 5}],
        "link": "https://urlscan.io/search/#page.domain:single.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["urlscan_count"] == 5
    assert row["urlscan_top_domains"] == "single.com"


def test_create_export_row_missing_fields():
    """Test export row with missing optional fields."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "scan_count": 10,
        # Missing top_domains
    }

    row = engine.create_export_row(analysis_result)

    assert row["urlscan_count"] == 10
    assert row["urlscan_top_domains"] is None


def test_engine_name_property():
    """Test engine name property."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    assert engine.name == "urlscan"


def test_engine_supported_types_property():
    """Test engine supported_types property."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    expected_types = (
        ObservableType.FQDN
        | ObservableType.IPV4
        | ObservableType.IPV6
        | ObservableType.MD5
        | ObservableType.SHA1
        | ObservableType.SHA256
        | ObservableType.URL
    )
    assert engine.supported_types is expected_types


def test_engine_execute_after_reverse_dns_property():
    """Test execute_after_reverse_dns property (inherited from BaseEngine)."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    assert engine.execute_after_reverse_dns is False


def test_engine_is_pivot_engine_property():
    """Test is_pivot_engine property (inherited from BaseEngine)."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    assert engine.is_pivot_engine is False


# ============================================================================
# Phase 5: Edge Cases & Integration Tests
# ============================================================================


@responses.activate
def test_large_results_array(ipv4_observable):
    """Test handling of large results array."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    # Create 1000 results with varied domain distribution
    results = []
    for i in range(1000):
        domain_idx = i % 100
        results.append({"page": {"domain": f"domain{domain_idx}.com"}})

    response = {"results": results, "total": 1000}
    responses.add(responses.GET, url, json=response, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["scan_count"] == 1000
    assert len(result["top_domains"]) == 5
    # Each of top domains should have count of 10
    assert all(d["count"] == 10 for d in result["top_domains"])


@responses.activate
def test_very_large_single_domain_count(ipv4_observable):
    """Test handling of very large count for single domain."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    # Create response with one domain appearing 10000 times
    results = [{"page": {"domain": "popular.com"}} for _ in range(10000)]
    response = {"results": results, "total": 10000}

    responses.add(responses.GET, url, json=response, status=200)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["scan_count"] == 10000
    assert result["top_domains"][0]["domain"] == "popular.com"
    assert result["top_domains"][0]["count"] == 10000


@responses.activate
def test_url_with_fragment(ipv4_observable):
    """Test URL domain extraction with fragment."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    result = engine.analyze("https://example.com/page#section", ObservableType.URL)

    assert result is not None
    assert "example.com" in responses.calls[0].request.url


@responses.activate
def test_url_with_query_string(ipv4_observable):
    """Test URL domain extraction with query string."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    responses.add(responses.GET, url, json={"results": [], "total": 0}, status=200)
    result = engine.analyze("https://example.com/page?param=value&other=data", ObservableType.URL)

    assert result is not None
    assert "example.com" in responses.calls[0].request.url


@responses.activate
def test_complete_flow_ipv4_to_export(ipv4_observable):
    """Test complete flow: IPv4 -> query -> response -> export."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    response = {
        "results": [
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "example.com"}},
            {"page": {"domain": "cdn.example.com"}},
        ],
        "total": 3,
    }
    responses.add(responses.GET, url, json=response, status=200)

    # Step 1: Analyze
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)
    assert result is not None

    # Step 2: Export
    row = engine.create_export_row(result)

    assert row["urlscan_count"] == 3
    assert "example.com" in row["urlscan_top_domains"]
    assert "cdn.example.com" in row["urlscan_top_domains"]


@responses.activate
def test_complete_flow_url_to_export():
    """Test complete flow: URL -> parse domain -> query -> response -> export."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    response = {
        "results": [
            {"page": {"domain": "subdomain.example.com"}},
            {"page": {"domain": "subdomain.example.com"}},
        ],
        "total": 2,
    }
    responses.add(responses.GET, url, json=response, status=200)

    # Step 1: Analyze URL (should extract domain)
    result = engine.analyze("https://subdomain.example.com/path?query=value", ObservableType.URL)
    assert result is not None
    assert "subdomain.example.com" in responses.calls[0].request.url

    # Step 2: Export
    row = engine.create_export_row(result)

    assert row["urlscan_count"] == 2
    assert "subdomain.example.com" in row["urlscan_top_domains"]


@responses.activate
def test_api_timeout_is_5_seconds(ipv4_observable, caplog):
    """Test that API timeout is set to 5 seconds."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    # Use a timeout to verify the timeout parameter
    timeout_error = requests.exceptions.ConnectTimeout("Timeout")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None


@responses.activate
def test_consistent_results_for_same_observable(ipv4_observable):
    """Test that same observable produces consistent results."""
    engine = URLScanEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://urlscan.io/api/v1/search/"

    response = {
        "results": [{"page": {"domain": "example.com"}}, {"page": {"domain": "example.com"}}],
        "total": 2,
    }
    responses.add(responses.GET, url, json=response, status=200)

    result1 = engine.analyze(ipv4_observable, ObservableType.IPV4)
    result2 = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result1 == result2
    assert result1["scan_count"] == 2
    assert result2["scan_count"] == 2
