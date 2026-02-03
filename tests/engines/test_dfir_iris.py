import json
import logging

import pytest
import requests
import responses

from engines.dfir_iris import DFIRIrisEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_both_keys():
    s = Secrets()
    s.dfir_iris_api_key = "test_api_key_12345"
    s.dfir_iris_url = "https://dfir-iris.example.com"
    return s


@pytest.fixture
def secrets_without_api_key():
    s = Secrets()
    s.dfir_iris_api_key = ""
    s.dfir_iris_url = "https://dfir-iris.example.com"
    return s


@pytest.fixture
def secrets_without_url():
    s = Secrets()
    s.dfir_iris_api_key = "test_api_key_12345"
    s.dfir_iris_url = ""
    return s


@pytest.fixture
def ipv4_observable():
    return "192.168.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:db8::1"


@pytest.fixture
def md5_observable():
    return "5d41402abc4b2a76b9719d911017c592"


@pytest.fixture
def sha1_observable():
    return "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"


@pytest.fixture
def sha256_observable():
    return "2c26b46911185131006ba5991d4e39ffe58fc1ed"


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def url_observable():
    return "https://example.com/path"


@pytest.fixture
def bogon_observable():
    return "127.0.0.1"


# ============================================================================
# High Priority: Credentials + Success Paths
# ============================================================================


@responses.activate
def test_analyze_success_ipv4_with_credentials(secrets_with_both_keys, ipv4_observable):
    """Test successful analysis of IPv4 with credentials."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {
        "data": [
            {"case_id": 1, "case_name": "Case 1"},
            {"case_id": 2, "case_name": "Case 2"},
        ]
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["reports"] == 2
    assert len(result["links"]) == 2
    # Verify both case IDs appear in the links
    for cid in [1, 2]:
        assert any(f"cid={cid}" in link for link in result["links"])


@responses.activate
def test_analyze_missing_api_key(secrets_without_api_key, ipv4_observable, caplog):
    """Test behavior when API key is missing."""
    engine = DFIRIrisEngine(secrets_without_api_key, proxies={}, ssl_verify=True)
    url = f"{secrets_without_api_key.dfir_iris_url}/search?cid=1"

    # With empty API key, auth header will be "Bearer " (invalid)
    # API should reject it with 401
    responses.add(responses.POST, url, json={"error": "unauthorized"}, status=401)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying DFIR-IRIS" in caplog.text


@responses.activate
def test_analyze_missing_iris_url(secrets_without_url, ipv4_observable, caplog):
    """Test behavior when DFIR-IRIS URL is missing."""
    engine = DFIRIrisEngine(secrets_without_url, proxies={}, ssl_verify=True)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    # URL construction will fail with empty URL
    assert result is None
    assert "Error querying DFIR-IRIS" in caplog.text


@responses.activate
def test_analyze_unauthorized_401(secrets_with_both_keys, ipv4_observable, caplog):
    """Test handling of 401 Unauthorized response."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    responses.add(responses.POST, url, json={"error": "unauthorized"}, status=401)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying DFIR-IRIS" in caplog.text


@responses.activate
def test_analyze_forbidden_403(secrets_with_both_keys, ipv4_observable, caplog):
    """Test handling of 403 Forbidden response."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    responses.add(responses.POST, url, json={"error": "forbidden"}, status=403)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying DFIR-IRIS" in caplog.text


@responses.activate
def test_analyze_response_missing_data_key(secrets_with_both_keys, ipv4_observable):
    """Test handling of valid 200 response missing 'data' key."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"error": "No data"}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_response_empty_data(secrets_with_both_keys, ipv4_observable):
    """Test handling of response with empty data array."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": []}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None


@responses.activate
def test_analyze_success_with_duplicate_links(secrets_with_both_keys, ipv4_observable):
    """Test that duplicate case_ids are deduplicated."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {
        "data": [
            {"case_id": 1, "case_name": "Case 1"},
            {"case_id": 2, "case_name": "Case 2"},
            {"case_id": 1, "case_name": "Case 1 Duplicate"},
        ]
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Should only have 2 unique links even though 3 case_ids
    assert result["reports"] == 2
    assert len(result["links"]) == 2


# ============================================================================
# Medium Priority: Observable Types + Wildcard Patterns
# ============================================================================


@responses.activate
def test_analyze_ipv4_prefix_wildcard(secrets_with_both_keys, ipv4_observable):
    """Test that IPv4 uses prefix wildcard pattern (%value)."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Verify the request body contained prefix wildcard
    request_body = json.loads(responses.calls[0].request.body)
    assert request_body["search_value"] == f"%{ipv4_observable}"
    assert request_body["search_type"] == "ioc"


@responses.activate
def test_analyze_ipv6_prefix_wildcard(secrets_with_both_keys, ipv6_observable):
    """Test that IPv6 uses prefix wildcard pattern (%value)."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable, "IPv6")

    assert result is not None
    request_body = json.loads(responses.calls[0].request.body)
    assert request_body["search_value"] == f"%{ipv6_observable}"


@responses.activate
def test_analyze_md5_prefix_wildcard(secrets_with_both_keys, md5_observable):
    """Test that MD5 uses prefix wildcard pattern (%value)."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(md5_observable, "MD5")

    assert result is not None
    request_body = json.loads(responses.calls[0].request.body)
    assert request_body["search_value"] == f"%{md5_observable}"


@responses.activate
def test_analyze_sha1_prefix_wildcard(secrets_with_both_keys, sha1_observable):
    """Test that SHA1 uses prefix wildcard pattern (%value)."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(sha1_observable, "SHA1")

    assert result is not None
    request_body = json.loads(responses.calls[0].request.body)
    assert request_body["search_value"] == f"%{sha1_observable}"


@responses.activate
def test_analyze_sha256_prefix_wildcard(secrets_with_both_keys, sha256_observable):
    """Test that SHA256 uses prefix wildcard pattern (%value)."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(sha256_observable, "SHA256")

    assert result is not None
    request_body = json.loads(responses.calls[0].request.body)
    assert request_body["search_value"] == f"%{sha256_observable}"


@responses.activate
def test_analyze_bogon_prefix_wildcard(secrets_with_both_keys, bogon_observable):
    """Test that BOGON uses prefix wildcard pattern (%value)."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(bogon_observable, "BOGON")

    assert result is not None
    request_body = json.loads(responses.calls[0].request.body)
    assert request_body["search_value"] == f"%{bogon_observable}"


@responses.activate
def test_analyze_fqdn_suffix_wildcard(secrets_with_both_keys, fqdn_observable):
    """Test that FQDN uses suffix wildcard pattern (value%)."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    request_body = json.loads(responses.calls[0].request.body)
    # FQDN should use suffix wildcard (different from IPs/hashes!)
    assert request_body["search_value"] == f"{fqdn_observable}%"


@responses.activate
def test_analyze_url_suffix_wildcard(secrets_with_both_keys, url_observable):
    """Test that URL uses suffix wildcard pattern (value%)."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(url_observable, "URL")

    assert result is not None
    request_body = json.loads(responses.calls[0].request.body)
    # URL should use suffix wildcard (different from IPs/hashes!)
    assert request_body["search_value"] == f"{url_observable}%"


# ============================================================================
# Medium Priority: Error Handling + Response Processing
# ============================================================================


@responses.activate
def test_analyze_http_error_500(secrets_with_both_keys, ipv4_observable, caplog):
    """Test handling of HTTP 500 Internal Server Error."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    responses.add(responses.POST, url, json={"error": "server error"}, status=500)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying DFIR-IRIS" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(secrets_with_both_keys, ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON response."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    responses.add(responses.POST, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying DFIR-IRIS" in caplog.text


@responses.activate
def test_analyze_connection_error(secrets_with_both_keys, ipv4_observable, caplog):
    """Test handling of connection timeout."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.POST, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying DFIR-IRIS" in caplog.text


@responses.activate
def test_analyze_multiple_cases_sorted(secrets_with_both_keys, ipv4_observable):
    """Test that multiple case results are sorted alphabetically."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    # Provide unsorted case IDs
    mock_resp = {
        "data": [
            {"case_id": 10, "case_name": "Case 10"},
            {"case_id": 5, "case_name": "Case 5"},
            {"case_id": 1, "case_name": "Case 1"},
            {"case_id": 20, "case_name": "Case 20"},
        ]
    }

    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["reports"] == 4
    # Links should be sorted alphabetically
    links = result["links"]
    assert links == sorted(links)


@responses.activate
def test_analyze_request_timeout(secrets_with_both_keys, ipv4_observable, caplog):
    """Test handling of request timeout."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    timeout_error = requests.exceptions.ReadTimeout("Read timed out")
    responses.add(responses.POST, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying DFIR-IRIS" in caplog.text


# ============================================================================
# Low Priority: Export Row & Properties
# ============================================================================


@responses.activate
def test_create_export_row_with_data(secrets_with_both_keys):
    """Test export row with analysis results."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)

    analysis_result = {
        "reports": 3,
        "links": [
            "https://dfir-iris.example.com/case/ioc?cid=1",
            "https://dfir-iris.example.com/case/ioc?cid=2",
            "https://dfir-iris.example.com/case/ioc?cid=3",
        ],
    }

    row = engine.create_export_row(analysis_result)

    assert row["dfir_iris_total_count"] == 3
    assert "case/ioc?cid=1" in row["dfir_iris_link"]
    assert "case/ioc?cid=2" in row["dfir_iris_link"]
    assert "case/ioc?cid=3" in row["dfir_iris_link"]
    # Should be comma-separated
    assert ", " in row["dfir_iris_link"]


def test_create_export_row_with_none():
    """Test export row with None analysis result."""
    engine = DFIRIrisEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["dfir_iris_total_count"] is None
    assert row["dfir_iris_link"] is None


def test_create_export_row_empty_links():
    """Test export row with empty links list."""
    engine = DFIRIrisEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "reports": 0,
        "links": [],
    }

    row = engine.create_export_row(analysis_result)

    assert row["dfir_iris_total_count"] == 0
    assert row["dfir_iris_link"] is None


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = DFIRIrisEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "dfir_iris"
    expected_types = ["BOGON", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]
    assert engine.supported_types == expected_types
    assert engine.execute_after_reverse_dns is False
    assert engine.is_pivot_engine is False


@responses.activate
def test_analyze_authorization_header_format(secrets_with_both_keys, ipv4_observable):
    """Test that Authorization header is properly formatted."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Verify Authorization header format
    auth_header = responses.calls[0].request.headers.get("Authorization")
    assert auth_header == f"Bearer {secrets_with_both_keys.dfir_iris_api_key}"


@responses.activate
def test_analyze_content_type_header(secrets_with_both_keys, ipv4_observable):
    """Test that Content-Type header is set to application/json."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Verify Content-Type header
    content_type = responses.calls[0].request.headers.get("Content-Type")
    assert content_type == "application/json"


@responses.activate
def test_analyze_url_includes_cid_parameter(secrets_with_both_keys, ipv4_observable):
    """Test that URL includes cid=1 query parameter."""
    engine = DFIRIrisEngine(secrets_with_both_keys, proxies={}, ssl_verify=True)
    url = f"{secrets_with_both_keys.dfir_iris_url}/search?cid=1"

    mock_resp = {"data": [{"case_id": 1}]}
    responses.add(responses.POST, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Verify the request was made to the correct URL
    assert "cid=1" in responses.calls[0].request.url
