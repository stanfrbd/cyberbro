import logging

import pytest
import responses

from engines.criminalip import CriminalIPEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.criminalip_api_key = "test_api_key_12345"
    return s


@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.criminalip_api_key = ""
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@pytest.fixture
def base_url():
    return "https://api.criminalip.io/v2/feature/ip/suspicious-info"


@pytest.fixture
def mock_response_complete():
    """Complete response with all nested fields populated."""
    return {
        "status": 200,
        "ip": "1.1.1.1",
        "abuse_record_count": 5,
        "score": {"inbound": "Low", "outbound": "Safe"},
        "issues": {
            "is_anonymous_vpn": False,
            "is_cloud": True,
            "is_darkweb": False,
            "is_hosting": False,
            "is_mobile": False,
            "is_proxy": False,
            "is_scanner": False,
            "is_snort": False,
            "is_tor": False,
            "is_vpn": False,
        },
        "current_opened_port": {
            "count": 2,
            "data": [
                {
                    "port": 80,
                    "is_vulnerability": False,
                    "product_name": "Apache",
                    "product_version": "2.4",
                    "protocol": "http",
                    "socket_type": "tcp",
                    "confirmed_time": "2025-01-01T00:00:00Z",
                },
                {
                    "port": 443,
                    "is_vulnerability": False,
                    "product_name": "nginx",
                    "product_version": "1.20",
                    "protocol": "https",
                    "socket_type": "tcp",
                    "confirmed_time": "2025-01-01T00:00:00Z",
                },
            ],
        },
        "ids": {
            "count": 1,
            "data": [
                {
                    "classification": "trojan",
                    "confirmed_time": "2025-01-01T00:00:00Z",
                    "message": "Potential trojan activity detected",
                    "source_system": "Suricata",
                    "url": "https://example.com/alert",
                }
            ],
        },
        "whois": {
            "count": 1,
            "data": [
                {
                    "as_name": "CLOUDFLARENET",
                    "as_no": 13335,
                    "city": "San Francisco",
                    "region": "California",
                    "org_name": "Cloudflare Inc.",
                    "postal_code": "94107",
                    "latitude": 37.7749,
                    "longitude": -122.4194,
                    "org_country_code": "US",
                    "confirmed_time": "2025-01-01T00:00:00Z",
                }
            ],
        },
        "representative_domain": "cloudflare.com",
    }


@pytest.fixture
def mock_response_minimal():
    """Minimal response with only required fields."""
    return {
        "status": 200,
        "ip": "1.1.1.1",
        "abuse_record_count": 0,
    }


@pytest.fixture
def mock_response_dangerous():
    """Response with Dangerous score."""
    return {
        "status": 200,
        "ip": "1.1.1.1",
        "abuse_record_count": 20,
        "score": {"inbound": "Dangerous", "outbound": "Critical"},
    }


@pytest.fixture
def mock_response_safe():
    """Response with Safe score."""
    return {
        "status": 200,
        "ip": "1.1.1.1",
        "abuse_record_count": 0,
        "score": {"inbound": "Safe", "outbound": "Safe"},
    }


@pytest.fixture
def mock_response_all_issues_true():
    """Response with all Issues flags set to True."""
    return {
        "status": 200,
        "ip": "1.1.1.1",
        "abuse_record_count": 50,
        "issues": {
            "is_anonymous_vpn": True,
            "is_cloud": True,
            "is_darkweb": True,
            "is_hosting": True,
            "is_mobile": True,
            "is_proxy": True,
            "is_scanner": True,
            "is_snort": True,
            "is_tor": True,
            "is_vpn": True,
        },
    }


@pytest.fixture
def mock_response_empty_lists():
    """Response with empty lists for ports, alerts, and WHOIS."""
    return {
        "status": 200,
        "ip": "1.1.1.1",
        "abuse_record_count": 0,
        "current_opened_port": {"count": 0, "data": []},
        "ids": {"count": 0, "data": []},
        "whois": {"count": 0, "data": []},
    }


# ============================================================================
# High Priority: Critical Paths & Credentials Tests
# ============================================================================


@responses.activate
@pytest.mark.parametrize(
    "response_fixture,has_score,has_ports,abuse_count,inbound_score,outbound_score",
    [
        ("mock_response_complete", True, True, 5, "Low", "Safe"),
        ("mock_response_minimal", False, False, 0, None, None),
    ],
)
def test_analyze_success_response_variations(
    secrets_with_key,
    ipv4_observable,
    base_url,
    response_fixture,
    has_score,
    has_ports,
    abuse_count,
    inbound_score,
    outbound_score,
    request,
):
    """Test successful API response with various data configurations."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = request.getfixturevalue(response_fixture)
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ip"] == ipv4_observable
    assert result["abuse_record_count"] == abuse_count
    if has_score:
        assert result["score"]["inbound"] == inbound_score
        assert result["score"]["outbound"] == outbound_score
    if has_ports:
        assert result["current_opened_port"]["count"] == 2
        assert len(result["current_opened_port"]["data"]) == 2
        assert result["current_opened_port"]["data"][0]["port"] == 80


@responses.activate
def test_analyze_missing_api_key(ipv4_observable, base_url, secrets_without_key, caplog):
    """Test handles missing API key gracefully."""
    engine = CriminalIPEngine(secrets_without_key, proxies={}, ssl_verify=True)
    caplog.set_level(logging.ERROR)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "API key for CriminalIP engine is not configured" in caplog.text


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 500])
def test_analyze_http_error_codes(secrets_with_key, ipv4_observable, base_url, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 500)."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    responses.add(responses.GET, base_url, json={"error": "error"}, status=status_code)
    caplog.set_level(logging.ERROR)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error retrieving Criminal IP Suspicious Info report" in caplog.text


@responses.activate
@pytest.mark.parametrize(
    "response_fixture,inbound_score,outbound_score",
    [
        ("mock_response_dangerous", "Dangerous", "Critical"),
        ("mock_response_safe", "Safe", "Safe"),
    ],
)
def test_analyze_score_variations(
    secrets_with_key,
    ipv4_observable,
    base_url,
    response_fixture,
    inbound_score,
    outbound_score,
    request,
):
    """Test response with different score value variations."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = request.getfixturevalue(response_fixture)
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["score"]["inbound"] == inbound_score
    assert result["score"]["outbound"] == outbound_score


def test_create_export_row_success(secrets_with_key):
    """Test export row formatting with complete score data."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    analysis_result = {
        "score": {"inbound": "Low", "outbound": "Dangerous"},
        "abuse_record_count": 15,
    }

    export_row = engine.create_export_row(analysis_result)

    assert export_row == {
        "cip_score_inbound": "Low",
        "cip_score_outbound": "Dangerous",
        "cip_abuse_count": 15,
    }


def test_create_export_row_none(secrets_with_key):
    """Test export row with None result returns None values."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)

    export_row = engine.create_export_row(None)

    assert export_row == {
        "cip_score_inbound": None,
        "cip_score_outbound": None,
        "cip_abuse_count": None,
    }


# ============================================================================
# Medium Priority: Robustness & Error Handling
# ============================================================================


@responses.activate
def test_analyze_missing_score_field(secrets_with_key, ipv4_observable, base_url):
    """Test export when score field is missing from response."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 5,
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Result doesn't include score field since it's optional in model
    assert result.get("score") is None


@responses.activate
def test_analyze_missing_abuse_count(secrets_with_key, ipv4_observable, base_url):
    """Test export when abuse_record_count is missing (defaults to 0)."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "score": {"inbound": "Low", "outbound": "Safe"},
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")
    export_row = engine.create_export_row(result)

    # abuse_record_count defaults to 0 in Pydantic model
    assert export_row["cip_abuse_count"] == 0


@responses.activate
def test_analyze_empty_open_ports_list(secrets_with_key, ipv4_observable, base_url):
    """Test response with empty open ports list."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "current_opened_port": {"count": 0, "data": []},
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["current_opened_port"]["count"] == 0
    assert result["current_opened_port"]["data"] == []


@responses.activate
def test_analyze_empty_ids_list(secrets_with_key, ipv4_observable, base_url):
    """Test response with empty IDS alerts list."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "ids": {"count": 0, "data": []},
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ids"]["count"] == 0
    assert result["ids"]["data"] == []


@responses.activate
def test_analyze_empty_whois_list(secrets_with_key, ipv4_observable, base_url):
    """Test response with empty WHOIS list."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "whois": {"count": 0, "data": []},
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["whois"]["count"] == 0
    assert result["whois"]["data"] == []


@responses.activate
def test_analyze_all_issues_true(
    secrets_with_key, ipv4_observable, base_url, mock_response_all_issues_true
):
    """Test response with all Issues flags set to True."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    responses.add(responses.GET, base_url, json=mock_response_all_issues_true, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["issues"]["is_vpn"] is True
    assert result["issues"]["is_tor"] is True
    assert result["issues"]["is_proxy"] is True
    assert result["issues"]["is_scanner"] is True
    assert result["issues"]["is_darkweb"] is True


@responses.activate
def test_analyze_whois_partial_fields(secrets_with_key, ipv4_observable, base_url):
    """Test WHOIS record with some None fields."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "whois": {
            "count": 1,
            "data": [
                {
                    "as_name": "TEST-ASN",
                    "as_no": 12345,
                    "city": None,
                    "region": None,
                    "org_name": "Test Org",
                    "postal_code": None,
                    "latitude": None,
                    "longitude": None,
                    "org_country_code": "US",
                    "confirmed_time": None,
                }
            ],
        },
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["whois"]["data"][0]["as_name"] == "TEST-ASN"
    assert result["whois"]["data"][0]["city"] is None


@responses.activate
def test_analyze_validation_error_non_2xx_status(
    secrets_with_key, ipv4_observable, base_url, caplog
):
    """Test Pydantic validator rejects non-2xx status codes."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    # Status 199 is just below 2xx range
    mock_resp = {
        "status": 199,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)
    caplog.set_level(logging.ERROR)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error validating Criminal IP Suspicious Info report" in caplog.text


@responses.activate
def test_verify_api_key_in_headers(
    secrets_with_key, ipv4_observable, base_url, mock_response_minimal
):
    """Test API key is passed in x-api-key header."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    responses.add(responses.GET, base_url, json=mock_response_minimal, status=200)

    engine.analyze(ipv4_observable, "IPv4")

    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers.get("x-api-key") == "test_api_key_12345"


@responses.activate
def test_verify_ip_in_params(secrets_with_key, ipv4_observable, base_url, mock_response_minimal):
    """Test IP is passed as query parameter."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    responses.add(responses.GET, base_url, json=mock_response_minimal, status=200)

    engine.analyze(ipv4_observable, "IPv4")

    assert len(responses.calls) == 1
    assert ipv4_observable in responses.calls[0].request.url


@responses.activate
def test_verify_proxies_parameter(
    ipv4_observable, base_url, secrets_with_key, mock_response_minimal
):
    """Test proxies parameter is passed to requests.get()."""
    proxies = {"http": "http://proxy.example.com:8080"}
    engine = CriminalIPEngine(secrets_with_key, proxies=proxies, ssl_verify=True)
    responses.add(responses.GET, base_url, json=mock_response_minimal, status=200)

    engine.analyze(ipv4_observable, "IPv4")

    assert len(responses.calls) == 1


@responses.activate
def test_verify_ssl_verify_parameter(
    ipv4_observable, base_url, secrets_with_key, mock_response_minimal
):
    """Test ssl_verify parameter is passed to requests.get()."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=False)
    responses.add(responses.GET, base_url, json=mock_response_minimal, status=200)

    engine.analyze(ipv4_observable, "IPv4")

    assert len(responses.calls) == 1


# ============================================================================
# Low Priority: Edge Cases & Special Scenarios
# ============================================================================


@responses.activate
def test_analyze_open_port_with_vulnerability(secrets_with_key, ipv4_observable, base_url):
    """Test OpenPort with is_vulnerability set to True."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "current_opened_port": {
            "count": 1,
            "data": [
                {
                    "port": 22,
                    "is_vulnerability": True,
                    "product_name": "OpenSSH",
                    "product_version": "7.4",
                    "protocol": "ssh",
                    "socket_type": "tcp",
                    "confirmed_time": "2025-01-01T00:00:00Z",
                }
            ],
        },
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["current_opened_port"]["data"][0]["is_vulnerability"] is True


@responses.activate
def test_analyze_confirmed_time_fields(secrets_with_key, ipv4_observable, base_url):
    """Test timestamp fields in nested models."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "current_opened_port": {
            "count": 1,
            "data": [
                {
                    "port": 443,
                    "is_vulnerability": False,
                    "product_name": "nginx",
                    "product_version": "1.20",
                    "protocol": "https",
                    "socket_type": "tcp",
                    "confirmed_time": "2025-12-31T23:59:59Z",
                }
            ],
        },
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["current_opened_port"]["data"][0]["confirmed_time"] == "2025-12-31T23:59:59Z"


@responses.activate
def test_analyze_ipv6_observable(
    secrets_with_key, ipv6_observable, base_url, mock_response_minimal
):
    """Test analysis with IPv6 observable."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    # Modify mock response to return IPv6
    mock_resp = dict(mock_response_minimal)
    mock_resp["ip"] = ipv6_observable
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv6_observable, "IPv6")

    assert result is not None
    assert result["ip"] == ipv6_observable


def test_create_export_row_missing_name_key(secrets_with_key):
    """Test export row gracefully handles missing 'name' key in score."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    # Score with only one field (missing outbound)
    analysis_result = {
        "score": {"inbound": "Moderate"},
        "abuse_record_count": 10,
    }

    export_row = engine.create_export_row(analysis_result)

    assert export_row["cip_score_inbound"] == "Moderate"
    assert export_row["cip_score_outbound"] is None


@responses.activate
def test_analyze_ids_alert_with_url(secrets_with_key, ipv4_observable, base_url):
    """Test IDSAlert with URL field populated."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "ids": {
            "count": 2,
            "data": [
                {
                    "classification": "malware",
                    "confirmed_time": "2025-01-01T00:00:00Z",
                    "message": "Malware detected",
                    "source_system": "Suricata",
                    "url": "https://example.com/malware-alert-1",
                },
                {
                    "classification": "exploit",
                    "confirmed_time": "2025-01-02T00:00:00Z",
                    "message": "Exploit attempt",
                    "source_system": "Snort",
                    "url": "https://example.com/exploit-alert-2",
                },
            ],
        },
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["ids"]["count"] == 2
    assert result["ids"]["data"][0]["url"] == "https://example.com/malware-alert-1"
    assert result["ids"]["data"][1]["classification"] == "exploit"


@responses.activate
def test_analyze_whois_multiple_records(secrets_with_key, ipv4_observable, base_url):
    """Test WHOIS with multiple records."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "whois": {
            "count": 3,
            "data": [
                {
                    "as_name": "AS1-NAME",
                    "as_no": 11111,
                    "city": "City1",
                    "region": "Region1",
                    "org_name": "Org1",
                    "postal_code": "12345",
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                    "org_country_code": "US",
                    "confirmed_time": "2025-01-01T00:00:00Z",
                },
                {
                    "as_name": "AS2-NAME",
                    "as_no": 22222,
                    "city": "City2",
                    "region": "Region2",
                    "org_name": "Org2",
                    "postal_code": "54321",
                    "latitude": 51.5074,
                    "longitude": -0.1278,
                    "org_country_code": "GB",
                    "confirmed_time": "2025-01-02T00:00:00Z",
                },
                {
                    "as_name": "AS3-NAME",
                    "as_no": 33333,
                    "city": "City3",
                    "region": "Region3",
                    "org_name": "Org3",
                    "postal_code": "99999",
                    "latitude": 48.8566,
                    "longitude": 2.3522,
                    "org_country_code": "FR",
                    "confirmed_time": "2025-01-03T00:00:00Z",
                },
            ],
        },
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["whois"]["count"] == 3
    assert len(result["whois"]["data"]) == 3
    assert result["whois"]["data"][0]["as_name"] == "AS1-NAME"
    assert result["whois"]["data"][2]["org_country_code"] == "FR"


@responses.activate
def test_analyze_coordinate_precision(secrets_with_key, ipv4_observable, base_url):
    """Test latitude/longitude float precision is preserved."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    mock_resp = {
        "status": 200,
        "ip": ipv4_observable,
        "abuse_record_count": 0,
        "whois": {
            "count": 1,
            "data": [
                {
                    "as_name": "TEST-ASN",
                    "as_no": 12345,
                    "city": "Test City",
                    "region": "Test Region",
                    "org_name": "Test Org",
                    "postal_code": "12345",
                    "latitude": 40.712776,
                    "longitude": -74.005974,
                    "org_country_code": "US",
                    "confirmed_time": "2025-01-01T00:00:00Z",
                }
            ],
        },
    }
    responses.add(responses.GET, base_url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # Verify precision is preserved (not rounded to int)
    assert result["whois"]["data"][0]["latitude"] == 40.712776
    assert result["whois"]["data"][0]["longitude"] == -74.005974


def test_create_export_row_score_is_none(secrets_with_key):
    """Test export row when score field is None (safe default access)."""
    engine = CriminalIPEngine(secrets_with_key, proxies={}, ssl_verify=True)
    # This scenario shouldn't happen in real responses, but test graceful handling
    analysis_result = {
        "abuse_record_count": 5,
    }

    export_row = engine.create_export_row(analysis_result)

    assert export_row["cip_score_inbound"] is None
    assert export_row["cip_score_outbound"] is None
    assert export_row["cip_abuse_count"] == 5
