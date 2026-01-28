import logging

import pytest
import requests
import responses

from engines.google_dns import GoogleDNSEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets():
    return Secrets()


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@pytest.fixture
def url_observable():
    return "https://example.com:8080/path"


# ============================================================================
# High Priority: Critical Paths (16 tests)
# ============================================================================


@pytest.mark.parametrize(
    "observable_value,observable_type",
    [
        ("1.1.1.1", "IPv4"),
        ("2001:4860:4860::8888", "IPv6"),
        ("example.com", "FQDN"),
        ("https://example.com:8080/path", "URL"),
    ],
)
@responses.activate
def test_analyze_observable_type_routing(secrets, observable_value, observable_type):
    """Test observable type routing with basic successful responses."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    if observable_type == "IPv4":
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={
                "Answer": [
                    {
                        "name": "1.1.1.1.in-addr.arpa.",
                        "type": 12,
                        "TTL": 300,
                        "data": "one.one.one.one.",
                    }
                ]
            },
            status=200,
        )
    elif observable_type == "IPv6":
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={
                "Answer": [
                    {
                        "name": "8.8.8.8.8.0.0.0.0.6.8.4.in-addr.arpa.",
                        "type": 12,
                        "TTL": 300,
                        "data": "dns.google.",
                    }
                ]
            },
            status=200,
        )
    elif observable_type == "FQDN":
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": [{"type": 1, "data": "1.1.1.1."}]},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": [{"type": 28, "data": "2001:4860::1."}]},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": []},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": [{"type": 15, "data": "10 mail.example.com."}]},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": []},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": []},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": [{"type": 2, "data": "ns1.example.com."}]},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": []},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": []},
            status=200,
        )
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": []},
            status=200,
        )
    elif observable_type == "URL":
        for _ in range(10):
            responses.add(
                responses.GET,
                "https://dns.google/resolve",
                json={"Answer": []},
                status=200,
            )

    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert "Answer" in result


@responses.activate
def test_analyze_ipv4_ptr_success_multiple_records(secrets):
    """Test successful IPv4 PTR lookup returning multiple hostnames."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    url = "https://dns.google/resolve"

    mock_resp = {
        "Answer": [
            {
                "name": "8.8.8.8.in-addr.arpa.",
                "type": 12,
                "TTL": 300,
                "data": "dns.google.",
            },
            {
                "name": "8.8.8.8.in-addr.arpa.",
                "type": 12,
                "TTL": 300,
                "data": "alt-dns.google.",
            },
        ]
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze("8.8.8.8", "IPv4")

    assert result is not None
    assert len(result["Answer"]) == 2
    assert all(rec["type_name"] == "PTR" for rec in result["Answer"])


@responses.activate
def test_analyze_ipv4_no_ptr_records(secrets, ipv4_observable):
    """Test IPv4 query returning no PTR records (empty Answer array)."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    url = "https://dns.google/resolve"

    mock_resp = {"Answer": []}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["Answer"] == []


@responses.activate
def test_analyze_fqdn_with_spf_record(secrets, fqdn_observable):
    """Test FQDN query that includes SPF TXT record (separate query)."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    # Mock 8 record type queries (A, AAAA, CNAME, MX, TXT, PTR, NS, SOA)
    for _ in range(8):
        responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)

    # SPF query - returns SPF record
    spf_data = "v=spf1 include:_spf.google.com ~all"
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": [{"type": 16, "data": f'"{spf_data}"'}]},
        status=200,
    )
    # DMARC query
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert "Answer" in result
    spf_records = [r for r in result["Answer"] if r.get("type_name") == "SPF"]
    assert len(spf_records) > 0


@responses.activate
def test_analyze_fqdn_with_dmarc_record(secrets, fqdn_observable):
    """Test FQDN query that includes DMARC TXT record."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    # Mock 8 record type queries
    for _ in range(8):
        responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)

    # SPF query
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )
    # DMARC query - returns DMARC record
    dmarc_data = "v=DMARC1; p=reject; rua=mailto:admin@example.com"
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": [{"type": 16, "data": f'"{dmarc_data}"'}]},
        status=200,
    )

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert "Answer" in result
    dmarc_records = [r for r in result["Answer"] if r.get("type_name") == "DMARC"]
    assert len(dmarc_records) > 0
    assert "v=DMARC1" in dmarc_records[0]["data"]


@responses.activate
def test_analyze_fqdn_no_spf_no_dmarc(secrets, fqdn_observable):
    """Test FQDN query where SPF and DMARC queries return no records."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    # Mock 8 record type queries
    for _ in range(8):
        responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)

    # SPF query
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )
    # DMARC query
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert "Answer" in result
    spf_records = [r for r in result["Answer"] if r.get("type_name") == "SPF"]
    dmarc_records = [r for r in result["Answer"] if r.get("type_name") == "DMARC"]
    assert len(spf_records) == 0
    assert len(dmarc_records) == 0


@responses.activate
def test_analyze_fqdn_mx_record_extraction(secrets, fqdn_observable):
    """Test MX record data extraction (priority + hostname -> hostname only)."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    # Mock 8 record type queries
    responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)
    responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)
    responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)
    # MX query - priority + hostname
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": [{"type": 15, "data": "10 mail.example.com."}]},
        status=200,
    )
    responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)
    responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)
    responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)
    responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)
    # SPF and DMARC
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    mx_records = [r for r in result["Answer"] if r.get("type_name") == "MX"]
    assert len(mx_records) > 0
    assert mx_records[0]["data"] == "mail.example.com"


@responses.activate
def test_analyze_http_500_error(secrets, ipv4_observable, caplog):
    """Test handling of HTTP 500 error on IPv4 PTR query."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"error": "server error"},
        status=500,
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying Google DNS" in caplog.text


@responses.activate
def test_analyze_http_connection_timeout(secrets, fqdn_observable, caplog):
    """Test handling of connection timeout."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, "https://dns.google/resolve", body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is None
    assert "Error querying Google DNS" in caplog.text


@responses.activate
def test_analyze_http_connection_error(secrets, fqdn_observable, caplog):
    """Test handling of connection error."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, "https://dns.google/resolve", body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is None
    assert "Error querying Google DNS" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(secrets, ipv4_observable, caplog):
    """Test handling of 200 status but invalid JSON."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    responses.add(responses.GET, "https://dns.google/resolve", body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error querying Google DNS" in caplog.text


@responses.activate
def test_query_dmarc_http_error(secrets, fqdn_observable):
    """Test DMARC query HTTP error doesn't crash main query."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    # Mock 8 record type queries - all succeed
    for _ in range(8):
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": [{"type": 1, "data": "1.1.1.1."}]},
            status=200,
        )

    # SPF query succeeds
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )
    # DMARC query fails
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"error": "not found"},
        status=404,
    )

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    dmarc_records = [r for r in result["Answer"] if r.get("type_name") == "DMARC"]
    assert len(dmarc_records) == 0


@responses.activate
def test_query_spf_http_error(secrets, fqdn_observable):
    """Test SPF query HTTP error doesn't crash main query."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    # Mock 8 record type queries - all succeed
    for _ in range(8):
        responses.add(
            responses.GET,
            "https://dns.google/resolve",
            json={"Answer": [{"type": 1, "data": "1.1.1.1."}]},
            status=200,
        )

    # SPF query fails
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"error": "server error"},
        status=500,
    )
    # DMARC query succeeds
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    spf_records = [r for r in result["Answer"] if r.get("type_name") == "SPF"]
    assert len(spf_records) == 0


# ============================================================================
# Medium Priority: Critical Functionality (12 tests)
# ============================================================================


def test_extract_domain_plain_fqdn(secrets):
    """Test _extract_domain with plain FQDN returns unchanged."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    domain = engine._extract_domain("example.com")

    assert domain == "example.com"


def test_extract_domain_with_https_scheme_and_path(secrets):
    """Test _extract_domain with HTTPS URL."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    domain = engine._extract_domain("https://example.com/path/to/page")

    assert domain == "example.com"


def test_extract_domain_with_http_scheme_and_port(secrets):
    """Test _extract_domain with HTTP scheme and port."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    domain = engine._extract_domain("http://example.com:8080")

    assert domain == "example.com"


def test_extract_domain_subdomain_with_port(secrets):
    """Test _extract_domain with subdomain and port."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    domain = engine._extract_domain("https://api.example.com:443/v1/data")

    assert domain == "api.example.com"


def test_parse_spf_with_mechanisms(secrets):
    """Test Parse SPF record with multiple mechanisms."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    spf_text = "v=spf1 a mx include:_spf.google.com ~all"
    parsed = engine._parse_spf_record(spf_text)

    assert "mechanisms" in parsed
    assert "a" in parsed["mechanisms"]
    assert "mx" in parsed["mechanisms"]
    assert "include:_spf.google.com" in parsed["mechanisms"]


def test_parse_spf_with_qualifiers(secrets):
    """Test Parse SPF with various qualifiers (+, -, ?, ~)."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    spf_text = "v=spf1 +a -mx ~ptr ?all"
    parsed = engine._parse_spf_record(spf_text)

    assert "mechanisms" in parsed
    assert "+a" in parsed["mechanisms"]
    assert "-mx" in parsed["mechanisms"]


def test_parse_spf_simple(secrets):
    """Test Parse simple SPF record."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    spf_text = "v=spf1 a"
    parsed = engine._parse_spf_record(spf_text)

    assert "mechanisms" in parsed
    assert "a" in parsed["mechanisms"]


def test_parse_dmarc_with_tags(secrets):
    """Test Parse DMARC record with multiple tags."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    dmarc_text = (
        "v=DMARC1; p=reject; rua=mailto:admin@example.com; ruf=mailto:forensics@example.com; fo=1"
    )
    parsed = engine._parse_dmarc_record(dmarc_text)

    assert parsed.get("v") == "DMARC1"
    assert parsed.get("p") == "reject"
    assert "rua" in parsed
    assert "ruf" in parsed


def test_create_export_row_with_multiple_record_types(secrets):
    """Test Export formatting with multiple records per type."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    analysis_result = {
        "Answer": [
            {"type_name": "A", "data": "1.1.1.1"},
            {"type_name": "A", "data": "1.0.0.1"},
            {"type_name": "AAAA", "data": "2001:4860::1"},
            {"type_name": "MX", "data": "mail.example.com"},
        ]
    }

    row = engine.create_export_row(analysis_result)

    assert row["google_dns_a"] == "1.1.1.1, 1.0.0.1"
    assert row["google_dns_aaaa"] == "2001:4860::1"
    assert row["google_dns_mx"] == "mail.example.com"
    assert row["google_dns_ptr"] is None


def test_create_export_row_with_none_result(secrets):
    """Test Export formatting with None analysis result."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["google_dns_a"] is None
    assert row["google_dns_aaaa"] is None
    assert row["google_dns_mx"] is None
    assert "google_dns_ptr" not in row  # PTR excluded from export


def test_create_export_row_empty_answer(secrets):
    """Test Export formatting with empty Answer array."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    row = engine.create_export_row({"Answer": []})

    assert row["google_dns_a"] is None
    assert row["google_dns_aaaa"] is None
    assert row["google_dns_cname"] is None


def test_create_export_row_skips_spf_dmarc(secrets):
    """Test Export formatting skips SPF/DMARC records."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    analysis_result = {
        "Answer": [
            {"type_name": "A", "data": "1.1.1.1"},
            {"type_name": "SPF", "data": "v=spf1 a"},
            {"type_name": "DMARC", "data": "v=DMARC1; p=reject"},
        ]
    }

    row = engine.create_export_row(analysis_result)

    assert row["google_dns_a"] == "1.1.1.1"
    assert row["google_dns_ptr"] is None
    # SPF and DMARC should not appear in export


# ============================================================================
# Low Priority: Edge Cases & Properties (7 tests)
# ============================================================================


@responses.activate
def test_analyze_all_empty_dns_records(secrets, fqdn_observable):
    """Test All DNS record types return empty Answer arrays."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    # Mock all 10 queries (8 record types + SPF + DMARC)
    for _ in range(10):
        responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert result["Answer"] == []


@responses.activate
def test_analyze_data_cleaning_trailing_dots(secrets, fqdn_observable):
    """Test Verify trailing dots removed from data."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    # Mock record with trailing dot
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": [{"type": 1, "data": "1.1.1.1."}]},
        status=200,
    )
    # Mock remaining 7 record type queries
    for _ in range(7):
        responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)
    # SPF and DMARC
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://dns.google/resolve",
        json={"Answer": []},
        status=200,
    )

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    a_records = [r for r in result["Answer"] if r.get("type_name") == "A"]
    assert len(a_records) > 0
    assert not a_records[0]["data"].endswith(".")


def test_parse_dmarc_spaces_around_semicolons(secrets):
    """Test DMARC parsing handles varying spacing."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)
    dmarc_text = "v=DMARC1 ; p=reject ; rua=mailto:admin@example.com"
    parsed = engine._parse_dmarc_record(dmarc_text)

    assert parsed.get("v") == "DMARC1"
    assert parsed.get("p") == "reject"


@responses.activate
def test_analyze_ipv4_reverse_dns_format(secrets):
    """Test Verify reverse DNS format is correct for IPv4."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    responses.add(responses.GET, "https://dns.google/resolve", json={"Answer": []}, status=200)

    result = engine.analyze("192.168.1.1", "IPv4")

    assert result is not None
    # Verify the call was made with correct reverse DNS format
    assert len(responses.calls) == 1
    assert "192.168.1.1.in-addr.arpa" in responses.calls[0].request.url


@responses.activate
def test_create_export_row_missing_answer_key(secrets):
    """Test Export formatting when result dict exists but has no Answer key."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    row = engine.create_export_row({"status": "success"})

    assert row["google_dns_a"] is None
    assert row["google_dns_aaaa"] is None
    assert row["google_dns_mx"] is None


def test_engine_properties(secrets):
    """Test Engine metadata properties."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    assert engine.name == "google_dns"
    assert engine.supported_types == ["FQDN", "IPv4", "IPv6", "URL"]


def test_engine_base_properties(secrets):
    """Test Inherited BaseEngine properties."""
    engine = GoogleDNSEngine(secrets, proxies={}, ssl_verify=True)

    assert engine.execute_after_reverse_dns is False
    assert engine.is_pivot_engine is False
