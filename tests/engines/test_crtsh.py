import logging

import pytest
import requests
import responses

from engines.crtsh import CrtShEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def url_observable_with_port():
    return "https://example.com:8443/api/path"


@pytest.fixture
def url_observable_without_port():
    return "https://subdomain.example.com/some/path"


@pytest.fixture
def subdomain_observable():
    return "www.example.com"


# ============================================================================
# High Priority: Critical Paths - FQDN/URL Analysis
# ============================================================================


@responses.activate
def test_analyze_fqdn_success_single_domain(fqdn_observable):
    """Test successful analysis of FQDN with single domain."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": None,
        }
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert "top_domains" in result
    assert len(result["top_domains"]) == 1
    assert result["top_domains"][0]["domain"] == "example.com"
    assert result["top_domains"][0]["count"] == 1
    assert result["link"] == f"https://crt.sh/?q={fqdn_observable}"


@responses.activate
def test_analyze_fqdn_success_multiple_domains(fqdn_observable):
    """Test successful analysis with multiple certificate records and domains."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com\napi.example.com",
        },
        {
            "common_name": "www.example.com",
            "name_value": "www.example.com\nmail.example.com",
        },
        {
            "common_name": "api.example.com",
            "name_value": None,
        },
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert "top_domains" in result
    top_domains = result["top_domains"]
    # Domain counts: api.example.com(2), www.example.com(2),
    # example.com(1), mail.example.com(1) - sorted by count desc
    assert len(top_domains) == 4
    # Two domains have count 2, verify they appear in results
    counts = [d["count"] for d in top_domains]
    assert counts[0] == 2
    assert counts[1] == 2
    assert counts[2] == 1
    assert counts[3] == 1


@responses.activate
def test_analyze_url_success_with_port(url_observable_with_port):
    """Test successful analysis of URL with port number."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    # Should extract "example.com" from the URL
    extracted_domain = "example.com"
    url = f"https://crt.sh/json?q={extracted_domain}"

    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com",
        }
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(url_observable_with_port, "URL")

    assert result is not None
    assert len(result["top_domains"]) == 2
    domain_names = {d["domain"] for d in result["top_domains"]}
    assert domain_names == {"example.com", "www.example.com"}


@responses.activate
def test_analyze_url_success_without_port(url_observable_without_port):
    """Test successful analysis of URL without port number."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    # Should extract "subdomain.example.com" from the URL
    extracted_domain = "subdomain.example.com"
    url = f"https://crt.sh/json?q={extracted_domain}"

    mock_resp = [
        {
            "common_name": "subdomain.example.com",
            "name_value": "subdomain.example.com\napi.subdomain.example.com",
        }
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(url_observable_without_port, "URL")

    assert result is not None
    assert len(result["top_domains"]) == 2
    assert result["link"] == f"https://crt.sh/?q={extracted_domain}"


@responses.activate
def test_analyze_empty_certificate_list(fqdn_observable):
    """Test analysis when domain has no certificates."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    mock_resp = []

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert result["top_domains"] == []
    assert result["link"] == f"https://crt.sh/?q={fqdn_observable}"


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 404, 500])
def test_analyze_http_error_codes(fqdn_observable, status_code, caplog):
    """Test handling of HTTP error responses (401, 403, 404, 500)."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is None
    assert "Error querying crt.sh" in caplog.text


@responses.activate
def test_analyze_connection_error(fqdn_observable, caplog):
    """Test handling of connection timeout."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is None
    assert "Error querying crt.sh" in caplog.text


# ============================================================================
# Medium Priority: Response Edge Cases
# ============================================================================


@responses.activate
def test_analyze_name_value_with_multiple_names(fqdn_observable):
    """Test parsing of name_value with multiple newline-separated domains."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    name_value = "example.com\nwww.example.com\napi.example.com\nmail.example.com\ncdn.example.com"
    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": name_value,
        }
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert len(result["top_domains"]) == 5
    # All should have count 1
    for domain in result["top_domains"]:
        assert domain["count"] == 1


@responses.activate
def test_analyze_common_name_only(fqdn_observable):
    """Test handling of records with only common_name (no name_value)."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": None,
        },
        {
            "common_name": "example.com",
            "name_value": None,
        },
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert len(result["top_domains"]) == 1
    assert result["top_domains"][0]["domain"] == "example.com"
    assert result["top_domains"][0]["count"] == 2


@responses.activate
def test_analyze_name_value_only(fqdn_observable):
    """Test handling of records with only name_value (no common_name)."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    mock_resp = [
        {
            "common_name": None,
            "name_value": "www.example.com\napi.example.com",
        },
        {
            "common_name": None,
            "name_value": "mail.example.com",
        },
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert len(result["top_domains"]) == 3
    domain_names = {d["domain"] for d in result["top_domains"]}
    assert domain_names == {"www.example.com", "api.example.com", "mail.example.com"}


@responses.activate
def test_analyze_name_value_with_empty_lines(fqdn_observable):
    """Test handling of name_value with empty lines and whitespace."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    mock_resp = [
        {
            "common_name": "example.com",
            "name_value": "example.com\n\nwww.example.com\napi.example.com\n",
        }
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    # Should have 3 domains (empty lines are skipped by "if el" check)
    assert len(result["top_domains"]) == 3
    domain_names = {d["domain"] for d in result["top_domains"]}
    assert domain_names == {"example.com", "www.example.com", "api.example.com"}


@responses.activate
def test_analyze_invalid_json_response(fqdn_observable, caplog):
    """Test handling of 200 status but invalid JSON response."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://crt.sh/json?q={fqdn_observable}"

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is None
    assert "Error querying crt.sh" in caplog.text


# ============================================================================
# Low Priority: Export Row Formatting & Edge Cases
# ============================================================================


@responses.activate
def test_create_export_row_with_domains():
    """Test export row formatting with populated top_domains."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "top_domains": [
            {"domain": "example.com", "count": 5},
            {"domain": "www.example.com", "count": 3},
            {"domain": "api.example.com", "count": 2},
        ],
        "link": "https://crt.sh/?q=example.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["crtsh_top_domains"] == "example.com, www.example.com, api.example.com"


def test_create_export_row_with_none():
    """Test export row with None analysis result."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["crtsh_top_domains"] is None


@responses.activate
def test_analyze_domain_count_sorting():
    """Test that domains are correctly sorted by count."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)
    fqdn = "example.com"
    url = f"https://crt.sh/json?q={fqdn}"

    mock_resp = [
        {"common_name": "a.example.com", "name_value": None},
        {"common_name": "a.example.com", "name_value": None},
        {"common_name": "a.example.com", "name_value": None},
        {"common_name": "a.example.com", "name_value": None},
        {"common_name": "a.example.com", "name_value": None},
        {"common_name": "b.example.com", "name_value": None},
        {"common_name": "b.example.com", "name_value": None},
        {"common_name": "b.example.com", "name_value": None},
        {"common_name": "c.example.com", "name_value": None},
        {"common_name": "c.example.com", "name_value": None},
    ]

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn, "FQDN")

    assert result is not None
    top_domains = result["top_domains"]
    assert len(top_domains) == 3
    assert top_domains[0]["domain"] == "a.example.com"
    assert top_domains[0]["count"] == 5
    assert top_domains[1]["domain"] == "b.example.com"
    assert top_domains[1]["count"] == 3
    assert top_domains[2]["domain"] == "c.example.com"
    assert top_domains[2]["count"] == 2


def test_create_export_row_empty_domains():
    """Test export row with empty top_domains list."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "top_domains": [],
        "link": "https://crt.sh/?q=example.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["crtsh_top_domains"] is None


# ============================================================================
# Properties Tests
# ============================================================================


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = CrtShEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "crtsh"
    assert engine.supported_types == ["FQDN", "URL"]
    assert engine.execute_after_reverse_dns is False
    assert engine.is_pivot_engine is False
