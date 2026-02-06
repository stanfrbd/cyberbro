import logging

import pytest
import requests
import responses
from urllib.parse import quote

from engines.hudsonrock import HudsonRockEngine
from models.observable import ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets():
    return Secrets()


@pytest.fixture
def email_observable():
    return "test@example.com"


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def url_observable():
    return "https://example.com/path"


# ============================================================================
# High Priority: Success Paths & Response Parsing Tests
# ============================================================================


@responses.activate
def test_analyze_email_success_complete(secrets, email_observable):
    """Test successful email search with complete response data."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    mock_resp = {
        "emails": ["test@example.com"],
        "breaches": [
            {
                "name": "breach1",
                "date": "2020-01-01",
                "password_exposed": True,
            }
        ],
        "related_domains": ["example.com", "related.com"],
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is not None
    assert result["emails"] == ["test@example.com"]
    assert len(result["breaches"]) == 1
    assert result["related_domains"] == ["example.com", "related.com"]


@responses.activate
def test_analyze_email_success_minimal(secrets, email_observable):
    """Test email search with minimal response fields."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    mock_resp = {"emails": [email_observable]}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is not None
    assert result["emails"] == [email_observable]


@responses.activate
def test_analyze_fqdn_success_complete(secrets, fqdn_observable):
    """Test FQDN search with complete data including URLs."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-domain?domain={fqdn_observable}"
    )

    mock_resp = {
        "data": {
            "all_urls": [
                {"url": "https://example.com/page1"},
                {"url": "https://example.com/page2"},
            ],
            "clients_urls": [{"url": "https://example.com/client"}],
            "employees_urls": [{"url": "https://example.com/employee"}],
        },
        "stats": {
            "total_urls": 3,
            "clients_urls": ["https://example.com/client"],
            "employees_urls": ["https://example.com/employee"],
        },
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, ObservableType.FQDN)

    assert result is not None
    assert len(result["data"]["all_urls"]) == 2
    assert result["stats"]["total_urls"] == 3


@responses.activate
def test_analyze_fqdn_with_masked_urls(secrets, fqdn_observable):
    """Test FQDN response cleaning for masked URLs (••)."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-domain?domain={fqdn_observable}"
    )

    mock_resp = {
        "data": {
            "all_urls": [
                {"url": "https://example.com/page1"},
                {"url": "https://••••••••/masked"},
                {"url": "https://example.com/page2"},
            ],
            "clients_urls": [
                {"url": "https://example.com/client"},
                {"url": "https://••••••••/masked_client"},
            ],
            "employees_urls": [{"url": "https://example.com/employee"}],
        },
        "stats": {
            "clients_urls": [
                "https://example.com/client",
                "https://••••••••/masked",
            ],
            "employees_urls": ["https://example.com/employee"],
        },
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, ObservableType.FQDN)

    # Verify masked URLs are removed
    assert len(result["data"]["all_urls"]) == 2
    assert all("••" not in item["url"] for item in result["data"]["all_urls"])
    assert len(result["data"]["clients_urls"]) == 1
    assert len(result["stats"]["clients_urls"]) == 1
    assert all("••" not in url for url in result["stats"]["clients_urls"])


@responses.activate
def test_analyze_fqdn_with_third_party_domains(secrets, fqdn_observable):
    """Test thirdPartyDomains filtering for null and masked entries."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-domain?domain={fqdn_observable}"
    )

    mock_resp = {
        "data": {},
        "stats": {},
        "thirdPartyDomains": [
            {"domain": "valid.com", "count": 5},
            {"domain": None, "count": 0},
            {"domain": "••••••.com", "count": 1},
            {"domain": "another.com", "count": 3},
        ],
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, ObservableType.FQDN)

    # Verify null and masked domains are removed
    assert len(result["thirdPartyDomains"]) == 2
    assert all(entry["domain"] is not None for entry in result["thirdPartyDomains"])
    assert all("••" not in entry["domain"] for entry in result["thirdPartyDomains"])


@responses.activate
def test_analyze_empty_response(secrets, email_observable):
    """Test with empty/minimal response."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    mock_resp = {}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is not None
    assert result == {}


@responses.activate
def test_analyze_server_error_500(secrets, email_observable, caplog):
    """Test handling of HTTP 500 server error."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    responses.add(responses.GET, url, json={"error": "server error"}, status=500)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


@responses.activate
def test_analyze_request_timeout(secrets, email_observable, caplog):
    """Test handling of request timeout."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(secrets, email_observable, caplog):
    """Test handling of 200 status but invalid JSON."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    responses.add(responses.GET, url, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


# ============================================================================
# High Priority: Observable Type Routing Tests
# ============================================================================


@responses.activate
def test_analyze_email_observable_routing(secrets, email_observable):
    """Test Email observable routes to email endpoint."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    mock_resp = {"emails": [email_observable]}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is not None
    assert len(responses.calls) == 1
    assert "search-by-email" in responses.calls[0].request.url
    assert f"email={quote(email_observable)}" in responses.calls[0].request.url


@responses.activate
def test_analyze_fqdn_observable_routing(secrets, fqdn_observable):
    """Test FQDN observable routes to domain endpoint."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-domain?domain={fqdn_observable}"
    )

    mock_resp = {"data": {}, "stats": {}}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, ObservableType.FQDN)

    assert result is not None
    assert len(responses.calls) == 1
    assert "search-by-domain" in responses.calls[0].request.url
    assert f"domain={quote(fqdn_observable)}" in responses.calls[0].request.url


@responses.activate
def test_analyze_url_observable_simple_domain(secrets, url_observable):
    """Test URL observable extracts domain and routes to domain endpoint."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        "search-by-domain?domain=example.com"
    )

    mock_resp = {"data": {}, "stats": {}}

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(url_observable, ObservableType.URL)

    assert result is not None
    assert len(responses.calls) == 1
    assert "search-by-domain" in responses.calls[0].request.url
    assert "domain=example.com" in responses.calls[0].request.url


@responses.activate
def test_analyze_url_observable_with_port(secrets):
    """Test URL domain extraction preserves port."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url_with_port = "https://example.com:8443/path"

    mock_resp = {"data": {}, "stats": {}}

    responses.add(
        responses.GET,
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
        json=mock_resp,
        status=200,
    )

    result = engine.analyze(url_with_port, ObservableType.URL)

    assert result is not None
    assert len(responses.calls) == 1
    # Port is URL encoded as %3A
    assert "example.com" in responses.calls[0].request.url


@responses.activate
def test_analyze_url_observable_with_query_params(secrets):
    """Test URL domain extraction ignores query parameters."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url_with_query = "https://example.com?param=value&other=123"

    mock_resp = {"data": {}, "stats": {}}

    responses.add(
        responses.GET,
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
        json=mock_resp,
        status=200,
    )

    result = engine.analyze(url_with_query, ObservableType.URL)

    assert result is not None
    assert len(responses.calls) == 1
    # Query params should NOT be included
    assert "param" not in responses.calls[0].request.url
    assert "domain=example.com" in responses.calls[0].request.url


@responses.activate
def test_analyze_url_observable_with_fragment(secrets):
    """Test URL domain extraction ignores fragment."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url_with_fragment = "https://example.com#section"

    mock_resp = {"data": {}, "stats": {}}

    responses.add(
        responses.GET,
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
        json=mock_resp,
        status=200,
    )

    result = engine.analyze(url_with_fragment, ObservableType.URL)

    assert result is not None
    assert len(responses.calls) == 1
    # Fragment should NOT be included
    assert "section" not in responses.calls[0].request.url
    assert "domain=example.com" in responses.calls[0].request.url


# ============================================================================
# Medium Priority: Error Handling Tests
# ============================================================================


@responses.activate
def test_analyze_unauthorized_401(secrets, email_observable, caplog):
    """Test handling of 401 Unauthorized response."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    responses.add(responses.GET, url, json={"error": "unauthorized"}, status=401)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


@responses.activate
def test_analyze_forbidden_403(secrets, email_observable, caplog):
    """Test handling of 403 Forbidden response."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    responses.add(responses.GET, url, json={"error": "forbidden"}, status=403)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


@responses.activate
def test_analyze_bad_request_400(secrets, email_observable, caplog):
    """Test handling of 400 Bad Request response."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    responses.add(responses.GET, url, json={"error": "bad request"}, status=400)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


@responses.activate
def test_analyze_connection_error(secrets, email_observable, caplog):
    """Test handling of connection failures."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    conn_error = requests.exceptions.ConnectionError("Connection failed")
    responses.add(responses.GET, url, body=conn_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


@responses.activate
def test_analyze_read_timeout(secrets, email_observable, caplog):
    """Test handling of read timeout."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    timeout_error = requests.exceptions.ReadTimeout("Read timed out")
    responses.add(responses.GET, url, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


@responses.activate
def test_analyze_json_decode_error(secrets, email_observable, caplog):
    """Test handling of JSON parsing failures."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    responses.add(responses.GET, url, body="not valid json", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(email_observable, ObservableType.EMAIL)

    assert result is None
    assert "Error while querying Hudson Rock" in caplog.text


# ============================================================================
# Medium Priority: Response Data Cleaning Tests
# ============================================================================


@responses.activate
def test_analyze_fqdn_clean_data_all_urls(secrets, fqdn_observable):
    """Test filtering of masked URLs in data.all_urls array."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-domain?domain={fqdn_observable}"
    )

    mock_resp = {
        "data": {
            "all_urls": [
                {"url": "https://example.com/page1"},
                {"url": "https://••••••••/masked"},
                {"url": "https://example.com/page2"},
                {"url": "https://••••••••/masked2"},
            ]
        },
        "stats": {},
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, ObservableType.FQDN)

    # Should have 2 clean entries
    assert len(result["data"]["all_urls"]) == 2
    assert all("••" not in item["url"] for item in result["data"]["all_urls"])


@responses.activate
def test_analyze_fqdn_clean_stats_urls(secrets, fqdn_observable):
    """Test filtering from stats.clients_urls and stats.employees_urls."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-domain?domain={fqdn_observable}"
    )

    mock_resp = {
        "data": {},
        "stats": {
            "clients_urls": [
                "https://example.com/client1",
                "https://••••••••/masked_client",
                "https://example.com/client2",
            ],
            "employees_urls": [
                "https://example.com/employee1",
                "https://••••••••/masked_employee",
            ],
        },
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, ObservableType.FQDN)

    # Should filter masked entries
    assert len(result["stats"]["clients_urls"]) == 2
    assert len(result["stats"]["employees_urls"]) == 1
    assert all("••" not in url for url in result["stats"]["clients_urls"])
    assert all("••" not in url for url in result["stats"]["employees_urls"])


@responses.activate
def test_analyze_email_no_cleaning_applied(secrets, email_observable):
    """Test email responses are NOT cleaned (returned as-is)."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={email_observable}"
    )

    mock_resp = {
        "emails": [email_observable],
        "data": {
            "all_urls": [
                {"url": "https://example.com/page"},
                {"url": "https://••••••••/masked"},
            ]
        },
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(email_observable, ObservableType.EMAIL)

    # Email responses should NOT have cleaning applied
    assert len(result["data"]["all_urls"]) == 2
    # Masked URL should still be present in email response
    masked_urls = [item for item in result["data"]["all_urls"] if "••" in item.get("url", "")]
    assert len(masked_urls) == 1


@responses.activate
def test_analyze_fqdn_clean_third_party_domains(secrets, fqdn_observable):
    """Test thirdPartyDomains filtering for null and masked entries."""
    engine = HudsonRockEngine(secrets, proxies={}, ssl_verify=True)
    url = (
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-domain?domain={fqdn_observable}"
    )

    mock_resp = {
        "data": {},
        "stats": {},
        "thirdPartyDomains": [
            {"domain": "valid1.com", "count": 5},
            {"domain": None, "count": 0},
            {"domain": "••••••.com", "count": 1},
            {"domain": "valid2.com", "count": 3},
            {"domain": "••valid••.com", "count": 2},
        ],
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(fqdn_observable, ObservableType.FQDN)

    # Should filter to only valid domains
    assert len(result["thirdPartyDomains"]) == 2
    assert all(entry["domain"] is not None for entry in result["thirdPartyDomains"])
    assert all("••" not in entry["domain"] for entry in result["thirdPartyDomains"])
    assert result["thirdPartyDomains"][0]["domain"] == "valid1.com"
    assert result["thirdPartyDomains"][1]["domain"] == "valid2.com"


# ============================================================================
# Low Priority: Export Formatting & Property Tests
# ============================================================================


def test_create_export_row_with_complete_data():
    """Test export row with all fields populated."""
    engine = HudsonRockEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "total_corporate_services": 10,
        "total_user_services": 20,
        "total": 30,
        "totalStealers": 5,
        "employees": 3,
        "users": 7,
        "third_parties": 4,
        "stealerFamilies": ["Vidar", "Raccoon", "Emotet"],
    }

    row = engine.create_export_row(analysis_result)

    assert row["hr_total_corporate_services"] == 10
    assert row["hr_total_user_services"] == 20
    assert row["hr_total"] == 30
    assert row["hr_total_stealers"] == 5
    assert row["hr_employees"] == 3
    assert row["hr_users"] == 7
    assert row["hr_third_parties"] == 4
    assert row["hr_stealer_families"] == "Vidar, Raccoon, Emotet"


def test_create_export_row_with_none_result():
    """Test export row with None analysis result."""
    engine = HudsonRockEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["hr_total_corporate_services"] is None
    assert row["hr_total_user_services"] is None
    assert row["hr_total"] is None
    assert row["hr_total_stealers"] is None
    assert row["hr_employees"] is None
    assert row["hr_users"] is None
    assert row["hr_third_parties"] is None
    assert row["hr_stealer_families"] is None


def test_create_export_row_with_missing_fields():
    """Test export row with some missing optional fields."""
    engine = HudsonRockEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "total_corporate_services": 5,
        "total": 15,
        # Missing other fields
    }

    row = engine.create_export_row(analysis_result)

    assert row["hr_total_corporate_services"] == 5
    assert row["hr_total"] == 15
    assert row["hr_total_user_services"] is None
    assert row["hr_employees"] is None
    # stealerFamilies defaults to empty string when key missing
    assert row["hr_stealer_families"] == ""


def test_create_export_row_empty_stealer_families():
    """Test export row with empty stealerFamilies array."""
    engine = HudsonRockEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "total": 10,
        "stealerFamilies": [],
    }

    row = engine.create_export_row(analysis_result)

    assert row["hr_total"] == 10
    assert row["hr_stealer_families"] == ""


def test_engine_properties():
    """Test BaseEngine property inheritance and values."""
    engine = HudsonRockEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "hudsonrock"
    assert engine.supported_types is ObservableType.EMAIL | ObservableType.FQDN | ObservableType.URL
    assert engine.is_pivot_engine is False
