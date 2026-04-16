import logging

import pytest
import requests
import responses

from engines.ransomware_live import RansomwareLiveEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

API_URL = "https://api-pro.ransomware.live/victims/search"


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def secrets_with_key():
    """Fixture with valid Ransomware.Live API key."""
    s = Secrets()
    s.ransomware_live_api_key = "test_api_key_12345"
    return s


@pytest.fixture
def secrets_without_key():
    """Fixture without Ransomware.Live API key."""
    s = Secrets()
    s.ransomware_live_api_key = ""
    return s


@pytest.fixture
def fqdn_observable():
    return Observable(value="example.com", type=ObservableType.FQDN)


@pytest.fixture
def url_observable():
    return Observable(value="https://example.com/some/path", type=ObservableType.URL)


VICTIM_RESPONSE = [
    {
        "victim_name": "Example Corp",
        "group_name": "lockbit3",
        "website": "example.com",
        "discovered": "2024-01-15T12:00:00Z",
    }
]


# ============================================================================
# High Priority: Critical Paths
# ============================================================================


@responses.activate
def test_analyze_fqdn_victim_found(fqdn_observable, secrets_with_key):
    """Test successful analysis where domain is found as ransomware victim."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, API_URL, json=VICTIM_RESPONSE, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["found"] is True
    assert result["count"] == 1
    assert len(result["victims"]) == 1
    victim = result["victims"][0]
    assert victim["victim_name"] == "Example Corp"
    assert victim["group_name"] == "lockbit3"
    assert victim["website"] == "example.com"
    assert victim["discovered"] == "2024-01-15T12:00:00Z"
    assert result["link"] == f"https://ransomware.live/victims?q={fqdn_observable.value}"


@responses.activate
def test_analyze_fqdn_no_victims(fqdn_observable, secrets_with_key):
    """Test analysis where domain is not found as ransomware victim."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, API_URL, json=[], status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["found"] is False
    assert result["count"] == 0
    assert result["victims"] == []


@responses.activate
def test_analyze_uses_correct_endpoint_and_auth(fqdn_observable, secrets_with_key):
    """Test that the correct endpoint, params, and auth header are used."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, API_URL, json=[], status=200)

    engine.analyze(fqdn_observable)

    assert len(responses.calls) == 1
    req = responses.calls[0].request
    assert "query=example.com" in req.url
    assert req.headers.get("api-key") == "test_api_key_12345"


@responses.activate
def test_analyze_url_extracts_domain(url_observable, secrets_with_key):
    """Test that URL observable has its domain extracted before querying."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, API_URL, json=VICTIM_RESPONSE, status=200)

    result = engine.analyze(url_observable)

    assert result is not None
    assert result["found"] is True
    assert result["link"] == "https://ransomware.live/victims?q=example.com"


def test_analyze_missing_api_key(fqdn_observable, secrets_without_key, caplog):
    """Test that engine returns None when API key is not configured."""
    engine = RansomwareLiveEngine(secrets_without_key, proxies={}, ssl_verify=True)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Ransomware.Live API key is not configured" in caplog.text


# ============================================================================
# Medium Priority: Error Handling
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 404, 500])
def test_analyze_http_errors(fqdn_observable, secrets_with_key, status_code, caplog):
    """Test handling of HTTP error responses."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, API_URL, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Error querying Ransomware.Live" in caplog.text


@responses.activate
def test_analyze_connection_error(fqdn_observable, secrets_with_key, caplog):
    """Test handling of connection errors."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(
        responses.GET,
        API_URL,
        body=requests.exceptions.ConnectTimeout("Connection timed out"),
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Error querying Ransomware.Live" in caplog.text


@responses.activate
def test_analyze_invalid_json(fqdn_observable, secrets_with_key, caplog):
    """Test handling of invalid JSON response."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, API_URL, body="not valid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Error querying Ransomware.Live" in caplog.text


def test_analyze_invalid_url_returns_none(secrets_with_key, caplog):
    """Test that invalid URL observable returns None."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)
    bad_url_obs = Observable(value="not-a-valid-url://??", type=ObservableType.URL)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(bad_url_obs)

    assert result is None


# ============================================================================
# Low Priority: Multiple victims and export row
# ============================================================================


@responses.activate
def test_analyze_multiple_victims(fqdn_observable, secrets_with_key):
    """Test that multiple victim records are returned and parsed correctly."""
    engine = RansomwareLiveEngine(secrets_with_key, proxies={}, ssl_verify=True)

    multi_response = [
        {
            "victim_name": "Example Corp",
            "group_name": "lockbit3",
            "website": "example.com",
            "discovered": "2024-01-15T12:00:00Z",
        },
        {
            "victim_name": "Example Corp",
            "group_name": "alphv",
            "website": "example.com",
            "discovered": "2023-11-01T08:30:00Z",
        },
    ]
    responses.add(responses.GET, API_URL, json=multi_response, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["count"] == 2
    assert result["found"] is True
    groups = {v["group_name"] for v in result["victims"]}
    assert groups == {"lockbit3", "alphv"}


def test_create_export_row_found():
    """Test export row when victim is found."""
    engine = RansomwareLiveEngine(Secrets(), proxies={}, ssl_verify=True)
    analysis_result = {
        "found": True,
        "count": 2,
        "victims": [
            {
                "victim_name": "Example Corp",
                "group_name": "lockbit3",
                "website": "example.com",
                "discovered": "2024-01-15T12:00:00Z",
            },
            {
                "victim_name": "Example Corp",
                "group_name": "alphv",
                "website": "example.com",
                "discovered": "2023-11-01T08:30:00Z",
            },
        ],
        "link": "https://ransomware.live/victims?q=example.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ransomware_live_found"] is True
    assert row["ransomware_live_count"] == 2
    assert "lockbit3" in row["ransomware_live_groups"]
    assert "alphv" in row["ransomware_live_groups"]
    assert "Example Corp" in row["ransomware_live_victims"]


def test_create_export_row_not_found():
    """Test export row when domain is not found."""
    engine = RansomwareLiveEngine(Secrets(), proxies={}, ssl_verify=True)
    analysis_result = {
        "found": False,
        "count": 0,
        "victims": [],
        "link": "https://ransomware.live/victims?q=example.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["ransomware_live_found"] is False
    assert row["ransomware_live_count"] == 0
    assert row["ransomware_live_groups"] is None
    assert row["ransomware_live_victims"] is None


def test_create_export_row_none():
    """Test export row when analysis result is None."""
    engine = RansomwareLiveEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["ransomware_live_found"] is None
    assert row["ransomware_live_count"] is None
    assert row["ransomware_live_groups"] is None
    assert row["ransomware_live_victims"] is None


# ============================================================================
# Properties
# ============================================================================


def test_engine_properties():
    """Test engine properties."""
    engine = RansomwareLiveEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "ransomware_live"
    assert engine.supported_types == ObservableType.FQDN | ObservableType.URL
    assert engine.execute_after_reverse_dns is False
    assert engine.is_pivot_engine is False
