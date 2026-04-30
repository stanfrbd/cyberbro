import json
import logging

import pytest
import requests
import responses

from engines.hister import HisterEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

BASE_URL = "http://hister.local"
SEARCH_URL = f"{BASE_URL}/search"


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def secrets_with_credentials():
    s = Secrets()
    s.hister_token = "test_token_abc"
    s.hister_base_url = BASE_URL
    return s


@pytest.fixture
def secrets_without_token():
    s = Secrets()
    s.hister_token = ""
    s.hister_base_url = BASE_URL
    return s


@pytest.fixture
def secrets_without_base_url():
    s = Secrets()
    s.hister_token = "test_token_abc"
    s.hister_base_url = ""
    return s


@pytest.fixture
def ip_observable():
    return Observable(value="1.2.3.4", type=ObservableType.IPV4)


@pytest.fixture
def fqdn_observable():
    return Observable(value="example.com", type=ObservableType.FQDN)


@pytest.fixture
def email_observable():
    return Observable(value="user@example.com", type=ObservableType.EMAIL)


@pytest.fixture
def sha256_observable():
    return Observable(
        value="abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
        type=ObservableType.SHA256,
    )


DOCUMENTS_RESPONSE = {
    "total": 2,
    "documents": [
        {
            "url": "https://pastebin.com/abc",
            "title": "Paste about example.com",
            "text": "some text mentioning example.com",
            "added": 1700000000,
        },
        {
            "url": "https://github.com/xyz",
            "title": "Repo mentioning example.com",
            "text": "another mention",
            "added": 1710000000,
        },
    ],
}


# ============================================================================
# High Priority: Critical Paths
# ============================================================================


@responses.activate
def test_analyze_success_returns_results(fqdn_observable, secrets_with_credentials):
    """Test successful analysis with documents returned."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, json=DOCUMENTS_RESPONSE, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["total"] == 2
    assert len(result["results"]) == 2
    assert result["results"][0]["url"] == "https://pastebin.com/abc"
    assert result["results"][0]["title"] == "Paste about example.com"
    assert result["results"][1]["url"] == "https://github.com/xyz"
    assert "link" in result
    assert "example.com" in result["link"]


@responses.activate
def test_analyze_success_empty_documents(fqdn_observable, secrets_with_credentials):
    """Test successful analysis with no documents."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, json={"total": 0, "documents": []}, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["total"] == 0
    assert result["results"] == []


@responses.activate
def test_analyze_sends_correct_headers_and_params(fqdn_observable, secrets_with_credentials):
    """Test that Authorization header, Origin, and query param are sent correctly."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, json={"total": 0, "documents": []}, status=200)

    engine.analyze(fqdn_observable)

    assert len(responses.calls) == 1
    req = responses.calls[0].request
    assert req.headers.get("Authorization") == "Bearer test_token_abc"
    assert req.headers.get("Origin") == "hister://"
    assert "query=" in req.url
    query_raw = [
        p.split("=", 1)[1] for p in req.url.split("?", 1)[1].split("&") if p.startswith("query=")
    ][0]
    from urllib.parse import unquote_plus

    query_obj = json.loads(unquote_plus(query_raw))
    assert query_obj["text"] == "example.com"
    assert query_obj["limit"] == 10
    assert "url" in query_obj["fields"]


def test_analyze_missing_token_returns_none(fqdn_observable, secrets_without_token, caplog):
    """Test that engine returns None when token is not set."""
    engine = HisterEngine(secrets_without_token, proxies={}, ssl_verify=True)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Hister token or base URL not set" in caplog.text


def test_analyze_missing_base_url_returns_none(fqdn_observable, secrets_without_base_url, caplog):
    """Test that engine returns None when base URL is not set."""
    engine = HisterEngine(secrets_without_base_url, proxies={}, ssl_verify=True)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Hister token or base URL not set" in caplog.text


# ============================================================================
# Medium Priority: Error Handling
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [400, 401, 403, 500])
def test_analyze_http_error(fqdn_observable, secrets_with_credentials, status_code, caplog):
    """Test that HTTP errors return None and log the error."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Error querying Hister" in caplog.text


@responses.activate
def test_analyze_connection_timeout(fqdn_observable, secrets_with_credentials, caplog):
    """Test that connection timeout returns None and logs the error."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(
        responses.GET,
        SEARCH_URL,
        body=requests.exceptions.ConnectTimeout("timed out"),
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Error querying Hister" in caplog.text


@responses.activate
def test_analyze_invalid_json(fqdn_observable, secrets_with_credentials, caplog):
    """Test that invalid JSON response returns None and logs the error."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, body="not json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Error querying Hister" in caplog.text


# ============================================================================
# Medium Priority: Response Parsing
# ============================================================================


@responses.activate
def test_analyze_deduplicates_urls(fqdn_observable, secrets_with_credentials):
    """Test that duplicate document URLs are deduplicated."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    duplicate_response = {
        "total": 3,
        "documents": [
            {"url": "https://pastebin.com/abc", "title": "First", "added": 1700000000},
            {"url": "https://pastebin.com/abc", "title": "Duplicate", "added": 1700000001},
            {"url": "https://github.com/xyz", "title": "Other", "added": 1710000000},
        ],
    }
    responses.add(responses.GET, SEARCH_URL, json=duplicate_response, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert len(result["results"]) == 2
    urls = [r["url"] for r in result["results"]]
    assert urls.count("https://pastebin.com/abc") == 1


@responses.activate
def test_analyze_skips_documents_without_url(fqdn_observable, secrets_with_credentials):
    """Test that documents with missing or empty URL are skipped."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    response_with_missing_url = {
        "total": 3,
        "documents": [
            {"url": "", "title": "No URL", "added": 1700000000},
            {"title": "Missing URL key", "added": 1700000000},
            {"url": "https://pastebin.com/abc", "title": "Valid", "added": 1710000000},
        ],
    }
    responses.add(responses.GET, SEARCH_URL, json=response_with_missing_url, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert len(result["results"]) == 1
    assert result["results"][0]["url"] == "https://pastebin.com/abc"


@responses.activate
def test_analyze_formats_added_timestamp(fqdn_observable, secrets_with_credentials):
    """Test that the 'added' timestamp is converted to a YYYY-MM-DD date string."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(
        responses.GET,
        SEARCH_URL,
        json={
            "total": 1,
            "documents": [
                {"url": "https://pastebin.com/abc", "title": "Test", "added": 1700000000},
            ],
        },
        status=200,
    )

    result = engine.analyze(fqdn_observable)

    assert result is not None
    added = result["results"][0]["added"]
    assert len(added) == 10
    assert added[4] == "-" and added[7] == "-"


@responses.activate
def test_analyze_added_zero_gives_empty_string(fqdn_observable, secrets_with_credentials):
    """Test that added=0 results in an empty string date."""
    engine = HisterEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(
        responses.GET,
        SEARCH_URL,
        json={
            "total": 1,
            "documents": [
                {"url": "https://pastebin.com/abc", "title": "Test", "added": 0},
            ],
        },
        status=200,
    )

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["results"][0]["added"] == ""


@responses.activate
def test_analyze_base_url_trailing_slash_normalized(secrets_with_credentials):
    """Test that a trailing slash in base_url is handled correctly."""
    s = Secrets()
    s.hister_token = "test_token_abc"
    s.hister_base_url = BASE_URL + "/"
    engine = HisterEngine(s, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, json={"total": 0, "documents": []}, status=200)

    result = engine.analyze(Observable(value="1.2.3.4", type=ObservableType.IPV4))

    assert result is not None
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url.startswith(SEARCH_URL)


# ============================================================================
# Low Priority: Export Row & Properties
# ============================================================================


def test_create_export_row_with_results():
    """Test export row with a valid analysis result."""
    engine = HisterEngine(Secrets(), proxies={}, ssl_verify=True)
    analysis_result = {
        "total": 5,
        "results": [
            {"url": "https://a.com", "title": "A", "added": "2024-01-01"},
            {"url": "https://b.com", "title": "B", "added": "2024-02-01"},
        ],
        "link": f"{BASE_URL}/?q=example.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["hister_total"] == 5
    assert row["hister_results"] == 2


def test_create_export_row_with_none():
    """Test export row when analysis result is None."""
    engine = HisterEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["hister_total"] is None
    assert row["hister_results"] is None


def test_create_export_row_empty_results():
    """Test export row with zero results."""
    engine = HisterEngine(Secrets(), proxies={}, ssl_verify=True)
    analysis_result = {"total": 0, "results": [], "link": f"{BASE_URL}/?q=example.com"}

    row = engine.create_export_row(analysis_result)

    assert row["hister_total"] == 0
    assert row["hister_results"] == 0


def test_engine_properties():
    """Test engine name and supported_types."""
    engine = HisterEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "hister"
    expected_types = (
        ObservableType.IPV4
        | ObservableType.IPV6
        | ObservableType.BOGON
        | ObservableType.FQDN
        | ObservableType.URL
        | ObservableType.EMAIL
        | ObservableType.CHROME_EXTENSION
        | ObservableType.MD5
        | ObservableType.SHA1
        | ObservableType.SHA256
    )
    assert engine.supported_types == expected_types
