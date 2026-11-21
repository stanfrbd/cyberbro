import json
import logging
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
import responses

from engines import NogonEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

BASE_URL = "http://nogon.local"
SEARCH_URL = f"{BASE_URL}/search"


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def secrets_with_credentials():
    s = Secrets()
    s.nogon_token = "test_token_abc"
    s.nogon_base_url = BASE_URL
    return s


@pytest.fixture
def secrets_without_token():
    s = Secrets()
    s.nogon_token = ""
    s.nogon_base_url = BASE_URL
    return s


@pytest.fixture
def secrets_without_base_url():
    s = Secrets()
    s.nogon_token = "test_token_abc"
    s.nogon_base_url = ""
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
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, json=DOCUMENTS_RESPONSE, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["total"] == 2
    assert len(result["results"]) == 2
    assert result["results"][0]["url"] == "https://pastebin.com/abc"
    assert result["results"][0]["title"] == "Paste about example.com"
    assert result["results"][1]["url"] == "https://github.com/xyz"
    assert result["link"] == f"{BASE_URL}/?q=%22example.com%22"


@pytest.mark.parametrize("documents", [[], None])
@responses.activate
def test_analyze_success_empty_documents(fqdn_observable, secrets_with_credentials, documents):
    """Test successful analysis with no documents."""
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, json={"total": 0, "documents": documents}, status=200)

    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["total"] == 0
    assert result["results"] == []


@responses.activate
def test_analyze_sends_correct_headers_and_params(fqdn_observable, secrets_with_credentials):
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.get(
        SEARCH_URL,
        json={"total": 0, "documents": []},
        match=[
            responses.matchers.header_matcher(
                {"Authorization": "Bearer test_token_abc", "Accept": "application/json"}
            ),
            responses.matchers.query_param_matcher(
                {"query": json.dumps({"text": '"example.com"', "limit": 10})}
            ),
        ],
    )

    assert engine.analyze(fqdn_observable) is not None
    assert "Origin" not in responses.calls[0].request.headers


@responses.activate
def test_analyze_preserves_path_prefix_and_escapes_query():
    base_url = f"{BASE_URL}/nogon"
    secrets = Secrets(nogon_base_url=f"{base_url}/", nogon_token="test_token")
    engine = NogonEngine(secrets, proxies={}, ssl_verify=True)
    value = 'https://example.com/?q="a"&x=1'
    observable = Observable(value=value, type=ObservableType.URL)
    responses.get(f"{base_url}/search", json={"total": 0, "documents": []})

    result = engine.analyze(observable)

    assert result is not None
    request_query = parse_qs(urlsplit(responses.calls[0].request.url).query)
    query_text = json.loads(request_query["query"][0])["text"]
    assert query_text == r'"https://example.com/?q=\"a\"&x=1"'
    link = urlsplit(result["link"])
    assert link.path == "/nogon/"
    assert parse_qs(link.query) == {"q": [query_text]}


def test_analyze_missing_token_returns_none(fqdn_observable, secrets_without_token, caplog):
    """Test that engine returns None when token is not set."""
    engine = NogonEngine(secrets_without_token, proxies={}, ssl_verify=True)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Nogon token or base URL not set" in caplog.text


def test_analyze_missing_base_url_returns_none(fqdn_observable, secrets_without_base_url, caplog):
    """Test that engine returns None when base URL is not set."""
    engine = NogonEngine(secrets_without_base_url, proxies={}, ssl_verify=True)

    caplog.set_level(logging.WARNING)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Nogon token or base URL not set" in caplog.text


# ============================================================================
# Medium Priority: Error Handling
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [400, 401, 403, 500])
def test_analyze_http_error(fqdn_observable, secrets_with_credentials, status_code, caplog):
    """Test that HTTP errors return None and log the error."""
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, json={"error": "error"}, status=status_code)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Error querying Nogon" in caplog.text


@responses.activate
def test_analyze_connection_timeout(fqdn_observable, secrets_with_credentials, caplog):
    """Test that connection timeout returns None and logs the error."""
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(
        responses.GET,
        SEARCH_URL,
        body=requests.exceptions.ConnectTimeout("timed out"),
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Error querying Nogon" in caplog.text


@responses.activate
def test_analyze_invalid_json(fqdn_observable, secrets_with_credentials, caplog):
    """Test that invalid JSON response returns None and logs the error."""
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.add(responses.GET, SEARCH_URL, body="not json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(fqdn_observable)

    assert result is None
    assert "Invalid search response returned by Nogon" in caplog.text


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"error": "search failed"},
        {"total": "1", "documents": []},
        {"total": 1, "documents": {}},
        {"total": 1, "documents": [{"url": "https://example.com", "added": "yesterday"}]},
        {"total": 1, "documents": [{"url": "https://example.com", "added": 10**20}]},
    ],
)
@responses.activate
def test_analyze_malformed_response(fqdn_observable, secrets_with_credentials, payload, caplog):
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    responses.get(SEARCH_URL, json=payload)

    assert engine.analyze(fqdn_observable) is None
    assert "Invalid search response returned by Nogon" in caplog.text


# ============================================================================
# Medium Priority: Response Parsing
# ============================================================================


@responses.activate
def test_analyze_deduplicates_urls(fqdn_observable, secrets_with_credentials):
    """Test that duplicate document URLs are deduplicated."""
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
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
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
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
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
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
    engine = NogonEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
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
    s.nogon_token = "test_token_abc"
    s.nogon_base_url = BASE_URL + "/"
    engine = NogonEngine(s, proxies={}, ssl_verify=True)
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
    engine = NogonEngine(Secrets(), proxies={}, ssl_verify=True)
    analysis_result = {
        "total": 5,
        "results": [
            {"url": "https://a.com", "title": "A", "added": "2024-01-01"},
            {"url": "https://b.com", "title": "B", "added": "2024-02-01"},
        ],
        "link": f"{BASE_URL}/?q=example.com",
    }

    row = engine.create_export_row(analysis_result)

    assert row["nogon_total"] == 5
    assert row["nogon_results"] == 2


def test_create_export_row_with_none():
    """Test export row when analysis result is None."""
    engine = NogonEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["nogon_total"] is None
    assert row["nogon_results"] is None


def test_create_export_row_empty_results():
    """Test export row with zero results."""
    engine = NogonEngine(Secrets(), proxies={}, ssl_verify=True)
    analysis_result = {"total": 0, "results": [], "link": f"{BASE_URL}/?q=example.com"}

    row = engine.create_export_row(analysis_result)

    assert row["nogon_total"] == 0
    assert row["nogon_results"] == 0


def test_engine_properties():
    """Test engine name and supported_types."""
    engine = NogonEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "nogon"
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
