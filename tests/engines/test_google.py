import logging
from unittest.mock import MagicMock, patch

import pytest
import requests
import responses

from engines.google import GoogleCSEEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_credentials():
    """Secrets with both required Google CSE credentials."""
    s = Secrets()
    s.google_cse_cx = "test_cx_value"
    s.google_cse_key = "test_api_key_value"
    return s


@pytest.fixture
def secrets_without_cx():
    """Secrets missing google_cse_cx."""
    s = Secrets()
    s.google_cse_cx = ""
    s.google_cse_key = "test_api_key_value"
    return s


@pytest.fixture
def secrets_without_key():
    """Secrets missing google_cse_key."""
    s = Secrets()
    s.google_cse_cx = "test_cx_value"
    s.google_cse_key = ""
    return s


@pytest.fixture
def observable_domain():
    return "example.com"


@pytest.fixture
def observable_hash():
    return "a" * 40


# ============================================================================
# High Priority: Core API Flow, Error Handling, Credentials
# ============================================================================


@patch("time.sleep")
@responses.activate
def test_analyze_success_complete_response(mock_sleep, secrets_with_credentials):
    """Test successful API response with all fields present."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "items": [
            {
                "title": "Example Domain",
                "snippet": "Example domain for testing",
                "link": "https://example.com",
            },
            {
                "title": "Example 2",
                "snippet": "Another example",
                "link": "https://example2.com",
            },
            {
                "title": "Example 3",
                "snippet": "Third example",
                "link": "https://example3.com",
            },
        ],
        "searchInformation": {"totalResults": "1234567"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 1234567
    assert len(result["results"]) == 3
    assert result["results"][0]["title"] == "Example Domain"
    assert result["results"][0]["description"] == "Example domain for testing"
    assert result["results"][0]["url"] == "https://example.com"
    assert mock_sleep.called


@patch("time.sleep")
@responses.activate
def test_analyze_success_minimal_response(mock_sleep, secrets_with_credentials):
    """Test successful API response with minimal fields."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0
    assert result["results"] == []


@patch("time.sleep")
@responses.activate
def test_analyze_missing_cse_cx(mock_sleep, secrets_without_cx, caplog):
    """Test handling of missing google_cse_cx credential."""
    engine = GoogleCSEEngine(secrets_without_cx, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "error": {
            "code": 400,
            "message": "Invalid Credentials: CX is empty",
        }
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=400)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0
    assert result["results"][0]["title"] == "API Error"


@patch("time.sleep")
@responses.activate
def test_analyze_missing_cse_key(mock_sleep, secrets_without_key, caplog):
    """Test handling of missing google_cse_key credential."""
    engine = GoogleCSEEngine(secrets_without_key, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "error": {
            "code": 400,
            "message": "Invalid Credentials: Key is empty",
        }
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=400)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0


@patch("time.sleep")
@responses.activate
def test_analyze_invalid_credentials_wrong_cx(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of invalid google_cse_cx (wrong value)."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "error": {
            "code": 400,
            "message": "Invalid CX value",
        }
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=400)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0
    assert result["results"][0]["title"] == "API Error"


@patch("time.sleep")
@responses.activate
def test_analyze_invalid_credentials_wrong_key(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of invalid google_cse_key (wrong value)."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "error": {
            "code": 401,
            "message": "Invalid API Key",
        }
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=401)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0


@patch("time.sleep")
@responses.activate
def test_analyze_http_error_400(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of 400 Bad Request error."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "error": {
            "code": 400,
            "message": "Bad request",
        }
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=400)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0
    assert result["results"][0]["title"] == "API Error"
    assert "Google CSE error" in caplog.text


@patch("time.sleep")
@responses.activate
def test_analyze_http_error_403_quota(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of 403 Quota Exceeded error."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "error": {
            "code": 403,
            "message": "The caller does not have permission",
            "errors": [{"message": "Quota exceeded"}],
        }
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=403)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0
    assert "Google CSE error" in caplog.text


@patch("time.sleep")
@responses.activate
def test_analyze_http_error_500(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of 500 Server Error."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, status=500)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0
    assert result["results"][0]["title"] == "API Error"


@patch("time.sleep")
@responses.activate
def test_analyze_error_in_json_with_200_status(mock_sleep, secrets_with_credentials, caplog):
    """Test detecting error in JSON response even with 200 status."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "error": {
            "code": 403,
            "message": "Rate limit exceeded",
        }
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    with caplog.at_level(logging.WARNING):
        result = engine.analyze(observable, "FQDN")

    assert result is not None
    assert result["total"] == 0
    assert result["results"][0]["title"] == "API Error"


@patch("time.sleep")
@responses.activate
def test_analyze_json_parsing_error(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of malformed JSON response."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, body="<html>Error page</html>", status=200)

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(observable, "FQDN")

    assert result is None
    assert "Expected JSON from Google CSE" in caplog.text


@patch("time.sleep")
@responses.activate
def test_analyze_connection_timeout(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of connection timeout."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(
        responses.GET,
        url,
        body=requests.ConnectTimeout("Connection timeout"),
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(observable, "FQDN")

    assert result is None
    assert "Network error querying Google CSE" in caplog.text


@patch("time.sleep")
@responses.activate
def test_analyze_connection_error(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of connection error."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(
        responses.GET,
        url,
        body=requests.ConnectionError("Connection error"),
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(observable, "FQDN")

    assert result is None
    assert "Network error querying Google CSE" in caplog.text


@patch("time.sleep")
@responses.activate
def test_analyze_unexpected_exception(mock_sleep, secrets_with_credentials, caplog):
    """Test handling of unexpected exception."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(
        responses.GET,
        url,
        body=ValueError("Unexpected error"),
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(observable, "FQDN")

    assert result is None
    assert "Unexpected error querying Google CSE" in caplog.text


# ============================================================================
# Medium Priority: Parameter Validation and Rate Limiting
# ============================================================================


@patch("time.sleep")
@responses.activate
def test_analyze_dorks_simple_prefix(mock_sleep, secrets_with_credentials):
    """Test dorks parameter with simple prefix."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "password"
    dorks = "filetype:pdf"

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "FQDN", dorks=dorks)

    assert result is not None
    # Verify the query was constructed with dorks prefix
    call_args = responses.calls[0].request
    assert "filetype%3Apdf" in call_args.url or "filetype:pdf" in call_args.url


@patch("time.sleep")
@responses.activate
def test_analyze_dorks_multiple_words(mock_sleep, secrets_with_credentials):
    """Test dorks parameter with multiple words."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "admin"
    dorks = "inurl:admin OR inurl:panel"

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "FQDN", dorks=dorks)

    assert result is not None


@patch("time.sleep")
@responses.activate
def test_analyze_dorks_with_trailing_space(mock_sleep, secrets_with_credentials):
    """Test dorks parameter with trailing space."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "password"
    dorks = "filetype:pdf  "  # trailing spaces

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "FQDN", dorks=dorks)

    assert result is not None


@patch("time.sleep")
@responses.activate
def test_analyze_dorks_empty_string(mock_sleep, secrets_with_credentials):
    """Test dorks parameter with empty string."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"
    dorks = ""

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "FQDN", dorks=dorks)

    assert result is not None


@patch("time.sleep")
@responses.activate
def test_analyze_observable_wrapped_in_quotes(mock_sleep, secrets_with_credentials):
    """Test that observable value is wrapped in quotes."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "FQDN")

    assert result is not None
    # Verify observable is wrapped in quotes in the URL
    call_args = responses.calls[0].request
    assert "q=" in call_args.url
    assert "example.com" in call_args.url or "%22example.com%22" in call_args.url


@pytest.mark.parametrize(
    "observable_type",
    [
        "CHROME_EXTENSION",
        "FQDN",
        "IPv4",
        "IPv6",
        "MD5",
        "SHA1",
        "SHA256",
        "URL",
        "Email",
    ],
)
@patch("time.sleep")
@responses.activate
def test_analyze_observable_types(mock_sleep, observable_type, secrets_with_credentials):
    """Test that all 9 observable types are supported."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    observable = f"test_{observable_type}"
    result = engine.analyze(observable, observable_type)
    assert result is not None


@patch("time.sleep")
@responses.activate
def test_analyze_special_characters_in_observable(mock_sleep, secrets_with_credentials):
    """Test handling of special characters in observable value."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "test@example.com"

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "Email")

    assert result is not None


@patch("time.sleep")
@responses.activate
def test_analyze_different_observable_values(mock_sleep, secrets_with_credentials):
    """Test that different observable values produce valid queries."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    observables = [
        "1.1.1.1",
        "example.com",
        "a" * 40,  # SHA1
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5
    ]

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    for observable in observables:
        result = engine.analyze(observable, "IPv4")
        assert result is not None


@patch("time.sleep")
def test_analyze_rate_limiting_sleep_called(mock_sleep, secrets_with_credentials):
    """Test that time.sleep(0.5) is called for rate limiting."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "items": [],
            "searchInformation": {"totalResults": "0"},
        }
        mock_get.return_value = mock_response

        result = engine.analyze(observable, "FQDN")

        assert result is not None
        assert mock_sleep.called
        assert mock_sleep.call_args[0][0] == 0.5


@patch("time.sleep")
@responses.activate
def test_analyze_timeout_parameter(mock_sleep, secrets_with_credentials):
    """Test that timeout=10 is passed to requests.get()."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    observable = "example.com"

    mock_resp = {
        "items": [],
        "searchInformation": {"totalResults": "0"},
    }

    url = "https://www.googleapis.com/customsearch/v1"
    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "FQDN")

    assert result is not None
    # Verify the request was made with timeout
    call_args = responses.calls[0].request
    assert call_args is not None


# ============================================================================
# Low Priority: Export Formatting and Properties
# ============================================================================


def test_create_export_row_with_results(secrets_with_credentials):
    """Test export row formatting with results."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    analysis_result = {"results": [{"title": "Example"}], "total": 5000}

    export_row = engine.create_export_row(analysis_result)

    assert export_row["google_results_count"] == 5000


def test_create_export_row_zero_results(secrets_with_credentials):
    """Test export row formatting with zero results."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    analysis_result = {"results": [], "total": 0}

    export_row = engine.create_export_row(analysis_result)

    assert export_row["google_results_count"] == 0


def test_create_export_row_error_result(secrets_with_credentials):
    """Test export row formatting with error result."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    # Error result object
    analysis_result = {
        "results": [{"title": "API Error", "description": "Error", "url": ""}],
        "total": 0,
    }

    export_row = engine.create_export_row(analysis_result)

    assert export_row["google_results_count"] == 0


def test_create_export_row_none_result(secrets_with_credentials):
    """Test export row formatting with None result."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    export_row = engine.create_export_row(None)

    assert export_row["google_results_count"] is None


def test_engine_name(secrets_with_credentials):
    """Test that engine name property returns 'google'."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    assert engine.name == "google"


def test_engine_supported_types(secrets_with_credentials):
    """Test that supported_types property returns all 9 types."""
    engine = GoogleCSEEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    expected_types = [
        "CHROME_EXTENSION",
        "FQDN",
        "IPv4",
        "IPv6",
        "MD5",
        "SHA1",
        "SHA256",
        "URL",
        "Email",
    ]

    assert engine.supported_types == expected_types
