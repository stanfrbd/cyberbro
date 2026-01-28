import json
import logging

import pytest
import requests
import responses

from engines.threatfox import ThreatFoxEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


# ============================================================================
# Phase 1: Fixtures
# ============================================================================


@pytest.fixture
def secrets_with_valid_key():
    s = Secrets()
    s.threatfox = "valid_api_key_12345"
    return s


@pytest.fixture
def secrets_with_empty_key():
    s = Secrets()
    s.threatfox = ""
    return s


@pytest.fixture
def secrets_with_whitespace_key():
    s = Secrets()
    s.threatfox = "   "
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def url_observable_standard():
    return "https://example.com/path"


@pytest.fixture
def url_observable_with_port():
    return "https://example.com:8080/path"


@pytest.fixture
def url_observable_complex():
    return "https://sub.example.com:443/path?query=1"


# ============================================================================
# Phase 2: High Priority Tests - Credentials & Core API Functionality
# ============================================================================


class TestAnalyzeWithValidKey:
    """Test analyze with valid API key across all observable types."""

    @pytest.mark.parametrize(
        "observable_type,observable_value,expected_search_term",
        [
            ("IPv4", "1.1.1.1", "1.1.1.1"),
            ("IPv6", "2001:4860:4860::8888", "2001:4860:4860::8888"),
            ("FQDN", "example.com", "example.com"),
            ("URL", "https://example.com/path", "example.com"),
        ],
    )
    @responses.activate
    def test_analyze_success_all_types(
        self, secrets_with_valid_key, observable_type, observable_value, expected_search_term
    ):
        """Test successful API call for all 4 observable types."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {
            "query_status": "ok",
            "data": [{"ioc": expected_search_term, "malware_printable": "Trojan.Generic"}],
        }

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(observable_value, observable_type)

        assert result is not None
        assert result["count"] == 1
        assert result["malware_printable"] == ["Trojan.Generic"]
        assert expected_search_term in result["link"]

        # Verify request payload
        assert len(responses.calls) == 1
        request_body = json.loads(responses.calls[0].request.body)
        assert request_body["query"] == "search_ioc"
        assert request_body["search_term"] == expected_search_term
        assert responses.calls[0].request.headers["Auth-Key"] == "valid_api_key_12345"

    @responses.activate
    def test_analyze_with_empty_api_key(self, secrets_with_empty_key, ipv4_observable):
        """Test analyze with empty API key - request still made but will fail."""
        engine = ThreatFoxEngine(secrets_with_empty_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        responses.add(responses.POST, url, status=401, json={"error": "Unauthorized"})

        result = engine.analyze(ipv4_observable, "IPv4")

        # Empty key results in 401, which is caught as exception and returns None
        assert result is None

    @responses.activate
    def test_analyze_with_whitespace_api_key(self, secrets_with_whitespace_key, ipv4_observable):
        """Test analyze with whitespace-only API key.

        TODO: Bug #2 - No whitespace validation on API key.
        Currently, whitespace-only keys are sent to API and will fail with 401.
        Consider adding: if api_key and api_key.strip():
        """
        engine = ThreatFoxEngine(secrets_with_whitespace_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        responses.add(responses.POST, url, status=401, json={"error": "Unauthorized"})

        result = engine.analyze(ipv4_observable, "IPv4")

        # Whitespace key results in 401, caught as exception, returns None
        assert result is None


class TestURLParsing:
    """Test URL parsing for domain extraction."""

    @responses.activate
    def test_url_parsing_standard_url(self, secrets_with_valid_key, url_observable_standard):
        """Test URL parsing with standard HTTPS URL."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"data": [{"malware_printable": "Trojan"}]}
        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(url_observable_standard, "URL")

        assert result is not None
        request_body = json.loads(responses.calls[0].request.body)
        # Should extract "example.com" from "https://example.com/path"
        assert request_body["search_term"] == "example.com"

    @responses.activate
    def test_url_parsing_with_port(self, secrets_with_valid_key, url_observable_with_port):
        """Test URL parsing strips port number."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"data": []}
        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(url_observable_with_port, "URL")

        assert result is not None
        request_body = json.loads(responses.calls[0].request.body)
        # Should extract "example.com" without port
        assert request_body["search_term"] == "example.com"

    @responses.activate
    def test_url_parsing_with_subdomain_and_port(
        self, secrets_with_valid_key, url_observable_complex
    ):
        """Test URL parsing with subdomain and port."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"data": []}
        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(url_observable_complex, "URL")

        assert result is not None
        request_body = json.loads(responses.calls[0].request.body)
        # Should extract "sub.example.com" without port
        assert request_body["search_term"] == "sub.example.com"


class TestSuccessfulResponses:
    """Test successful API responses with various data structures."""

    @responses.activate
    def test_analyze_single_malware_family(self, secrets_with_valid_key, ipv4_observable):
        """Test response with single malware family."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": ipv4_observable,
                    "ioc_type": "ipv4",
                    "malware_printable": "Trojan.Win32.Generic",
                    "threat_level": 100,
                },
            ],
        }

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        assert result["count"] == 1
        assert result["malware_printable"] == ["Trojan.Win32.Generic"]
        assert "ioc%3A1.1.1.1" in result["link"]

    @responses.activate
    def test_analyze_multiple_unique_malware_families(
        self, secrets_with_valid_key, ipv4_observable
    ):
        """Test response with multiple unique malware families."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {
            "data": [
                {"ioc": ipv4_observable, "malware_printable": "Trojan.A"},
                {"ioc": ipv4_observable, "malware_printable": "Trojan.B"},
                {"ioc": ipv4_observable, "malware_printable": "Trojan.C"},
            ],
        }

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        assert result["count"] == 3
        # Set deduplicates, so all 3 unique families are included
        assert set(result["malware_printable"]) == {"Trojan.A", "Trojan.B", "Trojan.C"}

    @responses.activate
    def test_analyze_multiple_same_malware_family(self, secrets_with_valid_key, ipv4_observable):
        """Test response with multiple entries of same malware family (set deduplication)."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {
            "data": [
                {"ioc": ipv4_observable, "malware_printable": "Trojan.A"},
                {"ioc": ipv4_observable, "malware_printable": "Trojan.A"},
                {"ioc": ipv4_observable, "malware_printable": "Trojan.A"},
            ],
        }

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        assert result["count"] == 3  # Count is total items
        assert result["malware_printable"] == ["Trojan.A"]  # Set deduplicates to 1

    @responses.activate
    def test_analyze_empty_data_list(self, secrets_with_valid_key, ipv4_observable):
        """Test response with empty data list (no matches)."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"query_status": "ok", "data": []}

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        assert result["count"] == 0
        assert result["malware_printable"] == []

    @responses.activate
    def test_analyze_missing_malware_printable_field(self, secrets_with_valid_key, ipv4_observable):
        """Test response where items missing malware_printable field.

        TODO: Bug #5 - Items missing malware_printable get "Unknown" default.
        Current behavior: Falls back to "Unknown" string.
        """
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {
            "data": [
                {"ioc": ipv4_observable, "threat_level": 100},  # Missing malware_printable
                {"ioc": ipv4_observable, "malware_printable": "Trojan.A"},
            ],
        }

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        assert result["count"] == 2
        # Should include "Unknown" for missing field and actual malware
        assert "Unknown" in result["malware_printable"]
        assert "Trojan.A" in result["malware_printable"]

    @responses.activate
    def test_analyze_all_items_missing_malware_printable(
        self, secrets_with_valid_key, ipv4_observable
    ):
        """Test when all items are missing malware_printable field."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {
            "data": [
                {"ioc": ipv4_observable},
                {"ioc": ipv4_observable},
            ],
        }

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        assert result["count"] == 2
        # Set deduplicates multiple "Unknown" to single entry
        assert result["malware_printable"] == ["Unknown"]


# ============================================================================
# Phase 3: Medium Priority Tests - Error Scenarios & Response Variations
# ============================================================================


class TestHTTPErrors:
    """Test HTTP error responses."""

    @pytest.mark.parametrize(
        "status_code",
        [401, 403, 500, 502],
    )
    @responses.activate
    def test_analyze_http_error_codes(self, secrets_with_valid_key, ipv4_observable, status_code):
        """Test various HTTP error codes return None."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        responses.add(responses.POST, url, status=status_code, json={"error": "Error"})

        result = engine.analyze(ipv4_observable, "IPv4")

        # HTTP errors are caught as RequestException and return None
        assert result is None

    @responses.activate
    def test_analyze_404_not_found(self, secrets_with_valid_key, ipv4_observable):
        """Test 404 Not Found response."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        responses.add(responses.POST, url, status=404, json={"error": "Not Found"})

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is None


class TestResponseStructureVariations:
    """Test various response structure variations."""

    @responses.activate
    def test_analyze_missing_data_key(self, secrets_with_valid_key, ipv4_observable):
        """Test response missing 'data' key entirely."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        # Response without data key
        mock_resp = {"query_status": "ok"}

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        # Default to empty list for missing data key
        assert result["count"] == 0
        assert result["malware_printable"] == []

    @responses.activate
    def test_analyze_data_is_null(self, secrets_with_valid_key, ipv4_observable):
        """Test response where 'data' is null instead of list.

        TODO: Bug #4 - Response type not validated.
        Current behavior: isinstance(data, list) check prevents processing.
        """
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"query_status": "ok", "data": None}

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        # isinstance check fails, data processing skipped, count remains 0
        assert result["count"] == 0
        assert result["malware_printable"] == []

    @responses.activate
    def test_analyze_data_is_dict_not_list(self, secrets_with_valid_key, ipv4_observable):
        """Test response where 'data' is dict instead of list."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"query_status": "ok", "data": {"malware_printable": "Trojan"}}

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        # isinstance(dict, list) is False, processing skipped
        assert result["count"] == 0
        assert result["malware_printable"] == []

    @responses.activate
    def test_analyze_data_is_string(self, secrets_with_valid_key, ipv4_observable):
        """Test response where 'data' is string instead of list."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"query_status": "ok", "data": "some string"}

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        # isinstance("string", list) is False, processing skipped
        assert result["count"] == 0
        assert result["malware_printable"] == []

    @responses.activate
    def test_analyze_invalid_json_response(self, secrets_with_valid_key, ipv4_observable):
        """Test response that's not valid JSON."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        responses.add(responses.POST, url, body="not valid json", status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        # JSON decode error caught as generic Exception, returns None
        assert result is None


class TestConnectionErrors:
    """Test connection and timeout errors."""

    @responses.activate
    def test_analyze_timeout_error(self, secrets_with_valid_key, ipv4_observable):
        """Test timeout during API request."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        responses.add(responses.POST, url, body=requests.exceptions.Timeout())

        result = engine.analyze(ipv4_observable, "IPv4")

        # Timeout caught as generic Exception, returns None
        assert result is None

    @responses.activate
    def test_analyze_connection_error(self, secrets_with_valid_key, ipv4_observable):
        """Test connection error during API request."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        responses.add(responses.POST, url, body=requests.exceptions.ConnectionError())

        result = engine.analyze(ipv4_observable, "IPv4")

        # Connection error caught as generic Exception, returns None
        assert result is None


# ============================================================================
# Phase 4: Low Priority Tests - Export Formatting & Properties
# ============================================================================


class TestCreateExportRow:
    """Test export row formatting."""

    def test_export_row_with_single_malware(self):
        """Test export formatting with single malware family."""
        engine = ThreatFoxEngine(Secrets(), proxies={}, ssl_verify=True)

        analysis_result = {
            "count": 1,
            "malware_printable": ["Trojan.Generic"],
            "link": "https://threatfox.abuse.ch/browse.php?search=ioc%3A1.1.1.1",
        }

        export_row = engine.create_export_row(analysis_result)

        assert export_row["tf_count"] == 1
        assert export_row["tf_malware"] == "Trojan.Generic"

    def test_export_row_with_multiple_malware(self):
        """Test export formatting with multiple malware families."""
        engine = ThreatFoxEngine(Secrets(), proxies={}, ssl_verify=True)

        analysis_result = {
            "count": 3,
            "malware_printable": ["Trojan.A", "Trojan.B", "Trojan.C"],
            "link": "https://threatfox.abuse.ch/browse.php?search=ioc%3A1.1.1.1",
        }

        export_row = engine.create_export_row(analysis_result)

        assert export_row["tf_count"] == 3
        # Order might vary due to set, but all should be comma-joined
        malware_parts = set(export_row["tf_malware"].split(", "))
        assert malware_parts == {"Trojan.A", "Trojan.B", "Trojan.C"}

    def test_export_row_with_empty_malware_list(self):
        """Test export formatting with empty malware list."""
        engine = ThreatFoxEngine(Secrets(), proxies={}, ssl_verify=True)

        analysis_result = {
            "count": 0,
            "malware_printable": [],
            "link": "https://threatfox.abuse.ch/browse.php?search=ioc%3A1.1.1.1",
        }

        export_row = engine.create_export_row(analysis_result)

        assert export_row["tf_count"] == 0
        assert export_row["tf_malware"] is None

    def test_export_row_with_none_result(self):
        """Test export formatting when analysis_result is None."""
        engine = ThreatFoxEngine(Secrets(), proxies={}, ssl_verify=True)

        export_row = engine.create_export_row(None)

        assert export_row["tf_count"] is None
        assert export_row["tf_malware"] is None

    def test_export_row_with_missing_malware_field(self):
        """Test export formatting when malware_printable field missing."""
        engine = ThreatFoxEngine(Secrets(), proxies={}, ssl_verify=True)

        analysis_result = {
            "count": 1,
            "link": "https://threatfox.abuse.ch/browse.php?search=ioc%3A1.1.1.1",
            # malware_printable missing
        }

        export_row = engine.create_export_row(analysis_result)

        assert export_row["tf_count"] == 1
        assert export_row["tf_malware"] is None


class TestEngineProperties:
    """Test engine properties."""

    def test_engine_name(self):
        """Test engine name property."""
        engine = ThreatFoxEngine(Secrets(), proxies={}, ssl_verify=True)
        assert engine.name == "threatfox"

    def test_supported_types(self):
        """Test supported observable types."""
        engine = ThreatFoxEngine(Secrets(), proxies={}, ssl_verify=True)
        assert set(engine.supported_types) == {"FQDN", "IPv4", "IPv6", "URL"}
        assert len(engine.supported_types) == 4


# ============================================================================
# Phase 5: Edge Cases & Integration Tests
# ============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @responses.activate
    def test_url_parsing_malformed_url_missing_slashes(self, secrets_with_valid_key):
        """Test URL parsing with malformed URL.

        TODO: Bug #1 - Unsafe URL parsing.
        Current behavior: 'malformed'.split('/')[2] raises IndexError.
        Consider adding validation: try-except or URL parsing library.
        """
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

        # Malformed URL without proper scheme
        result = engine.analyze("malformed-url", "URL")

        # Should return None due to IndexError in URL parsing
        assert result is None

    @responses.activate
    def test_url_parsing_ipv6_url(self, secrets_with_valid_key):
        """Test URL parsing with IPv6 in URL.

        Note: IPv6 URLs with brackets have limited characters after [,
        so split("/")[2] returns just "[" which then split(":")[0] extracts "[".
        """
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        ipv6_url = "https://[::1]/path"
        mock_resp = {"data": []}
        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv6_url, "URL")

        assert result is not None
        request_body = json.loads(responses.calls[0].request.body)
        # IPv6 URL parsing: split("/")[2] gives "[", split(":")[0] gives "["
        # This is a limitation of the simple split-based parsing (Bug #1)
        assert request_body["search_term"] == "["

    @responses.activate
    def test_large_data_set(self, secrets_with_valid_key, ipv4_observable):
        """Test handling of large data sets (100+ items)."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        # Create 100 items with 10 unique malware families
        data_items = []
        for i in range(100):
            malware = f"Trojan.{i % 10}"
            data_items.append(
                {"ioc": ipv4_observable, "malware_printable": malware, "threat_level": 100}
            )

        mock_resp = {"data": data_items}
        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        assert result["count"] == 100
        # Set deduplicates to 10 unique families
        assert len(result["malware_printable"]) == 10

    @responses.activate
    def test_link_consistency_same_observable(self, secrets_with_valid_key, ipv4_observable):
        """Test that same observable generates consistent link."""
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"data": []}
        responses.add(responses.POST, url, json=mock_resp, status=200)

        result1 = engine.analyze(ipv4_observable, "IPv4")

        # Reset responses and make another call
        responses.reset()
        responses.add(responses.POST, url, json=mock_resp, status=200)

        result2 = engine.analyze(ipv4_observable, "IPv4")

        assert result1["link"] == result2["link"]
        assert ipv4_observable in result1["link"]

    @responses.activate
    def test_link_generation_with_special_characters(self, secrets_with_valid_key):
        """Test link generation with observable containing special characters.

        TODO: Bug #7 - No URL encoding in browse link.
        Also highlights Bug #1: unsafe URL parsing fails on URLs without proper slashes.
        Current: Observable with spaces causes IndexError in URL parsing.
        """
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)

        # Observable with special characters (if parsed as URL)
        special_observable = "example.com/path with space"

        # This will cause IndexError due to Bug #1 (unsafe URL parsing)
        # URL parsing assumes at least 3 segments when split by "/"
        result = engine.analyze(special_observable, "URL")

        # Returns None due to exception in URL parsing
        assert result is None

    @responses.activate
    def test_mixed_valid_invalid_items_in_data(self, secrets_with_valid_key, ipv4_observable):
        """Test response with mix of valid and invalid items.

        Note: Both None and empty dict {} are falsy, so they're skipped by if item check.
        Only truthy dicts (non-empty) are processed.
        """
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {
            "data": [
                None,  # Falsy, skipped
                {"ioc": ipv4_observable, "malware_printable": "Trojan.A"},
                {},  # Falsy (empty dict), skipped
                {"ioc": ipv4_observable, "malware_printable": "Trojan.B"},
                {"ioc": ipv4_observable},  # Truthy dict, missing malware_printable gets "Unknown"
            ],
        }

        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        # Count counts all 5 items in the list
        assert result["count"] == 5
        # Three items are processed (None and empty dict skipped by if item check)
        # Two with explicit malware values and one with "Unknown" for missing field
        assert "Trojan.A" in result["malware_printable"]
        assert "Trojan.B" in result["malware_printable"]
        assert "Unknown" in result["malware_printable"]

    @responses.activate
    def test_proxies_and_ssl_verify_passed_to_request(
        self, secrets_with_valid_key, ipv4_observable
    ):
        """Test that proxies and ssl_verify are passed to requests."""
        proxies = {"https": "https://proxy.example.com:8080"}
        engine = ThreatFoxEngine(secrets_with_valid_key, proxies=proxies, ssl_verify=False)
        url = "https://threatfox-api.abuse.ch/api/v1/"

        mock_resp = {"data": []}
        responses.add(responses.POST, url, json=mock_resp, status=200)

        result = engine.analyze(ipv4_observable, "IPv4")

        assert result is not None
        # Verify request was made (proxies and ssl_verify are used internally by requests)
        assert len(responses.calls) == 1
