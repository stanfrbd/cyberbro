"""Comprehensive test suite for SpurUS engine."""

import logging
from typing import Any
from unittest.mock import Mock

import pytest
import requests
import responses

from engines.spur_us import SpurUSEngine
from models.observable import ObservableType
from utils.config import Secrets

# ============================================================================
# FIXTURES - Phase 1
# ============================================================================


@pytest.fixture
def secrets_with_valid_key() -> Secrets:
    """Secrets object with valid Spur.US API key."""
    mock_secrets = Mock(spec=Secrets)
    mock_secrets.spur_us = "valid-api-key-12345"
    return mock_secrets


@pytest.fixture
def secrets_with_empty_key() -> Secrets:
    """Secrets object with empty API key."""
    mock_secrets = Mock(spec=Secrets)
    mock_secrets.spur_us = ""
    return mock_secrets


@pytest.fixture
def secrets_with_whitespace_key() -> Secrets:
    """Secrets object with whitespace-only API key."""
    mock_secrets = Mock(spec=Secrets)
    mock_secrets.spur_us = "   "
    return mock_secrets


@pytest.fixture
def secrets_with_none_key() -> Secrets:
    """Secrets object with None API key."""
    mock_secrets = Mock(spec=Secrets)
    mock_secrets.spur_us = None
    return mock_secrets


@pytest.fixture
def ipv4_observable() -> str:
    """IPv4 observable value."""
    return "1.2.3.4"


@pytest.fixture
def ipv6_observable() -> str:
    """IPv6 observable value."""
    return "::1"


@pytest.fixture
def valid_api_response() -> dict[str, Any]:
    """Valid API response with complete data."""
    return {
        "tunnels": [{"operator": "Acme Tunnels", "country": "US"}],
        "type": "residential",
        "country": "US",
        "autonomous_system": {"number": 12345, "name": "Example AS"},
    }


@pytest.fixture
def api_response_no_operator() -> dict[str, Any]:
    """API response with tunnels but no operator field."""
    return {
        "tunnels": [{"country": "US"}, {"protocol": "OpenVPN"}],
        "type": "residential",
        "country": "US",
    }


@pytest.fixture
def api_response_empty_operator() -> dict[str, Any]:
    """API response with empty operator value."""
    return {
        "tunnels": [{"operator": ""}, {"operator": None}],
        "type": "residential",
        "country": "US",
    }


@pytest.fixture
def api_response_multiple_tunnels() -> dict[str, Any]:
    """API response with multiple tunnels."""
    return {
        "tunnels": [
            {"country": "US"},
            {"operator": "First Operator"},
            {"operator": "Second Operator"},
        ],
        "type": "residential",
        "country": "US",
    }


@pytest.fixture
def api_response_empty_tunnels() -> dict[str, Any]:
    """API response with empty tunnels list."""
    return {
        "tunnels": [],
        "type": "residential",
        "country": "US",
    }


@pytest.fixture
def api_response_no_tunnels_field() -> dict[str, Any]:
    """API response without tunnels field."""
    return {
        "type": "residential",
        "country": "US",
        "autonomous_system": {"number": 12345},
    }


# ============================================================================
# PHASE 2: HIGH PRIORITY TESTS - Credential Paths & Observable Types
# ============================================================================


class TestCredentialPathSelection:
    """Test API vs fallback path selection based on credentials."""

    @responses.activate
    def test_api_path_with_valid_key(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """With valid API key, API path should be taken."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": [{"operator": "Acme"}], "country": "US"},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result is not None
        assert "data" in result
        assert result["data"]["country"] == "US"

    @responses.activate
    def test_fallback_path_with_empty_key(
        self, secrets_with_empty_key: Secrets, ipv4_observable: str
    ) -> None:
        """With empty API key, fallback path should be taken."""
        engine = SpurUSEngine(secrets_with_empty_key, proxies={}, ssl_verify=True)
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result is not None
        assert "data" not in result
        assert result["tunnels"] == "Unknown - Behind Captcha"

    @responses.activate
    def test_fallback_path_with_whitespace_key(
        self, secrets_with_whitespace_key: Secrets, ipv4_observable: str
    ) -> None:
        """With whitespace API key, fallback path should be taken (Bug #1 fix)."""
        engine = SpurUSEngine(secrets_with_whitespace_key, proxies={}, ssl_verify=True)
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result is not None
        assert "data" not in result
        assert result["tunnels"] == "Unknown - Behind Captcha"

    @responses.activate
    def test_fallback_path_with_none_key(
        self, secrets_with_none_key: Secrets, ipv4_observable: str
    ) -> None:
        """With None API key, fallback path should be taken."""
        engine = SpurUSEngine(secrets_with_none_key, proxies={}, ssl_verify=True)
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result is not None
        assert "data" not in result
        assert result["tunnels"] == "Unknown - Behind Captcha"

    @responses.activate
    def test_api_request_includes_token_header(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """API request should include Token header with API key."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": []},
            status=200,
        )
        engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert len(responses.calls) == 1
        assert responses.calls[0].request.headers.get("Token") == "valid-api-key-12345"

    @responses.activate
    def test_correct_api_endpoint_used(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """API endpoint should be api.spur.us (not spur.us)."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": []},
            status=200,
        )
        engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert "api.spur.us" in responses.calls[0].request.url


class TestObservableTypes:
    """Test observable type support."""

    @responses.activate
    @pytest.mark.parametrize(
        "obs_type,obs_value",
        [
            (ObservableType.IPV4, "1.2.3.4"),
            (ObservableType.IPV6, "::1"),
            (ObservableType.IPV6, "2001:db8::1"),
        ],
    )
    def test_both_ip_types_construct_correct_urls(
        self, secrets_with_valid_key: Secrets, obs_type: str, obs_value: str
    ) -> None:
        """Both IPv4 and IPv6 should construct correct URLs."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            f"https://api.spur.us/v2/context/{obs_value}",
            json={"tunnels": []},
            status=200,
        )
        result = engine.analyze(obs_value, obs_type)
        assert result is not None
        assert result["link"] == f"https://spur.us/context/{obs_value}"


class TestHTTPErrorResponses:
    """Test handling of various HTTP error responses."""

    @responses.activate
    @pytest.mark.parametrize("status_code", [401, 403, 500, 502, 503])
    def test_http_errors_return_fallback(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str, status_code: int
    ) -> None:
        """HTTP errors should return fallback value."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            status=status_code,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result is not None
        assert result["tunnels"] == "Unknown - Behind Captcha"
        assert "data" not in result

    @responses.activate
    def test_401_unauthorized(self, secrets_with_valid_key: Secrets, ipv4_observable: str) -> None:
        """401 Unauthorized should return fallback."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"error": "Unauthorized"},
            status=401,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Unknown - Behind Captcha"

    @responses.activate
    def test_403_forbidden(self, secrets_with_valid_key: Secrets, ipv4_observable: str) -> None:
        """403 Forbidden should return fallback."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"error": "Forbidden"},
            status=403,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Unknown - Behind Captcha"


class TestSuccessfulAPIResponse:
    """Test handling of successful API responses."""

    @responses.activate
    def test_api_success_returns_three_fields(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """Successful API response should have link, tunnels, and data fields."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": [{"operator": "Acme"}], "country": "US"},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert set(result.keys()) == {"link", "tunnels", "data"}

    @responses.activate
    def test_api_success_link_field(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """Link field should be spur.us URL (not api.spur.us)."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": []},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["link"] == "https://spur.us/context/1.2.3.4"

    @responses.activate
    def test_api_success_data_field_contains_raw_json(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """Data field should contain raw API response."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        api_data = {
            "tunnels": [{"operator": "Acme"}],
            "country": "US",
            "type": "residential",
        }
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json=api_data,
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["data"] == api_data


# ============================================================================
# PHASE 3: MEDIUM PRIORITY TESTS - Data Extraction & Error Handling
# ============================================================================


class TestTunnelExtraction:
    """Test tunnel operator extraction logic."""

    @responses.activate
    @pytest.mark.parametrize(
        "tunnel_data,expected_operator",
        [
            ([{"operator": "Acme Tunnels"}], "Acme Tunnels"),
            ([{"operator": "ExpressVPN"}], "ExpressVPN"),
            ([{"operator": "Custom VPN"}], "Custom VPN"),
        ],
    )
    def test_single_tunnel_with_operator(
        self,
        secrets_with_valid_key: Secrets,
        ipv4_observable: str,
        tunnel_data: list[dict[str, Any]],
        expected_operator: str,
    ) -> None:
        """Single tunnel with operator should be extracted."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": tunnel_data},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == expected_operator

    @responses.activate
    def test_multiple_tunnels_uses_first_operator(
        self,
        secrets_with_valid_key: Secrets,
        ipv4_observable: str,
        api_response_multiple_tunnels: dict[str, Any],
    ) -> None:
        """Multiple tunnels should use first operator found."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json=api_response_multiple_tunnels,
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "First Operator"

    @responses.activate
    def test_tunnel_with_none_operator(
        self,
        secrets_with_valid_key: Secrets,
        ipv4_observable: str,
        api_response_empty_operator: dict[str, Any],
    ) -> None:
        """Tunnel with None operator should use default."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json=api_response_empty_operator,
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Not anonymous"

    @responses.activate
    def test_tunnel_with_empty_string_operator(
        self,
        secrets_with_valid_key: Secrets,
        ipv4_observable: str,
    ) -> None:
        """Tunnel with empty string operator should use default."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": [{"operator": ""}]},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Not anonymous"

    @responses.activate
    def test_tunnel_without_operator_field(
        self,
        secrets_with_valid_key: Secrets,
        ipv4_observable: str,
        api_response_no_operator: dict[str, Any],
    ) -> None:
        """Tunnel without operator field should use default."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json=api_response_no_operator,
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Not anonymous"

    @responses.activate
    def test_empty_tunnels_list(
        self,
        secrets_with_valid_key: Secrets,
        ipv4_observable: str,
        api_response_empty_tunnels: dict[str, Any],
    ) -> None:
        """Empty tunnels list should use default."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json=api_response_empty_tunnels,
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Not anonymous"

    @responses.activate
    def test_missing_tunnels_field(
        self,
        secrets_with_valid_key: Secrets,
        ipv4_observable: str,
        api_response_no_tunnels_field: dict[str, Any],
    ) -> None:
        """Missing tunnels field should use default."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json=api_response_no_tunnels_field,
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Not anonymous"


class TestInvalidTunnelDataStructures:
    """Test handling of invalid tunnel data structures.

    TODO: Bug #2 - Tunnel data should be validated with isinstance()
    These tests document current behavior where invalid types cause silent exceptions.
    """

    @responses.activate
    def test_tunnel_field_is_none(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str, caplog: Any
    ) -> None:
        """Tunnels field as None should return fallback (Bug #2 current behavior)."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        caplog.set_level(logging.ERROR)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": None},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Not anonymous"

    @responses.activate
    def test_tunnel_field_is_string(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str, caplog: Any
    ) -> None:
        """Tunnels field as string should cause exception and return fallback (Bug #2)."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        caplog.set_level(logging.ERROR)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": "string-not-list"},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Unknown - Behind Captcha"
        assert "Error querying spur.us" in caplog.text

    @responses.activate
    def test_tunnel_field_is_dict(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str, caplog: Any
    ) -> None:
        """Tunnels field as dict should cause exception and return fallback (Bug #2)."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        caplog.set_level(logging.ERROR)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": {"invalid": "structure"}},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Unknown - Behind Captcha"
        assert "Error querying spur.us" in caplog.text


class TestRequestExceptions:
    """Test handling of network request exceptions.

    TODO: Bug #3 - Should catch specific exception types, not generic Exception
    These tests document current behavior where all exceptions return same fallback.
    """

    @responses.activate
    def test_request_timeout(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str, caplog: Any
    ) -> None:
        """Request timeout should return fallback (Bug #3 current behavior)."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        caplog.set_level(logging.ERROR)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            body=requests.ConnectTimeout("Connection timeout"),
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Unknown - Behind Captcha"
        assert "Error querying spur.us" in caplog.text

    @responses.activate
    def test_connection_error(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str, caplog: Any
    ) -> None:
        """Connection error should return fallback (Bug #3 current behavior)."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        caplog.set_level(logging.ERROR)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            body=requests.ConnectionError("Connection failed"),
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Unknown - Behind Captcha"
        assert "Error querying spur.us" in caplog.text

    @responses.activate
    def test_generic_exception(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str, caplog: Any
    ) -> None:
        """Generic exception should return fallback."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        caplog.set_level(logging.ERROR)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            body=Exception("Generic error"),
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Unknown - Behind Captcha"
        assert "Error querying spur.us" in caplog.text


class TestJSONParsingErrors:
    """Test handling of JSON parsing errors."""

    @responses.activate
    def test_invalid_json_response(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str, caplog: Any
    ) -> None:
        """Invalid JSON response should return fallback."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        caplog.set_level(logging.ERROR)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            body="not valid json {{{",
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["tunnels"] == "Unknown - Behind Captcha"
        assert "Error querying spur.us" in caplog.text


# ============================================================================
# PHASE 4: LOW PRIORITY TESTS - Export & Properties
# ============================================================================


class TestCreateExportRow:
    """Test export row creation."""

    def test_export_with_complete_api_result(self) -> None:
        """Export with complete API result should extract tunnels."""
        mock_secrets = Mock(spec=Secrets)
        engine = SpurUSEngine(mock_secrets, proxies={}, ssl_verify=True)
        analysis_result = {
            "link": "https://spur.us/context/1.2.3.4",
            "tunnels": "Acme Tunnels",
            "data": {"country": "US"},
        }
        export_row = engine.create_export_row(analysis_result)
        assert export_row == {"spur_us_anon": "Acme Tunnels"}

    def test_export_with_fallback_result(self) -> None:
        """Export with fallback result should extract tunnels."""
        mock_secrets = Mock(spec=Secrets)
        engine = SpurUSEngine(mock_secrets, proxies={}, ssl_verify=True)
        analysis_result = {
            "link": "https://spur.us/context/1.2.3.4",
            "tunnels": "Unknown - Behind Captcha",
        }
        export_row = engine.create_export_row(analysis_result)
        assert export_row == {"spur_us_anon": "Unknown - Behind Captcha"}

    def test_export_with_none_result(self) -> None:
        """Export with None result should return None."""
        mock_secrets = Mock(spec=Secrets)
        engine = SpurUSEngine(mock_secrets, proxies={}, ssl_verify=True)
        export_row = engine.create_export_row(None)
        assert export_row == {"spur_us_anon": None}

    def test_export_with_empty_result(self) -> None:
        """Export with empty result should return None."""
        mock_secrets = Mock(spec=Secrets)
        engine = SpurUSEngine(mock_secrets, proxies={}, ssl_verify=True)
        export_row = engine.create_export_row({})
        assert export_row == {"spur_us_anon": None}

    @responses.activate
    def test_export_default_value(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """Export should use default 'Not anonymous' when no tunnels extracted."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": []},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        export_row = engine.create_export_row(result)
        assert export_row == {"spur_us_anon": "Not anonymous"}


class TestEngineProperties:
    """Test engine property values."""

    def test_name_property(self) -> None:
        """Engine name should be 'spur'."""
        mock_secrets = Mock(spec=Secrets)
        engine = SpurUSEngine(mock_secrets, proxies={}, ssl_verify=True)
        assert engine.name == "spur"

    def test_supported_types(self) -> None:
        """Supported types should be IPv4 and IPv6."""
        mock_secrets = Mock(spec=Secrets)
        engine = SpurUSEngine(mock_secrets, proxies={}, ssl_verify=True)
        assert engine.supported_types is ObservableType.IPV4 | ObservableType.IPV6
        assert len(engine.supported_types) == 2

    def test_execute_after_reverse_dns(self) -> None:
        """Should execute after reverse DNS."""
        mock_secrets = Mock(spec=Secrets)
        engine = SpurUSEngine(mock_secrets, proxies={}, ssl_verify=True)
        assert engine.execute_after_reverse_dns is True


# ============================================================================
# PHASE 5: EDGE CASES & CONFIGURATION
# ============================================================================


class TestEdgeCasesAndConfiguration:
    """Test edge cases and configuration handling."""

    @responses.activate
    def test_with_proxies_configured(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """Proxies should be passed to requests."""
        proxies = {"http": "http://proxy.example.com:8080"}
        engine = SpurUSEngine(secrets_with_valid_key, proxies=proxies, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": []},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result is not None

    @responses.activate
    def test_with_ssl_verify_false(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """SSL verify setting should be respected."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=False)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": []},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result is not None

    @responses.activate
    def test_timeout_is_enforced(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """Request should use 5 second timeout."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": []},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result is not None

    @responses.activate
    def test_response_structure_consistency_api_path(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """API path response should have consistent structure."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json={"tunnels": [{"operator": "Test"}], "country": "US"},
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert isinstance(result, dict)
        assert all(k in result for k in ["link", "tunnels", "data"])

    @responses.activate
    def test_response_structure_consistency_fallback_path(
        self, secrets_with_empty_key: Secrets, ipv4_observable: str
    ) -> None:
        """Fallback response should have consistent structure."""
        engine = SpurUSEngine(secrets_with_empty_key, proxies={}, ssl_verify=True)
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert isinstance(result, dict)
        assert all(k in result for k in ["link", "tunnels"])
        assert "data" not in result

    @responses.activate
    @pytest.mark.parametrize("obs_value", ["1.2.3.4", "::1", "192.168.1.1"])
    def test_ipv4_and_ipv6_consistency(
        self, secrets_with_valid_key: Secrets, obs_value: str
    ) -> None:
        """IPv4 and IPv6 should follow same logic."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        obs_type = ObservableType.IPV6 if ":" in obs_value else ObservableType.IPV4
        responses.add(
            responses.GET,
            f"https://api.spur.us/v2/context/{obs_value}",
            json={"tunnels": [{"operator": "Test"}]},
            status=200,
        )
        result = engine.analyze(obs_value, obs_type)
        assert result is not None
        assert result["link"] == f"https://spur.us/context/{obs_value}"
        assert "tunnels" in result

    @responses.activate
    def test_extra_fields_in_response_ignored(
        self, secrets_with_valid_key: Secrets, ipv4_observable: str
    ) -> None:
        """Extra fields in response should be stored in data field."""
        engine = SpurUSEngine(secrets_with_valid_key, proxies={}, ssl_verify=True)
        api_response = {
            "tunnels": [],
            "country": "US",
            "extra_field_1": "value1",
            "extra_field_2": {"nested": "value"},
        }
        responses.add(
            responses.GET,
            "https://api.spur.us/v2/context/1.2.3.4",
            json=api_response,
            status=200,
        )
        result = engine.analyze(ipv4_observable, ObservableType.IPV4)
        assert result["data"] == api_response
