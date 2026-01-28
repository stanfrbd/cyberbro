"""
Comprehensive test suite for PhishTank engine.

Tests cover:
- Observable type routing (FQDN and URL)
- FQDN to URL conversion
- URL path normalization
- Response structure variations
- API response content variations
- HTTP error handling (parametrized)
- Export row creation
- Engine properties
"""

from typing import Any

import pytest
import responses

from engines.phishtank import PhishTankEngine
from models.base_engine import BaseEngine
from utils.config import Secrets


@pytest.fixture
def engine() -> PhishTankEngine:
    """Fixture providing PhishTank engine (no credentials required)."""
    s = Secrets()
    return PhishTankEngine(secrets=s, proxies={}, ssl_verify=True)


@pytest.fixture
def realistic_api_response() -> dict[str, Any]:
    """Fixture providing realistic PhishTank API response."""
    return {
        "results": {
            "in_database": True,
            "verified": True,
            "valid": True,
        }
    }


class TestPhishTankSuccessfulAnalysis:
    """Test successful analysis scenarios."""

    @responses.activate
    def test_successful_analysis_url(
        self, engine: PhishTankEngine, realistic_api_response: dict
    ) -> None:
        """Test successful analysis with URL observable type."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json=realistic_api_response,
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is not None
        assert result["in_database"] is True
        assert result["verified"] is True
        assert result["valid"] is True

    @responses.activate
    def test_successful_analysis_fqdn(
        self, engine: PhishTankEngine, realistic_api_response: dict
    ) -> None:
        """Test successful analysis with FQDN observable type."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json=realistic_api_response,
            status=200,
        )

        result = engine.analyze("example.com", "FQDN")

        assert result is not None
        assert result["in_database"] is True


class TestPhishTankObservableTypeRouting:
    """Test observable type routing with parametrization."""

    @pytest.mark.parametrize(
        "observable_type,observable_value",
        [("URL", "http://example.com"), ("FQDN", "example.com")],
    )
    @responses.activate
    def test_all_observable_types(
        self, observable_type: str, observable_value: str, engine: PhishTankEngine
    ) -> None:
        """Test successful analysis for all supported observable types."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": True, "verified": True, "valid": True}},
            status=200,
        )

        result = engine.analyze(observable_value, observable_type)

        assert result is not None
        assert "in_database" in result

    def test_supported_types_property(self, engine: PhishTankEngine) -> None:
        """Test that engine returns supported types."""
        expected_types = ["FQDN", "URL"]
        assert engine.supported_types == expected_types


class TestPhishTankFQDNConversion:
    """Test FQDN to URL conversion."""

    @responses.activate
    def test_fqdn_simple_domain(self, engine: PhishTankEngine) -> None:
        """Test FQDN conversion for simple domain."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("example.com", "FQDN")

        assert result is not None
        assert result["in_database"] is False

    @responses.activate
    def test_fqdn_subdomain(self, engine: PhishTankEngine) -> None:
        """Test FQDN conversion for subdomain."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("sub.example.com", "FQDN")

        assert result is not None
        assert result["in_database"] is False


class TestPhishTankURLNormalization:
    """Test URL path normalization."""

    @responses.activate
    def test_url_without_path(self, engine: PhishTankEngine) -> None:
        """Test URL normalization adds trailing slash when path missing."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is not None

    @responses.activate
    def test_url_https_without_path(self, engine: PhishTankEngine) -> None:
        """Test HTTPS URL normalization adds trailing slash."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("https://example.com", "URL")

        assert result is not None

    @responses.activate
    def test_url_with_port_without_path(self, engine: PhishTankEngine) -> None:
        """Test URL with port but no path gets trailing slash added."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("http://example.com:8080", "URL")

        assert result is not None

    @responses.activate
    def test_url_with_path_no_normalization(self, engine: PhishTankEngine) -> None:
        """Test URL with path doesn't get modified."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("http://example.com/path", "URL")

        assert result is not None

    @responses.activate
    def test_url_with_path_and_trailing_slash(self, engine: PhishTankEngine) -> None:
        """Test URL with path and trailing slash stays unchanged."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("http://example.com/path/", "URL")

        assert result is not None


class TestPhishTankResponseStructure:
    """Test response structure variations."""

    @responses.activate
    def test_response_with_results_key(self, engine: PhishTankEngine) -> None:
        """Test normal response with 'results' key."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={
                "results": {
                    "in_database": True,
                    "verified": True,
                    "valid": True,
                }
            },
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is not None
        assert result["in_database"] is True

    @responses.activate
    def test_response_missing_results_key(self, engine: PhishTankEngine) -> None:
        """Test response missing 'results' key returns None."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"data": {"in_database": True}},
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is None

    @responses.activate
    def test_response_with_empty_results(self, engine: PhishTankEngine) -> None:
        """Test response with empty results object."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {}},
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is not None
        assert result == {}


class TestPhishTankAPIResponseContent:
    """Test API response content variations."""

    @responses.activate
    def test_complete_result_data(self, engine: PhishTankEngine) -> None:
        """Test result with all fields present."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={
                "results": {
                    "in_database": True,
                    "verified": True,
                    "valid": True,
                }
            },
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is not None
        assert result["in_database"] is True
        assert result["verified"] is True
        assert result["valid"] is True

    @responses.activate
    def test_partial_result_data(self, engine: PhishTankEngine) -> None:
        """Test result with missing optional fields."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False}},
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is not None
        assert result["in_database"] is False
        assert result.get("verified") is None

    @responses.activate
    def test_result_with_false_values(self, engine: PhishTankEngine) -> None:
        """Test result with all false/zero values."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={
                "results": {
                    "in_database": False,
                    "verified": False,
                    "valid": False,
                }
            },
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is not None
        assert result["in_database"] is False
        assert result["verified"] is False
        assert result["valid"] is False


class TestPhishTankBase64Encoding:
    """Test URL base64 encoding."""

    @responses.activate
    def test_simple_url_encoding(self, engine: PhishTankEngine) -> None:
        """Test base64 encoding of simple URL."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("http://example.com", "URL")

        assert result is not None

    @responses.activate
    def test_url_with_special_characters(self, engine: PhishTankEngine) -> None:
        """Test base64 encoding of URL with special characters."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"results": {"in_database": False, "verified": False, "valid": False}},
            status=200,
        )

        result = engine.analyze("http://example.com/path?query=value&other=123", "URL")

        assert result is not None


class TestPhishTankHTTPErrors:
    """Test HTTP error scenarios with parametrization."""

    @pytest.mark.parametrize(
        "status_code",
        [401, 403, 404, 500, 503],
    )
    @responses.activate
    def test_http_error_codes(self, status_code: int, engine: PhishTankEngine) -> None:
        """Test graceful handling of various HTTP error codes."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            json={"error": f"Error {status_code}"},
            status=status_code,
        )

        result = engine.analyze("http://example.com", "URL")
        assert result is None

    @responses.activate
    def test_connection_timeout(self, engine: PhishTankEngine) -> None:
        """Test graceful handling of connection timeout."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            body=ConnectionError("Connection timeout"),
        )

        result = engine.analyze("http://example.com", "URL")
        assert result is None

    @responses.activate
    def test_connection_refused(self, engine: PhishTankEngine) -> None:
        """Test graceful handling of connection refused."""
        responses.add(
            responses.POST,
            "https://checkurl.phishtank.com/checkurl/",
            body=ConnectionRefusedError("Connection refused"),
        )

        result = engine.analyze("http://example.com", "URL")
        assert result is None


class TestPhishTankExportRow:
    """Test export row creation."""

    def test_export_row_complete_data(self, engine: PhishTankEngine) -> None:
        """Test export row with complete result data."""
        analysis_result = {
            "in_database": True,
            "verified": True,
            "valid": True,
        }

        export_row = engine.create_export_row(analysis_result)

        assert "phishtank_in_db" in export_row
        assert "phishtank_verified" in export_row
        assert "phishtank_valid" in export_row
        assert export_row["phishtank_in_db"] is True
        assert export_row["phishtank_verified"] is True
        assert export_row["phishtank_valid"] is True

    def test_export_row_partial_data(self, engine: PhishTankEngine) -> None:
        """Test export row with partial result data."""
        analysis_result = {
            "in_database": True,
        }

        export_row = engine.create_export_row(analysis_result)

        assert export_row["phishtank_in_db"] is True
        assert export_row["phishtank_verified"] is None
        assert export_row["phishtank_valid"] is None

    def test_export_row_false_values(self, engine: PhishTankEngine) -> None:
        """Test export row with false/zero values."""
        analysis_result = {
            "in_database": False,
            "verified": False,
            "valid": False,
        }

        export_row = engine.create_export_row(analysis_result)

        assert export_row["phishtank_in_db"] is False
        assert export_row["phishtank_verified"] is False
        assert export_row["phishtank_valid"] is False

    def test_export_row_none_input(self, engine: PhishTankEngine) -> None:
        """Test export row creation with None input."""
        export_row = engine.create_export_row(None)

        assert export_row["phishtank_in_db"] is None
        assert export_row["phishtank_verified"] is None
        assert export_row["phishtank_valid"] is None


class TestPhishTankEngineProperties:
    """Test engine properties."""

    def test_engine_name(self, engine: PhishTankEngine) -> None:
        """Test that engine name is 'phishtank'."""
        assert engine.name == "phishtank"

    def test_engine_is_base_engine(self, engine: PhishTankEngine) -> None:
        """Test that PhishTankEngine is instance of BaseEngine."""
        assert isinstance(engine, BaseEngine)
