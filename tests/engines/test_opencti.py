"""
Comprehensive test suite for OpenCTI engine.

Tests cover:
- Credential validation and API errors
- Observable type routing (all 8 types)
- URL domain extraction (valid and malformed formats)
- Dual API call scenarios (globalSearch + indicator queries)
- Response structure variations and edge cases
- Indicator query variations
- HTTP error handling (parametrized)
- Export row creation
- Engine properties
"""

from typing import Any

import pytest
import responses

from engines.opencti import OpenCTIEngine
from models.base_engine import BaseEngine
from models.observable import ObservableType
from utils.config import Secrets


@pytest.fixture
def secrets_with_key() -> Secrets:
    """Fixture providing valid OpenCTI credentials."""
    s = Secrets()
    s.opencti_api_key = "test-api-key-12345"
    s.opencti_url = "https://opencti.example.com"
    return s


@pytest.fixture
def secrets_without_key() -> Secrets:
    """Fixture providing missing OpenCTI credentials."""
    s = Secrets()
    s.opencti_api_key = ""
    s.opencti_url = ""
    return s


@pytest.fixture
def engine_with_key(secrets_with_key: Secrets) -> OpenCTIEngine:
    """Fixture providing OpenCTI engine with valid credentials."""
    return OpenCTIEngine(secrets=secrets_with_key, proxies={}, ssl_verify=True)


@pytest.fixture
def engine_without_key(secrets_without_key: Secrets) -> OpenCTIEngine:
    """Fixture providing OpenCTI engine without credentials."""
    return OpenCTIEngine(secrets=secrets_without_key, proxies={}, ssl_verify=True)


@pytest.fixture
def realistic_global_search_response() -> dict[str, Any]:
    """Fixture providing realistic globalSearch response with Indicator entity."""
    return {
        "data": {
            "globalSearch": {
                "edges": [
                    {
                        "node": {
                            "id": "indicator-id-123",
                            "entity_type": "Indicator",
                            "created_at": "2024-01-15T10:30:00Z",
                            "createdBy": {"name": "System", "id": "system-id"},
                            "creators": [{"id": "creator-1", "name": "Admin"}],
                            "objectMarking": [
                                {
                                    "id": "marking-1",
                                    "definition_type": "statement",
                                    "definition": "Internal Use Only",
                                    "x_opencti_order": 1,
                                    "x_opencti_color": "#FF0000",
                                }
                            ],
                        },
                        "cursor": "cursor-1",
                    },
                    {
                        "node": {
                            "id": "malware-id-456",
                            "entity_type": "Malware",
                            "created_at": "2024-01-14T09:15:00Z",
                            "createdBy": {"name": "System", "id": "system-id"},
                            "creators": [{"id": "creator-1", "name": "Admin"}],
                            "objectMarking": [],
                        },
                        "cursor": "cursor-2",
                    },
                ],
                "pageInfo": {
                    "endCursor": "cursor-2",
                    "hasNextPage": False,
                    "globalCount": 2,
                },
            }
        }
    }


@pytest.fixture
def realistic_indicator_response() -> dict[str, Any]:
    """Fixture providing realistic indicator query response."""
    return {
        "data": {
            "indicator": {
                "name": "Test Indicator",
                "x_opencti_score": 75,
                "revoked": False,
                "valid_from": "2024-01-01T00:00:00Z",
                "valid_until": "2024-12-31T23:59:59Z",
                "confidence": 85,
            }
        }
    }


class TestOpenCTICredentialValidation:
    """Test credential validation and missing credentials scenarios."""

    def test_missing_api_key(self, engine_without_key: OpenCTIEngine) -> None:
        """Test analysis fails gracefully when API key is missing."""
        engine = engine_without_key
        engine.secrets.opencti_api_key = None
        result = engine.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    def test_missing_opencti_url(self, engine_without_key: OpenCTIEngine) -> None:
        """Test analysis fails gracefully when URL is missing."""
        engine = engine_without_key
        engine.secrets.opencti_url = None
        result = engine.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    def test_both_credentials_missing(self, engine_without_key: OpenCTIEngine) -> None:
        """Test analysis fails gracefully when both credentials are missing."""
        engine = engine_without_key
        engine.secrets.opencti_api_key = None
        engine.secrets.opencti_url = None
        result = engine.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None


class TestOpenCTISuccessfulAnalysis:
    """Test successful analysis scenarios."""

    @responses.activate
    def test_successful_analysis_with_indicator_entity(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test successful analysis when globalSearch returns Indicator entity."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "indicator": {
                        "name": "Test Indicator",
                        "x_opencti_score": 75,
                        "revoked": False,
                        "valid_from": "2024-01-01T00:00:00Z",
                        "valid_until": "2024-12-31T23:59:59Z",
                        "confidence": 85,
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is not None
        assert "entity_counts" in result
        assert result["entity_counts"]["Indicator"] == 1
        assert result["entity_counts"]["Malware"] == 1
        assert result["global_count"] == 2
        assert result["latest_created_at"] == "2024-01-15"
        assert result["latest_indicator_name"] == "Test Indicator"
        assert result["x_opencti_score"] == 75

    @responses.activate
    def test_successful_analysis_without_indicator_entity(
        self, engine_with_key: OpenCTIEngine
    ) -> None:
        """Test successful analysis when no Indicator entity is found (skips second query)."""
        response_no_indicator = {
            "data": {
                "globalSearch": {
                    "edges": [
                        {
                            "node": {
                                "id": "malware-id-789",
                                "entity_type": "Malware",
                                "created_at": "2024-01-14T08:00:00Z",
                                "createdBy": {"name": "System", "id": "sys"},
                                "creators": [],
                                "objectMarking": [],
                            },
                            "cursor": "cursor-1",
                        }
                    ],
                    "pageInfo": {
                        "endCursor": "cursor-1",
                        "hasNextPage": False,
                        "globalCount": 1,
                    },
                }
            }
        }

        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=response_no_indicator,
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is not None
        assert result["entity_counts"]["Malware"] == 1
        assert "Indicator" not in result["entity_counts"]
        assert result["latest_indicator_link"] is None
        assert result["latest_indicator_name"] is None


class TestOpenCTICredentialErrors:
    """Test credential-related API errors."""

    @responses.activate
    def test_invalid_api_key_401(self, engine_with_key: OpenCTIEngine) -> None:
        """Test graceful handling of 401 Unauthorized for invalid API key."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"errors": [{"message": "Invalid API key"}]},
            status=401,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_invalid_url_401(self, engine_with_key: OpenCTIEngine) -> None:
        """Test graceful handling of 401 Unauthorized for invalid URL."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"errors": [{"message": "Unauthorized"}]},
            status=401,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_forbidden_access_403(self, engine_with_key: OpenCTIEngine) -> None:
        """Test graceful handling of 403 Forbidden."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"errors": [{"message": "Forbidden"}]},
            status=403,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None


class TestOpenCTIObservableTypeRouting:
    """Test observable type routing with parametrization."""

    @pytest.mark.parametrize(
        "observable_type",
        [
            ObservableType.IPV4,
            ObservableType.IPV6,
            ObservableType.FQDN,
            ObservableType.MD5,
            ObservableType.SHA1,
            ObservableType.SHA256,
            ObservableType.URL,
            ObservableType.CHROME_EXTENSION,
        ],
    )
    @responses.activate
    def test_all_observable_types(
        self,
        observable_type: str,
        engine_with_key: OpenCTIEngine,
        realistic_global_search_response: dict,
        realistic_indicator_response: dict,
    ) -> None:
        """Test successful analysis for all supported observable types."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_indicator_response,
            status=200,
        )

        observable_value = "192.0.2.1"
        result = engine_with_key.analyze(observable_value, observable_type)

        assert result is not None
        assert result["global_count"] == 2
        assert "entity_counts" in result

    def test_supported_types_property(self, engine_with_key: OpenCTIEngine) -> None:
        """Test that engine returns all supported types."""
        engine = engine_with_key
        expected_types = (
            ObservableType.CHROME_EXTENSION
            | ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
        )
        assert engine.supported_types == expected_types


class TestOpenCTIURLExtraction:
    """Test URL domain extraction for HTTP-based observables."""

    @responses.activate
    def test_url_http_standard_port(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test URL extraction for HTTP with standard port."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": {}}},
            status=200,
        )

        result = engine_with_key.analyze("http://example.com", ObservableType.URL)
        assert result is not None

    @responses.activate
    def test_url_https_standard_port(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test URL extraction for HTTPS with standard port."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": {}}},
            status=200,
        )

        result = engine_with_key.analyze("https://example.com", ObservableType.URL)
        assert result is not None

    @responses.activate
    def test_url_with_explicit_port(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test URL extraction for URL with explicit port."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": {}}},
            status=200,
        )

        result = engine_with_key.analyze("https://example.com:8080", ObservableType.URL)
        assert result is not None

    @responses.activate
    def test_url_with_path(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test URL extraction for URL with path."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": {}}},
            status=200,
        )

        result = engine_with_key.analyze("https://example.com/some/path", ObservableType.URL)
        assert result is not None

    @responses.activate
    def test_url_with_subdomain(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test URL extraction for URL with subdomain."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": {}}},
            status=200,
        )

        result = engine_with_key.analyze("https://sub.example.com", ObservableType.URL)
        assert result is not None

    @responses.activate
    def test_malformed_url_missing_scheme(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test URL extraction for malformed URL without scheme."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": {}}},
            status=200,
        )

        result = engine_with_key.analyze("example.com", ObservableType.URL)
        assert result is None or isinstance(result, dict)

    @responses.activate
    def test_malformed_url_excessive_slashes(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test URL extraction for URL with excessive slashes."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": {}}},
            status=200,
        )

        result = engine_with_key.analyze("https:///example.com///path", ObservableType.URL)
        assert result is None or isinstance(result, dict)

    @responses.activate
    def test_malformed_url_port_without_number(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test URL extraction for URL with port but no number."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": {}}},
            status=200,
        )

        result = engine_with_key.analyze("https://example.com:/path", ObservableType.URL)
        assert result is None or isinstance(result, dict)


class TestOpenCTIDualAPICallScenarios:
    """Test dual API call scenarios (globalSearch + indicator queries)."""

    @responses.activate
    def test_both_queries_succeed(
        self,
        engine_with_key: OpenCTIEngine,
        realistic_global_search_response: dict,
        realistic_indicator_response: dict,
    ) -> None:
        """Test when both globalSearch and indicator queries succeed."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_indicator_response,
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is not None
        assert result["latest_indicator_name"] == "Test Indicator"
        assert result["x_opencti_score"] == 75

    @responses.activate
    def test_first_succeeds_second_empty_indicator(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test when first succeeds but second returns empty indicator data."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": None}},
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is None

    @responses.activate
    def test_first_succeeds_second_fails_401(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test when first query succeeds but second fails with 401."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"errors": [{"message": "Unauthorized"}]},
            status=401,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_first_succeeds_second_fails_500(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test when first query succeeds but second fails with 500."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"errors": [{"message": "Internal Server Error"}]},
            status=500,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_first_succeeds_no_indicator_entity(self, engine_with_key: OpenCTIEngine) -> None:
        """Test when first query succeeds but no Indicator entity (second never called)."""
        response_no_indicator = {
            "data": {
                "globalSearch": {
                    "edges": [
                        {
                            "node": {
                                "id": "malware-id-789",
                                "entity_type": "Malware",
                                "created_at": "2024-01-14T08:00:00Z",
                                "createdBy": {"name": "System", "id": "sys"},
                                "creators": [],
                                "objectMarking": [],
                            },
                            "cursor": "cursor-1",
                        }
                    ],
                    "pageInfo": {
                        "endCursor": "cursor-1",
                        "hasNextPage": False,
                        "globalCount": 1,
                    },
                }
            }
        }

        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=response_no_indicator,
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is not None
        assert len(responses.calls) == 1


class TestOpenCTIResponseStructure:
    """Test response structure variations and edge cases."""

    @responses.activate
    def test_missing_data_key(self, engine_with_key: OpenCTIEngine) -> None:
        """Test handling of response missing 'data' key."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"errors": [{"message": "GraphQL error"}]},
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_missing_global_search_key(self, engine_with_key: OpenCTIEngine) -> None:
        """Test handling of response missing 'globalSearch' key."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {}},
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_missing_edges_key(self, engine_with_key: OpenCTIEngine) -> None:
        """Test handling of response missing 'edges' key."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "globalSearch": {
                        "pageInfo": {
                            "endCursor": None,
                            "hasNextPage": False,
                            "globalCount": 0,
                        }
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is not None
        assert result["global_count"] == 0
        assert result["entity_counts"] == {}

    @responses.activate
    def test_missing_page_info_key(self, engine_with_key: OpenCTIEngine) -> None:
        """Test handling of response missing 'pageInfo' key."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "globalSearch": {
                        "edges": [
                            {
                                "node": {
                                    "id": "entity-1",
                                    "entity_type": "Indicator",
                                    "created_at": "2024-01-15T10:00:00Z",
                                    "createdBy": {"name": "System", "id": "sys"},
                                    "creators": [],
                                    "objectMarking": [],
                                },
                                "cursor": "cursor-1",
                            }
                        ]
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_missing_page_info_global_count(self, engine_with_key: OpenCTIEngine) -> None:
        """Test handling of response missing 'globalCount' in pageInfo."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "globalSearch": {
                        "edges": [],
                        "pageInfo": {
                            "endCursor": None,
                            "hasNextPage": False,
                        },
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_malformed_edge_structure(self, engine_with_key: OpenCTIEngine) -> None:
        """Test handling of malformed edge structure missing 'node'."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "globalSearch": {
                        "edges": [{"cursor": "cursor-1"}],
                        "pageInfo": {
                            "endCursor": "cursor-1",
                            "hasNextPage": False,
                            "globalCount": 1,
                        },
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_empty_edges_list(self, engine_with_key: OpenCTIEngine) -> None:
        """Test handling of empty edges list."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "globalSearch": {
                        "edges": [],
                        "pageInfo": {
                            "endCursor": None,
                            "hasNextPage": False,
                            "globalCount": 0,
                        },
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is not None
        assert result["entity_counts"] == {}
        assert result["latest_created_at"] is None


class TestOpenCTIIndicatorQueryEdgeCases:
    """Test indicator query response variations."""

    @responses.activate
    def test_complete_indicator_data(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test indicator query with all fields populated."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "indicator": {
                        "name": "Complete Indicator",
                        "x_opencti_score": 90,
                        "revoked": False,
                        "valid_from": "2024-01-01T00:00:00Z",
                        "valid_until": "2024-12-31T23:59:59Z",
                        "confidence": 95,
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is not None
        assert result["latest_indicator_name"] == "Complete Indicator"
        assert result["x_opencti_score"] == 90
        assert result["confidence"] == 95
        assert result["valid_from"] == "2024-01-01"
        assert result["valid_until"] == "2024-12-31"

    @responses.activate
    def test_partial_indicator_data(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test indicator query with missing optional fields."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "indicator": {
                        "name": "Partial Indicator",
                        "x_opencti_score": 50,
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is not None
        assert result["latest_indicator_name"] == "Partial Indicator"
        assert result["valid_from"] is None
        assert result["valid_until"] is None

    @responses.activate
    def test_indicator_with_null_values(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test indicator query with null values for optional fields."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={
                "data": {
                    "indicator": {
                        "name": "Null Value Indicator",
                        "valid_from": None,
                        "valid_until": None,
                        "confidence": None,
                    }
                }
            },
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is not None
        assert result["latest_indicator_name"] == "Null Value Indicator"
        assert result["valid_from"] is None
        assert result["valid_until"] is None

    @responses.activate
    def test_indicator_query_returns_null(
        self, engine_with_key: OpenCTIEngine, realistic_global_search_response: dict
    ) -> None:
        """Test indicator query when entire indicator is null."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json=realistic_global_search_response,
            status=200,
        )
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"data": {"indicator": None}},
            status=200,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)

        assert result is None


class TestOpenCTIHTTPErrors:
    """Test HTTP error scenarios with parametrization."""

    @pytest.mark.parametrize(
        "status_code",
        [401, 403, 404, 500, 503],
    )
    @responses.activate
    def test_http_error_codes(self, status_code: int, engine_with_key: OpenCTIEngine) -> None:
        """Test graceful handling of various HTTP error codes."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            json={"errors": [{"message": f"Error {status_code}"}]},
            status=status_code,
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_connection_timeout(self, engine_with_key: OpenCTIEngine) -> None:
        """Test graceful handling of connection timeout."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            body=ConnectionError("Connection timeout"),
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None

    @responses.activate
    def test_connection_refused(self, engine_with_key: OpenCTIEngine) -> None:
        """Test graceful handling of connection refused."""
        responses.add(
            responses.POST,
            "https://opencti.example.com/graphql",
            body=ConnectionRefusedError("Connection refused"),
        )

        result = engine_with_key.analyze("192.0.2.1", ObservableType.IPV4)
        assert result is None


class TestOpenCTIExportRow:
    """Test export row creation."""

    def test_export_row_complete_data(self, engine_with_key: OpenCTIEngine) -> None:
        """Test export row creation with complete analysis result."""
        analysis_result = {
            "entity_counts": {"Indicator": 5, "Malware": 3, "Campaign": 2},
            "global_count": 10,
            "latest_created_at": "2024-01-15",
        }

        export_row = engine_with_key.create_export_row(analysis_result)

        assert "opencti_entity_counts" in export_row
        assert "opencti_global_count" in export_row
        assert "opencti_last_seen" in export_row
        assert export_row["opencti_global_count"] == 10
        assert export_row["opencti_last_seen"] == "2024-01-15"
        assert "Indicator:5" in export_row["opencti_entity_counts"]
        assert "Malware:3" in export_row["opencti_entity_counts"]

    def test_export_row_single_entity_type(self, engine_with_key: OpenCTIEngine) -> None:
        """Test export row with single entity type."""
        analysis_result = {
            "entity_counts": {"Indicator": 1},
            "global_count": 1,
            "latest_created_at": "2024-01-14",
        }

        export_row = engine_with_key.create_export_row(analysis_result)

        assert export_row["opencti_entity_counts"] == "Indicator:1"
        assert export_row["opencti_global_count"] == 1

    def test_export_row_empty_result(self, engine_with_key: OpenCTIEngine) -> None:
        """Test export row creation with empty analysis result."""
        analysis_result = {}

        export_row = engine_with_key.create_export_row(analysis_result)

        assert export_row["opencti_entity_counts"] is None
        assert export_row["opencti_global_count"] is None
        assert export_row["opencti_last_seen"] is None

    def test_export_row_none_input(self, engine_with_key: OpenCTIEngine) -> None:
        """Test export row creation with None input."""
        export_row = engine_with_key.create_export_row(None)

        assert export_row["opencti_entity_counts"] is None
        assert export_row["opencti_global_count"] is None
        assert export_row["opencti_last_seen"] is None


class TestOpenCTIEngineProperties:
    """Test engine properties."""

    def test_engine_name(self, engine_with_key: OpenCTIEngine) -> None:
        """Test that engine name is 'opencti'."""
        assert engine_with_key.name == "opencti"

    def test_engine_is_base_engine(self, engine_with_key: OpenCTIEngine) -> None:
        """Test that OpenCTIEngine is instance of BaseEngine."""
        assert isinstance(engine_with_key, BaseEngine)
