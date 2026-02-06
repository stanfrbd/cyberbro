import logging
from unittest.mock import MagicMock, patch

import pytest

from engines.crowdstrike import CrowdstrikeEngine
from models.observable import ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def secrets_with_credentials():
    s = Secrets()
    s.crowdstrike_client_id = "test_client_id"
    s.crowdstrike_client_secret = "test_client_secret"
    s.crowdstrike_falcon_base_url = "https://api.crowdstrike.com"
    return s


@pytest.fixture
def secrets_missing_client_id():
    s = Secrets()
    s.crowdstrike_client_id = ""
    s.crowdstrike_client_secret = "test_secret"
    s.crowdstrike_falcon_base_url = "https://api.crowdstrike.com"
    return s


@pytest.fixture
def secrets_missing_client_secret():
    s = Secrets()
    s.crowdstrike_client_id = "test_id"
    s.crowdstrike_client_secret = ""
    s.crowdstrike_falcon_base_url = "https://api.crowdstrike.com"
    return s


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@pytest.fixture
def url_observable():
    return "https://example.com/path?query=1"


@pytest.fixture
def url_observable_with_port():
    return "https://example.com:8443/path?query=1"


@pytest.fixture
def domain_observable():
    return "example.com"


@pytest.fixture
def hash_md5_observable():
    return "5d41402abc4b2a76b9719d911017c592"


@pytest.fixture
def hash_sha1_observable():
    return "da39a3ee5e6b4b0d3255bfef95601890afd80709"


@pytest.fixture
def hash_sha256_observable():
    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ============================================================================
# HIGH Priority: Credentials Tests
# ============================================================================


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_missing_client_id(mock_get_client, secrets_missing_client_id, ipv4_observable):
    """Missing client_id should raise exception and return None."""
    mock_get_client.side_effect = Exception("Missing or invalid credentials")

    engine = CrowdstrikeEngine(secrets_missing_client_id, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_missing_client_secret(
    mock_get_client, secrets_missing_client_secret, ipv4_observable
):
    """Missing client_secret should raise exception and return None."""
    mock_get_client.side_effect = Exception("Missing or invalid credentials")

    engine = CrowdstrikeEngine(secrets_missing_client_secret, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None


# ============================================================================
# HIGH Priority: Success Path Tests
# ============================================================================


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_success_complete(mock_get_client, secrets_with_credentials, ipv4_observable):
    """Both API calls succeed with full data, all fields populated."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 15}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "actors": ["APT28", "Wizard Spider"],
                        "malicious_confidence": "high",
                        "threat_types": ["trojan", "backdoor"],
                        "kill_chains": ["Delivery", "Exploitation"],
                        "malware_families": ["Emotet", "TrickBot"],
                        "vulnerabilities": ["CVE-2021-1234"],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["device_count"] == 15
    assert result["indicator_found"] is True
    assert "APT28" in result["actors"]
    assert result["malicious_confidence"] == "high"
    assert "trojan" in result["threat_types"]
    assert "Delivery" in result["kill_chain"]
    assert "Emotet" in result["malware_families"]
    assert "CVE-2021-1234" in result["vulnerabilities"]
    assert "published_date" in result
    assert result["published_date"] == "2023-01-01"
    assert result["last_updated"] == "2023-01-02"


# ============================================================================
# HIGH Priority: Auth Error Tests
# ============================================================================


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_invalid_credentials_401(
    mock_get_client, secrets_with_credentials, ipv4_observable
):
    """Falcon API returns 401 Unauthorized."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {"status_code": 401, "body": {"errors": "Invalid API key"}},
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["indicator_found"] is False
    assert result["device_count"] == 0


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_invalid_credentials_403(
    mock_get_client, secrets_with_credentials, ipv4_observable
):
    """Falcon API returns 403 Forbidden."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {"status_code": 403, "body": {"errors": "Forbidden"}},
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["indicator_found"] is False


# ============================================================================
# HIGH Priority: Indicator Not Found Tests
# ============================================================================


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_indicator_not_found(mock_get_client, secrets_with_credentials, ipv4_observable):
    """Status 200 but empty resources array."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 5}]}},
        {"status_code": 200, "body": {"resources": []}},
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["indicator_found"] is False
    assert result["device_count"] == 5
    assert "link" in result


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_device_count_only(mock_get_client, secrets_with_credentials, ipv4_observable):
    """Phase 1 succeeds, phase 2 returns no resources."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 25}]}},
        {"status_code": 200, "body": {"resources": []}},
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["indicator_found"] is False
    assert result["device_count"] == 25


# ============================================================================
# HIGH Priority: Observable Type and Processing Tests
# ============================================================================


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_url_observable_extraction(
    mock_get_client, secrets_with_credentials, url_observable
):
    """URL type: host extraction and processing."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "actors": [],
                        "malicious_confidence": "medium",
                        "threat_types": [],
                        "kill_chains": [],
                        "malware_families": [],
                        "vulnerabilities": [],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(url_observable, ObservableType.URL)

    assert result is not None
    assert result["indicator_found"] is True
    assert result["malicious_confidence"] == "medium"


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_observable_type_mapping(mock_get_client, secrets_with_credentials):
    """Test _map_observable_type for all supported types."""
    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    # Test all type mappings
    assert engine._map_observable_type(ObservableType.IPV4) == "ipv4"
    assert engine._map_observable_type(ObservableType.IPV6) == "ipv6"
    assert engine._map_observable_type(ObservableType.MD5) == "md5"
    assert engine._map_observable_type(ObservableType.SHA1) == "sha1"
    assert engine._map_observable_type(ObservableType.SHA256) == "sha256"
    assert engine._map_observable_type(ObservableType.FQDN) == "domain"
    assert engine._map_observable_type(ObservableType.URL) == "domain"
    assert engine._map_observable_type("UNKNOWN") is None


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_ioc_id_generation(mock_get_client, secrets_with_credentials):
    """Test _generate_ioc_id for all types."""
    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    # Test IOC ID generation for each type
    assert engine._generate_ioc_id("example.com", "domain") == "domain_example.com"
    assert engine._generate_ioc_id("1.1.1.1", "ipv4") == "ip_address_1.1.1.1"
    assert engine._generate_ioc_id("2001:db8::1", "ipv6") == "ip_address_2001:db8::1"
    assert engine._generate_ioc_id("5d41402abc4b2a76b9719d911017c592", "md5") == (
        "hash_md5_5d41402abc4b2a76b9719d911017c592"
    )
    assert engine._generate_ioc_id("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1") == (
        "hash_sha1_da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )
    assert engine._generate_ioc_id(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"
    ) == ("hash_sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert engine._generate_ioc_id("observable", "unknown") is None


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_timestamp_parsing(mock_get_client, secrets_with_credentials, ipv4_observable):
    """Valid epoch timestamps converted to YYYY-MM-DD."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1609459200,
                        "last_updated": 1672531200,
                        "actors": [],
                        "malicious_confidence": "",
                        "threat_types": [],
                        "kill_chains": [],
                        "malware_families": [],
                        "vulnerabilities": [],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["published_date"] == "2021-01-01"
    assert result["last_updated"] == "2023-01-01"


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_exception_handling(mock_get_client, secrets_with_credentials, ipv4_observable):
    """Generic exception caught and logged, returns None."""
    mock_get_client.side_effect = RuntimeError("Unexpected error")

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None


# ============================================================================
# MEDIUM Priority: Field Handling Tests
# ============================================================================


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_success_minimal_fields(mock_get_client, secrets_with_credentials, ipv4_observable):
    """Response with minimal required fields, empty arrays default correctly."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "actors": [],
                        "malicious_confidence": "",
                        "threat_types": [],
                        "kill_chains": [],
                        "malware_families": [],
                        "vulnerabilities": [],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["indicator_found"] is True
    assert result["actors"] == []
    assert result["threat_types"] == []
    assert result["kill_chain"] == []
    assert result["malware_families"] == []
    assert result["vulnerabilities"] == []


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_missing_optional_fields(
    mock_get_client, secrets_with_credentials, ipv4_observable
):
    """Response missing some optional fields."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 3}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "malicious_confidence": "low",
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["indicator_found"] is True
    assert result["device_count"] == 3
    assert result["malicious_confidence"] == "low"
    assert result.get("actors", []) == []


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_empty_array_fields(mock_get_client, secrets_with_credentials, ipv4_observable):
    """Response includes empty arrays for optional fields."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "actors": [],
                        "malicious_confidence": "critical",
                        "threat_types": [],
                        "kill_chains": [],
                        "malware_families": [],
                        "vulnerabilities": [],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["actors"] == []
    assert result["threat_types"] == []
    assert result["kill_chain"] == []
    assert result["malware_families"] == []
    assert result["vulnerabilities"] == []


@pytest.mark.parametrize(
    "observable_value,observable_type",
    [
        ("1.1.1.1", ObservableType.IPV4),
        ("2001:4860:4860::8888", ObservableType.IPV6),
        ("example.com", ObservableType.FQDN),
        ("5d41402abc4b2a76b9719d911017c592", ObservableType.MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", ObservableType.SHA1),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ObservableType.SHA256),
        ("https://example.com:8443/path?query=1", ObservableType.URL),
    ],
)
@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_observable_types(
    mock_get_client, secrets_with_credentials, observable_value, observable_type
):
    """Test observable type routing and processing for various types."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 1}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "actors": [],
                        "malicious_confidence": "medium",
                        "threat_types": [],
                        "kill_chains": [],
                        "malware_families": [],
                        "vulnerabilities": [],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert result["indicator_found"] is True
    assert result["device_count"] == 1


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_device_count_zero(mock_get_client, secrets_with_credentials, ipv4_observable):
    """Device count returns 0 (legitimate case)."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "actors": ["APT99"],
                        "malicious_confidence": "low",
                        "threat_types": [],
                        "kill_chains": [],
                        "malware_families": [],
                        "vulnerabilities": [],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is not None
    assert result["device_count"] == 0
    assert result["indicator_found"] is True


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_observable_case_normalization(mock_get_client, secrets_with_credentials):
    """Mixed case observable lowercased before search."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    mixed_case_observable = "EXAMPLE.COM"

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "actors": [],
                        "malicious_confidence": "",
                        "threat_types": [],
                        "kill_chains": [],
                        "malware_families": [],
                        "vulnerabilities": [],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(mixed_case_observable, ObservableType.FQDN)

    assert result is not None
    assert result["indicator_found"] is True


# ============================================================================
# LOW Priority: Edge Case Tests
# ============================================================================


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_observed_type_unmapped(mock_get_client, secrets_with_credentials):
    """Observable type not in supported list."""
    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)

    # Unsupported type should return None from _map_observable_type
    mapped = engine._map_observable_type("UNSUPPORTED_TYPE")
    assert mapped is None


@patch("engines.crowdstrike.CrowdstrikeEngine._get_falcon_client")
def test_analyze_special_characters_in_observable(mock_get_client, secrets_with_credentials):
    """Observable with special chars (handled via lowercase)."""
    mock_falcon = MagicMock()
    mock_get_client.return_value = mock_falcon

    special_observable = "Example-Domain.COM"

    mock_falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": [{"device_count": 0}]}},
        {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "published_date": 1672531200,
                        "last_updated": 1672617600,
                        "actors": [],
                        "malicious_confidence": "",
                        "threat_types": [],
                        "kill_chains": [],
                        "malware_families": [],
                        "vulnerabilities": [],
                    }
                ]
            },
        },
    ]

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.analyze(special_observable, ObservableType.FQDN)

    assert result is not None
    assert result["indicator_found"] is True


# ============================================================================
# Export Formatting Tests
# ============================================================================


def test_create_export_row_with_none_result(secrets_with_credentials):
    """Export row when analysis returns None."""
    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.create_export_row(None)

    assert result is not None
    assert result["cs_device_count"] is None
    assert result["cs_actor"] is None
    assert result["cs_confidence"] is None
    assert result["cs_threat_types"] is None
    assert result["cs_malwares"] is None
    assert result["cs_kill_chain"] is None
    assert result["cs_vulns"] is None


def test_create_export_row_complete(secrets_with_credentials):
    """Export row with all fields populated."""
    analysis_result = {
        "device_count": 15,
        "actors": ["APT28", "Wizard Spider"],
        "malicious_confidence": "high",
        "threat_types": ["trojan", "backdoor"],
        "kill_chain": ["Delivery", "Exploitation"],
        "malware_families": ["Emotet", "TrickBot"],
        "vulnerabilities": ["CVE-2021-1234"],
    }

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.create_export_row(analysis_result)

    assert result["cs_device_count"] == 15
    assert result["cs_actor"] == "APT28, Wizard Spider"
    assert result["cs_confidence"] == "high"
    assert result["cs_threat_types"] == "trojan, backdoor"
    assert result["cs_malwares"] == "Emotet, TrickBot"
    assert result["cs_kill_chain"] == "Delivery, Exploitation"
    assert result["cs_vulns"] == "CVE-2021-1234"


def test_create_export_row_array_joining(secrets_with_credentials):
    """Arrays properly joined with ', '."""
    analysis_result = {
        "device_count": 5,
        "actors": ["Actor1", "Actor2", "Actor3"],
        "malicious_confidence": "medium",
        "threat_types": ["Type1", "Type2"],
        "kill_chain": [],
        "malware_families": ["Family1"],
        "vulnerabilities": [],
    }

    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.create_export_row(analysis_result)

    assert result["cs_actor"] == "Actor1, Actor2, Actor3"
    assert result["cs_threat_types"] == "Type1, Type2"
    assert result["cs_kill_chain"] == ""
    assert result["cs_malwares"] == "Family1"
    assert result["cs_vulns"] == ""


def test_create_export_row_all_none_fields(secrets_with_credentials):
    """When result is None, all cs_* fields are None."""
    engine = CrowdstrikeEngine(secrets_with_credentials, proxies={}, ssl_verify=True)
    result = engine.create_export_row(None)

    expected_keys = [
        "cs_device_count",
        "cs_actor",
        "cs_confidence",
        "cs_threat_types",
        "cs_malwares",
        "cs_kill_chain",
        "cs_vulns",
    ]

    for key in expected_keys:
        assert key in result
        assert result[key] is None
