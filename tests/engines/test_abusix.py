import logging
from unittest.mock import patch

import pytest
from models.observable import ObservableType

from engines.abusix import AbusixEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets_with_config():
    return Secrets()


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


# High Priority Tests: Credentials/Auth Error Handling


@patch("querycontacts.ContactFinder")
def test_analyze_auth_error(mock_contact_finder, secrets_with_config, ipv4_observable):
    """Test handling of authentication/authorization errors from querycontacts."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.side_effect = Exception("Invalid API credentials")

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    mock_instance.find.assert_called_once_with(ipv4_observable)


@patch("querycontacts.ContactFinder")
def test_analyze_exception_generic(mock_contact_finder, secrets_with_config, ipv4_observable):
    """Test handling of generic exceptions (network, service errors)."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.side_effect = Exception("Connection timeout")

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    mock_instance.find.assert_called_once_with(ipv4_observable)


# Medium Priority Tests: Critical Paths


@pytest.mark.parametrize(
    "observable_value,observable_type,expected_email",
    [
        ("1.1.1.1", ObservableType.IPV4, "abuse@example.com"),
        ("2001:4860:4860::8888", ObservableType.IPV6, "abuse-ipv6@example.com"),
    ],
)
@patch("querycontacts.ContactFinder")
def test_analyze_success(
    mock_contact_finder, secrets_with_config, observable_value, observable_type, expected_email
):
    """Test successful analysis of IPv4 and IPv6 addresses."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.return_value = [expected_email]

    result = engine.analyze(observable_value, observable_type)

    assert result == {"abuse": expected_email}
    mock_instance.find.assert_called_once_with(observable_value)


@patch("querycontacts.ContactFinder")
def test_analyze_empty_results(mock_contact_finder, secrets_with_config, ipv4_observable):
    """Test handling of empty results from querycontacts."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.return_value = []

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result is None
    mock_instance.find.assert_called_once_with(ipv4_observable)


@patch("querycontacts.ContactFinder")
def test_analyze_multiple_results_uses_first(
    mock_contact_finder, secrets_with_config, ipv4_observable
):
    """Test that only first result is used when multiple are returned."""
    engine = AbusixEngine(secrets_with_config, proxies={}, ssl_verify=True)
    mock_instance = mock_contact_finder.return_value
    mock_instance.find.return_value = [
        "abuse1@example.com",
        "abuse2@example.com",
    ]

    result = engine.analyze(ipv4_observable, ObservableType.IPV4)

    assert result == {"abuse": "abuse1@example.com"}
    mock_instance.find.assert_called_once_with(ipv4_observable)


# Low Priority Tests: Edge Cases and Properties


def test_create_export_row_with_result():
    """Test export row creation with valid analysis result."""
    engine = AbusixEngine(Secrets(), proxies={}, ssl_verify=True)
    analysis_result = {"abuse": "abuse@example.com"}

    export_row = engine.create_export_row(analysis_result)

    assert export_row == {"abusix_abuse": "abuse@example.com"}


def test_create_export_row_with_none():
    """Test export row creation with None result."""
    engine = AbusixEngine(Secrets(), proxies={}, ssl_verify=True)

    export_row = engine.create_export_row(None)

    assert export_row == {"abusix_abuse": None}


def test_create_export_row_missing_abuse_key():
    """Test export row creation when abuse key is missing from result."""
    engine = AbusixEngine(Secrets(), proxies={}, ssl_verify=True)
    analysis_result = {"other_key": "other_value"}

    export_row = engine.create_export_row(analysis_result)

    assert export_row == {"abusix_abuse": None}


def test_create_export_row_empty_dict():
    """Test export row creation with empty dictionary result."""
    engine = AbusixEngine(Secrets(), proxies={}, ssl_verify=True)

    export_row = engine.create_export_row({})

    assert export_row == {"abusix_abuse": None}


def test_name_property():
    """Test that name property returns correct engine identifier."""
    engine = AbusixEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "abusix"


def test_supported_types_property():
    """Test that supported_types includes both IPv4 and IPv6."""
    engine = AbusixEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.supported_types is ObservableType.IPV4 | ObservableType.IPV6


def test_execute_after_reverse_dns_property():
    """Test that execute_after_reverse_dns returns True (post-pivot engine)."""
    engine = AbusixEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.execute_after_reverse_dns is True


def test_is_pivot_engine_property():
    """Test that is_pivot_engine returns False (inherited default)."""
    engine = AbusixEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.is_pivot_engine is False
