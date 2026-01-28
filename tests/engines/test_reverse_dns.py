import logging
from unittest.mock import MagicMock, patch

import pytest

from engines.reverse_dns import ReverseDNSEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def ipv6_observable():
    return "2001:4860:4860::8888"


@pytest.fixture
def bogon_observable():
    return "127.0.0.1"


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def url_observable():
    return "https://example.com/path"


@pytest.fixture
def url_observable_with_port():
    return "https://example.com:8443/path"


@pytest.fixture
def url_observable_with_ipv4_port():
    return "https://1.1.1.1:8080/path"


@pytest.fixture
def url_observable_with_ipv6():
    return "https://[2001:db8::1]/path"


@pytest.fixture
def url_observable_with_ipv6_port():
    return "https://[2001:db8::1]:8443/path"


def mock_dns_answer(values):
    """Create a mock DNS answer object that can be iterated and converted to string."""
    mock_list = []
    for value in values:
        mock_obj = MagicMock()
        mock_obj.__str__.return_value = value
        mock_list.append(mock_obj)
    return mock_list


# ============================================================================
# Observable Type Routing Tests (Parametrized)
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
@pytest.mark.parametrize(
    "observable_type,observable_value",
    [
        ("IPv4", "1.1.1.1"),
        ("IPv6", "2001:4860:4860::8888"),
        ("BOGON", "127.0.0.1"),
        ("FQDN", "example.com"),
        ("URL", "https://example.com/path"),
    ],
)
def test_analyze_observable_type_routing(
    mock_reversename, mock_resolver, observable_type, observable_value
):
    """Test that all 5 observable types are handled correctly."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    # Mock return based on type
    if observable_type in ["IPv4", "IPv6", "BOGON"]:
        mock_reversename.return_value = MagicMock()
        mock_resolver.return_value = mock_dns_answer(["hostname.example.com"])
    elif observable_type == "FQDN":
        mock_resolver.return_value = mock_dns_answer(["192.0.2.1"])
    elif observable_type == "URL":
        # URL to example.com -> A lookup
        mock_resolver.return_value = mock_dns_answer(["192.0.2.1"])

    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert "reverse_dns" in result
    assert isinstance(result["reverse_dns"], list)
    assert len(result["reverse_dns"]) > 0


# ============================================================================
# IPv4 Resolution Tests
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_ipv4_resolution_success_single_hostname(mock_reversename, mock_resolver, ipv4_observable):
    """Test successful PTR lookup for IPv4 returning single hostname."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    mock_resolver.return_value = mock_dns_answer(["one.one.one.one"])

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["reverse_dns"] == ["one.one.one.one"]
    mock_reversename.assert_called_once_with(ipv4_observable)


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_ipv4_resolution_success_multiple_hostnames(
    mock_reversename, mock_resolver, ipv4_observable
):
    """Test PTR lookup only returns first hostname (engine behavior)."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    # Engine uses answer[0] so even with multiple results, only first is returned
    mock_resolver.return_value = mock_dns_answer(["host1.example.com", "host2.example.com"])

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    # PTR lookups only return first result (answer[0])
    assert len(result["reverse_dns"]) == 1
    assert result["reverse_dns"][0] == "host1.example.com"


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_ipv4_resolution_not_found(mock_reversename, mock_resolver, ipv4_observable, caplog):
    """Test PTR lookup returns no results (raises exception, returns None)."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    # Empty list causes IndexError when accessing answer[0]
    mock_resolver.return_value = mock_dns_answer([])

    with caplog.at_level(logging.DEBUG):
        result = engine.analyze(ipv4_observable, "IPv4")

    # Empty results cause exception, engine returns None
    assert result is None
    assert "Reverse DNS failed" in caplog.text


# ============================================================================
# IPv6 Resolution Tests
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_ipv6_resolution_success_single_hostname(mock_reversename, mock_resolver, ipv6_observable):
    """Test successful PTR lookup for IPv6 returning single hostname."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    mock_resolver.return_value = mock_dns_answer(["ipv6host.example.com"])

    result = engine.analyze(ipv6_observable, "IPv6")

    assert result is not None
    assert result["reverse_dns"] == ["ipv6host.example.com"]
    mock_reversename.assert_called_once_with(ipv6_observable)


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_ipv6_resolution_success_multiple_hostnames(
    mock_reversename, mock_resolver, ipv6_observable
):
    """Test IPv6 PTR lookup only returns first hostname (engine behavior)."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    mock_resolver.return_value = mock_dns_answer(["v6host1.example.com", "v6host2.example.com"])

    result = engine.analyze(ipv6_observable, "IPv6")

    assert result is not None
    # PTR lookups only return first result (answer[0])
    assert len(result["reverse_dns"]) == 1
    assert result["reverse_dns"][0] == "v6host1.example.com"


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_ipv6_resolution_not_found(mock_reversename, mock_resolver, ipv6_observable, caplog):
    """Test IPv6 PTR lookup returns no results (raises exception, returns None)."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    # Empty list causes IndexError when accessing answer[0]
    mock_resolver.return_value = mock_dns_answer([])

    with caplog.at_level(logging.DEBUG):
        result = engine.analyze(ipv6_observable, "IPv6")

    # Empty results cause exception, engine returns None
    assert result is None
    assert "Reverse DNS failed" in caplog.text


# ============================================================================
# BOGON Resolution Tests
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_bogon_resolution(mock_reversename, mock_resolver, bogon_observable):
    """Test BOGON resolution (treated same as IPv4)."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    mock_resolver.return_value = mock_dns_answer(["localhost"])

    result = engine.analyze(bogon_observable, "BOGON")

    assert result is not None
    assert result["reverse_dns"] == ["localhost"]
    mock_reversename.assert_called_once_with(bogon_observable)


# ============================================================================
# FQDN Resolution Tests
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_fqdn_resolution_success_single_ip(mock_resolver, fqdn_observable):
    """Test successful A record lookup for FQDN returning single IP."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resolver.return_value = mock_dns_answer(["192.0.2.1"])

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert result["reverse_dns"] == ["192.0.2.1"]
    mock_resolver.assert_called_once_with(fqdn_observable, "A")


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_fqdn_resolution_success_multiple_ips(mock_resolver, fqdn_observable):
    """Test A record lookup for FQDN returning multiple IPs."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resolver.return_value = mock_dns_answer(["192.0.2.1", "192.0.2.2", "192.0.2.3"])

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert len(result["reverse_dns"]) == 3
    assert "192.0.2.1" in result["reverse_dns"]


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_fqdn_resolution_not_found(mock_resolver, fqdn_observable):
    """Test A record lookup returns no results."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resolver.return_value = mock_dns_answer([])

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert result["reverse_dns"] == []


# ============================================================================
# URL Resolution Tests - Simple URLs
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_url_with_domain_a_lookup(mock_resolver, url_observable):
    """Test URL with FQDN performs A record lookup."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resolver.return_value = mock_dns_answer(["192.0.2.1"])

    result = engine.analyze(url_observable, "URL")

    assert result is not None
    assert result["reverse_dns"] == ["192.0.2.1"]
    # Verify A record lookup was called for extracted domain
    mock_resolver.assert_called_once_with("example.com", "A")


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_url_with_ipv4_ptr_lookup(mock_reversename, mock_resolver):
    """Test URL with IPv4 performs PTR reverse lookup."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://192.0.2.1/path"

    mock_reversename.return_value = MagicMock()
    mock_resolver.return_value = mock_dns_answer(["host.example.com"])

    result = engine.analyze(url, "URL")

    assert result is not None
    assert result["reverse_dns"] == ["host.example.com"]
    mock_reversename.assert_called_once_with("192.0.2.1")


# ============================================================================
# URL Resolution Tests - With Port
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_url_with_fqdn_and_port(mock_resolver, url_observable_with_port):
    """Test URL with FQDN and port strips port before lookup."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resolver.return_value = mock_dns_answer(["192.0.2.1"])

    result = engine.analyze(url_observable_with_port, "URL")

    assert result is not None
    assert result["reverse_dns"] == ["192.0.2.1"]
    # Verify port was stripped and domain extracted
    mock_resolver.assert_called_once_with("example.com", "A")


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_url_with_ipv4_and_port(mock_reversename, mock_resolver, url_observable_with_ipv4_port):
    """Test URL with IPv4 and port performs PTR lookup."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    mock_resolver.return_value = mock_dns_answer(["host.example.com"])

    result = engine.analyze(url_observable_with_ipv4_port, "URL")

    assert result is not None
    assert result["reverse_dns"] == ["host.example.com"]
    mock_reversename.assert_called_once_with("1.1.1.1")


# ============================================================================
# URL Resolution Tests - IPv6 Special Cases
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
@patch("engines.reverse_dns.is_really_ipv6")
def test_url_with_ipv6_in_brackets(mock_is_ipv6, mock_reversename, mock_resolver):
    """Test URL with IPv6 in brackets without port."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://[2001:db8::1]/path"

    # When brackets exist with no colon after ], is_really_ipv6() on "[2001:db8::1]" returns False
    # Then split(":")[0] gets "[2001" which is not a valid FQDN or IPv4
    # Engine returns None
    mock_is_ipv6.return_value = False

    result = engine.analyze(url, "URL")

    # Brackets without port don't work with current split logic - returns None
    assert result is None


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
@patch("engines.reverse_dns.is_really_ipv6")
def test_url_with_ipv6_and_port_in_brackets(
    mock_is_ipv6, mock_reversename, mock_resolver, url_observable_with_ipv6_port
):
    """Test URL with IPv6 and port in brackets."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    # Extract logic: split("/")[2] gets "[2001:db8::1]:8443"
    # Check if contains ":"
    # Call is_really_ipv6("[2001:db8::1]:8443") - should detect IPv6
    mock_is_ipv6.return_value = True
    mock_reversename.return_value = MagicMock()
    mock_resolver.return_value = mock_dns_answer(["ipv6host.example.com"])

    result = engine.analyze(url_observable_with_ipv6_port, "URL")

    assert result is not None
    # If is_really_ipv6 returns True, it performs PTR lookup directly
    assert result["reverse_dns"] == ["ipv6host.example.com"]


# ============================================================================
# URL Resolution Tests - Edge Cases
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_url_https_with_query_params(mock_resolver):
    """Test URL with query parameters."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://example.com:8080/path?query=value&foo=bar"

    mock_resolver.return_value = mock_dns_answer(["192.0.2.1"])

    result = engine.analyze(url, "URL")

    assert result is not None
    # Should extract example.com and perform A lookup
    mock_resolver.assert_called_once_with("example.com", "A")


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_url_http_protocol(mock_resolver):
    """Test URL with http protocol (not https)."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "http://example.org/path"

    mock_resolver.return_value = mock_dns_answer(["192.0.2.5"])

    result = engine.analyze(url, "URL")

    assert result is not None
    assert result["reverse_dns"] == ["192.0.2.5"]
    mock_resolver.assert_called_once_with("example.org", "A")


# ============================================================================
# Exception Handling Tests (Parametrized)
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_exception_dns_nxdomain(mock_reversename, mock_resolver, ipv4_observable, caplog):
    """Test handling of DNS NXDOMAIN exception (domain not found)."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    import dns.exception

    mock_resolver.side_effect = dns.exception.DNSException("NXDOMAIN")

    with caplog.at_level(logging.DEBUG):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Reverse DNS failed" in caplog.text


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_exception_dns_noanswer(mock_reversename, mock_resolver, ipv4_observable, caplog):
    """Test handling of DNS NoAnswer exception."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    import dns.exception

    mock_resolver.side_effect = dns.exception.DNSException("NoAnswer")

    with caplog.at_level(logging.DEBUG):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Reverse DNS failed" in caplog.text


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_exception_generic_exception(mock_reversename, mock_resolver, ipv4_observable, caplog):
    """Test handling of generic exception."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    mock_resolver.side_effect = Exception("Network error")

    with caplog.at_level(logging.DEBUG):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Reverse DNS failed" in caplog.text


# ============================================================================
# Exception Handling - URL Cases
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_exception_url_fqdn_lookup(mock_resolver, fqdn_observable, caplog):
    """Test exception handling when URL contains FQDN that fails DNS lookup."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    url = f"https://{fqdn_observable}/path"

    mock_resolver.side_effect = Exception("DNS resolution failed")

    with caplog.at_level(logging.DEBUG):
        result = engine.analyze(url, "URL")

    assert result is None


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_exception_url_ipv4_lookup(mock_reversename, mock_resolver, caplog):
    """Test exception handling when URL contains IPv4 that fails DNS lookup."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://192.0.2.1/path"

    mock_reversename.return_value = MagicMock()
    mock_resolver.side_effect = Exception("DNS resolution failed")

    with caplog.at_level(logging.DEBUG):
        result = engine.analyze(url, "URL")

    assert result is None


# ============================================================================
# Unsupported Observable Type Tests
# ============================================================================


def test_analyze_unsupported_type():
    """Test handling of unsupported observable type."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    result = engine.analyze("5d41402abc4b2a76b9719d911017c592", "MD5")

    assert result is None


# ============================================================================
# Export Row Tests
# ============================================================================


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_create_export_row_with_complete_data(mock_reversename, mock_resolver, ipv4_observable):
    """Test export row creation with successful DNS lookup."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    mock_resolver.return_value = mock_dns_answer(["hostname.example.com"])

    result = engine.analyze(ipv4_observable, "IPv4")
    export_row = engine.create_export_row(result)

    assert export_row["rev_dns"] is True
    assert export_row["dns_lookup"] == ["hostname.example.com"]


@patch("engines.reverse_dns.dns.resolver.resolve")
def test_create_export_row_with_empty_dns_data(mock_resolver, fqdn_observable):
    """Test export row creation with empty DNS results."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_resolver.return_value = mock_dns_answer([])

    result = engine.analyze(fqdn_observable, "FQDN")
    export_row = engine.create_export_row(result)

    assert export_row["rev_dns"] is True  # Empty list is still truthy as dict exists
    assert export_row["dns_lookup"] == []


def test_create_export_row_with_null_result():
    """Test export row creation when analysis returns None."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    export_row = engine.create_export_row(None)

    assert export_row["rev_dns"] is False
    assert export_row["dns_lookup"] is None


@patch("engines.reverse_dns.dns.resolver.resolve")
@patch("engines.reverse_dns.dns.reversename.from_address")
def test_create_export_row_with_multiple_results(mock_reversename, mock_resolver, ipv4_observable):
    """Test export row with PTR result (only first hostname)."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)

    mock_reversename.return_value = MagicMock()
    # PTR lookups only use first result
    mock_resolver.return_value = mock_dns_answer(["host1.example.com", "host2.example.com"])

    result = engine.analyze(ipv4_observable, "IPv4")
    export_row = engine.create_export_row(result)

    assert export_row["rev_dns"] is True
    # PTR lookups only return first hostname
    assert len(export_row["dns_lookup"]) == 1
    assert export_row["dns_lookup"][0] == "host1.example.com"


# ============================================================================
# Engine Properties Tests
# ============================================================================


def test_engine_name():
    """Test engine name property."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    assert engine.name == "reverse_dns"


def test_engine_supported_types():
    """Test engine supported types property."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    assert set(engine.supported_types) == {"IPv4", "IPv6", "BOGON", "FQDN", "URL"}


def test_engine_is_pivot_engine():
    """Test engine is_pivot_engine property."""
    engine = ReverseDNSEngine(Secrets(), proxies={}, ssl_verify=True)
    assert engine.is_pivot_engine is True
