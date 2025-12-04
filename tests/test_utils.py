import pytest

import sys

sys.path.append("utils")

from utils.utils import is_really_ipv6, identify_observable_type, extract_observables


def test_is_really_ipv6():
    # Test a valid IPv6 address
    ipv6_address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert is_really_ipv6(ipv6_address)

    # Test an IPv4 address (should not be identified as IPv6)
    ipv4_address = "192.168.0.1"
    assert not is_really_ipv6(ipv4_address)

    # Test an invalid IPv6 address
    invalid_ipv6_address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234"
    assert not is_really_ipv6(invalid_ipv6_address)


def test_identify_observable_type():
    # Test identifying a URL
    observable = "http://example.com"
    expected = "URL"
    result = identify_observable_type(observable)
    assert result == expected

    # Test identifying an IPv6 address
    observable = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    expected = "IPv6"
    result = identify_observable_type(observable)
    assert result == expected

    # Test identifying an IPv4 address
    observable = "8.8.8.8"
    expected = "IPv4"
    result = identify_observable_type(observable)
    assert result == expected

    # Test identifying a fully qualified domain name (FQDN)
    observable = "example.com"
    expected = "FQDN"
    result = identify_observable_type(observable)
    assert result == expected

    # Test identifying an MD5 hash
    observable = "d41d8cd98f00b204e9800998ecf8427e"
    expected = "MD5"
    result = identify_observable_type(observable)
    assert result == expected

    # Test identifying a SHA1 hash
    observable = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    expected = "SHA1"
    result = identify_observable_type(observable)
    assert result == expected

    # Test identifying a SHA256 hash
    observable = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    expected = "SHA256"
    result = identify_observable_type(observable)
    assert result == expected


def test_extract_observables():
    # Test extracting observables from a text containing a URL and an IPv4 address
    text = "http://example.com oui non pas vraiment 1.1.1.1 192.168.1.0"
    expected = [
        {"value": "http://example.com", "type": "URL"},
        {"value": "1.1.1.1", "type": "IPv4"},
        {"value": "192.168.1.0", "type": "IPv4"},
    ]
    result = extract_observables(text)
    assert all(any(item == expected_item for item in result) for expected_item in expected)
