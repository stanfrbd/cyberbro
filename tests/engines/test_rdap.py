import logging

import pytest
import responses

from engines.rdap import RDAPEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def url_observable():
    return "https://example.com/path"


@pytest.fixture
def complete_rdap_response():
    """Complete RDAP response with all data fields."""
    return {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Example Registrar Inc"],
                        ["email", {}, "text", "registrar@example.com"],
                    ],
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "John Registrant"],
                        ["email", {}, "text", "registrant@example.com"],
                        ["org", {}, "text", "Example Organization"],
                    ],
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse-sub@example.com"]],
                        ],
                    }
                ],
            },
        ],
        "nameservers": [
            {"ldhName": "NS1.EXAMPLE.COM"},
            {"ldhName": "NS2.EXAMPLE.COM"},
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-01-15T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2023-06-20T00:00:00Z"},
        ],
        "links": [
            {"rel": "self", "href": "https://rdap.net/domain/example.com"},
        ],
    }


@pytest.fixture
def empty_entities_response():
    """Minimal response with empty entities array."""
    return {
        "entities": [],
        "nameservers": [],
        "events": [],
        "links": [],
    }


# ============================================================================
# High Priority: Successful Analysis Tests
# ============================================================================


@responses.activate
def test_analyze_success_complete_fqdn(fqdn_observable, complete_rdap_response):
    """Test successful analysis of complete RDAP response for FQDN."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"

    responses.add(responses.GET, url, json=complete_rdap_response, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    assert result["abuse_contact"] == "abuse-sub@example.com"
    assert result["registrar"] == "Example Registrar Inc"
    assert result["registrant"] == "John Registrant"
    assert result["registrant_email"] == "registrant@example.com"
    assert result["organization"] == "Example Organization"
    assert result["creation_date"] == "2020-01-15"
    assert result["expiration_date"] == "2025-01-15"
    assert result["update_date"] == "2023-06-20"
    assert result["link"] == "https://rdap.net/domain/example.com"
    assert result["name_servers"] == ["ns1.example.com", "ns2.example.com"]


@responses.activate
def test_analyze_success_complete_url(url_observable, complete_rdap_response):
    """Test successful analysis of complete RDAP response for URL."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"

    responses.add(responses.GET, url, json=complete_rdap_response, status=200)

    result = engine.analyze(url_observable, "URL")

    assert result is not None
    assert result["registrar"] == "Example Registrar Inc"
    assert result["creation_date"] == "2020-01-15"


# ============================================================================
# Observable Type Routing (Parametrized)
# ============================================================================


@responses.activate
@pytest.mark.parametrize(
    "observable_type,observable_value",
    [
        ("FQDN", "example.com"),
        ("URL", "https://example.com/path"),
    ],
)
def test_analyze_observable_type_routing(observable_type, observable_value, complete_rdap_response):
    """Test that both FQDN and URL types are handled correctly."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"

    responses.add(responses.GET, url, json=complete_rdap_response, status=200)

    result = engine.analyze(observable_value, observable_type)

    assert result is not None
    assert isinstance(result, dict)
    assert "registrar" in result
    assert "creation_date" in result


# ============================================================================
# TLD Extraction Tests
# ============================================================================


@responses.activate
def test_analyze_valid_domain_extraction(fqdn_observable, complete_rdap_response):
    """Test successful registered domain extraction from FQDN."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"

    responses.add(responses.GET, url, json=complete_rdap_response, status=200)

    result = engine.analyze(fqdn_observable, "FQDN")

    assert result is not None
    # Verify the API was called with the correct domain
    assert len(responses.calls) == 1
    assert "example.com" in responses.calls[0].request.url


@responses.activate
def test_analyze_subdomain_extraction():
    """Test that tldextract correctly extracts registered domain from subdomain."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("sub.example.com", "FQDN")

    assert result is not None
    # Verify the API was called with registered_domain (sub.example.com -> example.com)
    assert "example.com" in responses.calls[0].request.url


@responses.activate
def test_analyze_invalid_domain_no_registered_domain():
    """Test handling when tldextract returns no registered_domain."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)

    # Invalid domain with no registered_domain
    result = engine.analyze("invalid_local_host", "FQDN")

    assert result is None
    # No API call should be made
    assert len(responses.calls) == 0


# ============================================================================
# vCard Field Extraction Tests
# ============================================================================


@responses.activate
def test_vcard_extraction_complete_fields():
    """Test extraction of all vCard fields (fn, email, org)."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Full Name"],
                        ["email", {}, "text", "email@example.com"],
                        ["org", {}, "text", "Organization"],
                    ],
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["registrar"] == "Full Name"


@responses.activate
def test_vcard_extraction_empty_vcard_array():
    """Test handling of empty vCard array (len < 2)."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [],  # Empty array
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["registrar"] == ""


@responses.activate
def test_vcard_extraction_missing_vcardarray():
    """Test handling when vcardArray key is missing."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrar"],
                # No vcardArray key
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["registrar"] == ""


@responses.activate
def test_vcard_extraction_missing_field_value():
    """Test handling when vCard field value (item[3]) is missing."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", ""],  # Empty value
                    ],
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["registrar"] == ""


@responses.activate
def test_vcard_extraction_malformed_item_not_four_elements():
    """Test handling of vCard item that doesn't have 4 elements."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text"],  # Only 3 elements instead of 4
                        ["fn", {}, "text", "Real Name"],  # Valid 4-element entry
                    ],
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["registrar"] == "Real Name"


# ============================================================================
# Entity Role Processing Tests
# ============================================================================


@responses.activate
def test_entity_role_abuse_contact():
    """Test extraction of abuse contact from abuse role."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [["email", {}, "text", "abuse@example.com"]],
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["abuse_contact"] == "abuse@example.com"


@responses.activate
def test_entity_role_registrar():
    """Test extraction of registrar from registrar role."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Registrar Corp"]],
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["registrar"] == "Registrar Corp"


@responses.activate
def test_entity_role_registrant():
    """Test extraction of registrant from registrant role."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Jane Registrant"],
                        ["email", {}, "text", "jane@example.com"],
                        ["org", {}, "text", "Jane Corp"],
                    ],
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["registrant"] == "Jane Registrant"
    assert result["registrant_email"] == "jane@example.com"
    assert result["organization"] == "Jane Corp"


@responses.activate
def test_entity_multi_role_entity():
    """Test handling of entity with multiple roles."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["abuse", "registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Multi Role Entity"],
                        ["email", {}, "text", "multi@example.com"],
                    ],
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    # Both roles should be processed
    assert result["abuse_contact"] == "multi@example.com"
    assert result["registrar"] == "Multi Role Entity"


# ============================================================================
# Sub-Entity Processing Tests
# ============================================================================


@responses.activate
def test_subentity_abuse_contact_extraction():
    """Test extraction of abuse contact from sub-entity."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Registrant"]],
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse-sub@example.com"]],
                        ],
                    }
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["abuse_contact"] == "abuse-sub@example.com"


@responses.activate
def test_subentity_parent_abuse_priority():
    """Test that sub-entity abuse contact overwrites parent entity if both exist."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": [
                    "vcard",
                    [["email", {}, "text", "abuse-parent@example.com"]],
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Registrant"]],
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse-sub@example.com"]],
                        ],
                    }
                ],
            },
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    # Sub-entity abuse contact is processed after parent and overwrites it (or logic)
    assert result["abuse_contact"] == "abuse-sub@example.com"


@responses.activate
def test_subentity_multiple_subentities():
    """Test handling of multiple sub-entities."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Registrant"]],
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse1@example.com"]],
                        ],
                    },
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse2@example.com"]],
                        ],
                    },
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    # Last abuse contact wins (or logic)
    assert result["abuse_contact"] == "abuse2@example.com"


# ============================================================================
# Nameserver Processing Tests
# ============================================================================


@responses.activate
def test_nameserver_extraction_multiple():
    """Test extraction of multiple nameservers."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [
            {"ldhName": "NS1.EXAMPLE.COM"},
            {"ldhName": "NS2.EXAMPLE.COM"},
            {"ldhName": "NS3.EXAMPLE.COM"},
        ],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["name_servers"] == [
        "ns1.example.com",
        "ns2.example.com",
        "ns3.example.com",
    ]


@responses.activate
def test_nameserver_lowercase_conversion():
    """Test that nameservers are converted to lowercase."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [
            {"ldhName": "UPPERCASE.EXAMPLE.COM"},
            {"ldhName": "MixedCase.Example.Com"},
        ],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert all(ns.islower() for ns in result["name_servers"])


@responses.activate
def test_nameserver_missing_ldhname():
    """Test handling of nameserver without ldhName field."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [
            {"ldhName": "NS1.EXAMPLE.COM"},
            {},  # Missing ldhName
            {"ldhName": "NS3.EXAMPLE.COM"},
        ],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    # Only nameservers with ldhName are included
    assert result["name_servers"] == ["ns1.example.com", "ns3.example.com"]


# ============================================================================
# Event Date Processing Tests
# ============================================================================


@responses.activate
def test_event_date_extraction_all_types():
    """Test extraction of all three event types."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2025-01-15T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2023-06-20T00:00:00Z"},
        ],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["creation_date"] == "2020-01-15"
    assert result["expiration_date"] == "2025-01-15"
    assert result["update_date"] == "2023-06-20"


@responses.activate
def test_event_date_missing_events():
    """Test handling when events array is missing or empty."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["creation_date"] == ""
    assert result["expiration_date"] == ""
    assert result["update_date"] == ""


@responses.activate
def test_event_date_without_t_separator():
    """Test handling of date without 'T' separator (returns full string)."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-15"},  # No T separator
        ],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["creation_date"] == "2020-01-15"


@responses.activate
def test_event_date_missing_eventdate():
    """Test handling of event without eventDate field."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [
            {"eventAction": "registration"},  # Missing eventDate
        ],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["creation_date"] == ""


# ============================================================================
# Link Extraction Tests
# ============================================================================


@responses.activate
def test_link_extraction_self_link_present():
    """Test extraction of self link."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [],
        "links": [
            {"rel": "self", "href": "https://rdap.net/domain/example.com"},
        ],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["link"] == "https://rdap.net/domain/example.com"


@responses.activate
def test_link_extraction_missing_self_link():
    """Test handling when self link is missing."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [],
        "links": [
            {"rel": "other", "href": "https://example.com"},
        ],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["link"] == ""


@responses.activate
def test_link_extraction_empty_links_array():
    """Test handling when links array is empty."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["link"] == ""


# ============================================================================
# API Response Variation Tests
# ============================================================================


@responses.activate
def test_analyze_minimal_response():
    """Test analysis with minimal RDAP response (empty sections)."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert all(v == "" or v == [] for v in result.values())


@responses.activate
def test_analyze_partial_response_missing_section():
    """Test analysis when some response sections are missing."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Registrar"]],
                ],
            }
        ],
        # Missing nameservers, events, links sections
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    assert result["registrar"] == "Registrar"
    assert result["name_servers"] == []


@responses.activate
def test_analyze_response_with_extra_unknown_fields():
    """Test that analysis ignores unknown/extra fields in response."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [],
        "nameservers": [],
        "events": [],
        "links": [],
        "extra_field": "ignored",
        "another_field": {"nested": "value"},
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")

    assert result is not None
    # Verify standard fields are present
    assert "registrar" in result
    assert "abuse_contact" in result


# ============================================================================
# HTTP Error Handling Tests (Parametrized)
# ============================================================================


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 404, 500, 503])
def test_analyze_http_error_codes(status_code):
    """Test handling of HTTP error responses."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"

    responses.add(responses.GET, url, status=status_code)

    result = engine.analyze("example.com", "FQDN")

    assert result is None


@responses.activate
def test_analyze_network_exception(caplog):
    """Test handling of network exception during API call."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"

    responses.add(
        responses.GET,
        url,
        body=ConnectionError("Network unreachable"),
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze("example.com", "FQDN")

    assert result is None
    assert "Error querying RDAP" in caplog.text


# ============================================================================
# Export Row Tests
# ============================================================================


@responses.activate
def test_create_export_row_complete_data(complete_rdap_response):
    """Test export row creation with complete analysis result."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"

    responses.add(responses.GET, url, json=complete_rdap_response, status=200)

    result = engine.analyze("example.com", "FQDN")
    export_row = engine.create_export_row(result)

    assert export_row["rdap_abuse"] == "abuse-sub@example.com"
    assert export_row["rdap_registrar"] == "Example Registrar Inc"
    assert export_row["rdap_registrant"] == "John Registrant"
    assert export_row["rdap_registrant_email"] == "registrant@example.com"
    assert export_row["rdap_org"] == "Example Organization"
    assert export_row["rdap_creation"] == "2020-01-15"
    assert export_row["rdap_expiration"] == "2025-01-15"
    assert export_row["rdap_update"] == "2023-06-20"
    assert "ns1.example.com" in export_row["rdap_ns"]
    assert "ns2.example.com" in export_row["rdap_ns"]


@responses.activate
def test_create_export_row_partial_data():
    """Test export row creation with partial analysis result."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    url = "https://rdap.net/domain/example.com"
    response = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Registrar"]],
                ],
            }
        ],
        "nameservers": [],
        "events": [],
        "links": [],
    }

    responses.add(responses.GET, url, json=response, status=200)

    result = engine.analyze("example.com", "FQDN")
    export_row = engine.create_export_row(result)

    assert export_row["rdap_registrar"] == "Registrar"
    assert export_row["rdap_abuse"] == ""
    assert export_row["rdap_creation"] == ""
    assert export_row["rdap_ns"] == ""


@responses.activate
def test_create_export_row_null_result():
    """Test export row creation when analysis result is None."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)

    export_row = engine.create_export_row(None)

    # All fields should be None
    assert export_row["rdap_abuse"] is None
    assert export_row["rdap_registrar"] is None
    assert export_row["rdap_org"] is None
    assert export_row["rdap_registrant"] is None
    assert export_row["rdap_registrant_email"] is None
    assert export_row["rdap_ns"] is None
    assert export_row["rdap_creation"] is None
    assert export_row["rdap_expiration"] is None
    assert export_row["rdap_update"] is None


# ============================================================================
# Engine Properties Tests
# ============================================================================


def test_engine_name():
    """Test engine name property."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    assert engine.name == "rdap"


def test_engine_supported_types():
    """Test engine supported types property."""
    engine = RDAPEngine(Secrets(), proxies={}, ssl_verify=True)
    assert engine.supported_types == ["FQDN", "URL"]
