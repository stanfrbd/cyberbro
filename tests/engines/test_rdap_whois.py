import logging

import pytest
import responses

from engines.rdap_whois import RDAPWhoisEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)

API_URL = "https://whois.cyberbro.net/whois-proxy"


@pytest.fixture
def engine():
    secrets = Secrets()
    return RDAPWhoisEngine(secrets, proxies={}, ssl_verify=True)


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def url_observable():
    return "https://example.com/path"


@pytest.fixture
def complete_rdap_response():
    """Complete API response using RDAP as data source."""
    return {
        "domain_name": "20minutes.fr",
        "tld": "fr",
        "status": ["client transfer prohibited"],
        "registrar": "GANDI",
        "registrar_url": "https://rdap.nic.fr/entity/RAR524-FRNIC",
        "whois_server": None,
        "creation_date": "2001-07-11",
        "expiration_date": "2028-01-08",
        "updated_date": "2025-11-12",
        "registrant_name": "20 Minutes France SAS",
        "registrant_org": "20 Minutes France SAS",
        "registrant_email": "9d882bff1f92c7932581ac41a3323275-52062398@contact.gandi.net",
        "registrant_street": "24 Rue du Cotentin",
        "registrant_city": "Paris",
        "registrant_state": None,
        "registrant_postal_code": "75009",
        "registrant_country": "FR",
        "admin_name": "20 Minutes France SAS",
        "admin_org": "20 Minutes France SAS",
        "admin_email": "9d882bff1f92c7932581ac41a3323275-52062398@contact.gandi.net",
        "admin_street": "24 Rue du Cotentin",
        "admin_city": "Paris",
        "admin_state": None,
        "admin_postal_code": "75009",
        "admin_country": "FR",
        "tech_name": "GANDI",
        "tech_org": "GANDI",
        "tech_email": "noc@gandi.net",
        "tech_street": "63-65 Boulevard MASSENA",
        "tech_city": "Paris",
        "tech_state": None,
        "tech_postal_code": "75013",
        "tech_country": "FR",
        "abuse_contact": None,
        "dnssec": None,
        "name_servers": [
            "ns-1271.awsdns-30.org",
            "ns-16.awsdns-02.com",
            "ns-1958.awsdns-52.co.uk",
            "ns-748.awsdns-29.net",
        ],
        "emails": [
            "9d882bff1f92c7932581ac41a3323275-52062398@contact.gandi.net",
            "noc@gandi.net",
        ],
        "rdap_link": "https://rdap.nic.fr/domain/20minutes.fr",
        "data_source": "rdap",
        "raw_tld_server": "rdap.nic.fr",
        "raw_results": None,
    }


@pytest.fixture
def complete_whois_response():
    """Complete API response using WHOIS as data source (fallback)."""
    return {
        "domain_name": "equans.pt",
        "tld": "pt",
        "status": ["Registered"],
        "registrar": None,
        "registrar_url": None,
        "whois_server": None,
        "creation_date": "2026-01-21",
        "expiration_date": "2027-01-21",
        "updated_date": None,
        "registrant_name": "SAS EQUANS",
        "registrant_org": None,
        "registrant_email": "e12cccc7b6c659251a4cc160692f9872-57985885@contact.gandi.net",
        "registrant_street": "49 RUE LOUIS BLANC",
        "registrant_city": "COURBEVOIE",
        "registrant_state": None,
        "registrant_postal_code": "92400",
        "registrant_country": None,
        "admin_name": None,
        "admin_org": None,
        "admin_email": "reg.pt-notification@gandi.net,tld-pt-gandi@registry-auto.rrpproxy.net",
        "admin_street": "63-65 boulevard Massena",
        "admin_city": "Paris",
        "admin_state": None,
        "admin_postal_code": "75013",
        "admin_country": None,
        "tech_name": None,
        "tech_org": None,
        "tech_email": None,
        "tech_street": None,
        "tech_city": None,
        "tech_state": None,
        "tech_postal_code": None,
        "tech_country": None,
        "abuse_contact": None,
        "dnssec": None,
        "name_servers": [
            "ns-104.awsdns-13.com",
            "ns-1072.awsdns-06.org",
            "ns-524.awsdns-01.net",
            "ns-1653.awsdns-14.co.uk",
        ],
        "emails": [
            "e12cccc7b6c659251a4cc160692f9872-57985885@contact.gandi.net",
            "reg.pt-notification@gandi.net",
            "tld-pt-gandi@registry-auto.rrpproxy.net",
        ],
        "rdap_link": None,
        "data_source": "whois",
        "raw_tld_server": None,
        "raw_results": None,
    }


@pytest.fixture
def minimal_response():
    """Minimal API response with many null fields."""
    return {
        "domain_name": "example.com",
        "tld": "com",
        "status": [],
        "registrar": "Example Registrar",
        "registrar_url": "https://example-registrar.com",
        "whois_server": None,
        "creation_date": "2020-01-01",
        "expiration_date": "2025-01-01",
        "updated_date": None,
        "registrant_name": None,
        "registrant_org": None,
        "registrant_email": None,
        "registrant_street": None,
        "registrant_city": None,
        "registrant_state": None,
        "registrant_postal_code": None,
        "registrant_country": None,
        "admin_name": None,
        "admin_org": None,
        "admin_email": None,
        "admin_street": None,
        "admin_city": None,
        "admin_state": None,
        "admin_postal_code": None,
        "admin_country": None,
        "tech_name": None,
        "tech_org": None,
        "tech_email": None,
        "tech_street": None,
        "tech_city": None,
        "tech_state": None,
        "tech_postal_code": None,
        "tech_country": None,
        "abuse_contact": None,
        "dnssec": None,
        "name_servers": [],
        "emails": [],
        "rdap_link": None,
        "data_source": "rdap",
        "raw_tld_server": None,
        "raw_results": None,
    }


# ===== Engine properties =====


class TestEngineProperties:
    def test_engine_name(self, engine):
        assert engine.name == "rdap_whois"

    def test_supported_types(self, engine):
        assert engine.supported_types == ["FQDN", "URL"]

    def test_not_pivot_engine(self, engine):
        assert engine.is_pivot_engine is False

    def test_not_post_pivot(self, engine):
        assert engine.execute_after_reverse_dns is False


# ===== Successful analysis =====


class TestSuccessfulAnalysis:
    @responses.activate
    def test_fqdn_rdap_response(self, engine, fqdn_observable, complete_rdap_response):
        """Test successful FQDN analysis with RDAP data source."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        result = engine.analyze(fqdn_observable, "FQDN")

        assert result is not None
        assert result["registrar"] == "GANDI"
        assert result["registrant"] == "20 Minutes France SAS"
        assert result["organization"] == "20 Minutes France SAS"
        assert (
            result["registrant_email"]
            == "9d882bff1f92c7932581ac41a3323275-52062398@contact.gandi.net"
        )
        assert result["creation_date"] == "2001-07-11"
        assert result["expiration_date"] == "2028-01-08"
        assert result["update_date"] == "2025-11-12"
        assert result["link"] == "https://rdap.nic.fr/domain/20minutes.fr"
        assert result["data_source"] == "rdap"
        assert result["registrant_country"] == "FR"
        assert len(result["name_servers"]) == 4
        assert "ns-1271.awsdns-30.org" in result["name_servers"]
        assert len(result["emails"]) == 2
        assert "noc@gandi.net" in result["emails"]

    @responses.activate
    def test_url_rdap_response(self, engine, complete_rdap_response):
        """Test successful URL analysis - domain extracted from URL."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        result = engine.analyze("https://www.20minutes.fr/news/article", "URL")

        assert result is not None
        assert result["registrar"] == "GANDI"
        assert result["data_source"] == "rdap"

    @responses.activate
    def test_whois_fallback_response(self, engine, complete_whois_response):
        """Test successful analysis with WHOIS data source (API fallback)."""
        responses.add(responses.POST, API_URL, json=complete_whois_response, status=200)

        result = engine.analyze("equans.pt", "FQDN")

        assert result is not None
        assert result["data_source"] == "whois"
        assert result["registrant"] == "SAS EQUANS"
        assert (
            result["registrant_email"]
            == "e12cccc7b6c659251a4cc160692f9872-57985885@contact.gandi.net"
        )
        assert len(result["emails"]) == 3
        assert result["link"] == ""  # No rdap_link and no registrar_url

    @responses.activate
    def test_minimal_response(self, engine, minimal_response):
        """Test analysis with minimal data (many null fields)."""
        responses.add(responses.POST, API_URL, json=minimal_response, status=200)

        result = engine.analyze("example.com", "FQDN")

        assert result is not None
        assert result["registrar"] == "Example Registrar"
        assert result["registrant"] is None
        assert result["organization"] is None
        assert result["registrant_email"] is None
        assert result["name_servers"] == []
        assert result["emails"] == []
        assert result["data_source"] == "rdap"
        # link falls back to registrar_url when rdap_link is None
        assert result["link"] == "https://example-registrar.com"


# ===== Domain extraction =====


class TestDomainExtraction:
    @responses.activate
    def test_subdomain_extraction(self, engine, complete_rdap_response):
        """Subdomain should be stripped to registered domain."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        result = engine.analyze("sub.domain.example.com", "FQDN")
        assert result is not None
        # Verify the POST was made with just the registered domain
        assert responses.calls[0].request.body is not None

    @responses.activate
    def test_url_with_port_extraction(self, engine, complete_rdap_response):
        """URL with port should have port stripped during domain extraction."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        result = engine.analyze("https://example.com:8443/path", "URL")
        assert result is not None

    @responses.activate
    def test_url_with_path_extraction(self, engine, complete_rdap_response):
        """URL with deep path should correctly extract domain."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        result = engine.analyze("https://example.com/a/b/c?q=1", "URL")
        assert result is not None

    def test_invalid_domain_returns_none(self, engine):
        """Domain that tldextract can't parse returns None."""
        result = engine.analyze("notadomain", "FQDN")
        assert result is None


# ===== Observable type routing =====


class TestObservableTypeRouting:
    def test_unsupported_type_ipv4(self, engine):
        result = engine.analyze("1.2.3.4", "IPv4")
        assert result is None

    def test_unsupported_type_hash(self, engine):
        result = engine.analyze("d41d8cd98f00b204e9800998ecf8427e", "MD5")
        assert result is None

    def test_unsupported_type_email(self, engine):
        result = engine.analyze("test@example.com", "EMAIL")
        assert result is None


# ===== Name server handling =====


class TestNameServerHandling:
    @responses.activate
    def test_name_servers_lowercased(self, engine):
        """Name servers should be lowercased for consistency."""
        api_response = {
            "domain_name": "example.com",
            "tld": "com",
            "registrar": "Test",
            "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
            "emails": [],
            "data_source": "rdap",
        }
        responses.add(responses.POST, API_URL, json=api_response, status=200)

        result = engine.analyze("example.com", "FQDN")
        assert result is not None
        assert result["name_servers"] == ["ns1.example.com", "ns2.example.com"]

    @responses.activate
    def test_null_name_servers_filtered(self, engine):
        """Null values in name_servers array should be filtered out."""
        api_response = {
            "domain_name": "example.com",
            "tld": "com",
            "registrar": "Test",
            "name_servers": ["ns1.example.com", None, "ns2.example.com"],
            "emails": [],
            "data_source": "rdap",
        }
        responses.add(responses.POST, API_URL, json=api_response, status=200)

        result = engine.analyze("example.com", "FQDN")
        assert result is not None
        assert len(result["name_servers"]) == 2


# ===== Link fallback logic =====


class TestLinkFallback:
    @responses.activate
    def test_rdap_link_preferred(self, engine):
        """rdap_link should be used when available."""
        api_response = {
            "domain_name": "example.com",
            "tld": "com",
            "registrar": "Test",
            "registrar_url": "https://registrar.com",
            "rdap_link": "https://rdap.example.com/domain/example.com",
            "name_servers": [],
            "emails": [],
            "data_source": "rdap",
        }
        responses.add(responses.POST, API_URL, json=api_response, status=200)

        result = engine.analyze("example.com", "FQDN")
        assert result["link"] == "https://rdap.example.com/domain/example.com"

    @responses.activate
    def test_registrar_url_fallback(self, engine):
        """registrar_url should be used when rdap_link is None."""
        api_response = {
            "domain_name": "example.com",
            "tld": "com",
            "registrar": "Test",
            "registrar_url": "https://registrar.com",
            "rdap_link": None,
            "name_servers": [],
            "emails": [],
            "data_source": "whois",
        }
        responses.add(responses.POST, API_URL, json=api_response, status=200)

        result = engine.analyze("example.com", "FQDN")
        assert result["link"] == "https://registrar.com"

    @responses.activate
    def test_no_link_available(self, engine):
        """Both rdap_link and registrar_url are None."""
        api_response = {
            "domain_name": "example.com",
            "tld": "com",
            "registrar": "Test",
            "registrar_url": None,
            "rdap_link": None,
            "name_servers": [],
            "emails": [],
            "data_source": "whois",
        }
        responses.add(responses.POST, API_URL, json=api_response, status=200)

        result = engine.analyze("example.com", "FQDN")
        assert result["link"] == ""


# ===== API error handling =====


class TestAPIErrorHandling:
    @responses.activate
    def test_invalid_domain_error(self, engine):
        """API returns 400 for invalid domain."""
        responses.add(
            responses.POST,
            API_URL,
            json={"error": "invalid_domain", "message": "Domain validation failed"},
            status=400,
        )

        result = engine.analyze("example.com", "FQDN")
        assert result is None

    @responses.activate
    def test_not_found_error(self, engine):
        """API returns 404 for non-existent domain."""
        responses.add(
            responses.POST,
            API_URL,
            json={"error": "not_found", "message": "Domain not found: nonexistent.com"},
            status=404,
        )

        result = engine.analyze("nonexistent.com", "FQDN")
        assert result is None

    @responses.activate
    def test_service_unavailable_error(self, engine):
        """API returns 503 when bootstrap service is initializing."""
        responses.add(
            responses.POST,
            API_URL,
            json={"error": "service_unavailable", "message": "Bootstrap service initializing"},
            status=503,
        )

        result = engine.analyze("example.com", "FQDN")
        assert result is None

    @responses.activate
    def test_lookup_failed_error(self, engine):
        """API returns 500 when both RDAP and WHOIS queries fail."""
        responses.add(
            responses.POST,
            API_URL,
            json={"error": "lookup_failed", "message": "Both RDAP and WHOIS queries failed"},
            status=500,
        )

        result = engine.analyze("example.com", "FQDN")
        assert result is None

    @responses.activate
    def test_json_error_in_200_response(self, engine):
        """API returns 200 but with error in JSON body."""
        responses.add(
            responses.POST,
            API_URL,
            json={"error": "lookup_failed", "message": "Unexpected error"},
            status=200,
        )

        result = engine.analyze("example.com", "FQDN")
        assert result is None

    @responses.activate
    def test_network_error(self, engine):
        """Network connection error should return None."""
        responses.add(
            responses.POST,
            API_URL,
            body=ConnectionError("Connection refused"),
        )

        result = engine.analyze("example.com", "FQDN")
        assert result is None

    @responses.activate
    def test_timeout_error(self, engine):
        """Request timeout should return None."""
        from requests.exceptions import Timeout

        responses.add(
            responses.POST,
            API_URL,
            body=Timeout("Request timed out"),
        )

        result = engine.analyze("example.com", "FQDN")
        assert result is None

    @responses.activate
    def test_invalid_json_response(self, engine):
        """Non-JSON response should return None."""
        responses.add(
            responses.POST,
            API_URL,
            body="Not JSON",
            status=200,
            content_type="text/plain",
        )

        result = engine.analyze("example.com", "FQDN")
        assert result is None


# ===== Request verification =====


class TestRequestVerification:
    @responses.activate
    def test_post_method_used(self, engine, complete_rdap_response):
        """Verify POST method is used (not GET)."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        engine.analyze("example.com", "FQDN")

        assert len(responses.calls) == 1
        assert responses.calls[0].request.method == "POST"

    @responses.activate
    def test_user_agent_header(self, engine, complete_rdap_response):
        """Verify User-Agent header is set to 'Cyberbro'."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        engine.analyze("example.com", "FQDN")

        assert responses.calls[0].request.headers["User-Agent"] == "Cyberbro"

    @responses.activate
    def test_content_type_header(self, engine, complete_rdap_response):
        """Verify Content-Type is application/json."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        engine.analyze("example.com", "FQDN")

        assert "application/json" in responses.calls[0].request.headers["Content-Type"]

    @responses.activate
    def test_request_body_contains_domain(self, engine, complete_rdap_response):
        """Verify request body contains the domain."""
        import json

        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        engine.analyze("example.com", "FQDN")

        body = json.loads(responses.calls[0].request.body)
        assert body["domain"] == "example.com"

    @responses.activate
    def test_request_body_registered_domain_only(self, engine, complete_rdap_response):
        """Verify subdomain is stripped to registered domain in request."""
        import json

        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        engine.analyze("sub.domain.example.com", "FQDN")

        body = json.loads(responses.calls[0].request.body)
        assert body["domain"] == "example.com"


# ===== Data source field =====


class TestDataSource:
    @responses.activate
    def test_rdap_data_source(self, engine, complete_rdap_response):
        """Verify data_source is correctly set for RDAP responses."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        result = engine.analyze("20minutes.fr", "FQDN")
        assert result["data_source"] == "rdap"

    @responses.activate
    def test_whois_data_source(self, engine, complete_whois_response):
        """Verify data_source is correctly set for WHOIS responses."""
        responses.add(responses.POST, API_URL, json=complete_whois_response, status=200)

        result = engine.analyze("equans.pt", "FQDN")
        assert result["data_source"] == "whois"


# ===== Emails array =====


class TestEmailsArray:
    @responses.activate
    def test_multiple_emails(self, engine, complete_rdap_response):
        """Multiple emails should be preserved as array."""
        responses.add(responses.POST, API_URL, json=complete_rdap_response, status=200)

        result = engine.analyze("20minutes.fr", "FQDN")
        assert isinstance(result["emails"], list)
        assert len(result["emails"]) == 2

    @responses.activate
    def test_three_emails_whois(self, engine, complete_whois_response):
        """WHOIS response can have more emails from different contacts."""
        responses.add(responses.POST, API_URL, json=complete_whois_response, status=200)

        result = engine.analyze("equans.pt", "FQDN")
        assert len(result["emails"]) == 3

    @responses.activate
    def test_empty_emails(self, engine, minimal_response):
        """Empty emails array should be handled."""
        responses.add(responses.POST, API_URL, json=minimal_response, status=200)

        result = engine.analyze("example.com", "FQDN")
        assert result["emails"] == []


# ===== Export row =====


class TestExportRow:
    def test_export_row_complete(self, engine):
        """Export row with complete analysis result."""
        analysis_result = {
            "abuse_contact": "abuse@example.com",
            "registrar": "GANDI",
            "organization": "Example Org",
            "registrant": "John Doe",
            "registrant_email": "john@example.com",
            "emails": ["john@example.com", "abuse@example.com"],
            "name_servers": ["ns1.example.com", "ns2.example.com"],
            "creation_date": "2020-01-01",
            "expiration_date": "2025-01-01",
            "update_date": "2024-06-15",
            "link": "https://rdap.example.com/domain/example.com",
            "data_source": "rdap",
            "registrant_country": "FR",
        }

        row = engine.create_export_row(analysis_result)

        assert row["rdap_whois_abuse"] == "abuse@example.com"
        assert row["rdap_whois_registrar"] == "GANDI"
        assert row["rdap_whois_org"] == "Example Org"
        assert row["rdap_whois_registrant"] == "John Doe"
        assert row["rdap_whois_registrant_email"] == "john@example.com"
        assert row["rdap_whois_emails"] == "john@example.com, abuse@example.com"
        assert row["rdap_whois_ns"] == "ns1.example.com, ns2.example.com"
        assert row["rdap_whois_creation"] == "2020-01-01"
        assert row["rdap_whois_expiration"] == "2025-01-01"
        assert row["rdap_whois_update"] == "2024-06-15"
        assert row["rdap_whois_data_source"] == "rdap"
        assert row["rdap_whois_country"] == "FR"

    def test_export_row_none_input(self, engine):
        """Export row with None analysis result should return all None values."""
        row = engine.create_export_row(None)

        assert row["rdap_whois_abuse"] is None
        assert row["rdap_whois_registrar"] is None
        assert row["rdap_whois_org"] is None
        assert row["rdap_whois_registrant"] is None
        assert row["rdap_whois_registrant_email"] is None
        assert row["rdap_whois_emails"] is None
        assert row["rdap_whois_ns"] is None
        assert row["rdap_whois_creation"] is None
        assert row["rdap_whois_expiration"] is None
        assert row["rdap_whois_update"] is None
        assert row["rdap_whois_data_source"] is None
        assert row["rdap_whois_country"] is None

    def test_export_row_empty_lists(self, engine):
        """Export row with empty lists should produce empty strings."""
        analysis_result = {
            "abuse_contact": "",
            "registrar": "",
            "organization": "",
            "registrant": "",
            "registrant_email": "",
            "emails": [],
            "name_servers": [],
            "creation_date": "",
            "expiration_date": "",
            "update_date": "",
            "link": "",
            "data_source": "rdap",
            "registrant_country": "",
        }

        row = engine.create_export_row(analysis_result)

        assert row["rdap_whois_emails"] == ""
        assert row["rdap_whois_ns"] == ""
        assert row["rdap_whois_data_source"] == "rdap"

    def test_export_row_has_all_expected_keys(self, engine):
        """Export row should have exactly 12 keys with rdap_whois_ prefix."""
        row = engine.create_export_row(None)
        assert len(row) == 12
        for key in row:
            assert key.startswith("rdap_whois_")
