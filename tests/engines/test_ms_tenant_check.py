import logging

import pytest
import responses

from engines.ms_tenant_check import MsTenantCheckEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

OIDC_URL_TEMPLATE = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
GOOGLE_DNS_URL = "https://dns.google/resolve"

SAMPLE_OIDC_RESPONSE = {
    "token_endpoint": "https://login.microsoftonline.com/aaaa-bbbb-cccc/oauth2/token",
    "issuer": "https://sts.windows.net/aaaa1234-bbbb-cccc-dddd-eeee00000001/",
    "tenant_region_scope": "EU",
}

SAMPLE_MX_RESPONSE = {
    "Answer": [
        {
            "name": "example.com.",
            "type": 15,
            "TTL": 300,
            "data": "10 example-com.mail.protection.outlook.com.",
        }
    ]
}

NO_MX_RESPONSE: dict = {"Answer": []}


@pytest.fixture
def secrets() -> Secrets:
    return Secrets()


@pytest.fixture
def fqdn_observable() -> Observable:
    return Observable(value="example.com", type=ObservableType.FQDN)


@pytest.fixture
def email_observable() -> Observable:
    return Observable(value="user@example.com", type=ObservableType.EMAIL)


# ============================================================================
# Engine properties
# ============================================================================


def test_engine_name(secrets: Secrets) -> None:
    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    assert engine.name == "ms_tenant_check"


def test_engine_supported_types(secrets: Secrets) -> None:
    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    assert ObservableType.FQDN in engine.supported_types
    assert ObservableType.EMAIL in engine.supported_types
    assert ObservableType.IPV4 not in engine.supported_types


# ============================================================================
# _extract_domain
# ============================================================================


def test_extract_domain_from_fqdn(secrets: Secrets) -> None:
    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    obs = Observable(value="contoso.com", type=ObservableType.FQDN)
    assert engine._extract_domain(obs) == "contoso.com"


def test_extract_domain_from_email(secrets: Secrets) -> None:
    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    obs = Observable(value="alice@contoso.com", type=ObservableType.EMAIL)
    assert engine._extract_domain(obs) == "contoso.com"


# ============================================================================
# Successful tenant found (FQDN)
# ============================================================================


@responses.activate
def test_analyze_tenant_found_fqdn(secrets: Secrets, fqdn_observable: Observable) -> None:
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json=SAMPLE_OIDC_RESPONSE,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=SAMPLE_MX_RESPONSE, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["tenant_found"] is True
    assert result["tenant_id"] == "aaaa1234-bbbb-cccc-dddd-eeee00000001"
    assert result["tenant_region_scope"] == "EU"
    assert result["is_office365_mx"] is True
    assert "example-com.mail.protection.outlook.com" in result["mx_records"]
    assert result["domain"] == "example.com"


# ============================================================================
# Successful tenant found (EMAIL)
# ============================================================================


@responses.activate
def test_analyze_tenant_found_email(secrets: Secrets, email_observable: Observable) -> None:
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json=SAMPLE_OIDC_RESPONSE,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=SAMPLE_MX_RESPONSE, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(email_observable)

    assert result is not None
    assert result["tenant_found"] is True
    assert result["domain"] == "example.com"


# ============================================================================
# No tenant found (404 response)
# ============================================================================


@responses.activate
def test_analyze_no_tenant(secrets: Secrets, fqdn_observable: Observable) -> None:
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json={"error": "unknown_tenant"},
        status=400,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=NO_MX_RESPONSE, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["tenant_found"] is False
    assert result["tenant_id"] is None
    assert result["tenant_region_scope"] is None
    assert result["is_office365_mx"] is False


# ============================================================================
# Office 365 MX detection
# ============================================================================


@responses.activate
def test_analyze_office365_mx_detected(secrets: Secrets, fqdn_observable: Observable) -> None:
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json=SAMPLE_OIDC_RESPONSE,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=SAMPLE_MX_RESPONSE, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["is_office365_mx"] is True


@responses.activate
def test_analyze_no_office365_mx(secrets: Secrets, fqdn_observable: Observable) -> None:
    non_o365_mx = {
        "Answer": [{"name": "example.com.", "type": 15, "TTL": 300, "data": "10 mail.example.com."}]
    }
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json=SAMPLE_OIDC_RESPONSE,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=non_o365_mx, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["is_office365_mx"] is False


# ============================================================================
# Connection timeout → returns None
# ============================================================================


@responses.activate
def test_analyze_connection_timeout(
    secrets: Secrets, fqdn_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        body=Exception("Connection timed out"),
    )

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is None


# ============================================================================
# MX lookup failure (returns empty list, not None)
# ============================================================================


@responses.activate
def test_analyze_mx_lookup_failure(secrets: Secrets, fqdn_observable: Observable) -> None:
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json=SAMPLE_OIDC_RESPONSE,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, body=Exception("DNS timeout"))

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["tenant_found"] is True
    assert result["mx_records"] == []
    assert result["is_office365_mx"] is False


# ============================================================================
# Malformed OIDC JSON (tenant_id not extracted)
# ============================================================================


@responses.activate
def test_analyze_malformed_oidc_json(secrets: Secrets, fqdn_observable: Observable) -> None:
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        body=b"not-json",
        status=200,
        content_type="application/json",
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=NO_MX_RESPONSE, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["tenant_found"] is True
    assert result["tenant_id"] is None


# ============================================================================
# OIDC issuer without recognizable tenant ID
# ============================================================================


@responses.activate
def test_analyze_no_tenant_id_in_issuer(secrets: Secrets, fqdn_observable: Observable) -> None:
    oidc_no_guid = {"issuer": "https://sts.windows.net/", "tenant_region_scope": "NA"}
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json=oidc_no_guid,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=NO_MX_RESPONSE, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert result["tenant_id"] is None
    assert result["tenant_region_scope"] == "NA"


# ============================================================================
# Multiple MX records
# ============================================================================


@responses.activate
def test_analyze_multiple_mx_records(secrets: Secrets, fqdn_observable: Observable) -> None:
    multi_mx = {
        "Answer": [
            {
                "name": "example.com.",
                "type": 15,
                "TTL": 300,
                "data": "10 example-com.mail.protection.outlook.com.",
            },
            {"name": "example.com.", "type": 15, "TTL": 300, "data": "20 backup.mail.example.com."},
        ]
    }
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json=SAMPLE_OIDC_RESPONSE,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=multi_mx, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(fqdn_observable)

    assert result is not None
    assert len(result["mx_records"]) == 2
    assert result["is_office365_mx"] is True


# ============================================================================
# create_export_row
# ============================================================================


def test_create_export_row_with_result(secrets: Secrets) -> None:
    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    analysis_result = {
        "tenant_found": True,
        "tenant_id": "aaaa1234-bbbb-cccc-dddd-eeee00000001",
        "tenant_region_scope": "EU",
        "is_office365_mx": True,
        "mx_records": ["example-com.mail.protection.outlook.com"],
        "domain": "example.com",
    }
    row = engine.create_export_row(analysis_result)

    assert row["ms_tenant_check_found"] is True
    assert row["ms_tenant_check_id"] == "aaaa1234-bbbb-cccc-dddd-eeee00000001"
    assert row["ms_tenant_check_region"] == "EU"
    assert row["ms_tenant_check_is_office365_mx"] is True


def test_create_export_row_with_none(secrets: Secrets) -> None:
    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    row = engine.create_export_row(None)

    assert row["ms_tenant_check_found"] is None
    assert row["ms_tenant_check_id"] is None
    assert row["ms_tenant_check_region"] is None
    assert row["ms_tenant_check_is_office365_mx"] is None


def test_create_export_row_no_tenant(secrets: Secrets) -> None:
    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    analysis_result = {
        "tenant_found": False,
        "tenant_id": None,
        "tenant_region_scope": None,
        "is_office365_mx": False,
        "mx_records": [],
        "domain": "example.com",
    }
    row = engine.create_export_row(analysis_result)

    assert row["ms_tenant_check_found"] is False
    assert row["ms_tenant_check_id"] is None
    assert row["ms_tenant_check_region"] is None
    assert row["ms_tenant_check_is_office365_mx"] is False


# ============================================================================
# Parametrized: various domain/email inputs
# ============================================================================


@pytest.mark.parametrize(
    "observable",
    [
        Observable(value="contoso.com", type=ObservableType.FQDN),
        Observable(value="admin@contoso.com", type=ObservableType.EMAIL),
        Observable(value="support@sub.contoso.com", type=ObservableType.EMAIL),
    ],
)
@responses.activate
def test_analyze_parametrized_inputs(secrets: Secrets, observable: Observable) -> None:
    domain = observable.value.split("@")[-1] if "@" in observable.value else observable.value
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain=domain),
        json=SAMPLE_OIDC_RESPONSE,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=SAMPLE_MX_RESPONSE, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(observable)

    assert result is not None
    assert result["tenant_found"] is True
    assert result["domain"] == domain


# ============================================================================
# Region name mapping
# ============================================================================


@pytest.mark.parametrize(
    "scope, expected_name",
    [
        ("EU", "European Union"),
        ("NA", "North America"),
        ("SA", "South America"),
        ("AS", "Asia"),
        ("OC", "Oceania"),
        ("AF", "Africa"),
        ("WW", "Worldwide"),
        ("USGov", "US Government"),
        ("USG", "US Government"),
        ("ME", "Middle East"),
        ("IN", "India"),
        ("JP", "Japan"),
        ("KR", "Korea"),
        ("CN", "China"),
        ("CA", "Canada"),
        ("FR", "France"),
        ("DE", "Germany"),
        ("UK", "United Kingdom"),
        ("US", "United States"),
        ("AP", "Asia Pacific"),
        ("UNKNOWN", None),
    ],
)
@responses.activate
def test_region_name_mapping(secrets: Secrets, scope: str, expected_name: str | None) -> None:
    oidc_with_scope = {
        "issuer": "https://sts.windows.net/aaaa1234-bbbb-cccc-dddd-eeee00000001/",
        "tenant_region_scope": scope,
    }
    responses.add(
        responses.GET,
        OIDC_URL_TEMPLATE.format(domain="example.com"),
        json=oidc_with_scope,
        status=200,
    )
    responses.add(responses.GET, GOOGLE_DNS_URL, json=NO_MX_RESPONSE, status=200)

    engine = MsTenantCheckEngine(secrets, proxies={}, ssl_verify=True)
    result = engine.analyze(Observable(value="example.com", type=ObservableType.FQDN))

    assert result is not None
    assert result["tenant_region_scope"] == scope
    assert result["tenant_region_name"] == expected_name
