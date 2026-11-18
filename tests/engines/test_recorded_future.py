import json
import logging
import urllib.parse
from pathlib import Path

import pytest
import requests
import responses

from engines.recorded_future import RecordedFutureEngine
from models.observable import Observable, ObservableFlag
from utils.config import Secrets

# ---------------------------------------------------------------------------
# Phase 1 — Fixtures & Setup
# ---------------------------------------------------------------------------

_FIXTURE_DIR = Path("tests/api_responses/recorded_future")

RF_BASE = "https://api.recordedfuture.com/v2"


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.recorded_future_api_key = "test_rf_api_key_123456789"
    return s


@pytest.fixture
def secrets_without_key():
    s = Secrets()
    s.recorded_future_api_key = ""
    return s


@pytest.fixture
def ip_observable():
    return Observable(value="1.1.1.1", type=ObservableFlag.IPV4)


@pytest.fixture
def domain_observable():
    return Observable(value="example.com", type=ObservableFlag.FQDN)


@pytest.fixture
def hash_observable():
    return Observable(
        value="abc123def456abc123def456abc123def456abc123def456abc123def456abc12",
        type=ObservableFlag.SHA256,
    )


@pytest.fixture
def url_observable():
    return Observable(value="https://malicious.example.com/path", type=ObservableFlag.URL)


@pytest.fixture(scope="session")
def ip_response():
    return json.loads((_FIXTURE_DIR / "ip_api_response.json").read_text())


@pytest.fixture(scope="session")
def domain_response():
    return json.loads((_FIXTURE_DIR / "domain_api_response.json").read_text())


@pytest.fixture(scope="session")
def hash_response():
    return json.loads((_FIXTURE_DIR / "hash_api_response.json").read_text())


@pytest.fixture(scope="session")
def url_response():
    return json.loads((_FIXTURE_DIR / "url_api_response.json").read_text())


# ---------------------------------------------------------------------------
# Phase 2 — High Priority
# ---------------------------------------------------------------------------


def test_engine_name(secrets_with_key):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    assert engine.name == "recorded_future"


def test_engine_supported_types(secrets_with_key):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    for flag in (
        ObservableFlag.IPV4,
        ObservableFlag.IPV6,
        ObservableFlag.FQDN,
        ObservableFlag.MD5,
        ObservableFlag.SHA1,
        ObservableFlag.SHA256,
        ObservableFlag.URL,
    ):
        assert flag in engine.supported_types


def test_analyze_missing_api_key_returns_none(secrets_without_key, ip_observable, caplog):
    engine = RecordedFutureEngine(secrets_without_key, proxies={}, ssl_verify=False)
    caplog.set_level(logging.WARNING)
    result = engine.analyze(ip_observable)
    assert result is None
    assert "Recorded Future" in caplog.text


@pytest.mark.parametrize(
    "obs_value,obs_type,expected_entity_type",
    [
        ("1.1.1.1", ObservableFlag.IPV4, "ip"),
        ("::1", ObservableFlag.IPV6, "ip"),
        ("example.com", ObservableFlag.FQDN, "domain"),
        ("5d41402abc4b2a76b9719d911017c592", ObservableFlag.MD5, "hash"),
        ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", ObservableFlag.SHA1, "hash"),
        (
            "abc123def456abc123def456abc123def456abc123def456abc123def456abc12",
            ObservableFlag.SHA256,
            "hash",
        ),
        ("https://malicious.example.com/path", ObservableFlag.URL, "url"),
    ],
)
@responses.activate
def test_analyze_correct_endpoint_per_type(
    secrets_with_key, obs_value, obs_type, expected_entity_type, ip_response
):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    observable = Observable(value=obs_value, type=obs_type)
    encoded = urllib.parse.quote(obs_value, safe="")
    url = f"{RF_BASE}/{expected_entity_type}/{encoded}"
    responses.add(responses.GET, url, json=ip_response, status=200)
    engine.analyze(observable)
    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers.get("X-RFToken") == "test_rf_api_key_123456789"


@responses.activate
def test_analyze_ip_response_parsing(secrets_with_key, ip_observable, ip_response):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    responses.add(responses.GET, url, json=ip_response, status=200)
    result = engine.analyze(ip_observable)
    assert result is not None
    assert result["risk_score"] == 85
    assert result["risk_level"] == "Malicious"
    assert result["rules"] == [
        "C&C Server",
        "Recent Phishing Source",
        "Historically Reported in Threat List",
    ]
    assert result["sightings"] == 2  # fixture contains 2 sighting objects
    assert result["first_seen"] == "2023-01-15"
    assert result["last_seen"] == "2024-06-01"
    assert result["threat_lists"] == ["Ransomware C2", "APT28 Infrastructure"]
    assert result["country"] == "Russia"
    assert result["asn"] == "AS12345 Example ISP"
    assert result["hash_algorithm"] == ""
    assert "app.recordedfuture.com" in result["link"]


@responses.activate
def test_analyze_domain_response_parsing(secrets_with_key, domain_observable, domain_response):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/domain/example.com"
    responses.add(responses.GET, url, json=domain_response, status=200)
    result = engine.analyze(domain_observable)
    assert result is not None
    assert result["risk_score"] == 45
    assert result["risk_level"] == "Suspicious"
    assert result["sightings"] == 2  # fixture contains 2 sighting objects
    assert result["country"] == ""
    assert result["asn"] == ""
    assert result["hash_algorithm"] == ""
    assert result["threat_lists"] == ["Phishing Domains"]


@responses.activate
def test_analyze_hash_response_parsing(secrets_with_key, hash_observable, hash_response):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    encoded = urllib.parse.quote(hash_observable.value, safe="")
    url = f"{RF_BASE}/hash/{encoded}"
    responses.add(responses.GET, url, json=hash_response, status=200)
    result = engine.analyze(hash_observable)
    assert result is not None
    assert result["risk_score"] == 97
    assert result["risk_level"] == "Very Malicious"
    assert result["sightings"] == 3  # fixture contains 3 sighting objects
    assert result["hash_algorithm"] == "SHA-256"
    assert result["threat_lists"] == []
    assert result["country"] == ""
    assert result["asn"] == ""


@responses.activate
def test_analyze_url_response_parsing(secrets_with_key, url_observable, url_response):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    encoded = urllib.parse.quote(url_observable.value, safe="")
    url = f"{RF_BASE}/url/{encoded}"
    responses.add(responses.GET, url, json=url_response, status=200)
    result = engine.analyze(url_observable)
    assert result is not None
    assert result["risk_score"] == 72
    assert result["risk_level"] == "Malicious"
    assert result["sightings"] == 2  # fixture contains 2 sighting objects
    assert result["threat_lists"] == []
    assert result["country"] == ""
    assert result["asn"] == ""
    assert result["hash_algorithm"] == ""


@responses.activate
def test_analyze_url_value_is_encoded(secrets_with_key, url_observable, url_response):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    encoded = urllib.parse.quote(url_observable.value, safe="")
    # Confirm the raw URL contains reserved chars that must be encoded
    assert "%" in encoded
    url = f"{RF_BASE}/url/{encoded}"
    responses.add(responses.GET, url, json=url_response, status=200)
    result = engine.analyze(url_observable)
    assert result is not None
    called_path = responses.calls[0].request.path_url
    assert urllib.parse.quote(url_observable.value, safe="") in called_path


# ---------------------------------------------------------------------------
# Phase 3 — Error Scenarios
# ---------------------------------------------------------------------------


@responses.activate
@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
def test_analyze_http_errors_return_none(secrets_with_key, ip_observable, status_code, caplog):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    responses.add(responses.GET, url, json={"error": "error"}, status=status_code)
    caplog.set_level(logging.ERROR)
    result = engine.analyze(ip_observable)
    assert result is None
    assert "Error querying Recorded Future" in caplog.text


@responses.activate
def test_analyze_timeout_returns_none(secrets_with_key, ip_observable, caplog):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    responses.add(responses.GET, url, body=requests.Timeout())
    caplog.set_level(logging.ERROR)
    result = engine.analyze(ip_observable)
    assert result is None
    assert "Error querying Recorded Future" in caplog.text


@responses.activate
def test_analyze_connection_error_returns_none(secrets_with_key, ip_observable, caplog):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    responses.add(responses.GET, url, body=requests.ConnectionError())
    caplog.set_level(logging.ERROR)
    result = engine.analyze(ip_observable)
    assert result is None
    assert "Error querying Recorded Future" in caplog.text


@responses.activate
def test_analyze_missing_data_key_returns_none(secrets_with_key, ip_observable):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    responses.add(responses.GET, url, json={"status": "ok"}, status=200)
    result = engine.analyze(ip_observable)
    assert result is None


@responses.activate
def test_analyze_missing_risk_returns_defaults(secrets_with_key, ip_observable):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    minimal = {"data": {"intelCard": "https://example.com", "sightings": {"totalCount": 0}}}
    responses.add(responses.GET, url, json=minimal, status=200)
    result = engine.analyze(ip_observable)
    assert result is not None
    assert result["risk_score"] == 0
    assert result["risk_level"] == ""
    assert result["rules"] == []


# ---------------------------------------------------------------------------
# Phase 4 — Export Row
# ---------------------------------------------------------------------------


def test_create_export_row_full_result(secrets_with_key):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    full = {
        "risk_score": 85,
        "risk_level": "Malicious",
        "rules": ["C&C Server", "Phishing Source"],
        "sightings": 14,
        "first_seen": "2023-01-15",
        "last_seen": "2024-06-01",
        "threat_lists": ["Ransomware C2", "APT28"],
        "country": "Russia",
        "asn": "AS12345 Example ISP",
        "hash_algorithm": "",
    }
    row = engine.create_export_row(full)
    assert row["rf_risk_score"] == 85
    assert row["rf_risk_level"] == "Malicious"
    assert row["rf_rules"] == "C&C Server, Phishing Source"
    assert row["rf_sightings"] == 14
    assert row["rf_first_seen"] == "2023-01-15"
    assert row["rf_last_seen"] == "2024-06-01"
    assert row["rf_threat_lists"] == "Ransomware C2, APT28"
    assert row["rf_country"] == "Russia"
    assert row["rf_asn"] == "AS12345 Example ISP"
    assert row["rf_hash_algorithm"] == ""


def test_create_export_row_none_result(secrets_with_key):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    row = engine.create_export_row(None)
    for key in (
        "rf_risk_score",
        "rf_risk_level",
        "rf_rules",
        "rf_sightings",
        "rf_first_seen",
        "rf_last_seen",
        "rf_threat_lists",
        "rf_country",
        "rf_asn",
        "rf_hash_algorithm",
    ):
        assert row[key] is None


def test_create_export_row_empty_dict(secrets_with_key):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    row = engine.create_export_row({})
    for key in (
        "rf_risk_score",
        "rf_risk_level",
        "rf_rules",
        "rf_sightings",
        "rf_first_seen",
        "rf_last_seen",
        "rf_threat_lists",
        "rf_country",
        "rf_asn",
        "rf_hash_algorithm",
    ):
        assert row[key] is None


def test_create_export_row_empty_lists(secrets_with_key):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    row = engine.create_export_row(
        {"risk_score": 0, "rules": [], "threat_lists": [], "sightings": 0}
    )
    assert row["rf_rules"] is None
    assert row["rf_threat_lists"] is None


# ---------------------------------------------------------------------------
# Phase 5 — Edge Cases
# ---------------------------------------------------------------------------


@responses.activate
def test_analyze_rules_sorted_by_criticality_desc(secrets_with_key, ip_observable):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    payload = {
        "data": {
            "intelCard": "https://example.com",
            "risk": {
                "score": 70,
                "level": "Malicious",
                "evidenceDetails": [
                    {"rule": "Low Rule", "criticality": 1},
                    {"rule": "High Rule", "criticality": 4},
                    {"rule": "Medium Rule", "criticality": 2},
                ],
            },
        }
    }
    responses.add(responses.GET, url, json=payload, status=200)
    result = engine.analyze(ip_observable)
    assert result is not None
    assert result["rules"] == ["High Rule", "Medium Rule", "Low Rule"]


@responses.activate
def test_analyze_more_than_3_rules_truncated(secrets_with_key, ip_observable):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    evidence = [{"rule": f"Rule {i}", "criticality": i} for i in range(5, 0, -1)]
    payload = {"data": {"intelCard": "https://example.com", "risk": {"evidenceDetails": evidence}}}
    responses.add(responses.GET, url, json=payload, status=200)
    result = engine.analyze(ip_observable)
    assert result is not None
    assert len(result["rules"]) == 3


@responses.activate
def test_analyze_more_than_3_threat_lists_truncated(secrets_with_key, ip_observable):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    lists = [{"name": f"List {i}"} for i in range(5)]
    payload = {"data": {"intelCard": "https://example.com", "threatLists": lists}}
    responses.add(responses.GET, url, json=payload, status=200)
    result = engine.analyze(ip_observable)
    assert result is not None
    assert len(result["threat_lists"]) == 3


@responses.activate
def test_analyze_empty_evidence_details_gives_empty_rules(secrets_with_key, ip_observable):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    payload = {
        "data": {
            "intelCard": "https://example.com",
            "risk": {"score": 50, "level": "Suspicious", "evidenceDetails": []},
        }
    }
    responses.add(responses.GET, url, json=payload, status=200)
    result = engine.analyze(ip_observable)
    assert result is not None
    assert result["rules"] == []


@responses.activate
def test_analyze_missing_timestamps_gives_empty_strings(secrets_with_key, ip_observable):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    url = f"{RF_BASE}/ip/1.1.1.1"
    payload = {"data": {"intelCard": "https://example.com"}}
    responses.add(responses.GET, url, json=payload, status=200)
    result = engine.analyze(ip_observable)
    assert result is not None
    assert result["first_seen"] == ""
    assert result["last_seen"] == ""


@responses.activate
def test_analyze_ipv6_uses_ip_entity_type(secrets_with_key, ip_response):
    engine = RecordedFutureEngine(secrets_with_key, proxies={}, ssl_verify=False)
    observable = Observable(value="::1", type=ObservableFlag.IPV6)
    encoded = urllib.parse.quote("::1", safe="")
    url = f"{RF_BASE}/ip/{encoded}"
    responses.add(responses.GET, url, json=ip_response, status=200)
    result = engine.analyze(observable)
    assert result is not None
    assert responses.calls[0].request.path_url.startswith("/v2/ip/")
