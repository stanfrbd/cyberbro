import logging

import pytest
import requests
import responses

from engines.google_safe_browsing import GOOGLE_SAFE_BROWSING_V5_URL, GoogleSafeBrowsingEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


def _encode_varint(value: int) -> bytes:
    output = bytearray()
    number = value
    while number > 0x7F:
        output.append((number & 0x7F) | 0x80)
        number >>= 7
    output.append(number)
    return bytes(output)


def _encode_length_delimited(field_number: int, value: bytes) -> bytes:
    tag = (field_number << 3) | 2
    return _encode_varint(tag) + _encode_varint(len(value)) + value


def _encode_varint_field(field_number: int, value: int) -> bytes:
    tag = field_number << 3
    return _encode_varint(tag) + _encode_varint(value)


@pytest.fixture
def secrets_with_key() -> Secrets:
    s = Secrets()
    s.google_safe_browsing = "AIzaSy_test_api_key_12345678"
    return s


@pytest.fixture
def secrets_without_key() -> Secrets:
    s = Secrets()
    s.google_safe_browsing = ""
    return s


@pytest.fixture
def url_observable() -> Observable:
    return Observable(value="http://malicious-site.com", type=ObservableType.URL)


@pytest.fixture
def fqdn_observable() -> Observable:
    return Observable(value="example.com", type=ObservableType.FQDN)


@pytest.fixture
def ipv4_observable() -> Observable:
    return Observable(value="192.168.1.1", type=ObservableType.IPV4)


@pytest.fixture
def ipv6_observable() -> Observable:
    return Observable(value="2001:4860:4860::8888", type=ObservableType.IPV6)


@responses.activate
def test_analyze_threat_found_complete(
    secrets_with_key: Secrets, url_observable: Observable
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    mock_resp = {
        "threats": [
            {
                "url": url_observable.value,
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            }
        ],
        "cacheDuration": "300s",
    }

    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json=mock_resp, status=200)

    result = engine.analyze(url_observable)

    assert result is not None
    assert result["threat_found"] == "Threat found"
    assert result["details"] is not None
    assert len(result["details"]) == 1
    assert result["details"][0]["url"] == url_observable.value
    assert result["threat_types"] == ["MALWARE", "SOCIAL_ENGINEERING"]


@responses.activate
def test_analyze_no_threat_found(secrets_with_key: Secrets, url_observable: Observable) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    mock_resp = {"threats": [], "cacheDuration": "60s"}

    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json=mock_resp, status=200)

    result = engine.analyze(url_observable)

    assert result is not None
    assert result["threat_found"] == "No threat found"
    assert result["details"] is None
    assert result["threat_types"] == []


@responses.activate
def test_analyze_response_without_threats_key(
    secrets_with_key: Secrets, url_observable: Observable
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json={}, status=200)

    result = engine.analyze(url_observable)

    assert result is not None
    assert result["threat_found"] == "No threat found"
    assert result["details"] is None
    assert result["threat_types"] == []


@responses.activate
def test_analyze_protobuf_response_with_threat(secrets_with_key: Secrets) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    threat_message = b"".join(
        [
            _encode_length_delimited(1, b"http://malicious.com"),
            _encode_varint_field(2, 1),
            _encode_varint_field(2, 2),
        ]
    )
    duration_message = _encode_varint_field(1, 300)
    response_payload = b"".join(
        [
            _encode_length_delimited(1, threat_message),
            _encode_length_delimited(2, duration_message),
        ]
    )

    responses.add(
        responses.GET,
        GOOGLE_SAFE_BROWSING_V5_URL,
        body=response_payload,
        status=200,
        content_type="application/x-protobuf",
    )

    result = engine.analyze(Observable(value="malicious.com", type=ObservableType.FQDN))

    assert result is not None
    assert result["threat_found"] == "Threat found"
    assert result["details"] == [
        {
            "url": "http://malicious.com",
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
        }
    ]
    assert result["threat_types"] == ["MALWARE", "SOCIAL_ENGINEERING"]


@responses.activate
def test_analyze_protobuf_response_with_packed_threat_types(
    secrets_with_key: Secrets,
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    packed_threat_types = _encode_varint(1) + _encode_varint(2)
    threat_message = b"".join(
        [
            _encode_length_delimited(1, b"http://packed-threat.com"),
            _encode_length_delimited(2, packed_threat_types),
        ]
    )
    duration_message = _encode_varint_field(1, 300)
    response_payload = b"".join(
        [
            _encode_length_delimited(1, threat_message),
            _encode_length_delimited(2, duration_message),
        ]
    )

    responses.add(
        responses.GET,
        GOOGLE_SAFE_BROWSING_V5_URL,
        body=response_payload,
        status=200,
        content_type="application/x-protobuf",
    )

    result = engine.analyze(Observable(value="packed-threat.com", type=ObservableType.FQDN))

    assert result is not None
    assert result["threat_found"] == "Threat found"
    assert result["details"] == [
        {
            "url": "http://packed-threat.com",
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
        }
    ]
    assert result["threat_types"] == ["MALWARE", "SOCIAL_ENGINEERING"]


@responses.activate
def test_analyze_unauthorized_response(
    secrets_with_key: Secrets, url_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(
        responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json={"error": "unauthorized"}, status=401
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable)

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_server_error_500(
    secrets_with_key: Secrets, url_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(
        responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json={"error": "server error"}, status=500
    )

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable)

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_request_timeout(
    secrets_with_key: Secrets, url_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    timeout_error = requests.exceptions.ConnectTimeout("Connection timed out")
    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, body=timeout_error)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable)

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@responses.activate
def test_analyze_invalid_json_response(
    secrets_with_key: Secrets, url_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, body="invalid json{", status=200)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable)

    assert result is None
    assert "Error while querying Google Safe Browsing" in caplog.text


@pytest.mark.parametrize(
    "observable_value,observable_type,expected_url",
    [
        ("http://malicious-site.com", ObservableType.URL, "http://malicious-site.com"),
        ("example.com", ObservableType.FQDN, "http://example.com"),
        ("192.168.1.1", ObservableType.IPV4, "http://192.168.1.1"),
        ("2001:4860:4860::8888", ObservableType.IPV6, "http://2001:4860:4860::8888"),
    ],
)
@responses.activate
def test_analyze_observable_types_success(
    secrets_with_key: Secrets,
    observable_value: str,
    observable_type: ObservableType,
    expected_url: str,
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    mock_resp = {"threats": [{"url": expected_url, "threatTypes": ["MALWARE"]}]}

    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json=mock_resp, status=200)

    result = engine.analyze(Observable(value=observable_value, type=observable_type))

    assert result is not None
    assert result["threat_found"] == "Threat found"


@responses.activate
def test_analyze_request_uses_get_method(
    secrets_with_key: Secrets, url_observable: Observable
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json={"threats": []}, status=200)

    engine.analyze(url_observable)

    assert len(responses.calls) == 1
    assert responses.calls[0].request.method == "GET"


@responses.activate
def test_analyze_request_contains_urls_query_param(
    secrets_with_key: Secrets, url_observable: Observable
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json={"threats": []}, status=200)

    engine.analyze(url_observable)

    assert len(responses.calls) == 1
    request_url = responses.calls[0].request.url
    assert f"key={secrets_with_key.google_safe_browsing}" in request_url
    assert "urls=http%3A%2F%2Fmalicious-site.com" in request_url


@responses.activate
def test_analyze_request_contains_user_agent_header(
    secrets_with_key: Secrets, url_observable: Observable
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_with_key, proxies={}, ssl_verify=True)

    responses.add(responses.GET, GOOGLE_SAFE_BROWSING_V5_URL, json={"threats": []}, status=200)

    engine.analyze(url_observable)

    assert len(responses.calls) == 1
    assert responses.calls[0].request.headers.get("User-Agent") == "cyberbro/1.0"


def test_analyze_missing_api_key_returns_none(
    secrets_without_key: Secrets, url_observable: Observable, caplog: pytest.LogCaptureFixture
) -> None:
    engine = GoogleSafeBrowsingEngine(secrets_without_key, proxies={}, ssl_verify=True)

    caplog.set_level(logging.ERROR)
    result = engine.analyze(url_observable)

    assert result is None
    assert "Missing Google Safe Browsing API key" in caplog.text


def test_create_export_row_with_threat_found() -> None:
    engine = GoogleSafeBrowsingEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "threat_found": "Threat found",
        "threat_types": ["MALWARE", "SOCIAL_ENGINEERING"],
        "details": [
            {
                "url": "http://malicious.com",
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            }
        ],
    }

    row = engine.create_export_row(analysis_result)

    assert row["gsb_threat"] == "Threat found"
    assert row["gsb_threat_types"] == "MALWARE, SOCIAL_ENGINEERING"
    assert row["gsb_matched_urls"] == "http://malicious.com"


def test_create_export_row_with_no_threat() -> None:
    engine = GoogleSafeBrowsingEngine(Secrets(), proxies={}, ssl_verify=True)

    analysis_result = {
        "threat_found": "No threat found",
        "threat_types": [],
        "details": None,
    }

    row = engine.create_export_row(analysis_result)

    assert row["gsb_threat"] == "No threat found"
    assert row["gsb_threat_types"] is None
    assert row["gsb_matched_urls"] is None


def test_create_export_row_with_none_result() -> None:
    engine = GoogleSafeBrowsingEngine(Secrets(), proxies={}, ssl_verify=True)

    row = engine.create_export_row(None)

    assert row["gsb_threat"] is None
    assert row["gsb_threat_types"] is None
    assert row["gsb_matched_urls"] is None


def test_engine_properties() -> None:
    engine = GoogleSafeBrowsingEngine(Secrets(), proxies={}, ssl_verify=True)

    assert engine.name == "google_safe_browsing"
    assert (
        engine.supported_types
        is ObservableType.FQDN | ObservableType.IPV4 | ObservableType.IPV6 | ObservableType.URL
    )
    assert engine.is_pivot_engine is False
