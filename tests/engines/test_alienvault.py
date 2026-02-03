import pytest
import responses
from engines.alienvault import parse_alienvault_response, query_alienvault, get_endpoint
from utils.config import QueryError
from pathlib import Path
import json
from urllib.parse import quote
from requests.exceptions import HTTPError, Timeout
from pytest_mock import MockerFixture


@pytest.fixture(scope="session")
def fqdn_response_from_file():
    file_response: Path = Path("tests/api_responses/alienvault/fqdn_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def ip_response_from_file():
    file_response: Path = Path("tests/api_responses/alienvault/ip_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture()
def md5_response():
    return {
        "sections": ["general", "analysis"],
        "type": "md5",
        "type_title": "FileHash-MD5",
        "indicator": "1fd35d9dc2eb919088f4eb48ab18b5a8",
        "validation": [],
        "base_indicator": {
            "id": 4084275658,
            "indicator": "a9ffd8047677bc2612cc97596c0c2386817ce80d",
            "type": "FileHash-SHA1",
            "title": "",
            "description": "",
            "content": "",
            "access_type": "public",
            "access_reason": "",
        },
        "pulse_info": {
            "count": 1,
            "pulses": [
                {
                    "id": "686b2966f904d473662ebd22",
                    "name": "malware",
                    "description": "",
                    "modified": "2025-07-07T03:51:15.250000",
                    "created": "2025-07-07T01:56:54.935000",
                    "tags": [],
                    "references": [],
                    "public": 1,
                    "adversary": "",
                    "targeted_countries": [],
                    "malware_families": [],
                    "attack_ids": [],
                    "industries": [],
                    "TLP": "white",
                    "cloned_from": None,
                    "export_count": 5,
                    "upvotes_count": 0,
                    "downvotes_count": 0,
                    "votes_count": 0,
                    "locked": False,
                    "pulse_source": "web",
                    "validator_count": 0,
                    "comment_count": 0,
                    "follower_count": 0,
                }
            ],
            "references": [],
            "related": {
                "alienvault": {"adversary": [], "malware_families": [], "industries": []},
                "other": {"adversary": [], "malware_families": [], "industries": []},
            },
        },
        "false_positive": [],
    }


@pytest.fixture()
def expected_fqdn_report():
    return {
        "count": 4,
        "pulses": [
            {
                "title": "Backdoor:Linux/Mirai.B\t  - TikTok",
                "url": "https://otx.alienvault.com/pulse/686b20fc7023e207712491d9",
            },
            {
                "title": "Delete service | Affects Threat Research Platforms",
                "url": "https://otx.alienvault.com/pulse/68596260a9ca6c4cc92ca068",
            },
            {
                "title": "Zooming through BlueNoroff Indicators with Validin.",
                "url": "https://www.validin.com/blog/zooming_through_bluenoroff_pivots/",
            },
            {
                "title": "ELF:Mirai AMAZON-02 - Autonomous System  65.0.0.0/14",
                "url": "https://otx.alienvault.com/pulse/684a93360163e8802e213158",
            },
        ],
        "malware_families": ["Apnic"],
        "adversary": ["Lazarus"],
        "link": "https://otx.alienvault.com/browse/global/pulses?q=support-gmeet.com",
    }


@pytest.fixture()
def expected_ip_report():
    return {
        "count": 1,
        "pulses": [
            {
                "title": "LCIA HoneyNet Data - July 2025 - Redishoneypot",
                "url": "https://github.com/telekom-security/tpotce",
            }
        ],
        "malware_families": [],
        "adversary": [],
        "link": "https://otx.alienvault.com/browse/global/pulses?q=186.180.44.234",
    }


@pytest.fixture()
def expected_md5_report():
    return {
        "count": 1,
        "pulses": [
            {"title": "malware", "url": "https://otx.alienvault.com/pulse/686b2966f904d473662ebd22"}
        ],
        "malware_families": [],
        "adversary": [],
        "link": "https://otx.alienvault.com/browse/global/pulses?q=1fd35d9dc2eb919088f4eb48ab18b5a8",
    }


@pytest.mark.parametrize(
    "input_query_response,expected_report",
    [
        ("md5_response", "expected_md5_report"),
        ("ip_response_from_file", "expected_ip_report"),
        ("fqdn_response_from_file", "expected_fqdn_report"),
    ],
)
def test_parse_alienvault(request, input_query_response, expected_report):
    """
    Use the built-in pytest fixture, request, to take the fixture name
    **as a string** in the parametrized list and retrieve the **actual**
    fixture data to be used in the test.

    Thanks to https://engineeringfordatascience.com/posts/pytest_fixtures_with_parameterize/#using-requestgetfixturevalue-
    for this solution.
    """
    input: dict = request.getfixturevalue(input_query_response)
    expected: dict = request.getfixturevalue(expected_report)
    report: dict = parse_alienvault_response(input)

    assert report == expected


@pytest.fixture()
def fqdn_response_missing_pulse_info(fqdn_response_from_file):
    input_data: dict = fqdn_response_from_file.copy()
    input_data.pop("pulse_info")
    return input_data


def test_bad_or_empty_parse_alienvault(fqdn_response_missing_pulse_info):
    expected: dict = {
        "count": 0,
        "pulses": [],
        "malware_families": [],
        "adversary": [],
        "link": "https://otx.alienvault.com/browse/global/pulses?q=support-gmeet.com",
    }

    report: dict = parse_alienvault_response(fqdn_response_missing_pulse_info)

    assert report == expected


@pytest.fixture()
def fqdn_response_missing_indicator(fqdn_response_from_file):
    input_data: dict = fqdn_response_from_file.copy()
    input_data.pop("indicator")
    return input_data


def test_missing_indicator_parse_alienvault(fqdn_response_missing_indicator):
    with pytest.raises(QueryError):
        _ = parse_alienvault_response(fqdn_response_missing_indicator)


@pytest.fixture()
def fqdn_response_missing_pulse_id(expected_fqdn_report, fqdn_response_from_file):
    input_data: dict = fqdn_response_from_file.copy()
    input_data["pulse_info"]["pulses"][0].pop("id")

    return input_data


def test_parse_alienvault_response_missing_pulse_id(
    fqdn_response_missing_pulse_id, expected_fqdn_report
):
    expected_report: dict = expected_fqdn_report.copy()
    expected_report["pulses"].pop(0)
    expected_report["count"] = 3

    report = parse_alienvault_response(fqdn_response_missing_pulse_id)

    assert report == expected_report


@responses.activate
def test_query_alienvault(fqdn_observable_dict, api_key, fqdn_response_from_file):
    responses.add(
        responses.GET,
        f"https://otx.alienvault.com/api/v1/indicators/domain/{fqdn_observable_dict['value']}/general",
        json=fqdn_response_from_file,
    )

    result: dict = query_alienvault(fqdn_observable_dict, api_key)

    assert result == fqdn_response_from_file


@responses.activate
def test_query_alienvault_http_error(api_key, ip_observable_dict):
    responses.add(
        responses.GET,
        "https://otx.alienvault.com/api/v1/indicators/IPv4/1.1.1.1/general",
        body=HTTPError(),
    )

    with pytest.raises(QueryError):
        _ = query_alienvault(ip_observable_dict, api_key)


def test_query_alienvault_request_timeout(ip_observable_dict, api_key, mocker: MockerFixture):
    mocker.patch("requests.get", side_effect=Timeout)

    with pytest.raises(QueryError):
        _ = query_alienvault(ip_observable_dict, api_key)


def test_query_alienvault_missing_endpoint(api_key):
    observable_dict: dict = {"value": "1.1.1.1", "type": "NaN"}

    with pytest.raises(QueryError):
        _ = query_alienvault(observable_dict, api_key)


@pytest.mark.parametrize(
    "type,artifact,endpoint",
    [
        ("IPv4", "1.1.1.1", "/indicators/IPv4/1.1.1.1/general"),
        ("IPv6", "fe00::0", f"/indicators/IPv6/{quote('fe00::0')}/general"),
        ("FQDN", "example.net", "/indicators/domain/example.net/general"),
        (
            "SHA1",
            "3a30948f8cd5655fede389d73b5fecd91251df4a",
            "/indicators/file/3a30948f8cd5655fede389d73b5fecd91251df4a/general",
        ),
        (
            "MD5",
            "781e5e245d69b566979b86e28d23f2c7",
            "/indicators/file/781e5e245d69b566979b86e28d23f2c7/general",
        ),
        (
            "SHA256",
            "84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882",
            "/indicators/file/84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882/general",
        ),
        ("NaN", "1.1.1.1", None),
    ],
)
def test_get_endpoint(type: str, artifact: str, endpoint: str | None):
    result: str | None = get_endpoint(artifact, type)

    assert endpoint == result
