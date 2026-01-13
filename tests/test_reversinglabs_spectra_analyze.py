import json
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest
import responses
from engines.reversinglabs_spectra_analyze import RLAnalyzeEngine
from models.base_engine import BaseEngine
from pytest_mock import MockerFixture
from requests.exceptions import HTTPError, Timeout
from utils.config import QueryError

# Test constants
API_URL = "https://a1000-example123.reversinglabs.com"
IP4 = "1.1.1.1"
IP6 = "fe00::0"
FQDN = "kosmicband.com"
URL_UNKNOWN = "https://datatracker.ietf.org/doc/html/rfc2606"
URL_MALWARE = "https://earsi.com/H1.zip"
MD5 = "3749f52bb326ae96782b42dc0a97b4c1"
SHA1 = "3a30948f8cd5655fede389d73b5fecd91251df4a"
SHA256 = "c67c199595622dfbdc9e415c4a0ad6166eb49cbf74c6aac7bb3e958604d5ecb8"


# Tests
def rlengine_object():
    """
    This initiates the base object with dummy data.
    """
    rlengine = RLAnalyzeEngine("secret", None, False)
    return rlengine


# Example JSON data from Reversing Labs API response
@pytest.fixture(scope="session")
def fqdn_response_from_file():
    file_response: Path = Path("tests/api_responses/reversinglabs_spectra_analyze/domain_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def hash_response_from_file():
    file_response: Path = Path("tests/api_responses/reversinglabs_spectra_analyze/hash_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def ipv4_response_from_file():
    file_response: Path = Path("tests/api_responses/reversinglabs_spectra_analyze/ipv4_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def ipv6_response_from_file():
    file_response: Path = Path("tests/api_responses/reversinglabs_spectra_analyze/ipv6_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def url_unknown_response_from_file():
    file_response: Path = Path("tests/api_responses/reversinglabs_spectra_analyze/url_unknown_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def url_malware_response_from_file():
    file_response: Path = Path("tests/api_responses/reversinglabs_spectra_analyze/url_malware_api_response.json")
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


# Example result from the Reversing Labs engine lookup
@pytest.fixture()
def expected_fqdn_report():
    return {
        "link": f"{API_URL}/domain/{FQDN}/analysis/domain/",
        "malicious": 0,
        "malicious_files": 0,
        "report_color": "green",
        "report_type": "network",
        "reports": 13,
        "suspicious": 0,
        "suspicious_files": 0,
        "threats": [],
        "total_files": 0,
    }


@pytest.fixture()
def expected_md5_report():
    return {
        "classification": "GOODWARE",
        "link": f"{API_URL}/{MD5}/",
        "report_color": "green",
        "report_type": "file",
        "reports": 29,
        "riskscore": 0,
        "scanners": 0,
        "threats": ["goodware", None, "Certificate Validation"],
    }


@pytest.fixture()
def expected_sha1_report():
    return {
        "classification": "GOODWARE",
        "link": f"{API_URL}/{SHA1}/",
        "report_color": "green",
        "report_type": "file",
        "reports": 29,
        "riskscore": 0,
        "scanners": 0,
        "threats": ["goodware", None, "Certificate Validation"],
    }


@pytest.fixture()
def expected_sha256_report():
    return {
        "classification": "GOODWARE",
        "link": f"{API_URL}/{SHA256}/",
        "report_color": "green",
        "report_type": "file",
        "reports": 29,
        "riskscore": 0,
        "scanners": 0,
        "threats": ["goodware", None, "Certificate Validation"],
    }


@pytest.fixture()
def expected_ipv4_report():
    return {
        "link": f"{API_URL}/ip/{IP4}/analysis/ip/",
        "malicious": 2,
        "malicious_files": 0,
        "report_color": "yellow",
        "report_type": "network",
        "reports": 15,
        "suspicious": 0,
        "suspicious_files": 0,
        "threats": [],
        "total_files": 1733,
    }


@pytest.fixture()
def expected_ipv6_report():
    return {
        "link": f"{API_URL}/ip/{IP6}/analysis/ip/",
        "malicious": 0,
        "malicious_files": 0,
        "report_color": "green",
        "report_type": "network",
        "reports": 13,
        "suspicious": 0,
        "suspicious_files": 0,
        "threats": [],
        "total_files": 0,
    }


@pytest.fixture()
def expected_url_unknown_report():
    return {
        "link": f"{API_URL}/url/{quote_plus(URL_UNKNOWN)}/analysis/url/",
        "malicious": 0,
        "report_color": "green",
        "report_type": "network",
        "reports": 21,
        "suspicious": 0,
        "threats": [None, "information_technology", "business_economy"],
    }


@pytest.fixture()
def expected_url_malware_report():
    return {
        "link": f"{API_URL}/url/{quote_plus(URL_MALWARE)}/analysis/url/",
        "malicious": 7,
        "report_color": "red",
        "report_type": "network",
        "reports": 19,
        "suspicious": 0,
        "threats": [
            "Win32.Ransomware.Xorist",
            "Web.Hyperlink.Blacklisted",
            "malware_file",
        ],
    }


# Test API endpoint conversion
@pytest.mark.parametrize(
    "type,artifact,endpoint",
    [
        ("IPv4", IP4, f"/api/network-threat-intel/ip/{IP4}/report/"),
        ("IPv6", IP6, f"/api/network-threat-intel/ip/{IP6}/report/"),
        ("FQDN", FQDN, f"/api/network-threat-intel/domain/{FQDN}/"),
        ("URL", URL_UNKNOWN, f"/api/network-threat-intel/url/?url={quote_plus(URL_UNKNOWN)}"),
        ("SHA1", SHA1, f"/api/samples/v3/{SHA1}/classification/?av_scanners=1"),
        ("MD5", MD5, f"/api/samples/v3/{MD5}/classification/?av_scanners=1"),
        ("SHA256", SHA256, f"/api/samples/v3/{SHA256}/classification/?av_scanners=1"),
        ("NaN", IP4, None),
    ],
)
def test_get_api_endpoint(type: str, artifact: str, endpoint: str | None):
    rlengine: RLAnalyzeEngine = rlengine_object()
    result: str | None = rlengine._get_api_endpoint(artifact, type)

    assert endpoint == result


# Test UI endpoint conversion
@pytest.mark.parametrize(
    "type,artifact,endpoint",
    [
        ("IPv4", IP4, f"/ip/{IP4}/analysis/ip/"),
        ("IPv6", IP6, f"/ip/{IP6}/analysis/ip/"),
        ("FQDN", FQDN, f"/domain/{FQDN}/analysis/domain/"),
        ("URL", URL_UNKNOWN, f"/url/{quote_plus(URL_UNKNOWN)}/analysis/url/"),
        ("MD5", MD5, f"/{MD5}/"),
        ("SHA1", SHA1, f"/{SHA1}/"),
        ("SHA256", SHA256, f"/{SHA256}/"),
        ("NaN", IP4, None),
    ],
)
def test_get_ui_endpoint(type: str, artifact: str, endpoint: str | None):
    rlengine: RLAnalyzeEngine = rlengine_object()
    result: str | None = rlengine._get_ui_endpoint(artifact, type)

    assert endpoint == result


# Verify testdata
@pytest.mark.parametrize(
    "input_query_response,observable,observable_type,api_url,expected_report",
    [
        ("fqdn_response_from_file", FQDN, "FQDN", API_URL, "expected_fqdn_report"),
        ("hash_response_from_file", MD5, "MD5", API_URL, "expected_md5_report"),
        ("hash_response_from_file", SHA1, "SHA1", API_URL, "expected_sha1_report"),
        ("hash_response_from_file", SHA256, "SHA256", API_URL, "expected_sha256_report"),
        ("ipv4_response_from_file", IP4, "IPv4", API_URL, "expected_ipv4_report"),
        ("ipv6_response_from_file", IP6, "IPv6", API_URL, "expected_ipv6_report"),
        ("url_unknown_response_from_file", URL_UNKNOWN, "URL", API_URL, "expected_url_unknown_report"),
        ("url_malware_response_from_file", URL_MALWARE, "URL", API_URL, "expected_url_malware_report"),
    ],
)
def test_parse_rl_response(request: dict, input_query_response: dict, observable: str, observable_type: str, api_url: str, expected_report: dict):
    """
    Use the built-in pytest fixture, request, to take the fixture name
    **as a string** in the parametrized list and retrieve the **actual**
    fixture data to be used in the test.

    This is based on the tests from the Alienvault engine in this project.
    """
    input: dict = request.getfixturevalue(input_query_response)
    expected: dict = request.getfixturevalue(expected_report)
    rlengine: RLAnalyzeEngine = rlengine_object()
    report: dict = rlengine._parse_rl_response(input, observable, observable_type, api_url)

    assert report == expected
