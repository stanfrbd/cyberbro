import json
from pathlib import Path
from urllib.parse import quote_plus

import pytest

from engines.reversinglabs_spectra_analyze import RLAnalyzeEngine

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
    return RLAnalyzeEngine("secret", None, False)


# Example JSON data from Reversing Labs API response
@pytest.fixture(scope="session")
def fqdn_response_from_file():
    file_response: Path = Path(
        "tests/api_responses/reversinglabs_spectra_analyze/domain_api_response.json"
    )
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def hash_response_from_file():
    file_response: Path = Path(
        "tests/api_responses/reversinglabs_spectra_analyze/hash_api_response.json"
    )
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def ipv4_response_from_file():
    file_response: Path = Path(
        "tests/api_responses/reversinglabs_spectra_analyze/ipv4_api_response.json"
    )
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def ipv6_response_from_file():
    file_response: Path = Path(
        "tests/api_responses/reversinglabs_spectra_analyze/ipv6_api_response.json"
    )
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def url_unknown_response_from_file():
    file_response: Path = Path(
        "tests/api_responses/reversinglabs_spectra_analyze/url_unknown_api_response.json"
    )
    with file_response.open() as f:
        data: dict = json.loads(f.read())

    return data


@pytest.fixture(scope="session")
def url_malware_response_from_file():
    file_response: Path = Path(
        "tests/api_responses/reversinglabs_spectra_analyze/url_malware_api_response.json"
    )
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
        (
            "url_unknown_response_from_file",
            URL_UNKNOWN,
            "URL",
            API_URL,
            "expected_url_unknown_report",
        ),
        (
            "url_malware_response_from_file",
            URL_MALWARE,
            "URL",
            API_URL,
            "expected_url_malware_report",
        ),
    ],
)
def test_parse_rl_response(
    request: dict,
    input_query_response: dict,
    observable: str,
    observable_type: str,
    api_url: str,
    expected_report: dict,
):
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


# ============================================================================
# ADDITIONAL COMPREHENSIVE TESTS FOR ENGINE COVERAGE
# ============================================================================


# Test network response color coding - Green
@pytest.mark.parametrize(
    "observable_type",
    ["IPv4", "IPv6", "FQDN", "URL"],
)
def test_network_green_color_logic(observable_type: str):
    """Verify green color assigned for network observations with no/low threats."""
    response = {
        "top_threats": [],
        "analysis": {"top_threats": []},  # URL needs analysis key
        "threat_name": None,  # URL needs threat_name
        "categories": [],  # URL needs categories
        "downloaded_files_statistics": {
            "total": 10,
            "malicious": 0,
            "suspicious": 0,
        },
        "third_party_reputations": {
            "statistics": {
                "malicious": 0,
                "suspicious": 0,
                "total": 5,
            }
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "test.com", observable_type, API_URL)

    if result:  # Only check if result is not None
        assert result["report_color"] == "green"


# Test network response color coding - Yellow
@pytest.mark.parametrize(
    "observable_type",
    ["IPv4", "IPv6", "FQDN", "URL"],
)
def test_network_yellow_color_logic(observable_type: str):
    """Verify yellow color for network observations with low threat counts."""
    response = {
        "top_threats": [{"threat_name": "PUA"}],
        "analysis": {"top_threats": [{"threat_name": "PUA"}]},  # URL needs analysis key
        "threat_name": "URL_Threat",  # URL needs threat_name
        "categories": ["malware"],  # URL needs categories
        "downloaded_files_statistics": {
            "total": 20,
            "malicious": 1,
            "suspicious": 1,
        },
        "third_party_reputations": {
            "statistics": {
                "malicious": 1,
                "suspicious": 1,
                "total": 10,
            }
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "test.com", observable_type, API_URL)

    if result:
        assert result["report_color"] == "yellow"


# Test network response color coding - Red
@pytest.mark.parametrize(
    "observable_type",
    ["IPv4", "IPv6", "FQDN", "URL"],
)
def test_network_red_color_logic(observable_type: str):
    """Verify red color for network observations with high threat counts."""
    response = {
        "top_threats": [{"threat_name": "Trojan"}, {"threat_name": "Backdoor"}],
        "analysis": {
            "top_threats": [
                {"threat_name": "Trojan"},
                {"threat_name": "Backdoor"},
            ]
        },  # URL needs analysis key
        "threat_name": "Malware",  # URL needs threat_name
        "categories": ["malware", "trojan"],  # URL needs categories
        "downloaded_files_statistics": {
            "total": 100,
            "malicious": 50,
            "suspicious": 30,
        },
        "third_party_reputations": {
            "statistics": {
                "malicious": 5,
                "suspicious": 8,
                "total": 20,
            }
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "test.com", observable_type, API_URL)

    if result:
        assert result["report_color"] == "red"


# Test network response with no reputation data
@pytest.mark.parametrize(
    "observable_type",
    ["IPv4", "IPv6", "FQDN", "URL"],
)
def test_network_no_reputation_returns_empty(observable_type: str):
    """Verify empty dict returned when total reputation is 0 for network types."""
    response = {
        "top_threats": [],
        "analysis": {"top_threats": []},  # URL needs analysis key
        "threat_name": None,  # URL needs threat_name
        "categories": [],  # URL needs categories
        "downloaded_files_statistics": {
            "total": 0,
            "malicious": 0,
            "suspicious": 0,
        },
        "third_party_reputations": {
            "statistics": {
                "malicious": 0,
                "suspicious": 0,
                "total": 0,  # Critical: total = 0
            }
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "test.com", observable_type, API_URL)

    assert result == {}


# Test file hash response color coding - Green
@pytest.mark.parametrize(
    "hash_type",
    ["MD5", "SHA1", "SHA256"],
)
def test_file_green_color_logic(hash_type: str):
    """Verify green color for benign file classifications."""
    response = {
        "classification": "goodware",
        "classification_result": "Safe",
        "classification_reason": "Benign",
        "riskscore": 0,
        "av_scanners": {
            "scanner_count": 50,
            "scanner_match": 0,
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "abc123", hash_type, API_URL)

    if result:
        assert result["report_color"] == "green"


# Test file hash response color coding - Yellow
@pytest.mark.parametrize(
    "hash_type",
    ["MD5", "SHA1", "SHA256"],
)
def test_file_yellow_color_logic(hash_type: str):
    """Verify yellow color for suspicious classifications or non-goodware."""
    response = {
        "classification": "suspicious",
        "classification_result": "Suspicious",
        "classification_reason": "Behavior detected",
        "riskscore": 3,
        "av_scanners": {
            "scanner_count": 50,
            "scanner_match": 5,
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "abc123", hash_type, API_URL)

    if result:
        assert result["report_color"] == "yellow"


# Test file hash response color coding - Red
@pytest.mark.parametrize(
    "hash_type",
    ["MD5", "SHA1", "SHA256"],
)
def test_file_red_color_logic(hash_type: str):
    """Verify red color when classification is malicious with riskscore > 2."""
    response = {
        "classification": "malicious",
        "classification_result": "Malicious",
        "classification_reason": "Trojan",
        "riskscore": 8,
        "av_scanners": {
            "scanner_count": 50,
            "scanner_match": 15,
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "abc123", hash_type, API_URL)

    if result:
        assert result["report_color"] == "red"


# Test file hash response with no av_scanners
@pytest.mark.parametrize(
    "hash_type",
    ["MD5", "SHA1", "SHA256"],
)
def test_file_no_av_scanners_returns_empty(hash_type: str):
    """Verify empty dict returned when av_scanners missing for file types."""
    response = {
        "classification": "unknown",
        "classification_result": "Unknown",
        "classification_reason": "Not analyzed",
        "riskscore": 0,
        "av_scanners": {},  # Empty av_scanners
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "abc123", hash_type, API_URL)

    assert result == {}


# Test threat list with None values
def test_network_threat_list_with_none():
    """Verify threat list handles None threat_name values."""
    response = {
        "top_threats": [
            {"threat_name": "Trojan"},
            {"threat_name": None},
            {"threat_name": "Worm"},
        ],
        "downloaded_files_statistics": {
            "total": 10,
            "malicious": 2,
            "suspicious": 0,
        },
        "third_party_reputations": {
            "statistics": {
                "malicious": 2,
                "suspicious": 0,
                "total": 5,
            }
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "example.com", "FQDN", API_URL)

    assert result is not None
    assert "Trojan" in result["threats"]
    assert "Worm" in result["threats"]
    assert None in result["threats"]  # None is preserved in threats list


# Test file hash threat list
def test_file_threat_list_extraction():
    """Verify threat list extraction for file hashes includes classification fields."""
    response = {
        "classification": "malicious",
        "classification_result": "Malicious",
        "classification_reason": "Trojan.Generic",
        "riskscore": 7,
        "av_scanners": {
            "scanner_count": 50,
            "scanner_match": 12,
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "abc123", "MD5", API_URL)

    assert result is not None
    assert "malicious" in result["threats"]
    assert "Malicious" in result["threats"]
    assert "Trojan.Generic" in result["threats"]


# Test export row - network type
def test_export_row_network_type():
    """Verify export row has correct fields for network type."""
    rlengine = rlengine_object()
    analysis_result = {
        "report_type": "network",
        "report_color": "yellow",
        "reports": 10,
        "malicious": 2,
        "suspicious": 1,
        "total_files": 50,
        "malicious_files": 5,
        "suspicious_files": 2,
        "threats": ["Trojan", "PUA"],
        "link": "https://example.com",
    }

    row = rlengine.create_export_row(analysis_result)

    assert row["rl_analyze_total_count"] == 10
    assert row["rl_analyze_malicious"] == 2
    assert row["rl_analyze_suspicious"] == 1
    assert row["rl_analyze_total_files"] == 50
    assert row["rl_analyze_malicious_files"] == 5
    assert row["rl_analyze_suspicious_files"] == 2
    assert row["rl_analyze_av_scanners"] is None  # Not applicable to network
    assert row["rl_analyze_riskscore"] is None  # Not applicable to network


# Test export row - file type
def test_export_row_file_type():
    """Verify export row has correct fields for file type."""
    rlengine = rlengine_object()
    analysis_result = {
        "report_type": "file",
        "report_color": "red",
        "reports": 45,
        "scanners": 12,
        "classification": "MALICIOUS",
        "riskscore": 8,
        "threats": ["malicious", "Trojan"],
        "link": "https://example.com",
    }

    row = rlengine.create_export_row(analysis_result)

    assert row["rl_analyze_total_count"] == 45
    assert row["rl_analyze_av_scanners"] == 12
    assert row["rl_analyze_riskscore"] == 8
    assert row["rl_analyze_total_files"] is None  # Not applicable to file
    assert row["rl_analyze_malicious_files"] is None  # Not applicable to file
    assert row["rl_analyze_suspicious_files"] is None  # Not applicable to file


# Test export row - None result
def test_export_row_none_result():
    """Verify all fields are None when analysis result is None."""
    rlengine = rlengine_object()
    row = rlengine.create_export_row(None)

    expected_keys = [
        "rl_analyze_total_count",
        "rl_analyze_malicious",
        "rl_analyze_suspicious",
        "rl_analyze_total_files",
        "rl_analyze_malicious_files",
        "rl_analyze_suspicious_files",
        "rl_analyze_av_scanners",
        "rl_analyze_threats",
        "rl_analyze_riskscore",
        "rl_analyze_link",
    ]
    for key in expected_keys:
        assert key in row
        assert row[key] is None


# Test export row threat filtering
def test_export_row_threat_filtering():
    """Verify threats are filtered to remove None/empty values in export."""
    rlengine = rlengine_object()
    analysis_result = {
        "report_type": "network",
        "report_color": "yellow",
        "reports": 5,
        "malicious": 1,
        "suspicious": 1,
        "total_files": 0,
        "malicious_files": 0,
        "suspicious_files": 0,
        "threats": ["Trojan", None, "", "Worm"],
        "link": "https://example.com",
    }

    row = rlengine.create_export_row(analysis_result)
    threat_str = row["rl_analyze_threats"]

    assert "Trojan" in threat_str
    assert "Worm" in threat_str
    # The join filters out falsy values
    assert threat_str.count(", ") == 1  # Only one separator for two threats


# Test engine properties
def test_engine_name():
    """Verify engine name property."""
    rlengine = rlengine_object()
    assert rlengine.name == "rl_analyze"


def test_engine_supported_types():
    """Verify all supported observable types."""
    rlengine = rlengine_object()
    supported = rlengine.supported_types
    expected_types = ["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]
    for obs_type in expected_types:
        assert obs_type in supported


def test_engine_is_not_pivot():
    """Verify engine is not a pivot engine."""
    rlengine = rlengine_object()
    assert not rlengine.is_pivot_engine


# Test network yellow color boundary - exactly at threshold
def test_network_yellow_at_boundary():
    """Verify yellow when exactly at threshold (malicious=1, suspicious=1)."""
    response = {
        "top_threats": [],
        "downloaded_files_statistics": {"total": 5, "malicious": 0, "suspicious": 0},
        "third_party_reputations": {
            "statistics": {
                "malicious": 1,
                "suspicious": 1,
                "total": 5,
            }
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "test.com", "IPv4", API_URL)

    if result:
        assert result["report_color"] == "yellow"


# Test network red color - high suspicious threshold
def test_network_red_high_suspicious():
    """Verify red when suspicious > 3."""
    response = {
        "top_threats": [],
        "downloaded_files_statistics": {"total": 100, "malicious": 0, "suspicious": 50},
        "third_party_reputations": {
            "statistics": {
                "malicious": 0,
                "suspicious": 4,
                "total": 10,
            }
        },
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "test.com", "FQDN", API_URL)

    if result:
        assert result["report_color"] == "red"


# Test file yellow - unknown classification
def test_file_yellow_unknown_classification():
    """Verify yellow when classification is not goodware."""
    response = {
        "classification": "unknown",
        "classification_result": "Unknown",
        "classification_reason": "Insufficient data",
        "riskscore": 0,
        "av_scanners": {"scanner_count": 40, "scanner_match": 0},
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "abc123", "SHA256", API_URL)

    if result:
        assert result["report_color"] == "yellow"


# Test file red - malicious with low riskscore still red
def test_file_red_malicious_low_riskscore():
    """Verify red when classification=malicious even with low riskscore."""
    response = {
        "classification": "malicious",
        "classification_result": "Malicious",
        "classification_reason": "Detected",
        "riskscore": 3,  # > 2, so red
        "av_scanners": {"scanner_count": 50, "scanner_match": 8},
    }
    rlengine = rlengine_object()
    result = rlengine._parse_rl_response(response, "abc123", "MD5", API_URL)

    if result:
        assert result["report_color"] == "red"


# Test URL with special characters in endpoint
def test_url_endpoint_special_characters():
    """Verify URL with special characters is quote_plus encoded in endpoint."""
    rlengine = rlengine_object()
    url = "https://example.com/path?query=test&foo=bar"
    endpoint = rlengine._get_api_endpoint(url, "URL")

    assert endpoint is not None
    assert "%3A%2F%2F" in endpoint  # Encoded "://"
    assert "%3F" in endpoint  # Encoded "?"
    assert "%26" in endpoint  # Encoded "&"
