import logging

import pytest
import requests
import responses

from engines.github import GitHubEngine
from utils.config import Secrets

logger = logging.getLogger(__name__)


@pytest.fixture
def secrets():
    """GitHub engine requires no credentials."""
    return Secrets()


@pytest.fixture
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture
def fqdn_observable():
    return "example.com"


@pytest.fixture
def hash_observable():
    return "a" * 40


# ============================================================================
# High Priority: Core API Flow, Response Parsing, Result Limiting
# ============================================================================


@responses.activate
def test_analyze_success_complete(secrets, ipv4_observable):
    """Test successful API response with multiple results from different repos."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    mock_resp = {
        "hits": {
            "total": 3,
            "hits": [
                {
                    "repo": "owner1/repo1",
                    "branch": "main",
                    "path": "src/config.py",
                },
                {
                    "repo": "owner2/repo2",
                    "branch": "dev",
                    "path": "config/settings.json",
                },
                {
                    "repo": "owner3/repo3",
                    "branch": "master",
                    "path": "docs/example.md",
                },
            ],
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["total"] == 3
    assert len(result["results"]) == 3
    assert result["results"][0]["title"] == "owner1/repo1"
    assert result["results"][1]["title"] == "owner2/repo2"
    assert result["results"][2]["title"] == "owner3/repo3"


@responses.activate
def test_analyze_success_minimal(secrets, ipv4_observable):
    """Test successful API response with minimal required fields."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    mock_resp = {
        "hits": {
            "total": 1,
            "hits": [
                {
                    "repo": "owner1/repo1",
                    "branch": "main",
                    "path": "file.txt",
                }
            ],
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["total"] == 1
    assert len(result["results"]) == 1
    assert result["results"][0]["title"] == "owner1/repo1"
    assert result["results"][0]["description"] == "file.txt"


@responses.activate
def test_analyze_zero_results(secrets, ipv4_observable):
    """Test handling of API response with zero results."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    mock_resp = {
        "hits": {
            "total": 0,
            "hits": [],
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["results"] == []


@responses.activate
def test_analyze_result_limiting_5_repos(secrets, ipv4_observable):
    """Test that analyze() limits results to maximum 5 unique repos."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    # Create 10 hits from different repos
    hits = [
        {
            "repo": f"owner{i}/repo{i}",
            "branch": "main",
            "path": f"file{i}.txt",
        }
        for i in range(10)
    ]

    mock_resp = {
        "hits": {
            "total": 10,
            "hits": hits,
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["total"] == 10
    assert len(result["results"]) == 5


@responses.activate
def test_analyze_duplicate_repo_deduplication(secrets, ipv4_observable):
    """Test that duplicate repos are deduplicated."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    # Same repo appears twice (different branches/paths)
    mock_resp = {
        "hits": {
            "total": 2,
            "hits": [
                {
                    "repo": "owner1/repo1",
                    "branch": "main",
                    "path": "file1.txt",
                },
                {
                    "repo": "owner1/repo1",
                    "branch": "dev",
                    "path": "file2.txt",
                },
            ],
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["total"] == 2
    assert len(result["results"]) == 1
    assert result["results"][0]["title"] == "owner1/repo1"


@responses.activate
def test_analyze_multiple_duplicates_with_limiting(secrets, ipv4_observable):
    """Test deduplication and limiting work together correctly."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    # Pattern: repo1 twice, repo2 twice, repo3 twice
    mock_resp = {
        "hits": {
            "total": 6,
            "hits": [
                {
                    "repo": "owner1/repo1",
                    "branch": "main",
                    "path": "file1a.txt",
                },
                {
                    "repo": "owner1/repo1",
                    "branch": "dev",
                    "path": "file1b.txt",
                },
                {
                    "repo": "owner2/repo2",
                    "branch": "main",
                    "path": "file2a.txt",
                },
                {
                    "repo": "owner2/repo2",
                    "branch": "master",
                    "path": "file2b.txt",
                },
                {
                    "repo": "owner3/repo3",
                    "branch": "main",
                    "path": "file3a.txt",
                },
                {
                    "repo": "owner3/repo3",
                    "branch": "staging",
                    "path": "file3b.txt",
                },
            ],
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(ipv4_observable, "IPv4")

    assert result is not None
    assert result["total"] == 6
    assert len(result["results"]) == 3
    assert result["results"][0]["title"] == "owner1/repo1"
    assert result["results"][1]["title"] == "owner2/repo2"
    assert result["results"][2]["title"] == "owner3/repo3"


@responses.activate
def test_analyze_http_401_unauthorized(secrets, ipv4_observable, caplog):
    """Test handling of 401 Unauthorized response."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    responses.add(responses.GET, url, status=401)

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error while querying GitHub" in caplog.text


@responses.activate
def test_analyze_http_500_server_error(secrets, ipv4_observable, caplog):
    """Test handling of 500 Server Error response."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    responses.add(responses.GET, url, status=500)

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error while querying GitHub" in caplog.text


@responses.activate
def test_analyze_connection_timeout(secrets, ipv4_observable, caplog):
    """Test handling of connection timeout."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    responses.add(
        responses.GET,
        url,
        body=requests.ConnectTimeout("Connection timeout"),
    )

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error while querying GitHub" in caplog.text


@responses.activate
def test_analyze_json_decode_error(secrets, ipv4_observable, caplog):
    """Test handling of malformed JSON response."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)
    url = f"https://grep.app/api/search?q={ipv4_observable}"

    responses.add(responses.GET, url, body="<html>Error page</html>", status=200)

    with caplog.at_level(logging.ERROR):
        result = engine.analyze(ipv4_observable, "IPv4")

    assert result is None
    assert "Error while querying GitHub" in caplog.text


# ============================================================================
# Medium Priority: Observable Types and Edge Cases
# ============================================================================


@responses.activate
def test_analyze_all_observable_types(secrets):
    """Test that analyze() accepts all 9 supported observable types."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    observable_types = [
        "CHROME_EXTENSION",
        "FQDN",
        "IPv4",
        "IPv6",
        "MD5",
        "SHA1",
        "SHA256",
        "URL",
        "Email",
    ]

    mock_resp = {
        "hits": {
            "total": 1,
            "hits": [
                {
                    "repo": "owner/repo",
                    "branch": "main",
                    "path": "file.txt",
                }
            ],
        }
    }

    for obs_type in observable_types:
        observable = f"test_{obs_type}"
        url = f"https://grep.app/api/search?q={observable}"
        responses.add(responses.GET, url, json=mock_resp, status=200)

        result = engine.analyze(observable, obs_type)
        assert result is not None


@responses.activate
def test_analyze_different_observable_values(secrets):
    """Test URL construction with different observable values."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    observables = [
        "1.1.1.1",
        "example.com",
        "a" * 40,  # SHA1
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5
    ]

    mock_resp = {
        "hits": {
            "total": 1,
            "hits": [
                {
                    "repo": "owner/repo",
                    "branch": "main",
                    "path": "file.txt",
                }
            ],
        }
    }

    for observable in observables:
        url = f"https://grep.app/api/search?q={observable}"
        responses.add(responses.GET, url, json=mock_resp, status=200)

        result = engine.analyze(observable, "IPv4")
        assert result is not None


@responses.activate
def test_analyze_special_characters_in_observable(secrets, caplog):
    """Test handling of special characters in observable values."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    observable = "test@example.com"
    url = f"https://grep.app/api/search?q={observable}"

    mock_resp = {
        "hits": {
            "total": 1,
            "hits": [
                {
                    "repo": "owner/repo",
                    "branch": "main",
                    "path": "file.txt",
                }
            ],
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "Email")
    assert result is not None


@responses.activate
def test_analyze_empty_observable_value(secrets, caplog):
    """Test handling of empty observable value."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    observable = ""
    url = f"https://grep.app/api/search?q={observable}"

    mock_resp = {
        "hits": {
            "total": 0,
            "hits": [],
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "IPv4")
    assert result is not None
    assert result["results"] == []


@responses.activate
def test_analyze_very_long_observable_value(secrets):
    """Test handling of very long observable values."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    observable = "a" * 1000
    url = f"https://grep.app/api/search?q={observable}"

    mock_resp = {
        "hits": {
            "total": 1,
            "hits": [
                {
                    "repo": "owner/repo",
                    "branch": "main",
                    "path": "file.txt",
                }
            ],
        }
    }

    responses.add(responses.GET, url, json=mock_resp, status=200)

    result = engine.analyze(observable, "IPv4")
    assert result is not None


# ============================================================================
# Low Priority: Export Formatting and Properties
# ============================================================================


def test_create_export_row_with_results(secrets):
    """Test export row formatting with results data."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    analysis_result = {"results": [{"title": "repo1"}], "total": 50}

    export_row = engine.create_export_row(analysis_result)

    assert export_row["github_results_count"] == 50


def test_create_export_row_zero_results(secrets):
    """Test export row formatting with zero results."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    analysis_result = {"results": [], "total": 0}

    export_row = engine.create_export_row(analysis_result)

    assert export_row["github_results_count"] == 0


def test_create_export_row_none_result(secrets):
    """Test export row formatting when analysis result is None."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    export_row = engine.create_export_row(None)

    assert export_row["github_results_count"] is None


def test_engine_name(secrets):
    """Test that engine name property returns 'github'."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    assert engine.name == "github"


def test_engine_supported_types(secrets):
    """Test that supported_types property returns all 9 types."""
    engine = GitHubEngine(secrets, proxies={}, ssl_verify=True)

    expected_types = [
        "CHROME_EXTENSION",
        "FQDN",
        "IPv4",
        "IPv6",
        "MD5",
        "SHA1",
        "SHA256",
        "URL",
        "Email",
    ]

    assert engine.supported_types == expected_types
