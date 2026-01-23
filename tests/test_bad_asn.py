"""
Tests for Bad ASN Check engine and manager.
"""

import json
from pathlib import Path

from pytest_mock import MockerFixture

from engines.bad_asn import BadASNEngine
from utils.bad_asn_manager import (
    check_asn,
    download_brianhama_bad_asn,
    download_spamhaus_asndrop,
    normalize_asn,
    update_bad_asn_cache,
)
from utils.config import Secrets


def test_normalize_asn():
    """Test ASN normalization."""
    assert normalize_asn("AS12345") == "12345"
    assert normalize_asn("12345") == "12345"
    assert normalize_asn(12345) == "12345"
    assert normalize_asn("as12345") == "12345"
    assert normalize_asn("  AS12345  ") == "12345"


def test_download_spamhaus_asndrop(mocker: MockerFixture):
    """Test Spamhaus ASNDROP download and parsing (JSONL format)."""
    mock_response = mocker.Mock()
    # Mock JSONL format (one JSON object per line)
    mock_response.text = """{"asn":401696,"rir":"arin","domain":"cognetcloud.com","cc":"HK","asname":"COGNETCLOUD"}
{"asn":1234,"rir":"ripe","domain":"example.com","cc":"US","asname":"EXAMPLE"}
{"type":"metadata","timestamp":1767899078,"size":38060,"records":427}"""
    mock_response.raise_for_status = mocker.Mock()
    mocker.patch("requests.get", return_value=mock_response)

    result = download_spamhaus_asndrop()

    assert "401696" in result
    assert "1234" in result
    assert "Spamhaus ASNDROP" in result["401696"]
    assert "COGNETCLOUD" in result["401696"]
    assert "cognetcloud.com" in result["401696"]
    # Metadata line should be skipped
    assert len(result) == 2


def test_download_brianhama_bad_asn(mocker: MockerFixture):
    """Test Brianhama Bad ASN List download and parsing."""
    mock_response = mocker.Mock()
    mock_response.text = """ASN,Entity
198375,"INULOGIC SARL, FR"
12345,"Test Entity, US"
"""
    mock_response.raise_for_status = mocker.Mock()
    mocker.patch("requests.get", return_value=mock_response)

    result = download_brianhama_bad_asn()

    assert "198375" in result
    assert "12345" in result
    assert "Brianhama Bad ASN List" in result["198375"]
    assert "INULOGIC SARL, FR" in result["198375"]


def test_update_bad_asn_cache_creates_file(mocker: MockerFixture, tmp_path: Path):
    """Test that update_bad_asn_cache creates the cache file."""
    # Mock the CACHE_FILE to use tmp_path
    cache_file = tmp_path / "bad_asn_cache.json"
    mocker.patch("utils.bad_asn_manager.CACHE_FILE", cache_file)

    # Mock the download functions
    mocker.patch(
        "utils.bad_asn_manager.download_spamhaus_asndrop",
        return_value={"401696": "Spamhaus: Test"},
    )
    mocker.patch(
        "utils.bad_asn_manager.download_brianhama_bad_asn",
        return_value={"198375": "Brianhama: Test"},
    )

    # Run update
    result = update_bad_asn_cache()

    assert result is True
    assert cache_file.exists()

    # Verify cache contents
    with cache_file.open() as f:
        cache_data = json.load(f)
        assert "last_updated" in cache_data
        assert "asns" in cache_data
        assert "401696" in cache_data["asns"]
        assert "198375" in cache_data["asns"]


def test_update_bad_asn_cache_skips_if_fresh(mocker: MockerFixture, tmp_path: Path):
    """Test that update_bad_asn_cache skips update if cache is fresh."""
    # Create a fresh cache file
    cache_file = tmp_path / "bad_asn_cache.json"
    cache_data = {"last_updated": 9999999999999, "asns": {"12345": "Test"}}
    with cache_file.open("w") as f:
        json.dump(cache_data, f)

    mocker.patch("utils.bad_asn_manager.CACHE_FILE", cache_file)

    # Run update (should skip)
    result = update_bad_asn_cache()

    assert result is False


def test_check_asn_malicious(mocker: MockerFixture, tmp_path: Path):
    """Test check_asn with a malicious ASN."""
    # Create a cache file with a malicious ASN
    cache_file = tmp_path / "bad_asn_cache.json"
    cache_data = {
        "last_updated": 9999999999999,
        "asns": {"401696": "Spamhaus ASNDROP (COGNETCLOUD, cognetcloud.com, HK)"},
    }
    with cache_file.open("w") as f:
        json.dump(cache_data, f)

    mocker.patch("utils.bad_asn_manager.CACHE_FILE", cache_file)

    result = check_asn("401696")

    assert result is not None
    assert result["status"] == "malicious"
    assert result["asn"] == "401696"
    assert "Spamhaus ASNDROP" in result["source"]


def test_check_asn_clean(mocker: MockerFixture, tmp_path: Path):
    """Test check_asn with a clean ASN."""
    # Create a cache file without the ASN
    cache_file = tmp_path / "bad_asn_cache.json"
    cache_data = {"last_updated": 9999999999999, "asns": {"401696": "Spamhaus ASNDROP"}}
    with cache_file.open("w") as f:
        json.dump(cache_data, f)

    mocker.patch("utils.bad_asn_manager.CACHE_FILE", cache_file)

    result = check_asn("12345")

    assert result is None


def test_bad_asn_engine_analyze_with_context(mocker: MockerFixture):
    """Test BadASNEngine.analyze with ASN in context."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    # Create a context with ASN from ipquery
    context = {"ipquery": {"asn": "401696"}}

    # Mock check_asn to return malicious result
    def mock_check_asn(asn):
        if asn == "401696":
            return {
                "status": "malicious",
                "source": "Test Source",
                "details": "Test details",
                "asn": asn,
            }
        return None

    mocker.patch("engines.bad_asn.check_asn", side_effect=mock_check_asn)

    result = engine.analyze("1.2.3.4", "IPv4", context=context)

    assert result is not None
    assert result["status"] == "malicious"
    assert result["asn"] == "401696"
    assert "Test Source" in result["source"]


def test_bad_asn_engine_analyze_without_context():
    """Test BadASNEngine.analyze without context."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    result = engine.analyze("1.2.3.4", "IPv4", context=None)

    assert result is None


def test_bad_asn_engine_analyze_no_asn_in_context():
    """Test BadASNEngine.analyze with context but no ASN."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    # Context without ASN data
    context = {"some_other_engine": {"data": "value"}}

    result = engine.analyze("1.2.3.4", "IPv4", context=context)

    assert result is None


def test_bad_asn_engine_extract_asn_from_ipinfo():
    """Test ASN extraction from ipinfo."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    # ipinfo structure: {"asn": "AS15169 Google LLC"}
    context = {"ipinfo": {"asn": "AS15169 Google LLC"}}

    asn = engine._extract_asn_from_context(context)

    assert asn == "15169"


def test_bad_asn_engine_extract_asn_from_ipapi():
    """Test ASN extraction from ipapi."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    # ipapi structure: {"asn": {"asn": "AS15169", "org": "..."}}
    context = {"ipapi": {"asn": {"asn": "AS15169", "org": "Google LLC"}}}

    asn = engine._extract_asn_from_context(context)

    assert asn == "15169"


def test_bad_asn_engine_create_export_row():
    """Test create_export_row method."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    analysis_result = {
        "status": "malicious",
        "asn": "401696",
        "source": "Test Source",
        "details": "Test details",
    }

    export_row = engine.create_export_row(analysis_result)

    assert export_row["bad_asn_status"] == "malicious"
    assert export_row["bad_asn_asn"] == "401696"
    assert export_row["bad_asn_source"] == "Test Source"
    assert export_row["bad_asn_details"] == "Test details"


def test_bad_asn_engine_create_export_row_none():
    """Test create_export_row with None result."""
    secrets = Secrets()
    engine = BadASNEngine(secrets, {}, True)

    export_row = engine.create_export_row(None)

    assert export_row["bad_asn_status"] == "N/A"
    assert export_row["bad_asn_asn"] == ""
