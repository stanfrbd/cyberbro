import json
import time
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest
import requests

from app import (
    InvalidCachefileError,
    check_for_new_version,
    get_latest_version_from_cache_file,
    get_latest_version_from_updated_cache_file,
)


@pytest.fixture
def mock_cache_file():
    """Fixture for a mock cache file path"""

    return Path("/mock/path/version_cache.json")


@pytest.fixture
def valid_cache_data():
    """Fixture for valid cache data"""

    return {"last_checked": time.time(), "latest_version": "v1.0.0"}


@pytest.fixture
def old_cache_data():
    """Fixture for outdated cache data"""

    return {
        "last_checked": time.time() - 100000,  # More than a day old
        "latest_version": "v1.0.0",
    }


# Tests for get_latest_version_from_cache_file
def test_cache_file_not_exists(mock_cache_file):
    """Test when cache file doesn't exist"""

    with pytest.raises(InvalidCachefileError, match="Cache file does not exist"):
        get_latest_version_from_cache_file(mock_cache_file)


def test_valid_cache_file(mock_cache_file, valid_cache_data):
    """Test with valid cache file"""

    mock_file = mock_open(read_data=json.dumps(valid_cache_data))
    with patch("pathlib.Path.open", mock_file):
        with patch("pathlib.Path.exists", return_value=True):
            version = get_latest_version_from_cache_file(mock_cache_file)
            assert version == "v1.0.0"


def test_corrupted_json(mock_cache_file):
    """Test with corrupted JSON in cache file"""

    mock_file = mock_open(read_data="invalid json")
    with patch("pathlib.Path.open", mock_file):
        with patch("pathlib.Path.exists", return_value=True):
            with pytest.raises(InvalidCachefileError, match="Cache file is corrupted"):
                get_latest_version_from_cache_file(mock_cache_file)


def test_old_cache_file(mock_cache_file, old_cache_data):
    """Test with outdated cache file"""

    mock_file = mock_open(read_data=json.dumps(old_cache_data))
    with patch("pathlib.Path.open", mock_file):
        with patch("pathlib.Path.exists", return_value=True):
            with pytest.raises(InvalidCachefileError, match="Cache file is too old"):
                get_latest_version_from_cache_file(mock_cache_file)


# Tests for get_latest_version_from_updated_cache_file
def test_successful_update(mock_cache_file):
    """Test successful cache file update"""

    mock_response = MagicMock()
    mock_response.json.return_value = {"tag_name": "v1.1.0"}

    with patch("requests.get", return_value=mock_response):
        with patch("pathlib.Path.open", mock_open()):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("pathlib.Path.touch"):
                    version = get_latest_version_from_updated_cache_file(
                        mock_cache_file
                    )
                    assert version == "v1.1.0"


def test_request_error(mock_cache_file):
    """Test handling of request error"""

    with patch("requests.get", side_effect=requests.exceptions.RequestException()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.touch"):
                version = get_latest_version_from_updated_cache_file(mock_cache_file)
                assert version == ""


def test_json_decode_error(mock_cache_file):
    """Test handling of JSON decode error"""

    mock_response = MagicMock()
    mock_response.json.side_effect = json.JSONDecodeError("", "", 0)

    with patch("requests.get", return_value=mock_response):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.touch"):
                version = get_latest_version_from_updated_cache_file(mock_cache_file)
                assert version == ""


# Tests for check_for_new_version
def test_same_version():
    """Test when versions are the same"""

    # Clear the lru_cache before running the test to avoide caching issues
    check_for_new_version.cache_clear()

    with patch("app.get_latest_version_from_cache_file", return_value="v1.0.0"):
        result = check_for_new_version("v1.0.0")
        assert result is False


def test_different_version():
    """Test when versions are different"""

    # Clear the lru_cache before running the test to avoide caching issues
    check_for_new_version.cache_clear()

    with patch("app.get_latest_version_from_cache_file", return_value="v1.1.0"):
        result = check_for_new_version("v1.0.0")
        assert result is True


def test_cache_file_invalid():
    """Test when cache file is invalid and needs update"""

    # Clear the lru_cache before running the test to avoide caching issues
    check_for_new_version.cache_clear()

    with patch(
        "app.get_latest_version_from_cache_file",
        side_effect=InvalidCachefileError("Cache invalid"),
    ):
        with patch(
            "app.get_latest_version_from_updated_cache_file", return_value="v1.1.0"
        ):
            result = check_for_new_version("v1.0.0")
            assert result is True
