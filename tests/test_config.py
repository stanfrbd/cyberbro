from pathlib import Path

from pytest_mock import MockerFixture

from utils.config import (
    DEFAULT_SECRETS,
    Secrets,
    load_env_file,
    read_secrets_from_env,
)


def test_load_env_file_when_present(mocker: MockerFixture):
    mock_exists = mocker.patch("pathlib.Path.exists", return_value=True)
    mock_load_dotenv = mocker.patch("utils.config.load_dotenv")

    load_env_file(Path(".env"))

    mock_exists.assert_called_once()
    mock_load_dotenv.assert_called_once()


def test_load_env_file_when_missing(mocker: MockerFixture):
    mock_exists = mocker.patch("pathlib.Path.exists", return_value=False)
    mock_load_dotenv = mocker.patch("utils.config.load_dotenv")

    load_env_file(Path(".env"))

    mock_exists.assert_called_once()
    mock_load_dotenv.assert_not_called()


def test_handle_invalid_env_values(mocker: MockerFixture):
    mock_getenv = mocker.patch("os.getenv")
    mock_getenv.side_effect = lambda x: {
        "API_CACHE_TIMEOUT": "invalid",
    }.get(x)

    secrets = Secrets()
    result = read_secrets_from_env(secrets)

    assert result.api_cache_timeout == DEFAULT_SECRETS.api_cache_timeout


def test_read_secrets_from_env_success(mocker: MockerFixture):
    mock_getenv = mocker.patch("os.getenv")
    mock_getenv.side_effect = lambda x: {
        "ABUSEIPDB": "0123456789abcdef",
        "GUI_ENABLED_ENGINES": "engine1,engine2",
        "FLASK_DEBUG": "true",
    }.get(x)

    secrets = Secrets()
    result = read_secrets_from_env(secrets)

    assert result.abuseipdb == "0123456789abcdef"
    assert result.gui_enabled_engines == ["engine1", "engine2"]
    assert result.flask_debug is True


def test_maintain_defaults_no_config(mocker: MockerFixture):
    mock_getenv = mocker.patch("os.getenv")
    mock_getenv.return_value = None

    secrets = read_secrets_from_env(Secrets())

    assert secrets == DEFAULT_SECRETS


def test_secrets_get_method_existing_key():
    """Test the get method of Secrets class with an existing key."""
    secrets = Secrets(abuseipdb="test_key", api_cache_timeout=3600)

    assert secrets.get("abuseipdb") == "test_key"
    assert secrets.get("api_cache_timeout") == 3600


def test_secrets_get_method_nonexistent_key():
    """Test the get method of Secrets class with a nonexistent key."""
    secrets = Secrets()

    assert secrets.get("nonexistent_key") is None


def test_secrets_update_method_valid_keys():
    """Test the update method of Secrets class with valid keys."""
    secrets = Secrets()

    # Initial values should be defaults
    assert secrets.abuseipdb == ""
    assert secrets.api_cache_timeout == 86400

    # Update with new values
    secrets.update({"abuseipdb": "new_key", "api_cache_timeout": 7200})

    # Check that values were updated
    assert secrets.abuseipdb == "new_key"
    assert secrets.api_cache_timeout == 7200


def test_secrets_update_method_invalid_keys(mocker: MockerFixture):
    """Test the update method of Secrets class with invalid keys."""
    # Mock print and logger to check warnings
    mocker.patch("utils.config.logger.warning")

    secrets = Secrets()

    # Update with invalid key
    secrets.update({"invalid_key": "value"})

    assert secrets == DEFAULT_SECRETS


def test_secrets_update_method_invalid_value(mocker: MockerFixture):
    """Test the update method of Secrets class with invalid keys."""
    # Mock print and logger to check warnings
    mocker.patch("utils.config.logger.warning")

    secrets = Secrets()

    # Update with invalid key
    secrets.update({"api_cache_timeout": "value"})

    assert secrets.api_cache_timeout == DEFAULT_SECRETS.api_cache_timeout
