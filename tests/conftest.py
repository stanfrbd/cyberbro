import pytest


@pytest.fixture()
def ip_observable_dict():
    return {"value": "1.1.1.1", "type": "IPv4"}


@pytest.fixture()
def fqdn_observable_dict():
    return {"value": "example.net", "type": "FQDN"}


@pytest.fixture()
def url_observable_dict():
    return {"value": "https://www.example.com", "type": "URL"}


@pytest.fixture()
def api_key() -> str:
    return "test_api_key"
