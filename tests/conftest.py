import pytest
from models.observable import ObservableType


@pytest.fixture()
def ip_observable_dict():
    return {"value": "1.1.1.1", "type": ObservableType.IPV4}


@pytest.fixture()
def fqdn_observable_dict():
    return {"value": "example.net", "type": ObservableType.FQDN}


@pytest.fixture()
def url_observable_dict():
    return {"value": "https://www.example.com", "type": ObservableType.URL}


@pytest.fixture()
def api_key() -> str:
    return "test_api_key"


# Additional fixtures for IPAPI tests
@pytest.fixture()
def secrets_with_key():
    from utils.config import Secrets

    s = Secrets()
    s.ipapi = "X" * 20
    return s


@pytest.fixture()
def secrets_without_key():
    from utils.config import Secrets

    s = Secrets()
    s.ipapi = ""
    return s


@pytest.fixture()
def ipv4_observable():
    return "1.1.1.1"


@pytest.fixture()
def ipv6_observable():
    return "2001:4860:4860::8888"
