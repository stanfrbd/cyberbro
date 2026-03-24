import requests
from pytest_mock import MockerFixture

from engines.servicenow import ServiceNowEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets


def _build_response(mocker: MockerFixture, payload: dict):
    """Helper to create a mocked requests response."""
    mock_response = mocker.Mock()
    mock_response.json.return_value = payload
    mock_response.raise_for_status = mocker.Mock()
    return mock_response


def test_servicenow_analyze_success_inc_results(mocker: MockerFixture):
    """Test successful search for INC (standard incidents)."""
    payload = {
        "result": [
            {
                "sys_id": "123456789",
                "number": "INC0010001",
                "short_description": "Network breach detected",
                "created_on": "2025-03-20T10:30:00",
                "state": "open",
                "priority": "1",
                "type": "incident",
                "assignment_group": "Security Team",
            },
            {
                "sys_id": "123456790",
                "number": "INC0010002",
                "short_description": "Malware infection alert",
                "created_on": "2025-03-19T15:45:00",
                "state": "in_progress",
                "priority": "2",
                "type": "incident",
                "assignment_group": "Security Team",
            },
        ]
    }

    mocker.patch("requests.get", return_value=_build_response(mocker, payload))

    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )
    observable = Observable(value="malware.exe", type=ObservableType.MD5)
    result = engine.analyze(observable)

    assert result is not None
    assert result["inc_total"] == 2
    assert len(result["inc_results"]) == 2
    assert result["inc_results"][0]["number"] == "INC0010001"
    assert result["inc_types"]["incident"] == 2


def test_servicenow_analyze_success_sir_results(mocker: MockerFixture):
    """Test successful search for SIR (Security Incidents)."""
    payload = {
        "result": [
            {
                "sys_id": "234567890",
                "number": "SIR0000001",
                "short_description": "Security incident response",
                "created_on": "2025-03-21T12:00:00",
                "state": "open",
                "priority": "1",
                "type": "security_incident",
                "assignment_group": "SOC Team",
            }
        ]
    }

    mocker.patch("requests.get", return_value=_build_response(mocker, payload))

    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )
    observable = Observable(value="192.168.1.1", type=ObservableType.IPV4)
    result = engine.analyze(observable)

    assert result is not None
    assert result["sir_total"] == 1
    assert len(result["sir_results"]) == 1
    assert result["sir_results"][0]["number"] == "SIR0000001"


def test_servicenow_analyze_both_inc_and_sir(mocker: MockerFixture):
    """Test search returning both INC and SIR results."""

    def mock_get(url, **kwargs):
        if "incident" in url:
            payload = {
                "result": [
                    {
                        "sys_id": "123",
                        "number": "INC0010001",
                        "short_description": "Test incident",
                        "created_on": "2025-03-20T10:00:00",
                        "state": "open",
                        "priority": "1",
                        "type": "incident",
                        "assignment_group": "Team A",
                    }
                ]
            }
        else:
            payload = {
                "result": [
                    {
                        "sys_id": "456",
                        "number": "SIR0000001",
                        "short_description": "Test security incident",
                        "created_on": "2025-03-21T10:00:00",
                        "state": "open",
                        "priority": "1",
                        "type": "security_incident",
                        "assignment_group": "Team B",
                    }
                ]
            }
        return _build_response(mocker, payload)

    mocker.patch("requests.get", side_effect=mock_get)

    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )
    observable = Observable(value="example.com", type=ObservableType.FQDN)
    result = engine.analyze(observable)

    assert result is not None
    assert result["inc_total"] == 1
    assert result["sir_total"] == 1


def test_servicenow_analyze_no_results(mocker: MockerFixture):
    """Test search with no results."""
    payload = {"result": []}

    mocker.patch("requests.get", return_value=_build_response(mocker, payload))

    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )
    observable = Observable(value="notfound.example.com", type=ObservableType.FQDN)
    result = engine.analyze(observable)

    assert result is not None
    assert result["inc_total"] == 0
    assert result["sir_total"] == 0
    assert len(result["inc_results"]) == 0


def test_servicenow_analyze_top_5_limit(mocker: MockerFixture):
    """Test that only top 5 results are returned."""
    results = []
    for i in range(10):
        results.append(
            {
                "sys_id": f"id{i}",
                "number": f"INC000000{i}",
                "short_description": f"Incident {i}",
                "created_on": f"2025-03-{20 - i:02d}T10:00:00",
                "state": "open",
                "priority": "2",
                "type": "incident",
                "assignment_group": "Team",
            }
        )

    payload = {"result": results}
    mocker.patch("requests.get", return_value=_build_response(mocker, payload))

    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )
    observable = Observable(value="test", type=ObservableType.IPV4)
    result = engine.analyze(observable)

    assert result is not None
    assert result["inc_total"] == 10
    assert len(result["inc_results"]) == 5  # Only top 5


def test_servicenow_analyze_multiple_types(mocker: MockerFixture):
    """Test breakdown of results by type."""
    payload = {
        "result": [
            {
                "sys_id": "1",
                "number": "INC0010001",
                "short_description": "Test 1",
                "created_on": "2025-03-20T10:00:00",
                "state": "open",
                "priority": "1",
                "type": "incident",
                "assignment_group": "Team",
            },
            {
                "sys_id": "2",
                "number": "INC0010002",
                "short_description": "Test 2",
                "created_on": "2025-03-19T10:00:00",
                "state": "open",
                "priority": "2",
                "type": "problem",
                "assignment_group": "Team",
            },
            {
                "sys_id": "3",
                "number": "INC0010003",
                "short_description": "Test 3",
                "created_on": "2025-03-18T10:00:00",
                "state": "closed",
                "priority": "1",
                "type": "incident",
                "assignment_group": "Team",
            },
        ]
    }

    mocker.patch("requests.get", return_value=_build_response(mocker, payload))

    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )
    observable = Observable(value="test@example.com", type=ObservableType.EMAIL)
    result = engine.analyze(observable)

    assert result is not None
    assert result["inc_total"] == 3
    assert result["inc_types"]["incident"] == 2
    assert result["inc_types"]["problem"] == 1


def test_servicenow_missing_credentials(mocker: MockerFixture):
    """Test that missing username/password is handled gracefully."""
    mocker.patch("requests.get")

    engine = ServiceNowEngine(Secrets(), {}, True)
    observable = Observable(value="test.com", type=ObservableType.FQDN)
    result = engine.analyze(observable)

    assert result is None


def test_servicenow_missing_url(mocker: MockerFixture):
    """Test that missing ServiceNow URL is handled gracefully."""
    mocker.patch("requests.get")

    engine = ServiceNowEngine(
        Secrets(servicenow_username="test_user", servicenow_password="test_password"),
        {},
        True,
    )
    observable = Observable(value="test.com", type=ObservableType.FQDN)
    result = engine.analyze(observable)

    assert result is None


def test_servicenow_request_exception(mocker: MockerFixture):
    """Test that request exceptions are handled."""
    mocker.patch("requests.get", side_effect=requests.RequestException("Connection error"))

    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )
    observable = Observable(value="test.com", type=ObservableType.FQDN)
    result = engine.analyze(observable)

    assert result is not None
    assert result["inc_total"] == 0
    assert result["sir_total"] == 0


def test_servicenow_export_row_with_results():
    """Test export row creation with results."""
    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )
    analysis_result = {
        "inc_results": [
            {"number": "INC0010001", "short_description": "Test"},
            {"number": "INC0010002", "short_description": "Test2"},
        ],
        "inc_total": 5,
        "sir_results": [{"number": "SIR0000001", "short_description": "Security"}],
        "sir_total": 3,
        "inc_types": {},
        "sir_types": {},
        "links": {},
    }

    export_row = engine.create_export_row(analysis_result)

    assert export_row["servicenow_inc_top"] == "INC0010001, INC0010002"
    assert export_row["servicenow_inc_total"] == 5
    assert export_row["servicenow_sir_top"] == "SIR0000001"
    assert export_row["servicenow_sir_total"] == 3


def test_servicenow_export_row_no_results():
    """Test export row creation with no results."""
    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )

    export_row = engine.create_export_row(None)

    assert export_row["servicenow_inc_total"] is None
    assert export_row["servicenow_inc_top"] is None
    assert export_row["servicenow_sir_total"] is None
    assert export_row["servicenow_sir_top"] is None


def test_servicenow_supported_types():
    """Test that ServiceNow engine supports expected observable types."""
    engine = ServiceNowEngine(
        Secrets(
            servicenow_url="https://test.service-now.com",
            servicenow_username="test_user",
            servicenow_password="test_password",
        ),
        {},
        True,
    )

    supported = engine.supported_types

    assert ObservableType.IPV4 in supported
    assert ObservableType.IPV6 in supported
    assert ObservableType.FQDN in supported
    assert ObservableType.URL in supported
    assert ObservableType.EMAIL in supported
    assert ObservableType.MD5 in supported
    assert ObservableType.SHA1 in supported
    assert ObservableType.SHA256 in supported
