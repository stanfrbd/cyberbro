import requests

from pytest_mock import MockerFixture

# sys.path.append("engines")

from engines.abuseipdb import query_abuseipdb


def test_successful_api_query(mocker: MockerFixture):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "1.1.1.1",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": True,
            "abuseConfidenceScore": 0,
            "countryCode": "AU",
            "usageType": "Content Delivery Network",
            "isp": "APNIC and Cloudflare DNS Resolver project",
            "domain": "cloudflare.com",
            "hostnames": ["one.one.one.one"],
            "isTor": False,
            "totalReports": 24,
            "numDistinctUsers": 8,
            "lastReportedAt": "2025-04-22T13:01:09+00:00",
        }
    }
    mocker.patch("requests.get", return_value=mock_response)

    result = query_abuseipdb("1.1.1.1", "test_key", None)

    assert result == {
        "reports": 24,
        "risk_score": 0,
        "link": "https://www.abuseipdb.com/check/1.1.1.1",
    }


def test_request_timeout(mocker: MockerFixture):
    mocker.patch("requests.get", side_effect=requests.exceptions.Timeout)

    result = query_abuseipdb("1.1.1.1", "test_key", None)

    assert result is None


def test_invalid_json_response(mocker: MockerFixture):
    mock_response = mocker.Mock()
    mock_response.json.side_effect = ValueError
    mocker.patch("requests.get", return_value=mock_response)

    result = query_abuseipdb("1.1.1.1", "test_key", None)

    assert result is None


def test_missing_data_field(mocker: MockerFixture):
    mock_response = mocker.Mock()
    mock_response.json.return_value = {"error": "No data"}
    mocker.patch("requests.get", return_value=mock_response)

    result = query_abuseipdb("1.1.1.1", "test_key", None)

    assert result is None
