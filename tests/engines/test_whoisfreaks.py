import logging
from urllib.parse import parse_qs, urlparse

import pytest
import requests
import responses
import tldextract

from engines.whoisfreaks import WhoisFreaksEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)

HISTORY_URL = "https://api.whoisfreaks.com/v2.0/whois/history"
REVERSE_URL = "https://api.whoisfreaks.com/v2.0/whois/reverse"
API_KEY = "test_whoisfreaks_key_value"


def _record(
    query_time, registrar, name="", company="", email="", country="", create_date="2015-03-01"
):
    return {
        "num": 1,
        "status": True,
        "domain_name": "example.com",
        "query_time": query_time,
        "create_date": create_date,
        "update_date": "2020-01-01",
        "expiry_date": "2030-03-01",
        "domain_registrar": {"iana_id": "1", "registrar_name": registrar},
        "registrant_contact": {
            "name": name,
            "company": company,
            "email_address": email,
            "country_name": country,
        },
        "name_servers": ["ns1.example.net"],
        "domain_status": ["clientTransferProhibited"],
    }


@pytest.fixture(autouse=True, scope="module")
def _warm_tldextract():
    # tldextract fetches the public suffix list on first use; do it outside the HTTP mocks.
    tldextract.extract("example.com")


@pytest.fixture
def secrets_with_key():
    s = Secrets()
    s.whoisfreaks = API_KEY
    return s


@pytest.fixture
def engine(secrets_with_key):
    return WhoisFreaksEngine(secrets_with_key, proxies={}, ssl_verify=True)


@pytest.fixture
def fqdn_observable():
    return Observable(value="example.com", type=ObservableType.FQDN)


@pytest.fixture
def history_private_only():
    """History where every registrant email is privacy-protected."""
    return {
        "total_Result": 2,
        "total_Pages": 1,
        "current_Page": 1,
        "whois_domains_historical": [
            _record(
                "2021-05-10 10:00:00",
                "NameCheap, Inc.",
                company="Privacy service provided by Withheld for Privacy ehf",
                email="abc123@withheldforprivacy.com",
                country="Iceland",
            ),
            _record(
                "2023-08-01 09:30:00",
                "NameCheap, Inc.",
                company="Redacted for Privacy",
                email="redacted@privacy.example",
                country="Iceland",
            ),
        ],
    }


@pytest.fixture
def history_with_owner():
    """History with an old, real registrant email before privacy was turned on."""
    return {
        "total_Result": 3,
        "total_Pages": 1,
        "current_Page": 1,
        "whois_domains_historical": [
            _record(
                "2016-02-03 12:00:00",
                "GoDaddy.com, LLC",
                name="John Doe",
                company="Doe Corp",
                email="John.Doe@doecorp.example",
                country="United States",
                create_date="2015-03-01",
            ),
            _record(
                "2019-07-20 12:00:00",
                "GoDaddy.com, LLC",
                name="John Doe",
                company="Doe Corp",
                email="john.doe@doecorp.example",
                country="United States",
                create_date="2015-03-01",
            ),
            _record(
                "2022-11-11 12:00:00",
                "NameCheap, Inc.",
                company="Privacy service provided by Withheld for Privacy ehf",
                email="xyz@withheldforprivacy.com",
                country="Iceland",
                create_date="2015-03-01",
            ),
        ],
    }


@pytest.fixture
def reverse_response():
    return {
        "total_Result": 3,
        "total_Pages": 1,
        "current_Page": 1,
        "whois_domains_historical": [
            {"num": 1, "domain_name": "example.com"},
            {"num": 2, "domain_name": "doecorp-shop.example"},
            {"num": 3, "domain_name": "DoeCorp-Login.example"},
        ],
    }


class TestEngineProperties:
    def test_engine_name(self, engine):
        assert engine.name == "whoisfreaks"

    def test_supported_types(self, engine):
        assert engine.supported_types == ObservableType.FQDN | ObservableType.URL

    def test_not_pivot_engine(self, engine):
        assert engine.is_pivot_engine is False

    def test_not_post_pivot(self, engine):
        assert engine.execute_after_reverse_dns is False


class TestCredentials:
    @responses.activate
    def test_missing_key_returns_none_without_calling_api(self, fqdn_observable):
        engine = WhoisFreaksEngine(Secrets(), proxies={}, ssl_verify=True)
        assert engine.analyze(fqdn_observable) is None
        assert len(responses.calls) == 0

    @responses.activate
    def test_key_sent_as_query_param(self, engine, fqdn_observable, history_private_only):
        responses.add(responses.GET, HISTORY_URL, json=history_private_only, status=200)
        engine.analyze(fqdn_observable)
        params = parse_qs(urlparse(responses.calls[0].request.url).query)
        assert params["apiKey"] == [API_KEY]
        assert params["whois"] == ["historical"]
        assert params["domainName"] == ["example.com"]


class TestHistory:
    @responses.activate
    def test_privacy_emails_skip_reverse_lookup(
        self, engine, fqdn_observable, history_private_only
    ):
        responses.add(responses.GET, HISTORY_URL, json=history_private_only, status=200)

        result = engine.analyze(fqdn_observable)

        assert result is not None
        assert result["history_records"] == 2
        assert result["reverse_whois"] is None
        # Only the history call, no reverse WHOIS credits spent.
        assert len(responses.calls) == 1

    @responses.activate
    def test_history_parsing(self, engine, fqdn_observable, history_with_owner, reverse_response):
        responses.add(responses.GET, HISTORY_URL, json=history_with_owner, status=200)
        responses.add(responses.GET, REVERSE_URL, json=reverse_response, status=200)

        result = engine.analyze(fqdn_observable)

        assert result["domain"] == "example.com"
        assert result["history_records"] == 3
        assert result["first_record"] == "2016-02-03"
        assert result["last_record"] == "2022-11-11"
        assert result["earliest_creation_date"] == "2015-03-01"
        assert result["link"] == "https://whoisfreaks.com/tools/whois/history/lookup/example.com"

        # Registrars: deduplicated, most recent first, with first/last seen.
        assert [r["name"] for r in result["registrars"]] == ["NameCheap, Inc.", "GoDaddy.com, LLC"]
        godaddy = result["registrars"][1]
        assert godaddy["first_seen"] == "2016-02-03"
        assert godaddy["last_seen"] == "2019-07-20"

        # Registrants: same person with different email casing is one entry.
        assert len(result["registrants"]) == 2
        assert result["registrants"][0]["email"] == "xyz@withheldforprivacy.com"
        owner = result["registrants"][1]
        assert owner["name"] == "John Doe"
        assert owner["company"] == "Doe Corp"
        assert owner["first_seen"] == "2016-02-03"
        assert owner["last_seen"] == "2019-07-20"
        assert result["registrant_emails"] == [
            "john.doe@doecorp.example",
            "xyz@withheldforprivacy.com",
        ]

    @responses.activate
    def test_url_observable_uses_registered_domain(self, engine, history_private_only):
        responses.add(responses.GET, HISTORY_URL, json=history_private_only, status=200)
        observable = Observable(
            value="https://login.sub.example.co.uk:8443/path?q=1", type=ObservableType.URL
        )

        result = engine.analyze(observable)

        params = parse_qs(urlparse(responses.calls[0].request.url).query)
        assert params["domainName"] == ["example.co.uk"]
        assert result["domain"] == "example.co.uk"

    @responses.activate
    def test_empty_history(self, engine, fqdn_observable):
        responses.add(
            responses.GET,
            HISTORY_URL,
            json={"total_Result": 0, "whois_domains_historical": []},
            status=200,
        )

        result = engine.analyze(fqdn_observable)

        assert result["history_records"] == 0
        assert result["registrars"] == []
        assert result["registrants"] == []
        assert result["first_record"] == ""
        assert result["reverse_whois"] is None

    @responses.activate
    def test_not_found_is_empty_result(self, engine, fqdn_observable):
        responses.add(
            responses.GET,
            HISTORY_URL,
            json={"status": False, "error": "No record found"},
            status=404,
        )

        result = engine.analyze(fqdn_observable)

        assert result is not None
        assert result["history_records"] == 0
        assert len(responses.calls) == 1

    def test_unsupported_types_return_none(self, engine):
        for value, obs_type in [
            ("1.1.1.1", ObservableType.IPV4),
            ("user@example.com", ObservableType.EMAIL),
            ("d41d8cd98f00b204e9800998ecf8427e", ObservableType.MD5),
        ]:
            assert engine.analyze(Observable(value=value, type=obs_type)) is None


class TestReverseWhois:
    @responses.activate
    def test_reverse_lookup_on_real_email(
        self, engine, fqdn_observable, history_with_owner, reverse_response
    ):
        responses.add(responses.GET, HISTORY_URL, json=history_with_owner, status=200)
        responses.add(responses.GET, REVERSE_URL, json=reverse_response, status=200)

        result = engine.analyze(fqdn_observable)

        params = parse_qs(urlparse(responses.calls[1].request.url).query)
        assert params["whois"] == ["reverse"]
        assert params["email"] == ["john.doe@doecorp.example"]
        assert params["mode"] == ["mini"]
        assert params["exact"] == ["true"]

        reverse = result["reverse_whois"]
        assert reverse["pivot_email"] == "john.doe@doecorp.example"
        assert reverse["total_domains"] == 3
        # The analyzed domain is not listed again; names are lowercased.
        assert reverse["domains"] == ["doecorp-shop.example", "doecorp-login.example"]

    @responses.activate
    def test_reverse_domains_capped(self, engine, fqdn_observable, history_with_owner):
        many = {
            "total_Result": 250,
            "whois_domains_historical": [{"domain_name": f"d{i}.example"} for i in range(100)],
        }
        responses.add(responses.GET, HISTORY_URL, json=history_with_owner, status=200)
        responses.add(responses.GET, REVERSE_URL, json=many, status=200)

        reverse = engine.analyze(fqdn_observable)["reverse_whois"]

        assert reverse["total_domains"] == 250
        assert len(reverse["domains"]) == 20

    @responses.activate
    def test_reverse_error_keeps_history(self, engine, fqdn_observable, history_with_owner):
        responses.add(responses.GET, HISTORY_URL, json=history_with_owner, status=200)
        responses.add(
            responses.GET, REVERSE_URL, json={"error": "Insufficient credits"}, status=402
        )

        result = engine.analyze(fqdn_observable)

        assert result is not None
        assert result["history_records"] == 3
        assert result["reverse_whois"] is None


class TestErrors:
    @responses.activate
    def test_unauthorized_returns_none(self, engine, fqdn_observable):
        responses.add(responses.GET, HISTORY_URL, json={"error": "Invalid API key"}, status=401)
        assert engine.analyze(fqdn_observable) is None

    @responses.activate
    def test_server_error_returns_none(self, engine, fqdn_observable):
        responses.add(responses.GET, HISTORY_URL, status=500)
        assert engine.analyze(fqdn_observable) is None

    @responses.activate
    def test_invalid_json_returns_none(self, engine, fqdn_observable):
        responses.add(responses.GET, HISTORY_URL, body="<html>oops</html>", status=200)
        assert engine.analyze(fqdn_observable) is None

    @responses.activate
    def test_network_error_does_not_log_api_key(self, engine, fqdn_observable, caplog):
        responses.add(
            responses.GET,
            HISTORY_URL,
            body=requests.exceptions.ConnectionError(f"failed {HISTORY_URL}?apiKey={API_KEY}"),
        )

        with caplog.at_level(logging.DEBUG):
            assert engine.analyze(fqdn_observable) is None

        assert API_KEY not in caplog.text

    @responses.activate
    def test_http_error_does_not_log_api_key(self, engine, fqdn_observable, caplog):
        responses.add(responses.GET, HISTORY_URL, status=403)

        with caplog.at_level(logging.DEBUG):
            assert engine.analyze(fqdn_observable) is None

        assert API_KEY not in caplog.text


class TestExport:
    @responses.activate
    def test_export_row_complete(
        self, engine, fqdn_observable, history_with_owner, reverse_response
    ):
        responses.add(responses.GET, HISTORY_URL, json=history_with_owner, status=200)
        responses.add(responses.GET, REVERSE_URL, json=reverse_response, status=200)

        row = engine.create_export_row(engine.analyze(fqdn_observable))

        assert row["whoisfreaks_history_records"] == 3
        assert row["whoisfreaks_earliest_creation"] == "2015-03-01"
        assert row["whoisfreaks_registrars"] == "NameCheap, Inc., GoDaddy.com, LLC"
        assert row["whoisfreaks_reverse_pivot"] == "john.doe@doecorp.example"
        assert row["whoisfreaks_reverse_total"] == 3
        assert row["whoisfreaks_reverse_domains"] == "doecorp-shop.example, doecorp-login.example"

    def test_export_row_none_input(self, engine):
        row = engine.create_export_row(None)
        assert row
        assert all(value is None for value in row.values())
        assert all(key.startswith("whoisfreaks_") for key in row)


class TestRealWorldData:
    """Shapes seen in live WhoisFreaks responses (e.g. google.com history)."""

    @responses.activate
    def test_redacted_placeholders_are_ignored(self, engine, fqdn_observable):
        record = _record("2025-01-01 00:00:00", "MarkMonitor Inc")
        record["registrant_contact"] = {
            "name": "REDACTED REGISTRANT",
            "company": "REDACTED FOR PRIVACY",
            "email_address": "Select Request Email Form at https://domains.markmonitor.com/whois/example.com",
            "country_name": "United States",
        }
        responses.add(
            responses.GET,
            HISTORY_URL,
            json={"total_records": "1", "whois_domains_historical": [record]},
            status=200,
        )

        result = engine.analyze(fqdn_observable)

        assert result["history_records"] == 1
        assert result["registrants"] == []
        assert result["registrant_emails"] == []
        assert result["reverse_whois"] is None
        assert len(responses.calls) == 1

    @responses.activate
    def test_registrar_spellings_are_merged(self, engine, fqdn_observable):
        records = [
            _record("2020-03-30 21:10:18", "markmonitor inc"),
            _record("2022-06-01 10:00:00", "MarkMonitor, Inc"),
            _record("2026-11-10 11:22:08", "MarkMonitor Inc."),
        ]
        responses.add(
            responses.GET,
            HISTORY_URL,
            json={"total_records": "3", "whois_domains_historical": records},
            status=200,
        )

        registrars = engine.analyze(fqdn_observable)["registrars"]

        assert registrars == [
            {"name": "MarkMonitor Inc.", "first_seen": "2020-03-30", "last_seen": "2026-11-10"}
        ]

    @responses.activate
    def test_undated_records_do_not_break_dates(self, engine, fqdn_observable):
        undated = _record(
            None,
            "MarkMonitor Inc",
            name="Dns Admin",
            company="Google Inc",
            email="dns-admin@example.com",
            create_date="1997-09-15",
        )
        dated = _record("2020-03-30 21:10:18", "MarkMonitor Inc", company="Example LLC")
        responses.add(
            responses.GET,
            HISTORY_URL,
            json={"total_records": "2", "whois_domains_historical": [dated, undated]},
            status=200,
        )
        responses.add(responses.GET, REVERSE_URL, json={"total_records": "0"}, status=200)

        result = engine.analyze(fqdn_observable)

        assert result["first_record"] == "2020-03-30"
        assert result["last_record"] == "2020-03-30"
        assert result["earliest_creation_date"] == "1997-09-15"
        assert result["registrars"][0]["first_seen"] == "2020-03-30"
        # The dated registrant is listed first; the undated one has no dates.
        assert result["registrants"][0]["company"] == "Example LLC"
        assert result["registrants"][1]["email"] == "dns-admin@example.com"
        assert result["registrants"][1]["first_seen"] == ""
        # The real email in the undated record is still used for the reverse WHOIS pivot.
        assert result["reverse_whois"]["pivot_email"] == "dns-admin@example.com"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("Google LLC", "Google LLC"),
            ("  Doe Corp  ", "Doe Corp"),
            ("REDACTED FOR PRIVACY", ""),
            ("REDACTED REGISTRANT", ""),
            ("Data has been removed by Whoisfreaks.com due to GDPR Compliance", ""),
            ("Not Disclosed", ""),
            (None, ""),
        ],
    )
    def test_clean_placeholders(self, engine, value, expected):
        assert engine._clean(value) == expected

    @pytest.mark.parametrize(
        ("email", "usable"),
        [
            ("john.doe@doecorp.example", True),
            ("abc123@withheldforprivacy.com", False),
            ("contact@domainsbyproxy.com", False),
            ("redacted@redacted.example", False),
            ("abuse@registrar.example", False),
            ("Select Request Email Form at https://x.example", False),
            ("", False),
        ],
    )
    def test_is_usable_email(self, engine, email, usable):
        assert engine._is_usable_email(engine._clean_email(email)) is usable


class FakeClock:
    """Stands in for time.monotonic / time.sleep so rate-limit waits are instant."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def fake_clock(monkeypatch):
    import engines.whoisfreaks as module

    clock = FakeClock()
    monkeypatch.setattr(module.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(module.time, "sleep", clock.sleep)
    monkeypatch.setattr(WhoisFreaksEngine, "_next_request_at", 0.0)
    return clock


def _limit_headers(remaining: str, reset_ns: str) -> dict[str, str]:
    return {
        "X-RateLimit-Allowed-Requests": "1",
        "X-RateLimit-Remaining-Requests": remaining,
        "X-RateLimit-Remaining-Time": reset_ns,
    }


class TestRateLimit:
    @responses.activate
    def test_used_up_allowance_delays_the_reverse_lookup(
        self, engine, fqdn_observable, history_with_owner, reverse_response, fake_clock
    ):
        # Seen live: a 1-request-per-minute plan, allowance used by the history call.
        responses.add(
            responses.GET,
            HISTORY_URL,
            json=history_with_owner,
            status=200,
            headers=_limit_headers("0", "60000000000"),
        )
        responses.add(responses.GET, REVERSE_URL, json=reverse_response, status=200)

        result = engine.analyze(fqdn_observable)

        assert result["reverse_whois"]["total_domains"] == 3
        assert sum(fake_clock.slept) == pytest.approx(60.25)

    @responses.activate
    def test_remaining_allowance_does_not_wait(
        self, engine, fqdn_observable, history_with_owner, reverse_response, fake_clock
    ):
        responses.add(
            responses.GET,
            HISTORY_URL,
            json=history_with_owner,
            status=200,
            headers=_limit_headers("79", "30000000000"),
        )
        responses.add(responses.GET, REVERSE_URL, json=reverse_response, status=200)

        engine.analyze(fqdn_observable)

        assert fake_clock.slept == []

    @responses.activate
    def test_429_is_retried_once_after_the_reset_time(
        self, engine, fqdn_observable, history_private_only, fake_clock
    ):
        responses.add(
            responses.GET,
            HISTORY_URL,
            json={"status": 429, "error": "Too Many Requests"},
            status=429,
            headers=_limit_headers("0", "56573000000"),
        )
        responses.add(responses.GET, HISTORY_URL, json=history_private_only, status=200)

        result = engine.analyze(fqdn_observable)

        assert result["history_records"] == 2
        assert len(responses.calls) == 2
        assert fake_clock.now - 1000.0 == pytest.approx(56.823)

    @responses.activate
    def test_repeated_429_gives_up_without_logging_the_key(self, engine, fqdn_observable, caplog):
        for _ in range(2):
            responses.add(
                responses.GET,
                HISTORY_URL,
                json={"status": 429},
                status=429,
                headers=_limit_headers("0", "60000000000"),
            )

        with caplog.at_level(logging.DEBUG):
            assert engine.analyze(fqdn_observable) is None

        assert len(responses.calls) == 2
        assert API_KEY not in caplog.text
        assert "rate limit" in caplog.text.lower()

    @pytest.mark.parametrize(
        ("header", "expected"),
        [
            ("60000000000", 60.25),
            ("1500000000", 1.75),
            ("999000000000", 65.0),  # capped
            ("", 60.25),  # missing header: default wait
            ("soon", 60.25),
        ],
    )
    def test_reset_seconds(self, header, expected):
        import engines.whoisfreaks as module

        response = requests.Response()
        response.headers["X-RateLimit-Remaining-Time"] = header
        assert module._rate_limit_reset_seconds(response) == pytest.approx(expected)
