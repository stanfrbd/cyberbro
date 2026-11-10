import logging
import re
import threading
import time
from typing import Any, ClassVar

import requests
import tldextract
from requests.exceptions import HTTPError, RequestException
from tenacity import RetryCallState, retry, retry_if_exception, stop_after_attempt
from typing_extensions import override

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)

API_BASE = "https://api.whoisfreaks.com/v2.0/whois"

MAX_CONTACTS = 10
MAX_REVERSE_DOMAINS = 20

# Substrings that mark a privacy / proxy / redacted registrant email.
# A reverse WHOIS on such an address returns unrelated domains, so the pivot is skipped.
PRIVACY_EMAIL_MARKERS = (
    "privacy",
    "private",
    "redacted",
    "proxy",
    "whoisguard",
    "protect",
    "withheld",
    "anonym",
    "masked",
    "gdpr",
    "contactprivacy",
    "domainsbyproxy",
    "abuse",
)

# WHOIS placeholder values that carry no information (GDPR redaction and similar).
REDACTED_VALUE_MARKERS = (
    "redacted",
    "not disclosed",
    "data protected",
    "statutory masking",
    "data has been removed",
    "gdpr compliance",
)


# WhoisFreaks limits requests per minute per plan (the smallest plans allow one).
# Every response says how many requests are left and when the window resets, so
# once the allowance is used up, requests wait for the reset instead of failing.
# A 429 is still retried once after the wait the API gives, up to this cap.
MAX_RATE_LIMIT_WAIT = 65.0  # seconds
DEFAULT_RATE_LIMIT_WAIT = 60.0  # when the reset header is missing or not a number
RATE_LIMIT_BUFFER = 0.25  # seconds added to the reset time, as the API docs advise


class WhoisFreaksAPIError(Exception):
    """Raised when the WhoisFreaks API call fails. The message never contains the API key."""


def _rate_limit_reset_seconds(response: requests.Response | None) -> float:
    """Seconds until the per-minute allowance resets (header value is in nanoseconds)."""
    header = response.headers.get("X-RateLimit-Remaining-Time", "") if response is not None else ""
    try:
        seconds = int(header.strip()) / 1_000_000_000
    except ValueError:
        seconds = DEFAULT_RATE_LIMIT_WAIT
    return min(max(seconds, 0.0) + RATE_LIMIT_BUFFER, MAX_RATE_LIMIT_WAIT)


def _is_rate_limited(exception: BaseException) -> bool:
    return (
        isinstance(exception, HTTPError)
        and exception.response is not None
        and exception.response.status_code == 429
    )


def _rate_limit_wait(retry_state: RetryCallState) -> float:
    """Seconds to wait before retrying a 429, from the API's reset header.

    The limit is per account, so the wait also holds back every other lookup in
    this process rather than letting them spend their own retry on it.
    """
    exception = retry_state.outcome.exception() if retry_state.outcome else None
    response = exception.response if isinstance(exception, HTTPError) else None
    seconds = _rate_limit_reset_seconds(response)
    WhoisFreaksEngine.hold_requests_for(seconds)
    logger.warning("WhoisFreaks rate limit reached, retrying in %.0f s", seconds)
    return seconds


class WhoisFreaksEngine(BaseEngine):
    """WHOIS history for a domain, and a reverse WHOIS pivot on a past registrant email."""

    # Shared by every thread in the process, because the rate limit is per account.
    _throttle_lock: ClassVar[threading.Lock] = threading.Lock()
    _next_request_at: ClassVar[float] = 0.0

    @property
    @override
    def name(self) -> str:
        return "whoisfreaks"

    @property
    @override
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.URL

    def _extract_domain(self, observable: Observable) -> str | None:
        match observable.type:
            case ObservableType.URL:
                domain_part = observable.value.split("/")[2].split(":")[0]
            case ObservableType.FQDN:
                domain_part = observable.value
            case _:
                return None

        domain = tldextract.extract(domain_part).top_domain_under_public_suffix
        return domain.lower() if domain else None

    @classmethod
    def wait_for_slot(cls) -> None:
        """Wait until this process may start its next WhoisFreaks request.

        Recheck the shared deadline after every sleep: another thread may have
        been told to slow down while this caller was waiting.
        """
        while True:
            with cls._throttle_lock:
                delay = cls._next_request_at - time.monotonic()
                if delay <= 0:
                    return
            time.sleep(delay)

    @classmethod
    def hold_requests_for(cls, seconds: float) -> None:
        """Start no new WhoisFreaks request in this process for the next `seconds`."""
        with cls._throttle_lock:
            cls._next_request_at = max(cls._next_request_at, time.monotonic() + seconds)

    @classmethod
    def _respect_rate_limit(cls, response: requests.Response) -> None:
        """When the per-minute allowance is used up, hold requests until it resets."""
        if response.headers.get("X-RateLimit-Remaining-Requests", "").strip() == "0":
            seconds = _rate_limit_reset_seconds(response)
            cls.hold_requests_for(seconds)
            logger.info("WhoisFreaks per-minute limit used up, next request in %.0f s", seconds)

    @retry(
        retry=retry_if_exception(_is_rate_limited),
        wait=_rate_limit_wait,
        stop=stop_after_attempt(2),
        reraise=True,
    )
    def _request(self, endpoint: str, params: dict[str, str]) -> requests.Response:
        """One throttled GET. A 429 is raised so that it is retried once."""
        self.wait_for_slot()
        response = requests.get(
            f"{API_BASE}/{endpoint}",
            params=params,
            proxies=self.proxies,
            verify=self.ssl_verify,
            timeout=15,
        )
        self._respect_rate_limit(response)
        if response.status_code == 429:
            response.raise_for_status()
        return response

    def _get(self, endpoint: str, params: dict[str, str]) -> dict[str, Any]:
        """GET a WhoisFreaks endpoint.

        The API key travels as a query parameter, so request errors are re-raised
        with a sanitized message to keep the key out of the logs.
        """
        try:
            response = self._request(endpoint, params)
        except HTTPError as e:
            status = e.response.status_code if e.response is not None else "unknown"
            raise WhoisFreaksAPIError(f"{endpoint} returned HTTP {status}") from None
        except RequestException as e:
            raise WhoisFreaksAPIError(f"{endpoint} request failed ({type(e).__name__})") from None

        if response.status_code == 404:
            # WhoisFreaks answers 404 when it has no record for the query.
            return {}
        if not response.ok:
            raise WhoisFreaksAPIError(f"{endpoint} returned HTTP {response.status_code}")

        try:
            data = response.json()
        except ValueError:
            raise WhoisFreaksAPIError(f"{endpoint} returned a non-JSON body") from None
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _date(value: Any) -> str:
        """Keep only the YYYY-MM-DD part of a WhoisFreaks date or timestamp."""
        return str(value).split(" ")[0].split("T")[0] if value else ""

    @staticmethod
    def _clean(value: Any) -> str:
        """Return the stripped value, or "" for redaction placeholders."""
        text = str(value or "").strip()
        lowered = text.lower()
        return "" if any(marker in lowered for marker in REDACTED_VALUE_MARKERS) else text

    @classmethod
    def _clean_email(cls, value: Any) -> str:
        """Lowercased email, or "" for placeholders such as "Select Request Email Form at ..."."""
        email = cls._clean(value).lower()
        return email if "@" in email and " " not in email else ""

    @staticmethod
    def _registrar_key(name: str) -> str:
        """Group spellings like "MarkMonitor, Inc." and "markmonitor inc" together."""
        return re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()

    @staticmethod
    def _is_usable_email(email: str) -> bool:
        if not email or "@" not in email:
            return False
        lowered = email.lower()
        return not any(marker in lowered for marker in PRIVACY_EMAIL_MARKERS)

    def _parse_history(self, domain: str, data: dict[str, Any]) -> dict[str, Any]:
        records = data.get("whois_domains_historical") or []
        records = [r for r in records if isinstance(r, dict)]
        # Oldest first, so first_seen / last_seen are easy to track.
        records.sort(key=lambda r: str(r.get("query_time") or ""))

        registrars: dict[str, dict[str, str]] = {}
        registrants: dict[tuple[str, str, str], dict[str, str]] = {}
        creation_dates: list[str] = []

        for record in records:
            seen = self._date(record.get("query_time"))
            create_date = self._date(record.get("create_date"))
            if create_date:
                creation_dates.append(create_date)

            registrar_name = self._clean(
                (record.get("domain_registrar") or {}).get("registrar_name")
            )
            if registrar_name:
                entry = registrars.setdefault(
                    self._registrar_key(registrar_name),
                    {"name": registrar_name, "first_seen": seen, "last_seen": seen},
                )
                # Records are oldest first, so this keeps the most recent spelling.
                entry["name"] = registrar_name
                entry["first_seen"] = entry["first_seen"] or seen
                entry["last_seen"] = seen or entry["last_seen"]

            contact = record.get("registrant_contact") or {}
            name = self._clean(contact.get("name"))
            company = self._clean(contact.get("company"))
            # Lowercased so the same mailbox is one entry and matches the reverse WHOIS pivot.
            email = self._clean_email(contact.get("email_address"))
            if not (name or company or email):
                continue
            key = (name.lower(), company.lower(), email)
            entry = registrants.setdefault(
                key,
                {
                    "name": name,
                    "company": company,
                    "email": email,
                    "country": self._clean(
                        contact.get("country_name") or contact.get("country_code")
                    ),
                    "first_seen": seen,
                    "last_seen": seen,
                },
            )
            entry["first_seen"] = entry["first_seen"] or seen
            entry["last_seen"] = seen or entry["last_seen"]

        # Most recent first, capped, for display.
        registrar_list = sorted(registrars.values(), key=lambda r: r["last_seen"], reverse=True)
        registrant_list = sorted(registrants.values(), key=lambda r: r["last_seen"], reverse=True)

        total = data.get("total_records") or data.get("total_Result") or len(records)
        try:
            total = int(total)
        except (TypeError, ValueError):
            total = len(records)

        # Some old records have no query_time; they are kept but not used for the date span.
        seen_dates = [d for d in (self._date(r.get("query_time")) for r in records) if d]

        return {
            "domain": domain,
            "history_records": total,
            "first_record": seen_dates[0] if seen_dates else "",
            "last_record": seen_dates[-1] if seen_dates else "",
            "earliest_creation_date": min(creation_dates) if creation_dates else "",
            "registrars": registrar_list[:MAX_CONTACTS],
            "registrants": registrant_list[:MAX_CONTACTS],
            "registrant_emails": sorted({r["email"] for r in registrant_list if r["email"]}),
            "reverse_whois": None,
            "link": f"https://whoisfreaks.com/tools/whois/history/lookup/{domain}",
        }

    def _pick_pivot_email(self, registrants: list[dict[str, str]]) -> str | None:
        """Most recent registrant email that is not a privacy or redacted address."""
        for registrant in registrants:
            if self._is_usable_email(registrant.get("email", "")):
                return registrant["email"].lower()
        return None

    def _parse_reverse(self, domain: str, email: str, data: dict[str, Any]) -> dict[str, Any]:
        records = data.get("whois_domains_historical") or data.get("whois_domains") or []
        other_domains: list[str] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            name = (record.get("domain_name") or "").strip().lower()
            if name and name != domain and name not in other_domains:
                other_domains.append(name)

        total = data.get("total_Result") or len(records)
        try:
            total = int(total)
        except (TypeError, ValueError):
            total = len(records)

        return {
            "pivot_email": email,
            "total_domains": total,
            "domains": other_domains[:MAX_REVERSE_DOMAINS],
        }

    @override
    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        api_key: str = self.secrets.whoisfreaks
        if not api_key:
            logger.warning("WhoisFreaks API key not set")
            return None

        domain = self._extract_domain(observable)
        if not domain:
            return None

        try:
            history = self._get(
                "history",
                {"apiKey": api_key, "whois": "historical", "domainName": domain},
            )
        except WhoisFreaksAPIError as e:
            logger.error("Error querying WhoisFreaks WHOIS history for '%s': %s", domain, e)
            return None

        result = self._parse_history(domain, history)

        # Reverse WHOIS costs more credits, so only pivot on a real registrant email.
        pivot_email = self._pick_pivot_email(result["registrants"])
        if pivot_email:
            try:
                reverse = self._get(
                    "reverse",
                    {
                        "apiKey": api_key,
                        "whois": "reverse",
                        "email": pivot_email,
                        "mode": "mini",
                        "exact": "true",
                    },
                )
                result["reverse_whois"] = self._parse_reverse(domain, pivot_email, reverse)
            except WhoisFreaksAPIError as e:
                logger.error("Error querying WhoisFreaks reverse WHOIS for '%s': %s", domain, e)

        return result

    @override
    def create_export_row(self, analysis_result: Any) -> dict[str, Any]:
        keys = [
            "history_records",
            "earliest_creation",
            "registrars",
            "registrant_emails",
            "reverse_pivot",
            "reverse_total",
            "reverse_domains",
        ]
        if not analysis_result:
            return {f"whoisfreaks_{k}": None for k in keys}

        reverse = analysis_result.get("reverse_whois") or {}
        return {
            "whoisfreaks_history_records": analysis_result.get("history_records"),
            "whoisfreaks_earliest_creation": analysis_result.get("earliest_creation_date"),
            "whoisfreaks_registrars": ", ".join(
                r["name"] for r in analysis_result.get("registrars", [])
            ),
            "whoisfreaks_registrant_emails": ", ".join(
                analysis_result.get("registrant_emails", [])
            ),
            "whoisfreaks_reverse_pivot": reverse.get("pivot_email"),
            "whoisfreaks_reverse_total": reverse.get("total_domains"),
            "whoisfreaks_reverse_domains": ", ".join(reverse.get("domains", [])),
        }
