import logging
from urllib.parse import quote, urlsplit

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class AlienVaultPassiveDNSEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "alienvault_passive_dns"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.IPV4 | ObservableType.IPV6 | ObservableType.URL

    def _extract_domain(self, observable: Observable) -> str | None:
        if observable.type == ObservableType.FQDN:
            domain = observable.value.strip().lower().rstrip(".")
            return domain or None

        if observable.type == ObservableType.URL:
            host = urlsplit(observable.value).hostname
            if host:
                return host.strip().lower().rstrip(".")

        return None

    def _resolve_indicator_path(self, observable: Observable) -> tuple[str, str] | None:
        if observable.type == ObservableType.IPV4:
            value = observable.value.strip()
            return ("IPv4", value) if value else None

        if observable.type == ObservableType.IPV6:
            value = observable.value.strip()
            return ("IPv6", value) if value else None

        domain = self._extract_domain(observable)
        if domain:
            return ("domain", domain)

        return None

    def _sanitize_record(self, record: dict[str, object]) -> dict[str, str | None]:
        return {
            "hostname": self._to_clean_str(record.get("hostname")),
            "address": self._to_clean_str(record.get("address")),
            "record_type": self._to_clean_str(record.get("record_type")),
            "first": self._to_clean_str(record.get("first")),
            "last": self._to_clean_str(record.get("last")),
            "asn": self._to_clean_str(record.get("asn")),
            "country": self._to_clean_str(record.get("flag_title")),
        }

    @staticmethod
    def _to_clean_str(value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None

    def analyze(self, observable: Observable) -> dict[str, object] | None:
        api_key = self.secrets.alienvault
        if not api_key:
            logger.error("OTX AlienVault API key is required for passive DNS")
            return None

        indicator_path = self._resolve_indicator_path(observable)
        if not indicator_path:
            logger.warning(
                "Could not resolve passive DNS indicator from observable '%s'", observable.value
            )
            return None

        indicator_type, indicator_value = indicator_path

        url = (
            f"https://otx.alienvault.com/api/v1/indicators/"
            f"{indicator_type}/{quote(indicator_value)}/passive_dns"
        )
        headers = {"X-OTX-API-KEY": api_key}
        gui_indicator_type = "ip" if indicator_type in {"IPv4", "IPv6"} else "domain"
        link = f"https://otx.alienvault.com/indicator/{gui_indicator_type}/{quote(indicator_value)}"

        try:
            response = requests.get(
                url,
                headers=headers,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=30,
            )
            response.raise_for_status()
        except requests.exceptions.Timeout:
            logger.error("Timeout while querying AlienVault passive DNS for '%s'", indicator_value)
            return {
                "count": 0,
                "top_records": [],
                "passive_dns": [],
                "error": "timeout",
                "link": link,
            }
        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            logger.error(
                "AlienVault passive DNS returned HTTP %s for '%s'",
                status_code,
                indicator_value,
                exc_info=True,
            )
            return {
                "count": 0,
                "top_records": [],
                "passive_dns": [],
                "error": f"http_{status_code}",
                "link": link,
            }
        except requests.exceptions.RequestException:
            logger.error(
                "Network error while querying AlienVault passive DNS for '%s'",
                indicator_value,
                exc_info=True,
            )
            return {
                "count": 0,
                "top_records": [],
                "passive_dns": [],
                "error": "network_error",
                "link": link,
            }

        try:
            payload = response.json()
        except ValueError:
            logger.error(
                "Invalid JSON while querying AlienVault passive DNS for '%s'", indicator_value
            )
            return {
                "count": 0,
                "top_records": [],
                "passive_dns": [],
                "error": "invalid_json",
                "link": link,
            }

        raw_records = payload.get("passive_dns")
        if raw_records is None:
            raw_records = []

        if not isinstance(raw_records, list):
            logger.error("Unexpected passive_dns format from AlienVault for '%s'", indicator_value)
            return {
                "count": 0,
                "top_records": [],
                "passive_dns": [],
                "error": "invalid_payload",
                "link": link,
            }

        normalized_records: list[dict[str, str | None]] = []
        for entry in raw_records:
            if isinstance(entry, dict):
                normalized_records.append(self._sanitize_record(entry))

        raw_count = payload.get("count")
        count = len(normalized_records)
        if isinstance(raw_count, int) and raw_count >= 0:
            count = raw_count

        return {
            "count": count,
            "top_records": normalized_records[:10],
            "passive_dns": normalized_records,
            "error": None,
            "link": link,
        }

    def create_export_row(
        self, analysis_result: dict[str, object] | None
    ) -> dict[str, str | int | None]:
        if not analysis_result:
            return {
                "alienvault_passive_dns_count": None,
                "alienvault_passive_dns_top10": None,
            }

        top_records = analysis_result.get("top_records", [])
        if not isinstance(top_records, list):
            top_records = []

        top_values: list[str] = []
        for record in top_records:
            if not isinstance(record, dict):
                continue

            hostname = self._to_clean_str(record.get("hostname"))
            address = self._to_clean_str(record.get("address"))
            if hostname and address:
                top_values.append(f"{hostname} ({address})")
            elif hostname:
                top_values.append(hostname)
            elif address:
                top_values.append(address)

        count_value = analysis_result.get("count")
        count = count_value if isinstance(count_value, int) else None

        return {
            "alienvault_passive_dns_count": count,
            "alienvault_passive_dns_top10": ", ".join(top_values) if top_values else None,
        }
