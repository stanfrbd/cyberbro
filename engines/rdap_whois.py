import logging
from typing import Any

import requests
import tldextract

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)


class RDAPWhoisEngine(BaseEngine):
    @property
    def name(self):
        return "rdap_whois"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.URL

    def analyze(
        self, observable_value: str, observable_type: ObservableType
    ) -> dict[str, Any] | None:
        match observable_type:
            case ObservableType.URL:
                domain_part = observable_value.split("/")[2].split(":")[0]
            case ObservableType.FQDN:
                domain_part = observable_value
            case _:
                return None

        try:
            ext = tldextract.extract(domain_part)
            domain = ext.top_domain_under_public_suffix
            if not domain:
                return None

            api_url = "https://whois.cyberbro.net/whois-proxy"
            response = requests.post(
                api_url,
                json={"domain": domain},
                headers={"User-Agent": "Cyberbro"},
                verify=self.ssl_verify,
                proxies=self.proxies,
                timeout=10,
            )
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                logger.warning(
                    "RDAP/Whois API error for '%s': %s - %s",
                    observable_value,
                    data.get("error"),
                    data.get("message"),
                )
                return None

            name_servers = [ns.lower() for ns in data.get("name_servers", []) if ns]

            return {
                "abuse_contact": data.get("abuse_contact", ""),
                "registrar": data.get("registrar", ""),
                "organization": data.get("registrant_org", ""),
                "registrant": data.get("registrant_name", ""),
                "registrant_email": data.get("registrant_email", ""),
                "emails": data.get("emails", []),
                "name_servers": name_servers,
                "creation_date": data.get("creation_date", ""),
                "expiration_date": data.get("expiration_date", ""),
                "update_date": data.get("updated_date", ""),
                "link": data.get("rdap_link") or data.get("registrar_url") or "",
                "data_source": data.get("data_source", ""),
                "registrant_country": data.get("registrant_country", ""),
            }

        except Exception as e:
            logger.error(
                "Error querying RDAP/Whois for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                f"rdap_whois_{k}": None
                for k in [
                    "abuse",
                    "registrar",
                    "org",
                    "registrant",
                    "registrant_email",
                    "emails",
                    "ns",
                    "creation",
                    "expiration",
                    "update",
                    "data_source",
                    "country",
                ]
            }

        return {
            "rdap_whois_abuse": analysis_result.get("abuse_contact"),
            "rdap_whois_registrar": analysis_result.get("registrar"),
            "rdap_whois_org": analysis_result.get("organization"),
            "rdap_whois_registrant": analysis_result.get("registrant"),
            "rdap_whois_registrant_email": analysis_result.get("registrant_email"),
            "rdap_whois_emails": ", ".join(analysis_result.get("emails", [])),
            "rdap_whois_ns": ", ".join(analysis_result.get("name_servers", [])),
            "rdap_whois_creation": analysis_result.get("creation_date"),
            "rdap_whois_expiration": analysis_result.get("expiration_date"),
            "rdap_whois_update": analysis_result.get("update_date"),
            "rdap_whois_data_source": analysis_result.get("data_source"),
            "rdap_whois_country": analysis_result.get("registrant_country"),
        }
