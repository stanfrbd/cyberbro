import logging
from typing import Any, Optional

import requests
import tldextract

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class RDAPEngine(BaseEngine):
    @property
    def name(self):
        return "rdap"

    @property
    def supported_types(self):
        return ["FQDN", "URL"]

    def _extract_vcard_field(self, entity: dict[str, Any], field: str) -> str:
        """
        Helper to extract a specific field (e.g., 'email', 'fn', 'org') from
        an entity's 'vcardArray' if present.
        """
        vcard_array = entity.get("vcardArray", [])
        if len(vcard_array) < 2:
            return ""

        for item in vcard_array[1]:
            if len(item) == 4 and item[0] == field and item[3]:
                return item[3]
        return ""

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict[str, Any]]:
        try:
            if observable_type == "URL":
                domain_part = observable_value.split("/")[2].split(":")[0]
            elif observable_type == "FQDN":
                domain_part = observable_value
            else:
                return None

            ext = tldextract.extract(domain_part)
            domain = ext.registered_domain
            if not domain:
                return None

            api_url = f"https://rdap.net/domain/{domain}"
            response = requests.get(api_url, verify=self.ssl_verify, proxies=self.proxies, timeout=5)
            response.raise_for_status()

            data = response.json()

            result = {
                "abuse_contact": "",
                "registrar": "",
                "organization": "",
                "registrant": "",
                "registrant_email": "",
                "name_servers": [],
                "creation_date": "",
                "expiration_date": "",
                "update_date": "",
                "link": "",
            }

            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "abuse" in roles:
                    result["abuse_contact"] = self._extract_vcard_field(entity, "email") or result["abuse_contact"]
                if "registrar" in roles:
                    result["registrar"] = self._extract_vcard_field(entity, "fn") or result["registrar"]
                if "registrant" in roles:
                    result["registrant"] = self._extract_vcard_field(entity, "fn") or result["registrant"]
                    result["registrant_email"] = self._extract_vcard_field(entity, "email") or result["registrant_email"]
                    result["organization"] = self._extract_vcard_field(entity, "org") or result["organization"]

                for sub_entity in entity.get("entities", []):
                    if "abuse" in sub_entity.get("roles", []):
                        result["abuse_contact"] = self._extract_vcard_field(sub_entity, "email") or result["abuse_contact"]

            for ns in data.get("nameservers", []):
                ns_name = ns.get("ldhName")
                if ns_name:
                    result["name_servers"].append(ns_name.lower())

            for event in data.get("events", []):
                action = event.get("eventAction")
                date_str = event.get("eventDate", "").split("T")[0] if event.get("eventDate") and "T" in event.get("eventDate") else event.get("eventDate", "")
                if action == "registration":
                    result["creation_date"] = date_str
                elif action == "expiration":
                    result["expiration_date"] = date_str
                elif action == "last changed":
                    result["update_date"] = date_str

            for el in data.get("links", []):
                if el.get("rel") == "self":
                    result["link"] = el.get("href", "")

            return result

        except Exception as e:
            logger.error("Error querying RDAP for '%s': %s", observable_value, e, exc_info=True)
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                f"rdap_{k}": None
                for k in [
                    "abuse",
                    "registrar",
                    "org",
                    "registrant",
                    "registrant_email",
                    "ns",
                    "creation",
                    "expiration",
                    "update",
                ]
            }

        return {
            "rdap_abuse": analysis_result.get("abuse_contact"),
            "rdap_registrar": analysis_result.get("registrar"),
            "rdap_org": analysis_result.get("organization"),
            "rdap_registrant": analysis_result.get("registrant"),
            "rdap_registrant_email": analysis_result.get("registrant_email"),
            "rdap_ns": ", ".join(analysis_result.get("name_servers", [])),
            "rdap_creation": analysis_result.get("creation_date"),
            "rdap_expiration": analysis_result.get("expiration_date"),
            "rdap_update": analysis_result.get("update_date"),
        }
