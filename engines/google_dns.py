import logging
from typing import Any

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)

dns_record_types = [
    {"type": "A", "id": 1},
    {"type": "AAAA", "id": 28},
    {"type": "CNAME", "id": 5},
    {"type": "MX", "id": 15},
    {"type": "TXT", "id": 16},
    {"type": "PTR", "id": 12},
    {"type": "NS", "id": 2},
    {"type": "SOA", "id": 6},
]


class GoogleDNSEngine(BaseEngine):
    @property
    def name(self):
        return "google_dns"

    @property
    def supported_types(self):
        return ["FQDN", "IPv4", "IPv6", "URL"]

    def _extract_domain(self, observable: str) -> str:
        if "://" in observable:
            domain = observable.split("/")[2]
            if ":" in domain:
                domain = domain.split(":")[0]
            return domain
        return observable

    def _parse_dmarc_record(self, txt: str) -> dict:
        fields = {}
        for part in txt.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                fields[k.strip()] = v.strip()
        return fields

    def _parse_spf_record(self, txt: str) -> dict:
        fields = {}
        for part in txt.split():
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k.strip()] = v.strip()
            else:
                fields.setdefault("mechanisms", []).append(part)
        return fields

    def _query_dmarc(self, domain: str) -> dict[str, Any] | None:
        try:
            dmarc_domain = f"_dmarc.{domain}"
            url = f"https://dns.google/resolve?name={dmarc_domain}&type=TXT"
            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()
            data = response.json()

            for answer in data.get("Answer", []):
                txt = answer.get("data", "").replace('"', "").replace("; ", ";")
                if txt.strip().lower().startswith("v=dmarc1"):
                    return {"type_name": "DMARC", "present": True, "data": txt}
            return {"type_name": "DMARC", "present": False}
        except Exception as e:
            logger.error("Error querying DMARC for '%s': %s", domain, e, exc_info=True)
            return None

    def _query_spf(self, domain: str) -> dict[str, Any] | None:
        try:
            url = f"https://dns.google/resolve?name={domain}&type=TXT"
            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()
            data = response.json()

            for answer in data.get("Answer", []):
                txt = answer.get("data", "").replace('"', "")
                if txt.strip().lower().startswith("v=spf"):
                    return {"type_name": "SPF", "present": True, "data": txt}
            return {"type_name": "SPF", "present": False}
        except Exception as e:
            logger.error("Error querying SPF for '%s': %s", domain, e, exc_info=True)
            return None

    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        try:
            if observable_type in ["IPv4", "IPv6"]:
                reverse_name = f"{observable_value}.in-addr.arpa"
                url = f"https://dns.google/resolve?name={reverse_name}&type=PTR"
                response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify)
                response.raise_for_status()
                data = response.json()
                for answer in data.get("Answer", []):
                    answer["type_name"] = next(
                        (
                            record["type"]
                            for record in dns_record_types
                            if record["id"] == answer["type"]
                        ),
                        "Unknown",
                    )
                return data

            domain = self._extract_domain(observable_value)
            all_records = []

            # Query all standard records
            for record in dns_record_types:
                url = f"https://dns.google/resolve?name={domain}&type={record['id']}"
                response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify)
                response.raise_for_status()
                data = response.json()
                for answer in data.get("Answer", []):
                    answer["type_name"] = record["type"]
                    if answer["type_name"] == "TXT" and "spf" in answer["data"].lower():
                        continue
                    answer["data"] = answer["data"].rstrip(".")
                    if answer["type_name"] == "MX":
                        answer["data"] = answer["data"].strip().split(" ")[-1]
                    all_records.append(answer)

            # Parse SPF and DMARC
            spf_result = self._query_spf(domain)
            dmarc_result = self._query_dmarc(domain)

            if spf_result and spf_result.get("present"):
                all_records.append({"type_name": "SPF", "data": spf_result["data"]})
            if dmarc_result and dmarc_result.get("present"):
                all_records.append({"type_name": "DMARC", "data": dmarc_result["data"]})

            return {"Answer": all_records}

        except Exception as e:
            logger.error(
                "Error querying Google DNS for '%s': %s", observable_value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        row = {}
        if not analysis_result or "Answer" not in analysis_result:
            return {
                f"google_dns_{t['type'].lower()}": None
                for t in dns_record_types
                if t["type"] not in ["PTR"]
            }

        answers = analysis_result["Answer"]
        dns_records = {}

        for answer in answers:
            type_name = answer.get("type_name", "").lower()
            if type_name in ["spf", "dmarc"]:
                continue  # Skip SPF/DMARC as they were not in the original export

            # Use A/AAAA/etc keys from the original export logic
            if type_name.upper() in [t["type"] for t in dns_record_types]:
                dns_records.setdefault(type_name, []).append(answer.get("data"))

        # Add records from the original export list, only flattening if they were queried
        for record in dns_record_types:
            type_name = record["type"].lower()
            key = f"google_dns_{type_name}"
            row[key] = (
                ", ".join(dns_records.get(type_name, [])) if type_name in dns_records else None
            )

        return row
