import logging
from typing import Any, Optional
import requests

from utils.utils import identify_observable_type

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "URL",
]

dns_record_types = [
    {"type": "A", "id": 1},  # IPv4 address
    {"type": "AAAA", "id": 28},  # IPv6 address
    {"type": "CNAME", "id": 5},  # Canonical name
    {"type": "MX", "id": 15},  # Mail exchange
    {"type": "TXT", "id": 16},  # Text records (e.g., SPF, DKIM)
    {"type": "PTR", "id": 12},  # Reverse DNS
    {"type": "NS", "id": 2},  # Name server
    {"type": "SOA", "id": 6},  # Start of Authority
    # "SPF" and "DMARC" are logical types, not DNS types, so not included here
]

def extract_domain(observable: str) -> str:
    if "://" in observable:
        domain = observable.split("/")[2]
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain
    return observable

def parse_spf_record(txt: str) -> dict:
    fields = {}
    for part in txt.split():
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
        else:
            fields.setdefault("mechanisms", []).append(part)
    return fields

def parse_dmarc_record(txt: str) -> dict:
    fields = {}
    for part in txt.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            fields[k.strip()] = v.strip()
    return fields

def query_dmarc(
    observable: str,
    observable_type: str,
    proxies: Optional[dict[str, str]] = None,
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    try:
        domain = extract_domain(observable)
        dmarc_domain = f"_dmarc.{domain}"
        url = f"https://dns.google/resolve?name={dmarc_domain}&type=TXT"
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()

        for answer in data.get("Answer", []):
            txt = answer.get("data", "").replace('"', '').replace('; ', ';')
            if txt.strip().lower().startswith("v=dmarc1"):
                return {
                    "type_name": "DMARC",
                    "domain": domain,
                    "present": True,
                    "data": txt,
                    "parsed": parse_dmarc_record(txt),
                }
        return {
            "type_name": "DMARC",
            "domain": domain,
            "present": False,
            "data": None,
            "parsed": None,
            "message": "No DMARC record found.",
        }
    except Exception as e:
        logger.error("Error querying DMARC for '%s' (%s): %s", observable, observable_type, e, exc_info=True)
        return None

def query_spf(
    observable: str,
    observable_type: str,
    proxies: Optional[dict[str, str]] = None,
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    try:
        domain = extract_domain(observable)
        url = f"https://dns.google/resolve?name={domain}&type=TXT"
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()
        data = response.json()

        for answer in data.get("Answer", []):
            txt = answer.get("data", "").replace('"', '')
            if txt.strip().lower().startswith("v=spf"):
                return {
                    "type_name": "SPF",
                    "domain": domain,
                    "present": True,
                    "data": txt,
                    "parsed": parse_spf_record(txt),
                }
        return {
            "type_name": "SPF",
            "domain": domain,
            "present": False,
            "data": None,
            "parsed": None,
            "message": "No SPF record found.",
        }
    except Exception as e:
        logger.error("Error querying SPF for '%s' (%s): %s", observable, observable_type, e, exc_info=True)
        return None

def query_google_dns(
    observable: str, observable_type: str, proxies: Optional[dict[str, str]] = None, ssl_verify: bool = True
) -> Optional[dict[str, Any]]:
    try:
        if observable_type in ["IPv4", "IPv6"]:
            reverse_name = f"{observable}.in-addr.arpa"
            url = f"https://dns.google/resolve?name={reverse_name}&type=PTR"
            response = requests.get(url, proxies=proxies, verify=ssl_verify)
            response.raise_for_status()
            data = response.json()
            for answer in data.get("Answer", []):
                answer["type_name"] = next(
                    (record["type"] for record in dns_record_types if record["id"] == answer["type"]), "Unknown"
                )
            return data

        if observable_type == "FQDN":
            all_records = []
            for record in dns_record_types:
                url = f"https://dns.google/resolve?name={observable}&type={record['id']}"
                response = requests.get(url, proxies=proxies, verify=ssl_verify)
                response.raise_for_status()
                data = response.json()
                for answer in data.get("Answer", []):
                    answer["type_name"] = record["type"]
                    # ignore the TXT entry that contains SPF - it will be handled separately
                    if answer["type_name"] == "TXT" and "spf" in answer["data"].lower():
                        continue
                    # remove trailing "." from all data answers
                    answer["data"] = answer["data"].rstrip(".")
                    if answer["type_name"] == "MX":
                        answer["data"] = answer["data"].strip().split(" ")[-1]
                    all_records.append(answer)

            # Parse TXT records for SPF
            spf_result = query_spf(observable, observable_type, proxies, ssl_verify)
            dmarc_result = query_dmarc(observable, observable_type, proxies, ssl_verify)
            # Add SPF and DMARC as records for consistency
            if spf_result:
                all_records.append(spf_result)
            if dmarc_result:
                all_records.append(dmarc_result)
            return {"Answer": all_records}

        if observable_type == "URL":
            extracted = observable.split("/")[2]
            if ":" in extracted:
                extracted = extracted.split(":")[0]
            extracted_type = identify_observable_type(extracted)
            spf_result = query_spf(observable, observable_type, proxies, ssl_verify)
            dmarc_result = query_dmarc(observable, observable_type, proxies, ssl_verify)
            dns_result = query_google_dns(extracted, extracted_type, proxies, ssl_verify)
            if dns_result is None:
                dns_result = {"Answer": []}
            if spf_result:
                dns_result["Answer"].append(spf_result)
            if dmarc_result:
                dns_result["Answer"].append(dmarc_result)
            return dns_result

        logger.warning("Unsupported observable_type '%s' or no relevant logic found.", observable_type)
        return None

    except Exception as e:
        logger.error("Error querying Google DNS for '%s': %s", observable, e, exc_info=True)
        return None
