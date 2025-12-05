import logging
import urllib.parse
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]


def get_api_endpoint(observable: str, observable_type: str) -> str | None:
    # Map observable type to Reversing Labs Spectra Analyze endpoint
    endpoint_map = {
        "IPv4": f"/api/network-threat-intel/ip/{observable}/report/",
        "IPv6": f"/api/network-threat-intel/ip/{observable}/report/",
        "FQDN": f"/api/network-threat-intel/domain/{observable}/",
        "URL": f"/api/network-threat-intel/url/?url={urllib.parse.quote_plus(observable)}",
        "MD5": f"/api/samples/v3/{observable}/classification/?av_scanners=1",
        "SHA1": f"/api/samples/v3/{observable}/classification/?av_scanners=1",
        "SHA256": f"/api/samples/v3/{observable}/classification/?av_scanners=1",
    }

    return endpoint_map.get(observable_type)


def get_ui_endpoint(observable: str, observable_type: str) -> str | None:
    # Map observable type to Reversing Labs Spectra Analyze endpoint
    endpoint_map = {
        "IPv4": f"/ip/{observable}/analysis/ip/",
        "IPv6": f"/ip/{observable}/analysis/ip/",
        "FQDN": f"/domain/{observable}/analysis/domain/",
        "URL": f"/url/{urllib.parse.quote_plus(observable)}/analysis/url/",
        "MD5": f"/{observable}/",
        "SHA1": f"/{observable}/",
        "SHA256": f"/{observable}/",
    }

    return endpoint_map.get(observable_type)


def query_rl_analyze(
    observable: str,
    observable_type: str,
    rl_analyze_api_key: str,
    rl_analyze_url: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries the Reversing Labs API for information about a given observable (IP, domain, URL, or file hash).

    Args:
        observable (str): The IoC to query (IPv4, IPv6, domain, URL, or file hash).
        observable_type (str): What type of IOC, (IPv4, IPv6, FQDN, MD5, SHA1, SHA256, URL)
        rl_analyze_api_key (str): Reversing Labs Spectra Analyze API key.
        rl_analyze_url (str): Reversing Labs Spectra Analyze url.
        proxies (dict): Dictionary of proxies.
        ssl_verify (bool): Whether to verify SSL certificates.

    Returns:
        dict: A dictionary with the results from the Reversing Labs lookup.
        Example for Hashes:
            {
                "report_type": file,
                "report_color": red
                "reports": 27,   # Total number of engines run against
                "malicious": 2,   # Number of malicious verdicts
                "suspicious": 1,  # Number of suspicious verdicts
                "threats": ['Web.Hyperlink.Blacklisted', 'malware_file'],
                "link": "https://rl_analyze_url/<hash>/
            }
        Example for URL:
            {
                "report_type": network,
                "report_color": red
                "reports": 27,   # Total number of engines run against
                "malicious": 2,   # Number of malicious verdicts
                "suspicious": 1,  # Number of suspicious verdicts
                "threats": ['Web.Hyperlink.Blacklisted', 'malware_file'],
                "link": "https://rl_analyze_url/url/http://example.com/get.php/analysis/url/
            }
       Example for IPv4, IPv6, FQDN:
            {
                "report_type": network,
                "report_color": yellow
                "reports": 27,   # Total number of engines run against
                "malicious": 2,   # Number of malicious verdicts
                "suspicious": 1,  # Number of suspicious verdicts
                "total_files": 23,
                "malicious_files": 2,
                "suspicious_files": 1,
                "threats": ['Web.Hyperlink.Blacklisted', 'malware_file'],
                "link": "https://rl_analyze_url/ip/1.2.3.4/analysis/ip/
             }
        None: If any error occurs.
    """

    endpoint = get_api_endpoint(observable, observable_type)

    try:
        url = f"{rl_analyze_url}{endpoint}"
        headers = {
            "Authorization": f"Token {rl_analyze_api_key}",
            "accept": "application/json",
        }

        response = requests.get(url, headers=headers, proxies=None, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        return parse_rl_response(data, observable, observable_type, rl_analyze_url)

    except Exception as e:
        logger.error("Error querying Reversing Labs for '%s': %s", observable, e, exc_info=True)

    return None


def parse_rl_response(result: dict, observable: str, observable_type: str, url: str):
    top_threats: list[str] = []
    if observable_type in ["IPv4", "IPv6", "FQDN"]:
        top_threats.extend([i.get("threat_name") for i in result.get("top_threats")])
        total_files: int = result["downloaded_files_statistics"]["total"]
        malicious_files: int = result["downloaded_files_statistics"]["malicious"]
        suspicious_files: int = result["downloaded_files_statistics"]["suspicious"]
        malicious: int = result["third_party_reputations"]["statistics"]["malicious"]
        suspicious: int = result["third_party_reputations"]["statistics"]["suspicious"]
        total: int = result["third_party_reputations"]["statistics"]["total"]

        if malicious > 2 or suspicious > 3:
            report_color = "red"
        elif malicious > 0 or suspicious > 0:
            report_color = "yellow"
        else:
            report_color = "green"

        if observable_type in ["IPv4", "IPv6"]:
            link: str = url + get_ui_endpoint(result["requested_ip"], observable_type)
        elif observable_type in ["FQDN"]:
            link: str = url + get_ui_endpoint(result["requested_domain"], observable_type)

        if total > 0:
            return {
                "report_type": "network",
                "report_color": report_color,
                "reports": total,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_files": total_files,
                "malicious_files": malicious_files,
                "suspicious_files": suspicious_files,
                "threats": top_threats,
                "link": link,
            }
    elif observable_type in ["URL"]:
        top_threats.append(result.get("threat_name"))
        if "categories" in result:
            top_threats.extend(result.get("categories"))

        malicious: int = result["third_party_reputations"]["statistics"]["malicious"]
        suspicious: int = result["third_party_reputations"]["statistics"]["suspicious"]
        total: int = result["third_party_reputations"]["statistics"]["total"]
        link: str = url + get_ui_endpoint(observable, observable_type)

        if malicious > 2 or suspicious > 3:
            report_color = "red"
        elif malicious > 0 or suspicious > 0:
            report_color = "yellow"
        else:
            report_color = "green"

        if total > 0:
            return {
                "report_type": "network",
                "report_color": report_color,
                "reports": total,
                "malicious": malicious,
                "suspicious": suspicious,
                "threats": top_threats,
                "link": link,
            }

    elif observable_type in ["MD5", "SHA1", "SHA256"]:
        top_threats.append(result.get("classification"))
        top_threats.append(result.get("classification_result"))
        top_threats.append(result.get("classificatio n_reason"))

        classification: str = result.get("classification")
        riskscore: int = result.get("riskscore")
        if classification == "malicious" and riskscore > 2:
            report_color = "red"
        elif classification != "goodware" or riskscore > 5:
            report_color = "yellow"
        else:
            report_color = "green"

        if "av_scanners" in result:
            total: int = result["av_scanners"]["scanner_count"]
            scanners = result["av_scanners"]["scanner_match"]
            link: str = url + get_ui_endpoint(observable, observable_type)

            return {
                "report_type": "file",
                "report_color": report_color,
                "reports": total,
                "scanners": scanners,
                "classification": classification.upper(),
                "riskscore": riskscore,
                "threats": top_threats,
                "link": link,
            }

    return {}
