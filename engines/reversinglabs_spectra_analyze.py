import logging
import urllib.parse
from typing import Any, Optional

import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class RLAnalyzeEngine(BaseEngine):
    @property
    def name(self):
        return "rl_analyze"

    @property
    def supported_types(self):
        return ["FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]

    def _get_api_endpoint(self, observable: str, observable_type: str) -> str | None:
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

    def _get_ui_endpoint(self, observable: str, observable_type: str) -> str | None:
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

    def _parse_rl_response(self, result: dict, observable: str, observable_type: str, url: str) -> dict:
        threats: list[str] = []
        ui_link = url + self._get_ui_endpoint(observable, observable_type)

        if observable_type in ["IPv4", "IPv6", "FQDN"]:
            threats.extend([i.get("threat_name") for i in result.get("top_threats", [])])
            total_files: int = result.get("downloaded_files_statistics", {}).get("total", 0)
            malicious_files: int = result.get("downloaded_files_statistics", {}).get("malicious", 0)
            suspicious_files: int = result.get("downloaded_files_statistics", {}).get("suspicious", 0)

            reputation = result.get("third_party_reputations", {}).get("statistics", {})
            malicious: int = reputation.get("malicious", 0)
            suspicious: int = reputation.get("suspicious", 0)
            total: int = reputation.get("total", 0)

            report_color = "green"
            if malicious > 2 or suspicious > 3:
                report_color = "red"
            elif malicious > 0 or suspicious > 0:
                report_color = "yellow"

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
                    "threats": threats,
                    "link": ui_link,
                }

        elif observable_type in ["URL"]:
            threats.extend([i.get("threat_name") for i in result.get("analysis").get("top_threats", [])])
            threats.append(result.get("threat_name"))
            threats.extend(result.get("categories", []))

            reputation = result.get("third_party_reputations", {}).get("statistics", {})
            malicious: int = reputation.get("malicious", 0)
            suspicious: int = reputation.get("suspicious", 0)
            total: int = reputation.get("total", 0)

            report_color = "green"
            if malicious > 2 or suspicious > 3:
                report_color = "red"
            elif malicious > 0 or suspicious > 0:
                report_color = "yellow"

            if total > 0:
                return {
                    "report_type": "network",
                    "report_color": report_color,
                    "reports": total,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "threats": threats,
                    "link": ui_link,
                }

        elif observable_type in ["MD5", "SHA1", "SHA256"]:
            threats.append(result.get("classification"))
            threats.append(result.get("classification_result"))
            threats.append(result.get("classification_reason"))

            classification: str = result.get("classification", "")
            riskscore: int = result.get("riskscore", 0)

            report_color = "green"
            if classification == "malicious" and riskscore > 2:
                report_color = "red"
            elif classification != "goodware" or riskscore > 5:
                report_color = "yellow"

            av_scanners = result.get("av_scanners", {})
            if av_scanners:
                total: int = av_scanners.get("scanner_count", 0)
                scanners = av_scanners.get("scanner_match", 0)

                return {
                    "report_type": "file",
                    "report_color": report_color,
                    "reports": total,
                    "scanners": scanners,
                    "classification": classification.upper(),
                    "riskscore": riskscore,
                    "threats": threats,
                    "link": ui_link,
                }

        return {}

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict[str, Any]]:
        api_key = self.secrets.rl_analyze_api_key
        rl_analyze_url = self.secrets.rl_analyze_url

        endpoint = self._get_api_endpoint(observable_value, observable_type)
        if not endpoint:
            return None

        try:
            url = f"{rl_analyze_url}{endpoint}"
            headers = {
                "Authorization": f"Token {api_key}",
                "accept": "application/json",
            }

            # NOTE: Original implementation uses proxies=None
            response = requests.get(url, headers=headers, proxies=None, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            data = response.json()
            return self._parse_rl_response(data, observable_value, observable_type, rl_analyze_url)

        except Exception as e:
            logger.error("Error querying Reversing Labs for '%s': %s", observable_value, e, exc_info=True)
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                f"rl_analyze_{k}": None
                for k in [
                    "total_count",
                    "malicious",
                    "suspicious",
                    "total_files",
                    "malicious_files",
                    "suspicious_files",
                    "av_scanners",
                    "threats",
                    "riskscore",
                    "link",
                ]
            }

        # Helper for common fields
        common = {
            "rl_analyze_total_count": analysis_result.get("reports"),
            "rl_analyze_malicious": analysis_result.get("malicious"),
            "rl_analyze_suspicious": analysis_result.get("suspicious"),
            "rl_analyze_threats": ", ".join([t for t in analysis_result.get("threats", []) if t]),
            "rl_analyze_link": analysis_result.get("link"),
        }

        if analysis_result.get("report_type") == "network":
            # Network report fields
            common.update(
                {
                    "rl_analyze_total_files": analysis_result.get("total_files"),
                    "rl_analyze_malicious_files": analysis_result.get("malicious_files"),
                    "rl_analyze_suspicious_files": analysis_result.get("suspicious_files"),
                    "rl_analyze_av_scanners": None,  # Not applicable to network
                    "rl_analyze_riskscore": None,  # Not applicable to network
                }
            )
        elif analysis_result.get("report_type") == "file":
            # File hash report fields
            common.update(
                {
                    "rl_analyze_total_files": None,
                    "rl_analyze_malicious_files": None,
                    "rl_analyze_suspicious_files": None,
                    "rl_analyze_av_scanners": analysis_result.get("scanners"),
                    "rl_analyze_riskscore": analysis_result.get("riskscore"),
                }
            )

        # Ensure all expected keys are present even if None
        final_row = {
            f"rl_analyze_{k}": None
            for k in [
                "total_count",
                "malicious",
                "suspicious",
                "total_files",
                "malicious_files",
                "suspicious_files",
                "av_scanners",
                "threats",
                "riskscore",
                "link",
            ]
        }
        final_row.update(common)
        return final_row
