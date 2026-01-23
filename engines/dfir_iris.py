import json
import logging
from collections.abc import Mapping
from typing import Any

import requests
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class DFIRIrisEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "dfir_iris"

    @property
    @override
    def supported_types(self):
        return ["BOGON", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        dfir_iris_api_key = self.secrets.dfir_iris_api_key
        dfir_iris_url = self.secrets.dfir_iris_url

        # Use selective wildcards to match ioc
        match observable_type:
            case "IPv4" | "IPv6" | "MD5" | "SHA1" | "SHA256" | "BOGON":
                body = {"search_value": f"%{observable_value}", "search_type": "ioc"}
            case "FQDN" | "URL":
                body = {"search_value": f"{observable_value}%", "search_type": "ioc"}
            case _:
                body = {"search_value": f"{observable_value}", "search_type": "ioc"}

        try:
            url = f"{dfir_iris_url}/search?cid=1"
            headers = {
                "Authorization": f"Bearer {dfir_iris_api_key}",
                "Content-Type": "application/json",
            }
            payload = json.dumps(body)
            # NOTE: Original code uses proxies=None here, keeping that behavior.
            response = requests.post(
                url,
                headers=headers,
                data=payload,
                proxies=None,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()

            data = response.json()
            if "data" not in data or not data["data"]:
                return None

            links = []
            for i in data["data"]:
                case_id = i["case_id"]
                link = f"{dfir_iris_url}/case/ioc?cid={case_id}"
                links.append(link)

            unique_links = sorted(set(links))
            return {"reports": len(unique_links), "links": unique_links}

        except Exception as e:
            logger.error(
                "Error querying DFIR-IRIS for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result:
            return {"dfir_iris_total_count": None, "dfir_iris_link": None}

        links_str = ", ".join(analysis_result.get("links", []))
        return {
            "dfir_iris_total_count": analysis_result.get("reports"),
            "dfir_iris_link": links_str if links_str else None,
        }
