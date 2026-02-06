import json
import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)


class DFIRIrisEngine(BaseEngine):
    @property
    def name(self):
        return "dfir_iris"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.BOGON
            | ObservableType.FQDN
            | ObservableType.URL
        )

    def analyze(
        self, observable_value: str, observable_type: ObservableType
    ) -> dict[str, Any] | None:
        dfir_iris_api_key = self.secrets.dfir_iris_api_key
        dfir_iris_url = self.secrets.dfir_iris_url

        # Use selective wildcards to match ioc
        match observable_type:
            case (
                ObservableType.IPV4
                | ObservableType.IPV6
                | ObservableType.MD5
                | ObservableType.SHA1
                | ObservableType.SHA256
                | ObservableType.BOGON
            ):
                body = {"search_value": f"%{observable_value}", "search_type": "ioc"}
            case ObservableType.FQDN | ObservableType.URL:
                body = {"search_value": f"{observable_value}%", "search_type": "ioc"}
            case _:
                body = {"search_value": f"{observable_value}", "search_type": "ioc"}

        try:
            url = f"{dfir_iris_url}/search"
            params: dict[str, int] = {"cid": 1}
            headers = {
                "Authorization": f"Bearer {dfir_iris_api_key}",
                "Content-Type": "application/json",
            }
            payload = json.dumps(body)
            # NOTE: Original code uses proxies=None here, keeping that behavior.
            response = requests.post(
                url,
                params=params,
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
                "Error querying DFIR-IRIS for '%s': %s", observable_value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"dfir_iris_total_count": None, "dfir_iris_link": None}

        links_str = ", ".join(analysis_result.get("links", []))
        return {
            "dfir_iris_total_count": analysis_result.get("reports"),
            "dfir_iris_link": links_str if links_str else None,
        }
