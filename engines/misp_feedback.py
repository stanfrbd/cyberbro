import base64
import logging
from typing import Any

import requests
from requests.exceptions import ConnectTimeout, HTTPError, JSONDecodeError, ReadTimeout
from typing_extensions import override

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class MispFeedbackEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "misp_feedback"

    @property
    @override
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.FQDN
        )

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        server_url = self.secrets.get("misp_feedback_server_url")
        token = self.secrets.get("misp_feedback_token")

        if not server_url:
            logger.error("MISP_FEEDBACK_SERVER_URL is not configured")
            return None

        lookup_url = f"{server_url.rstrip('/')}/lookup"
        headers: dict[str, str] = {"accept": "application/json", "Content-Type": "application/json"}

        if token:
            auth_string = base64.b64encode(f":{token}".encode()).decode()
            headers["Authorization"] = f"Basic {auth_string}"

        payload = {"value": observable.value, "false_positives_only": False}

        try:
            response = requests.post(
                lookup_url,
                json=payload,
                headers=headers,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=10,
            )
            response.raise_for_status()

            result = response.json()

        except (ReadTimeout, ConnectTimeout):
            logger.info(f"Timeout occurred while querying MISP-feedback for {observable.value}.")
            return None
        except HTTPError as e:
            logger.error(
                "Error querying MISP-feedback for '%s': %s", observable.value, e, exc_info=True
            )
            return None
        except JSONDecodeError as e:
            msg = (
                f"Unexpected error while parsing response from MISP-feedback "
                f"for {observable.value}: {e}"
            )
            logger.error(msg)
            return None

        matches = result.get("matches", [])
        if matches:
            warninglist_names = [m.get("name", "Unknown") for m in matches]
            return {"status": "HIT", "warninglists": warninglist_names}
        return {"status": "CLEAN", "warninglists": []}

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {"misp_feedback_status": None, "misp_feedback_warninglists": None}

        status = analysis_result.get("status", "UNKNOWN")
        warninglists = analysis_result.get("warninglists", [])
        warninglists_str = ", ".join(warninglists) if warninglists else None

        return {
            "misp_feedback_status": status,
            "misp_feedback_warninglists": warninglists_str,
        }
