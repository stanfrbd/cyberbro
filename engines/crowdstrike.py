import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

from falconpy import APIHarnessV2  # Assuming falconpy is installed

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)


class CrowdstrikeEngine(BaseEngine):
    @property
    def name(self):
        return "crowdstrike"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.FQDN
            | ObservableType.URL
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
        )

    def _map_observable_type(self, observable_type: ObservableType) -> str | None:
        match observable_type:
            case ObservableType.FQDN | ObservableType.URL:
                return "domain"
            case ObservableType.IPV4:
                return "ipv4"
            case ObservableType.IPV6:
                return "ipv6"
            case ObservableType.MD5:
                return "md5"
            case ObservableType.SHA256:
                return "sha256"
            case ObservableType.SHA1:
                return "sha1"
            case _:
                return None

    def _generate_ioc_id(self, observable: str, mapped_type: str) -> str | None:
        match mapped_type:
            case "domain":
                prefix: str = "domain_"
            case "ipv4" | "ipv6":
                prefix = "ip_address_"
            case "md5":
                prefix = "hash_md5_"
            case "sha256":
                prefix = "hash_sha256_"
            case "sha1":
                prefix = "hash_sha1_"
            case _:
                return None

        return f"{prefix}{observable}"

    def _get_falcon_client(self) -> APIHarnessV2:
        return APIHarnessV2(
            client_id=self.secrets.crowdstrike_client_id,
            client_secret=self.secrets.crowdstrike_client_secret,
            proxy=self.proxies,
            user_agent="cyberbro",
            ssl_verify=self.ssl_verify,
            timeout=5,
        )

    def analyze(
        self, observable_value: str, observable_type: ObservableType
    ) -> dict[str, Any] | None:
        try:
            falcon = self._get_falcon_client()
            falcon_url = urljoin(self.secrets.crowdstrike_falcon_base_url, "/").rstrip("/")

            observable: str = (
                observable_value.split("/")[2].split(":")[0]
                if observable_type is ObservableType.URL
                else observable_value
            )

            observable = observable.lower()
            mapped_type: str = self._map_observable_type(observable_type)

            # 1. Get device count
            response = falcon.command(
                "indicator_get_device_count_v1", type=mapped_type, value=observable
            )
            device_count_result = {"device_count": 0}
            if response["status_code"] == 200:
                data = response["body"]["resources"][0]
                device_count_result["device_count"] = data.get("device_count", 0)

            # 2. Get Intel Indicators
            id_to_search = self._generate_ioc_id(observable, mapped_type)
            request_body = {"ids": [id_to_search]}
            response = falcon.command("GetIntelIndicatorEntities", body=request_body)

            result = device_count_result
            result["link"] = f"{falcon_url}/search/?term=_all%3A~%27{observable}%27"

            if response["status_code"] != 200 or not response["body"]["resources"]:
                result.update({"indicator_found": False})
                return result

            resource = response["body"]["resources"][0]
            result.update(
                {
                    "indicator_found": True,
                    "published_date": datetime.fromtimestamp(
                        resource.get("published_date", 0), tz=timezone.utc
                    ).strftime("%Y-%m-%d"),
                    "last_updated": datetime.fromtimestamp(
                        resource.get("last_updated", 0), tz=timezone.utc
                    ).strftime("%Y-%m-%d"),
                    "actors": resource.get("actors", []),
                    "malicious_confidence": resource.get("malicious_confidence", ""),
                    "threat_types": resource.get("threat_types", []),
                    "kill_chain": resource.get("kill_chains", []),
                    "malware_families": resource.get("malware_families", []),
                    "vulnerabilities": resource.get("vulnerabilities", []),
                }
            )
            return result

        except Exception as e:
            logger.error(
                "Error querying CrowdStrike Falcon for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                f"cs_{k}": None
                for k in [
                    "device_count",
                    "actor",
                    "confidence",
                    "threat_types",
                    "malwares",
                    "kill_chain",
                    "vulns",
                ]
            }

        return {
            "cs_device_count": analysis_result.get("device_count"),
            "cs_actor": ", ".join(analysis_result.get("actors", [])),
            "cs_confidence": analysis_result.get("malicious_confidence"),
            "cs_threat_types": ", ".join(analysis_result.get("threat_types", [])),
            "cs_malwares": ", ".join(analysis_result.get("malware_families", [])),
            "cs_kill_chain": ", ".join(analysis_result.get("kill_chain", [])),
            "cs_vulns": ", ".join(analysis_result.get("vulnerabilities", [])),
        }
