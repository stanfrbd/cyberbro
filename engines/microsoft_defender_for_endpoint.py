import logging
import time
from pathlib import Path
from typing import Any, Optional

import jwt
import requests

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class MDEEngine(BaseEngine):
    @property
    def name(self):
        return "mde"

    @property
    def supported_types(self):
        return ["BOGON", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]

    def _check_token_validity(self, token: str) -> bool:
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            exp = decoded_token.get("exp")
            if exp is None:
                logger.warning("MDE Token has no expiration claim.")
                return False
            if exp > time.time():
                return True
            logger.warning("MDE Token has expired.")
            return False
        except Exception as e:
            logger.error("Failed to decode MDE token: %s", e, exc_info=True)
            return False

    def _read_token(self) -> Optional[str]:
        try:
            token_path = Path("mde_token.txt")
            token = token_path.read_text().strip()
            if self._check_token_validity(token):
                return token
        except Exception as e:
            logger.error("Failed to read token from file: %s", e, exc_info=True)
        return None

    def _get_token(self) -> str:
        url = f"https://login.microsoftonline.com/{self.secrets.mde_tenant_id}/oauth2/token"
        resource_app_id_uri = "https://api.securitycenter.microsoft.com"
        body = {
            "resource": resource_app_id_uri,
            "client_id": self.secrets.mde_client_id,
            "client_secret": self.secrets.mde_client_secret,
            "grant_type": "client_credentials",
        }
        try:
            response = requests.post(url, data=body, proxies=self.proxies, verify=self.ssl_verify)
            response.raise_for_status()
            json_response = response.json()
        except Exception as err:
            logger.error("Error fetching token from Microsoft: %s", err, exc_info=True)
            return "invalid"

        try:
            aad_token = json_response["access_token"]
            token_path = Path("mde_token.txt")
            token_path.write_text(aad_token)
            return aad_token
        except KeyError:
            logger.error("Unable to retrieve token from JSON response: %s", json_response)
            return "invalid"

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict[str, Any]]:
        try:
            jwt_token = self._read_token() or self._get_token()
            if "invalid" in jwt_token:
                logger.error("No valid token available for Microsoft Defender for Endpoint.")
                return None

            headers = {"Authorization": f"Bearer {jwt_token}"}
            file_info_url = None
            link = None

            observable = observable_value
            extracted_domain = None

            if observable_type in ["MD5", "SHA1", "SHA256"]:
                url = f"https://api.securitycenter.microsoft.com/api/files/{observable}/stats"
                file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{observable}"
                link = f"https://security.microsoft.com/file/{observable}"
            elif observable_type in ["IPv4", "IPv6", "BOGON"]:
                url = f"https://api.securitycenter.microsoft.com/api/ips/{observable}/stats"
                link = f"https://security.microsoft.com/ip/{observable}/overview"
            elif observable_type == "FQDN":
                url = f"https://api.securitycenter.microsoft.com/api/domains/{observable}/stats"
                link = f"https://security.microsoft.com/domains?urlDomain={observable}"
            elif observable_type == "URL":
                extracted_domain = observable.split("/")[2].split(":")[0]
                url = f"https://api.securitycenter.microsoft.com/api/domains/{extracted_domain}/stats"
                link = f"https://security.microsoft.com/url?url={observable}"
            else:
                return None

            response = requests.get(url, headers=headers, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            data = response.json()
            data["link"] = link

            # Retrieve extended file info if applicable
            if file_info_url:
                file_info_response = requests.get(file_info_url, headers=headers, proxies=self.proxies, verify=self.ssl_verify)
                file_info_response.raise_for_status()
                file_info = file_info_response.json()
                data["issuer"] = file_info.get("issuer", "Unknown")
                data["signer"] = file_info.get("signer", "Unknown")
                data["isValidCertificate"] = file_info.get("isValidCertificate", "Unknown")
                data["filePublisher"] = file_info.get("filePublisher", "Unknown")
                data["fileProductName"] = file_info.get("fileProductName", "Unknown")
                data["determinationType"] = file_info.get("determinationType", "Unknown")
                data["determinationValue"] = file_info.get("determinationValue", "Unknown")

            # Simplify dates
            if data.get("orgFirstSeen"):
                data["orgFirstSeen"] = data["orgFirstSeen"].split("T")[0]
            if data.get("orgLastSeen"):
                data["orgLastSeen"] = data["orgLastSeen"].split("T")[0]

            return data

        except Exception as e:
            logger.error("Error querying Microsoft Defender for Endpoint for '%s': %s", observable_value, e, exc_info=True)
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {f"mde_{k}": None for k in ["first_seen", "last_seen", "org_prevalence"]}

        return {
            "mde_first_seen": analysis_result.get("orgFirstSeen"),
            "mde_last_seen": analysis_result.get("orgLastSeen"),
            "mde_org_prevalence": analysis_result.get("orgPrevalence"),
        }
