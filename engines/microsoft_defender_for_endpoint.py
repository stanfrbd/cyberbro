import logging
import time
from pathlib import Path
from typing import Any, Optional

import jwt
import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "BOGON",
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]

def check_token_validity(token: str) -> bool:
    try:
        # Decode the token without verifying the signature to check its expiration
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        exp = decoded_token.get("exp")
        if exp and exp > time.time():
            return True
        logger.warning("MDE Token has expired.")
        return False
    except Exception as e:
        logger.error("Failed to decode MDE token: %s", e, exc_info=True)
        return False


def read_token() -> Optional[str]:
    try:
        token_path = Path("mde_token.txt")
        token = token_path.read_text().strip()
        if check_token_validity(token):
            return token
        logger.warning("Invalid JWT token found in mde_token.txt")
    except Exception as e:
        logger.error("Failed to read token from file: %s", e, exc_info=True)
    return None


def get_token(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    resource_app_id_uri = "https://api.securitycenter.microsoft.com"
    body = {
        "resource": resource_app_id_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    try:
        response = requests.post(url, data=body, proxies=proxies, verify=ssl_verify)
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


def query_microsoft_defender_for_endpoint(
    observable: str,
    observable_type: str,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Queries Microsoft Defender for Endpoint for information about a given observable.

    Args:
        observable (str): The IoC (hash, IP, domain, or URL).
        observable_type (str): Type of the IoC, e.g., "MD5", "SHA1", "SHA256", "IPv4", "FQDN", "URL".
        tenant_id (str): Tenant ID for Microsoft Azure.
        client_id (str): Client ID for Azure app.
        client_secret (str): Client secret for Azure app.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary containing the response data from MDE, including a link to the observable's details.
        None: If the request fails or any exception occurs.
    """
    try:
        jwt_token = read_token() or get_token(tenant_id, client_id, client_secret, proxies, ssl_verify)
        if jwt_token == "invalid":
            logger.error("No valid token available for Microsoft Defender for Endpoint.")
            return None

        headers = {"Authorization": f"Bearer {jwt_token}"}
        file_info_url = None
        link = None

        if observable_type in ["MD5", "SHA1", "SHA256"]:
            url = f"https://api.securitycenter.microsoft.com/api/files/{observable}/stats"
            file_info_url = f"https://api.securitycenter.microsoft.com/api/files/{observable}"
            link = f"https://securitycenter.microsoft.com/file/{observable}"
        elif observable_type in ["IPv4", "IPv6", "BOGON"]:
            url = f"https://api.securitycenter.microsoft.com/api/ips/{observable}/stats"
            link = f"https://securitycenter.microsoft.com/ip/{observable}/overview"
        elif observable_type == "FQDN":
            url = f"https://api.securitycenter.microsoft.com/api/domains/{observable}/stats"
            link = f"https://securitycenter.microsoft.com/domains?urlDomain={observable}"
        elif observable_type == "URL":
            extracted_domain = observable.split("/")[2].split(":")[0]
            url = f"https://api.securitycenter.microsoft.com/api/domains/{extracted_domain}/stats"
            link = f"https://securitycenter.microsoft.com/url?url={observable}"
        else:
            logger.warning("Unknown observable_type '%s'", observable_type)
            return None

        response = requests.get(url, headers=headers, proxies=proxies, verify=ssl_verify, timeout=5)
        response.raise_for_status()

        data = response.json()
        data["link"] = link

        # If it's a file hash, we also retrieve extended file info
        if file_info_url:
            file_info_response = requests.get(file_info_url, headers=headers, proxies=proxies, verify=ssl_verify)
            file_info_response.raise_for_status()
            file_info = file_info_response.json()
            data["issuer"] = file_info.get("issuer", "Unknown")
            data["signer"] = file_info.get("signer", "Unknown")
            data["isValidCertificate"] = file_info.get("isValidCertificate", "Unknown")
            data["filePublisher"] = file_info.get("filePublisher", "Unknown")
            data["fileProductName"] = file_info.get("fileProductName", "Unknown")
            data["determinationType"] = file_info.get("determinationType", "Unknown")
            data["determinationValue"] = file_info.get("determinationValue", "Unknown")

        # Simplify dates if they exist
        if data.get("orgFirstSeen"):
            data["orgFirstSeen"] = data["orgFirstSeen"].split("T")[0]
        if data.get("orgLastSeen"):
            data["orgLastSeen"] = data["orgLastSeen"].split("T")[0]

        return data

    except Exception as e:
        logger.error(
            "Error querying Microsoft Defender for Endpoint for '%s': %s",
            observable,
            e,
            exc_info=True,
        )

    return None
