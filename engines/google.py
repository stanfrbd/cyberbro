import logging
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

SUPPORTED_OBSERVABLE_TYPES: list[str] = [
    "CHROME_EXTENSION",
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]


def query_google(
    observable: str,
    google_cse_cx: str,
    google_cse_key: str,
    proxies: dict[str, str],
    ssl_verify: bool = True,
    dorks: str = "",
) -> Optional[dict[str, Any]]:
    """
    Perform a Google Custom Search (CSE) query and return results in the same shape as before.

    dorks: optional prefix for the query (default empty). Example: 'site:example.com' or '""' if desired.

    Returns:
        {"results": [{"title": ..., "description": ..., "url": ...}, ...]} or None on error.
        If the API returns an error payload or a non-2xx HTTP status, returns {"results":[{"error":"..."}]}.
    """
    try:
        # Respect rate limit: sleep 500ms between requests (be conservative)
        time.sleep(0.5)

        dorks_prefix = dorks.strip()
        if dorks_prefix:
            dorks_prefix += " "

        q = f'{dorks_prefix}"{observable}"'

        url = "https://www.googleapis.com/customsearch/v1"
        params = {"key": google_cse_key, "cx": google_cse_cx, "q": q}

        resp = requests.get(url, params=params, proxies=proxies, verify=ssl_verify, timeout=10)

        # Try to parse JSON (if possible)
        data = None
        try:
            data = resp.json()
        except ValueError:
            data = None

        # If HTTP error or API returned an "error" payload, return that message in results
        if resp.status_code >= 400 or (isinstance(data, dict) and "error" in data):
            if isinstance(data, dict) and "error" in data:
                # Try to extract a friendly message
                err = data.get("error", {})
                msg = err.get("message") or (err.get("errors", [{}])[0].get("message")) or str(err)
            else:
                msg = resp.text or resp.reason or f"HTTP {resp.status_code}"
            logger.warning("Google CSE error for '%s': %s", observable, msg)
            return {"results": [{"title": "API Error", "description": "Check Cyberbro logs for details", "url": ""}]}

        # Ensure we have JSON data for successful responses
        if data is None:
            try:
                data = resp.json()
            except ValueError:
                logger.error("Expected JSON from Google CSE for '%s' but got none.", observable)
                return None

        items = data.get("items", []) if isinstance(data, dict) else []
        search_results = [
            {
                "title": item.get("title"),
                "description": item.get("snippet"),
                "url": item.get("link"),
            }
            for item in items
        ]

        return {"results": search_results}

    except requests.RequestException as e:
        logger.error("Network error querying Google CSE for '%s': %s", observable, e, exc_info=True)
    except Exception as e:
        logger.error("Unexpected error querying Google CSE for '%s': %s", observable, e, exc_info=True)

    return None
