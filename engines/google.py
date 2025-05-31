import logging
from typing import Any, Optional

from googlesearch import search

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

def query_google(observable: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Perform a Google search query limited to 5 search results.

    Args:
        observable (str): The search query.
        proxies (dict): Dictionary containing proxy settings, e.g. {"http": "...", "https": "..."}.

    Returns:
        dict: A dictionary containing the search results under the key "results":
            {
                "results": [
                    {"title": ..., "description": ..., "url": ...},
                    ...
                ]
            }
        None: If an error occurs (network, parsing, etc.).
    """
    try:
        search_iterator = search(
            f'"{observable}"',
            num_results=5,
            proxy=proxies.get("http"),
            ssl_verify=ssl_verify,
            advanced=True,
            lang="en",
            region="US",
        )

        search_results = []
        for result in search_iterator:
            search_results.append(
                {
                    "title": result.title,
                    "description": result.description,
                    "url": result.url,
                }
            )

        return {"results": search_results}

    except Exception as e:
        logger.error("Error while querying Google for '%s': %s", observable, e, exc_info=True)

    return None
