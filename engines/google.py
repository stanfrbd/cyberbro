import logging
from typing import Any, Optional
from urllib import parse as urlparse
import requests
from bs4 import BeautifulSoup
import json
import re

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
    Perform a Google search query via Mullvad's Leta service and parse the results.

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

        query = f'%22{urlparse.quote(observable)}%22'  # Add proper URL encoding for quotes
        url = f"https://leta.mullvad.net/search?q={query}&engine=google"  # Use the encoded query
        logger.info("Fetching URL: %s", url)
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}
        response = requests.get(url, proxies=proxies, verify=ssl_verify, timeout=5, headers=headers)
        response.encoding = 'utf-8'  # Ensure proper decoding of response text
        soup = BeautifulSoup(response.text, "html.parser")

        # Step 1: Find the <script> tag containing "items"
        script_tags = soup.find_all("script")
        target_script = None
        for script in script_tags:
            if script.string and "items:[" in script.string:
                target_script = script.string
                break

        # Step 2: Parse the JSON content directly
        if target_script:
            try:
                # Extract the JSON content from the script string
                start_index = target_script.find("items:[")
                end_index = target_script.find("],", start_index) + 1
                items_raw = target_script[start_index + len("items:"):end_index].strip()

                # Add quotes around property names (title, snippet, link, favicon)
                items_raw = re.sub(r'(?<!")\b(title|snippet|link|favicon)\b(?!")(?=\s*:)', r'"\1"', items_raw)

                # Load the JSON data
                items_json = json.loads(f"{{\"items\":{items_raw}}}")["items"]

                # Extract the results
                search_results = [
                    {
                        "title": item.get("title"),
                        "description": item.get("snippet"),
                        "url": item.get("link"),
                    }
                    for item in items_json
                ]

                return {"results": search_results}

            except (json.JSONDecodeError, KeyError) as e:
                logger.error("Error extracting data: %s", e, exc_info=True)
        else:
            logger.warning("No 'items' array found in the script tags.")

    except Exception as e:
        logger.error("Error while querying Google for '%s': %s", observable, e, exc_info=True)

    return None
