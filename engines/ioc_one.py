import logging
from typing import Any, Optional

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def query_ioc_one_html(observable: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Perform a deep search query on ioc.one (HTML).

    Args:
        observable (str): The search query.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary with keys "results" (list of dict) and "link" (str):
            {
                "results": [
                    {"header": ..., "title": ..., "source": ...},
                    ...
                ],
                "link": "https://ioc.one/..."
            }
        None: If any error occurs.
    """
    try:
        url = f"https://ioc.one/auth/deep_search?search={observable}"
        response = requests.get(
            url,
            proxies=proxies,
            verify=ssl_verify,
            headers={"User-Agent": "cyberbro"},
            timeout=5,
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        cards = soup.find_all("div", class_="card box-shadow my-1")

        search_results: list[dict[str, str]] = []
        for card in cards[:5]:
            header = card.find("div", class_="card-header").get_text(strip=True)
            title = card.find("h5", class_="card-title").get_text(strip=True)
            source = card.find("a", class_="btn border btn-primary m-1", target="_blank")["href"]
            search_results.append({"header": header, "title": title, "source": source})

        return {"results": search_results, "link": url}

    except Exception as e:
        logger.error("Error querying ioc.one (HTML) for '%s': %s", observable, e, exc_info=True)

    return None


def query_ioc_one_pdf(observable: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Perform a deep search query on ioc.one (PDF).

    Args:
        observable (str): The search query.
        proxies (dict): Dictionary containing proxy settings.

    Returns:
        dict: A dictionary with keys "results" (list of dict) and "link" (str).
        None: If any error occurs.
    """
    try:
        url = f"https://ioc.one/auth/deep_search/pdf?search={observable}"
        response = requests.get(
            url,
            proxies=proxies,
            verify=ssl_verify,
            headers={"User-Agent": "cyberbro"},
            timeout=5,
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        cards = soup.find_all("div", class_="card box-shadow my-1")

        search_results = []
        for card in cards[:5]:
            header = card.find("div", class_="card-header").get_text(strip=True)
            title = card.find("h5", class_="card-title").get_text(strip=True)
            source = card.find("a", class_="btn border btn-primary mx-1", target="_blank")["href"]
            search_results.append({"header": header, "title": title, "source": source})

        return {"results": search_results, "link": url}

    except Exception as e:
        logger.error("Error querying ioc.one (PDF) for '%s': %s", observable, e, exc_info=True)

    return None
