import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


def query_github(observable: str, proxies: dict[str, str], ssl_verify: bool = True) -> Optional[dict[str, Any]]:
    """
    Perform a search query using Grep API, limited to 5 search results, restricted to GitHub domains.

    Args:
        observable (str): The search query string (e.g., an IoC or keyword).
        proxies (dict): Dictionary containing proxy settings, e.g. {"http": "...", "https": "..."}.

    Returns:
        dict: A dictionary containing the search results under the key "results":
            {
                "results": [
                    {"title": ..., "url": ...},
                    ...
                ]
            }
        None: If an error occurs (network, parsing, etc.).
    """
    try:
        response = requests.get(
            f"https://grep.app/api/search?q={observable}",
            proxies=proxies,
            verify=ssl_verify,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()

        if data["hits"]["total"] == 0:
            return {"results": []}

        search_results = []
        seen_repos = set()
        for hit in data["hits"]["hits"]:
            repo_name = hit["repo"]["raw"]
            if repo_name not in seen_repos:
                seen_repos.add(repo_name)
                search_results.append(
                    {
                        "title": repo_name,
                        "url": f"https://github.com/{repo_name}/blob/{hit['branch']['raw']}/{hit['path']['raw']}",
                        "description": hit["path"]["raw"],
                    }
                )
            if len(search_results) >= 5:
                break

        return {"results": search_results}

    except Exception as e:
        logger.error("Error while querying GitHub for '%s': %s", observable, e, exc_info=True)

        return None
