import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType
from utils.http_headers import build_browser_like_headers

logger = logging.getLogger(__name__)


class GitHubEngine(BaseEngine):
    @property
    def name(self):
        return "github"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.CHROME_EXTENSION
            | ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
            | ObservableType.EMAIL
        )

    def _build_grep_headers(self) -> dict[str, str]:
        # grep.app returns 429 for obvious automation fingerprints
        # like the default python-requests User-Agent.
        return build_browser_like_headers(origin="https://grep.app", referer="https://grep.app/")

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        try:
            params: dict[str, str] = {"q": observable.value}
            response = requests.get(
                url="https://grep.app/api/search",
                params=params,
                headers=self._build_grep_headers(),
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )

            response.raise_for_status()
            data = response.json()

            if data["hits"]["total"] == 0:
                return {"results": []}

            search_results = []
            seen_repos = set()
            for hit in data["hits"]["hits"]:
                repo_name = hit["repo"]
                if repo_name not in seen_repos:
                    seen_repos.add(repo_name)
                    search_results.append(
                        {
                            "title": repo_name,
                            "url": f"https://github.com/{repo_name}/blob/{hit['branch']}/{hit['path']}",
                            "description": hit["path"],
                        }
                    )
                if len(search_results) >= 5:
                    break

            return {"results": search_results, "total": data["hits"]["total"]}

        except Exception as e:
            logger.error(
                "Error while querying GitHub for '%s': %s", observable.value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        # Since original export fields are missing, provide a count
        return {"github_results_count": analysis_result.get("total") if analysis_result else None}
