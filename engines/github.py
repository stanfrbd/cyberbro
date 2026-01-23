import logging
from collections.abc import Mapping
from typing import Any

from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class GitHubEngine(BaseEngine):
    @property
    @override
    def name(self) -> str:
        return "github"

    @property
    @override
    def supported_types(self) -> set[str]:
        return {
            "CHROME_EXTENSION",
            "FQDN",
            "IPv4",
            "IPv6",
            "MD5",
            "SHA1",
            "SHA256",
            "URL",
            "Email",
        }

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        url: str = f"https://grep.app/api/search?q={observable_value}"

        try:
            response = self._make_request(url, timeout=5)
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
                "Error while querying GitHub for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        # Since original export fields are missing, provide a count
        return {"github_results_count": analysis_result.get("total") if analysis_result else None}
