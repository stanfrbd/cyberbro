import json
import logging
from datetime import UTC, datetime
from typing import TypedDict
from urllib.parse import quote

import requests
from pydantic import BaseModel, Field, ValidationError
from typing_extensions import override

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableFlag

logger = logging.getLogger(__name__)


class NogonDocument(BaseModel):
    url: str = ""
    title: str = ""
    # UTC timestamps that can be represented as Python dates.
    added: int = Field(default=0, ge=-62135596800, le=253402300799)


class NogonSearchResponse(BaseModel):
    total: int = Field(ge=0)
    documents: list[NogonDocument] | None


class NogonResult(TypedDict):
    url: str
    title: str
    added: str


NogonAnalysis = dict[str, int | list[NogonResult] | str]


class NogonEngine(BaseEngine):
    @property
    @override
    def name(self) -> str:
        return "nogon"

    @property
    @override
    def supported_types(self) -> ObservableFlag:
        return (
            ObservableFlag.IPV4
            | ObservableFlag.IPV6
            | ObservableFlag.BOGON
            | ObservableFlag.FQDN
            | ObservableFlag.URL
            | ObservableFlag.EMAIL
            | ObservableFlag.CHROME_EXTENSION
            | ObservableFlag.MD5
            | ObservableFlag.SHA1
            | ObservableFlag.SHA256
        )

    @override
    def analyze(self, observable: Observable) -> NogonAnalysis | None:
        token: str = self.secrets.nogon_token
        base_url: str = self.secrets.nogon_base_url

        if not token or not base_url:
            logger.warning("Nogon token or base URL not set")
            return None

        base_url = base_url.rstrip("/")
        search_text = json.dumps(observable.value, ensure_ascii=False)
        params = {"query": json.dumps({"text": search_text, "limit": 10})}
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        try:
            response = requests.get(
                f"{base_url}/search",
                headers=headers,
                params=params,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.exception("Error querying Nogon: %s", e)
            return None

        try:
            payload = NogonSearchResponse.model_validate_json(response.content, strict=True)
        except ValidationError:
            logger.error("Invalid search response returned by Nogon")
            return None

        return {
            "total": payload.total,
            "results": self._format_documents(payload.documents or []),
            "link": f"{base_url}/?q={quote(search_text, safe='')}",
        }

    @staticmethod
    def _format_documents(documents: list[NogonDocument]) -> list[NogonResult]:
        results: list[NogonResult] = []
        seen_urls: set[str] = set()
        for doc in documents:
            if not doc.url or doc.url in seen_urls:
                continue
            seen_urls.add(doc.url)
            results.append(
                {
                    "url": doc.url,
                    "title": doc.title or doc.url,
                    "added": (
                        datetime.fromtimestamp(doc.added, tz=UTC).date().isoformat()
                        if doc.added
                        else ""
                    ),
                }
            )
        return results

    @override
    def create_export_row(self, analysis_result: NogonAnalysis | None) -> dict[str, int | None]:
        if not analysis_result:
            return {
                "nogon_total": None,
                "nogon_results": None,
            }
        total = analysis_result.get("total")
        results = analysis_result.get("results")
        return {
            "nogon_total": total if isinstance(total, int) else None,
            "nogon_results": len(results) if isinstance(results, list) else 0,
        }
