import contextlib
import logging
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict

import requests
from pydantic import Field
from pydantic.dataclasses import dataclass
from typing_extensions import override

from models.base_engine import BaseEngine, BaseReport

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CrtShDomain:
    domain: str
    count: int

    def __iter__(self):
        yield from asdict(self)

    def __getitem__(self, key):
        return asdict(self)[key]


@dataclass(slots=True)
class CrtShReport(BaseReport):
    top_domains: list[CrtShDomain] = Field(default_factory=list)
    link: str = ""


class CrtShEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "crtsh"

    @property
    @override
    def supported_types(self):
        return ["FQDN", "URL"]

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict:
        # If observable is a URL, extract domain
        if observable_type == "URL":
            domain_part = observable_value.split("/")[2].split(":")[0]
            observable = domain_part
        else:
            observable = observable_value

        url = "https://crt.sh/json"

        try:
            response = self._make_request(url=url, params={"q": observable}, timeout=60)
            response.raise_for_status()

            results = response.json()
        except requests.exceptions.RequestException as e:
            message: str = f"Error fetching data from crt.sh: {e}"
            logger.error(message)
            return CrtShReport(success=False, error_msg=message).__json__()

        domain_count: Counter = Counter()
        for entry in results:
            domains: set[str] = set()
            domains.add(entry.get("common_name"))

            name_value = entry.get("name_value")
            if name_value:
                for el in name_value.split("\n"):
                    domains.add(str(el).strip())

            """
            Easier and faster to not check for None every time and simply
            remove it at the end, ignoring any KeyErrors if there were
            no empty strings to begin with.
            """
            with contextlib.suppress(KeyError):
                domains.remove("")

            domain_count += Counter(domains)

        top_domains = [
            CrtShDomain(domain=dmn, count=cnt) for dmn, cnt in domain_count.most_common(5)
        ]

        return CrtShReport(
            success=True,
            top_domains=top_domains,
            link=f"https://crt.sh/?q={observable}",
        ).__json__()

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        if not analysis_result.get("success"):
            return {"crtsh_top_domains": None}

        domains = analysis_result.get("top_domains", [])
        top_domains_str = ", ".join([d["domain"] for d in domains])

        return {"crtsh_top_domains": top_domains_str if top_domains_str else None}

    @classmethod
    def create_export_row_from_report_object(cls, analysis_result: CrtShReport) -> dict:
        if not analysis_result.success:
            return {"crtsh_top_domains": None}
        if not analysis_result.top_domains:
            return {"crtsh_top_domains": None}

        top_domains_str = ", ".join([d.domain for d in analysis_result.top_domains])

        return {"crtsh_top_domains": top_domains_str}
