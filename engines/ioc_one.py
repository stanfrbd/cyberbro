import logging
from collections.abc import Mapping
from typing import Any

import requests
from bs4 import BeautifulSoup
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)

BASE_SUPPORTED_TYPES: list[str] = [
    "CHROME_EXTENSION",
    "FQDN",
    "IPv4",
    "IPv6",
    "MD5",
    "SHA1",
    "SHA256",
    "URL",
]


class IOCOneHTMLEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "ioc_one_html"

    @property
    @override
    def supported_types(self):
        return BASE_SUPPORTED_TYPES

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        try:
            url = f"https://ioc.one/auth/deep_search?search={observable_value}"
            response = requests.get(
                url,
                proxies=self.proxies,
                verify=self.ssl_verify,
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
                source = card.find("a", class_="btn border btn-primary m-1", target="_blank")[
                    "href"
                ]
                search_results.append({"header": header, "title": title, "source": source})

            return {
                "results": search_results,
                "link": url,
                "count": len(search_results),
            }

        except Exception as e:
            logger.error(
                "Error querying ioc.one (HTML) for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        # Since original export fields are missing, provide a count
        return {"ioc_one_html_count": analysis_result.get("count") if analysis_result else None}


class IOCOnePDFEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "ioc_one_pdf"

    @property
    @override
    def supported_types(self):
        return BASE_SUPPORTED_TYPES

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        try:
            url = f"https://ioc.one/auth/deep_search/pdf?search={observable_value}"
            response = requests.get(
                url,
                proxies=self.proxies,
                verify=self.ssl_verify,
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
                # Note the difference in class name for the source link
                # from the HTML engine
                source = card.find("a", class_="btn border btn-primary mx-1", target="_blank")[
                    "href"
                ]
                search_results.append({"header": header, "title": title, "source": source})

            return {
                "results": search_results,
                "link": url,
                "count": len(search_results),
            }

        except Exception as e:
            logger.error(
                "Error querying ioc.one (PDF) for '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        # Since original export fields are missing, provide a count
        return {"ioc_one_pdf_count": analysis_result.get("count") if analysis_result else None}
