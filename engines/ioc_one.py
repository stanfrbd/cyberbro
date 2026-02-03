import logging
from typing import Any

import requests
from bs4 import BeautifulSoup

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)

BASE_SUPPORTED_TYPES = ["CHROME_EXTENSION", "FQDN", "IPv4", "IPv6", "MD5", "SHA1", "SHA256", "URL"]


class IOCOneHTMLEngine(BaseEngine):
    @property
    def name(self):
        return "ioc_one_html"

    @property
    def supported_types(self):
        return BASE_SUPPORTED_TYPES

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
                # REFACTOR NOTE: Missing null checks on find() results.
                # If card-header div, card-title h5, or source link are missing,
                # calling .get_text() or ["href"] on None will raise AttributeError/TypeError.
                # Should check if elements exist before accessing properties to allow
                # graceful skipping of malformed cards rather than failing entire response.
                header = card.find("div", class_="card-header").get_text(strip=True)
                title = card.find("h5", class_="card-title").get_text(strip=True)
                source = card.find("a", class_="btn border btn-primary m-1", target="_blank")[
                    "href"
                ]
                search_results.append({"header": header, "title": title, "source": source})

            return {"results": search_results, "link": url, "count": len(search_results)}

        except Exception as e:
            logger.error(
                "Error querying ioc.one (HTML) for '%s': %s", observable_value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        # Since original export fields are missing, provide a count
        return {"ioc_one_html_count": analysis_result.get("count") if analysis_result else None}


class IOCOnePDFEngine(BaseEngine):
    @property
    def name(self):
        return "ioc_one_pdf"

    @property
    def supported_types(self):
        return BASE_SUPPORTED_TYPES

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
                # REFACTOR NOTE: Missing null checks on find() results (see IOCOneHTMLEngine).
                # If elements are missing, calling .get_text() or ["href"] on None will crash.
                # Should add existence checks before accessing properties to gracefully
                # skip malformed cards rather than failing entire response.
                header = card.find("div", class_="card-header").get_text(strip=True)
                title = card.find("h5", class_="card-title").get_text(strip=True)
                # Note the difference in class name for the source link from the HTML engine
                source = card.find("a", class_="btn border btn-primary mx-1", target="_blank")[
                    "href"
                ]
                search_results.append({"header": header, "title": title, "source": source})

            return {"results": search_results, "link": url, "count": len(search_results)}

        except Exception as e:
            logger.error(
                "Error querying ioc.one (PDF) for '%s': %s", observable_value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        # Since original export fields are missing, provide a count
        return {"ioc_one_pdf_count": analysis_result.get("count") if analysis_result else None}
