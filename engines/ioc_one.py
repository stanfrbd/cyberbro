import logging
from typing import Any

import requests
from bs4 import BeautifulSoup

from models.base_engine import BaseEngine
from models.observable import ObservableType

logger = logging.getLogger(__name__)

BASE_SUPPORTED_TYPES: ObservableType = (
    ObservableType.CHROME_EXTENSION
    | ObservableType.FQDN
    | ObservableType.IPV4
    | ObservableType.IPV6
    | ObservableType.MD5
    | ObservableType.SHA1
    | ObservableType.SHA256
    | ObservableType.URL
)


class IOCOneHTMLEngine(BaseEngine):
    @property
    def name(self):
        return "ioc_one_html"

    @property
    def supported_types(self):
        return BASE_SUPPORTED_TYPES

    def analyze(self, observable_value: str, observable_type: ObservableType) -> dict | None:
        try:
            base_url = "https://ioc.one/auth/deep_search"
            params: dict = {"search": observable_value}
            response = requests.get(
                url=base_url,
                params=params,
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

            link_url: str = base_url + f"?search={observable_value}"
            return {"results": search_results, "link": link_url, "count": len(search_results)}

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

    def analyze(
        self, observable_value: str, observable_type: ObservableType
    ) -> dict[str, Any] | None:
        try:
            base_url = "https://ioc.one/auth/deep_search/pdf"
            params: dict = {"search": observable_value}
            response = requests.get(
                url=base_url,
                params=params,
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

            link_url: str = base_url + f"?search={observable_value}"
            return {"results": search_results, "link": link_url, "count": len(search_results)}

        except Exception as e:
            logger.error(
                "Error querying ioc.one (PDF) for '%s': %s", observable_value, e, exc_info=True
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        # Since original export fields are missing, provide a count
        return {"ioc_one_pdf_count": analysis_result.get("count") if analysis_result else None}
