import logging
from typing import Any

import requests
from bs4 import BeautifulSoup

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class ChromeExtensionEngine(BaseEngine):
    @property
    def name(self):
        # NOTE: The original analysis logic uses "extension" as the result key,
        # but the engine file is named chrome_extension.py. Sticking to the file name
        # for consistency with the new system, but the old analysis.py logic
        # for CHROME_EXTENSION type would need a slight tweak or this engine needs
        # to be run in a dedicated pre-loop logic like the original, as it's not selected by users.
        return "chrome_extension"

    @property
    def supported_types(self):
        return ["CHROME_EXTENSION"]

    def _fetch_extension_name(self, url: str) -> dict[str, str] | None:
        try:
            response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=5)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, "html.parser")
            if "microsoftedge.microsoft.com" in url:
                title_tag = soup.find("title")
                if title_tag:
                    return {
                        "name": title_tag.text.strip().split("-")[0].strip(),
                        "url": url,
                    }
            else:
                h1_tag = soup.find("h1")
                if h1_tag:
                    return {"name": h1_tag.text.strip(), "url": url}

        except Exception as e:
            logger.error(
                "Error while fetching extension name from URL '%s': %s",
                url,
                e,
                exc_info=True,
            )
            return None

    def analyze(self, observable_value: str, observable_type: str) -> dict[str, Any] | None:
        chrome_url = f"https://chromewebstore.google.com/detail/{observable_value}"
        edge_url = f"https://microsoftedge.microsoft.com/addons/detail/{observable_value}"

        result = self._fetch_extension_name(chrome_url)
        if result and result["name"]:
            return result

        result = self._fetch_extension_name(edge_url)
        if result and result["name"]:
            return result

        return None

    def create_export_row(self, analysis_result: Any) -> dict:
        # Note: In the original export.py, this was explicitly handled for the
        # "CHROME_EXTENSION" type using the "extension" key in the result.
        # This implementation aligns with the goal of moving all logic into the class.
        return {"extension_name": analysis_result.get("name") if analysis_result else None}
