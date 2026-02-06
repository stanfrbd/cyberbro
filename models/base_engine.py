import logging
from abc import ABC, abstractmethod
from enum import Flag, auto
from typing import Any

import requests
from tenacity import after_log, retry, stop_after_attempt, wait_exponential

from models.observable import ObservableType
from utils.config import Secrets

logger = logging.getLogger(__name__)


class ExecutionPhase(Flag):
    """Defines the analysis phase(s) the engine should run duing.

    Not yet used.
    """

    EXTENSION = auto()  # Browser extension checks always run
    PRE_PIVOT = auto()
    PIVOT = auto()  # Can modify the observable in place (e.g. reverse DNS)
    POST_PIVOT = auto()
    DEPENDENT = auto()  # Engins that need results from other engines


class BaseEngine(ABC):
    """
    Abstract base class for all analysis engines.
    """

    def __init__(self, secrets: Secrets, proxies: dict, ssl_verify: bool):
        self.secrets = secrets
        self.proxies = proxies
        self.ssl_verify = ssl_verify

    @property
    @abstractmethod
    def name(self) -> str:
        """The unique slug/name of the engine (e.g., 'abuseipdb')."""
        pass

    @property
    @abstractmethod
    def supported_types(self) -> ObservableType:
        """List of observable types this engine supports.
        e.g., SupportedTypes.IPv4 | SupportedTypes.URL
        """
        pass

    @property
    def execute_after_reverse_dns(self) -> bool:
        """
        If True, this engine runs in the second pass (Post-Pivot).
        Useful for engines that only support IP addresses (like Shodan),
        so they can benefit from a URL/Domain -> IP resolution.
        """
        return False

    @property
    def is_pivot_engine(self) -> bool:
        """
        If True, this engine is responsible for resolving the observable
        (e.g., Reverse DNS) to change its type/value for subsequent engines.
        """
        return False

    @abstractmethod
    def analyze(self, observable_value: str, observable_type: ObservableType) -> dict | None:
        """
        Perform the analysis.
        Returns the report object, including success or the error message, present.
        """
        pass

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        after=after_log(logger, logging.DEBUG),
    )
    def _make_request(
        self,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
        timeout: int = 10,
    ) -> requests.Response:
        """Request data from the engine API.

        Up to 3 requests can be made before reraising the resulting
        API exception to the calling function.

        After each attempt, the delay between requests is exponentially increased
        and a DEBUG level log message is emitted.
        """
        response = requests.get(url, proxies=self.proxies, verify=self.ssl_verify, timeout=timeout)
        response.raise_for_status()
        return response

    @abstractmethod
    def create_export_row(self, analysis_result: Any) -> dict:
        """
        Format the raw result into a flat dictionary for CSV/Excel export.
        """
        pass
