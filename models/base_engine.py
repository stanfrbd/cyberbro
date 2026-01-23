import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import asdict
from typing import Any

import requests
from pydantic.dataclasses import dataclass
from tenacity import after_log, retry, stop_after_attempt, wait_exponential
from typing_extensions import override

from utils.config import Secrets

logger = logging.getLogger(__name__)


class BaseEngine(ABC):
    """
    Abstract base class for all analysis engines.
    """

    def __init__(self, secrets: Secrets, proxies: dict, ssl_verify: bool) -> None:
        self.secrets: Secrets = secrets
        self.proxies: dict[str, str] = proxies
        self.ssl_verify: bool = ssl_verify

    @override
    def __eq__(self, other) -> bool:
        """Allow an engine to be identified by it's name."""
        if isinstance(other, str):
            return self.name == other
        if isinstance(other, BaseEngine):
            return self.name == other.name
        raise NotImplementedError

    def __req__(self, other) -> bool:
        """Allow an engine to be identified by it's name, on the right hand
        side of an equation."""
        return other == self

    @override
    def __hash__(self) -> int:
        return hash(self.name)

    @property
    @abstractmethod
    def name(self) -> str:
        """The unique slug/name of the engine (e.g., 'abuseipdb')."""
        pass

    @property
    @abstractmethod
    def supported_types(self) -> Iterable[str]:
        """List of observable types this engine supports (e.g., ['IPv4', 'URL'])."""
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
    def analyze(self, observable_value: str, observable_type: str) -> Any:
        """
        Perform the analysis. Returns the raw result dictionary or None.
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

        if headers is None:
            headers = {}
        if params is None:
            params = {}

        response = requests.get(
            url,
            params=params,
            headers=headers,
            proxies=self.proxies,
            verify=self.ssl_verify,
            timeout=timeout,
        )
        response.raise_for_status()
        return response

    @classmethod
    @abstractmethod
    def create_export_row(cls, analysis_result: Mapping) -> Mapping:
        """
        Format the raw result into a flat dictionary for CSV/Excel export.
        """
        pass


@dataclass(slots=True)
class BaseReport:
    success: bool
    error_msg: str | None = None

    def __iter__(self):
        yield from asdict(self)

    def __getitem__(self, key):
        return asdict(self)[key]

    def __json__(self):
        return asdict(self)

    def get(self, name, default: Any | None = None):
        return getattr(self, name, default)
