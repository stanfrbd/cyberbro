from abc import ABC, abstractmethod
from typing import Any


class BaseEngine(ABC):
    """
    Abstract base class for all analysis engines.
    """

    def __init__(self, secrets: Any, proxies: dict, ssl_verify: bool):
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
    def supported_types(self) -> list[str]:
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

    @abstractmethod
    def create_export_row(self, analysis_result: Any) -> dict:
        """
        Format the raw result into a flat dictionary for CSV/Excel export.
        """
        pass
