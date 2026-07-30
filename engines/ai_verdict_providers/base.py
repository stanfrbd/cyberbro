from abc import ABC, abstractmethod

from models.ai_verdict import AiVerdictProvider, AiVerdictProviderRequest


class AiVerdictProviderClient(ABC):
    @property
    @abstractmethod
    def provider(self) -> AiVerdictProvider:
        pass

    @abstractmethod
    def validate_config(self, request: AiVerdictProviderRequest) -> str:
        pass

    @abstractmethod
    def query(self, request: AiVerdictProviderRequest) -> str:
        pass
