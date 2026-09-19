from engines.ai_verdict_providers.openai_compatible import OpenAICompatibleProvider
from models.ai_verdict import AiVerdictProvider


class GenericOpenAICompatibleProvider(OpenAICompatibleProvider):
    def __init__(self):
        super().__init__(
            provider=AiVerdictProvider.OPENAI_COMPATIBLE,
            default_url="",
            requires_api_key=False,
        )
