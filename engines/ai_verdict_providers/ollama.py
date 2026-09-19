from engines.ai_verdict_providers.openai_compatible import OpenAICompatibleProvider
from models.ai_verdict import AiVerdictProvider


class OllamaProvider(OpenAICompatibleProvider):
    def __init__(self):
        super().__init__(
            provider=AiVerdictProvider.OLLAMA,
            default_url="http://localhost:11434/v1/chat/completions",
            requires_api_key=False,
        )
