from engines.ai_verdict_providers.openai_compatible import OpenAICompatibleProvider
from models.ai_verdict import AiVerdictProvider


class LMStudioProvider(OpenAICompatibleProvider):
    def __init__(self):
        super().__init__(
            provider=AiVerdictProvider.LM_STUDIO,
            default_url="http://localhost:1234/v1/chat/completions",
            requires_api_key=False,
        )
