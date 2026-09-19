from engines.ai_verdict_providers.anthropic import AnthropicProvider
from engines.ai_verdict_providers.base import AiVerdictProviderClient
from engines.ai_verdict_providers.generic_openai_compatible import (
    GenericOpenAICompatibleProvider,
)
from engines.ai_verdict_providers.google import GoogleProvider
from engines.ai_verdict_providers.lm_studio import LMStudioProvider
from engines.ai_verdict_providers.microsoft_foundry import MicrosoftFoundryProvider
from engines.ai_verdict_providers.ollama import OllamaProvider
from engines.ai_verdict_providers.openai import OpenAIProvider
from models.ai_verdict import AiVerdictProvider


def get_ai_verdict_provider(provider: AiVerdictProvider) -> AiVerdictProviderClient:
    providers: dict[AiVerdictProvider, AiVerdictProviderClient] = {
        AiVerdictProvider.OPENAI: OpenAIProvider(),
        AiVerdictProvider.ANTHROPIC: AnthropicProvider(),
        AiVerdictProvider.GOOGLE: GoogleProvider(),
        AiVerdictProvider.MICROSOFT_FOUNDRY: MicrosoftFoundryProvider(),
        AiVerdictProvider.OLLAMA: OllamaProvider(),
        AiVerdictProvider.LM_STUDIO: LMStudioProvider(),
        AiVerdictProvider.OPENAI_COMPATIBLE: GenericOpenAICompatibleProvider(),
    }
    return providers[provider]
