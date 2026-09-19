from engines.ai_verdict_providers.openai_compatible import OpenAICompatibleProvider
from models.ai_verdict import AiVerdictProvider, AiVerdictProviderRequest


class MicrosoftFoundryProvider(OpenAICompatibleProvider):
    def __init__(self):
        super().__init__(
            provider=AiVerdictProvider.MICROSOFT_FOUNDRY,
            default_url="",
            requires_api_key=True,
            default_auth_header="api-key",
        )

    def validate_config(self, request: AiVerdictProviderRequest) -> str:
        # Azure/Foundry can embed the model name in the endpoint URL, so model may be empty.
        if not request.api_key:
            return "AI verdict API key is not configured."
        if not request.api_url:
            return "AI verdict API URL is required for provider 'microsoft_foundry'."
        return ""

    def _api_url(self, request: AiVerdictProviderRequest) -> str:
        if not request.api_url:
            return ""

        api_version = request.api_version.strip()
        if not api_version or "api-version=" in request.api_url:
            return request.api_url

        separator = "&" if "?" in request.api_url else "?"
        return f"{request.api_url}{separator}api-version={api_version}"
