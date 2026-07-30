import requests

from engines.ai_verdict_providers.base import AiVerdictProviderClient
from models.ai_verdict import AiVerdictProvider, AiVerdictProviderRequest


class AnthropicProvider(AiVerdictProviderClient):
    @property
    def provider(self) -> AiVerdictProvider:
        return AiVerdictProvider.ANTHROPIC

    def validate_config(self, request: AiVerdictProviderRequest) -> str:
        if not request.model:
            return "AI verdict model is not configured."
        if not request.api_key:
            return "AI verdict API key is not configured."
        return ""

    def query(self, request: AiVerdictProviderRequest) -> str:
        response = requests.post(
            request.api_url or "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": request.api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": request.model,
                "max_tokens": request.max_tokens,
                "temperature": 0,
                "messages": [{"role": "user", "content": request.prompt}],
            },
            proxies=request.proxies,
            verify=request.ssl_verify,
            timeout=request.timeout,
        )
        response.raise_for_status()
        data = response.json()

        content = data.get("content")
        if not isinstance(content, list) or not content:
            raise ValueError("Anthropic response did not include content.")

        text_chunks: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                text_chunks.append(item["text"])

        if not text_chunks:
            raise ValueError("Anthropic response did not include text content.")

        return "\n".join(text_chunks)
