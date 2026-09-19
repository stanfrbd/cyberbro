import requests

from engines.ai_verdict_providers.base import AiVerdictProviderClient
from models.ai_verdict import AiVerdictProvider, AiVerdictProviderRequest


class GoogleProvider(AiVerdictProviderClient):
    @property
    def provider(self) -> AiVerdictProvider:
        return AiVerdictProvider.GOOGLE

    def validate_config(self, request: AiVerdictProviderRequest) -> str:
        if not request.model:
            return "AI verdict model is not configured."
        if not request.api_key:
            return "AI verdict API key is not configured."
        return ""

    def query(self, request: AiVerdictProviderRequest) -> str:
        response = requests.post(
            self._api_url(request),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": request.api_key,
            },
            json={
                "systemInstruction": {
                    "parts": [
                        {
                            "text": (
                                "You return strict raw JSON for cybersecurity observable verdicts. "
                                "Do not use Markdown. Confidence must be an integer from 0 to 100."
                            )
                        }
                    ]
                },
                "contents": [{"role": "user", "parts": [{"text": request.prompt}]}],
                "generationConfig": {
                    "temperature": 0,
                    "maxOutputTokens": request.max_tokens,
                    "responseMimeType": "application/json",
                },
            },
            proxies=request.proxies,
            verify=request.ssl_verify,
            timeout=request.timeout,
        )
        response.raise_for_status()
        data = response.json()

        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise ValueError("Google response did not include candidates.")

        first_candidate = candidates[0]
        if not isinstance(first_candidate, dict):
            raise ValueError("Google response candidate is invalid.")

        content = first_candidate.get("content")
        if not isinstance(content, dict):
            raise ValueError("Google response candidate did not include content.")

        parts = content.get("parts")
        if not isinstance(parts, list) or not parts:
            raise ValueError("Google response content did not include parts.")

        text_chunks: list[str] = []
        for part in parts:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                text_chunks.append(part["text"])

        if not text_chunks:
            raise ValueError("Google response did not include text content.")

        return "\n".join(text_chunks)

    def _api_url(self, request: AiVerdictProviderRequest) -> str:
        if request.api_url:
            return request.api_url

        return (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{request.model}:generateContent"
        )
