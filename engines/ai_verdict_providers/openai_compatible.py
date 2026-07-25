from urllib.parse import urlsplit, urlunsplit

import requests

from engines.ai_verdict_providers.base import AiVerdictProviderClient
from models.ai_verdict import AiVerdictProvider, AiVerdictProviderRequest


class OpenAICompatibleProvider(AiVerdictProviderClient):
    def __init__(
        self,
        provider: AiVerdictProvider,
        default_url: str,
        requires_api_key: bool,
        default_auth_header: str = "authorization",
    ):
        self._provider = provider
        self._default_url = default_url
        self._requires_api_key = requires_api_key
        self._default_auth_header = default_auth_header

    @property
    def provider(self) -> AiVerdictProvider:
        return self._provider

    def validate_config(self, request: AiVerdictProviderRequest) -> str:
        if not request.model:
            return "AI verdict model is not configured."
        if self._requires_api_key and not request.api_key:
            return "AI verdict API key is not configured."
        if not self._api_url(request):
            return f"AI verdict API URL is required for provider '{self.provider.value}'."
        return ""

    def query(self, request: AiVerdictProviderRequest) -> str:
        response = requests.post(
            self._api_url(request),
            headers=self._headers(request),
            json=self._payload(request),
            proxies=request.proxies,
            verify=request.ssl_verify,
            timeout=request.timeout,
        )
        response.raise_for_status()
        data = response.json()

        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError("OpenAI-compatible response did not include choices.")

        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise ValueError("OpenAI-compatible response choice is invalid.")

        message = first_choice.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]

        text = first_choice.get("text")
        if isinstance(text, str):
            return text

        raise ValueError("OpenAI-compatible response did not include text content.")

    def _payload(self, request: AiVerdictProviderRequest) -> dict[str, object]:
        return {
            "model": request.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You return strict raw JSON for cybersecurity observable verdicts. "
                        "Do not use Markdown. Confidence must be an integer from 0 to 100."
                    ),
                },
                {"role": "user", "content": request.prompt},
            ],
            "temperature": 0,
            "max_tokens": request.max_tokens,
        }

    def _headers(self, request: AiVerdictProviderRequest) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if not request.api_key:
            return headers

        auth_header = request.auth_header.strip().lower() or self._default_auth_header
        if auth_header in {"api-key", "x-api-key"}:
            headers[auth_header] = request.api_key
        elif auth_header == "bearer":
            headers["Authorization"] = f"Bearer {request.api_key}"
        else:
            headers["Authorization"] = f"Bearer {request.api_key}"

        return headers

    def _api_url(self, request: AiVerdictProviderRequest) -> str:
        return self._normalize_chat_completions_url(request.api_url or self._default_url)

    def _normalize_chat_completions_url(self, api_url: str) -> str:
        if not api_url:
            return ""

        parsed_url = urlsplit(api_url)
        path = parsed_url.path.rstrip("/")
        if path.endswith("/chat/completions"):
            return api_url

        if path.endswith("/v1"):
            normalized_path = f"{path}/chat/completions"
        else:
            normalized_path = f"{path}/v1/chat/completions"

        return urlunsplit(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                normalized_path,
                parsed_url.query,
                parsed_url.fragment,
            )
        )
