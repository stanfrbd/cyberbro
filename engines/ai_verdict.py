import json
import logging

from pydantic import ValidationError
from requests.exceptions import RequestException

from engines.ai_verdict_providers import get_ai_verdict_provider
from models.ai_verdict import (
    INSUFFICIENT_CONTEXT_MESSAGE,
    TECHNICAL_CONTEXT_KEYS,
    AiVerdictProvider,
    AiVerdictProviderRequest,
    AiVerdictResult,
    AiVerdictSeverity,
    AiVerdictStatus,
    AiVerdictValue,
)
from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class AiVerdictEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "ai_verdict"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableType.CHROME_EXTENSION
            | ObservableType.EMAIL
            | ObservableType.FQDN
            | ObservableType.IPV4
            | ObservableType.IPV6
            | ObservableType.MD5
            | ObservableType.SHA1
            | ObservableType.SHA256
            | ObservableType.URL
            | ObservableType.BOGON
        )

    def analyze(self, observable: Observable, context: dict | None = None) -> dict[str, object]:
        provider_value = str(self.secrets.ai_verdict_provider).strip().lower()
        model = self.secrets.ai_verdict_model

        if not self.secrets.ai_verdict_enabled:
            return self._result(
                status=AiVerdictStatus.DISABLED,
                summary="AI verdict is disabled in configuration.",
                provider=provider_value,
                model=model,
            )

        try:
            provider = AiVerdictProvider(provider_value)
        except ValueError:
            valid_providers = ", ".join(item.value for item in AiVerdictProvider)
            return self._result(
                status=AiVerdictStatus.CONFIGURATION_ERROR,
                summary=(
                    f"Unsupported AI verdict provider '{provider_value}'. "
                    f"Use one of: {valid_providers}."
                ),
                provider=provider_value,
                model=model,
            )

        provider_client = get_ai_verdict_provider(provider)
        request = self._provider_request(provider=provider, prompt="")
        provider_error = provider_client.validate_config(request)
        if provider_error:
            return self._result(
                status=AiVerdictStatus.CONFIGURATION_ERROR,
                summary=provider_error,
                provider=provider.value,
                model=model,
            )

        engine_results = self._extract_engine_results(context)
        if len(engine_results) < 2:
            return self._result(
                status=AiVerdictStatus.INSUFFICIENT_CONTEXT,
                summary=INSUFFICIENT_CONTEXT_MESSAGE,
                provider=provider.value,
                model=model,
            )

        request = self._provider_request(
            provider=provider,
            prompt=self._build_prompt(observable, engine_results),
        )

        try:
            content = provider_client.query(request)
        except (RequestException, ValueError) as exc:
            logger.error("AI verdict provider error for '%s': %s", observable.value, exc)
            return self._result(
                status=AiVerdictStatus.PROVIDER_ERROR,
                summary=f"AI verdict provider error: {exc}",
                provider=provider.value,
                model=model,
            )

        try:
            return self._parse_provider_content(content, provider.value, model).model_dump(
                mode="json"
            )
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            logger.error("Invalid AI verdict response for '%s': %s", observable.value, exc)
            return self._result(
                status=AiVerdictStatus.PROVIDER_ERROR,
                summary="AI verdict provider returned an invalid JSON verdict.",
                provider=provider.value,
                model=model,
            )

    def _provider_request(
        self, provider: AiVerdictProvider, prompt: str
    ) -> AiVerdictProviderRequest:
        return AiVerdictProviderRequest(
            prompt=prompt,
            api_url=self.secrets.ai_verdict_api_url,
            api_key=self.secrets.ai_verdict_api_key,
            auth_header=self.secrets.ai_verdict_auth_header,
            api_version=self.secrets.ai_verdict_api_version,
            model=self.secrets.ai_verdict_model,
            max_tokens=self.secrets.ai_verdict_max_tokens,
            timeout=self.secrets.ai_verdict_timeout,
            proxies=self.proxies,
            ssl_verify=self.ssl_verify,
        )

    def _extract_engine_results(self, context: dict | None) -> dict[str, object]:
        if not context:
            return {}

        engine_results: dict[str, object] = {}
        for key, value in context.items():
            if key in TECHNICAL_CONTEXT_KEYS or value in (None, {}, []):
                continue
            engine_results[key] = value
        return engine_results

    def _build_prompt(self, observable: Observable, engine_results: dict[str, object]) -> str:
        engine_results_json = json.dumps(engine_results, default=str, ensure_ascii=False, indent=2)
        observable_json = json.dumps(
            {"value": observable.value, "type": str(observable.type)},
            ensure_ascii=False,
        )
        base_prompt = self.secrets.ai_verdict_prompt

        return (
            f"{base_prompt}\n\n"
            "Return a raw JSON object only. Do not use Markdown fences, comments, or extra text.\n"
            "All fields are mandatory. Use only the allowed enum values shown below.\n"
            "The confidence field must be an integer percentage from 0 to 100.\n"
            "Do not return confidence as a decimal fraction such as 0.98; return 98 instead.\n\n"
            "Required JSON schema:\n"
            "{\n"
            '  "verdict": "malicious|suspicious|benign|unknown",\n'
            '  "severity": "critical|high|medium|low|info",\n'
            '  "confidence": 0-100 integer,\n'
            '  "summary": "short analyst explanation",\n'
            '  "rationales": ["engine-backed rationale"],\n'
            '  "recommendations": ["analyst next step"]\n'
            "}\n\n"
            "Example confidence values: 0, 42, 85, 100.\n"
            'Invalid confidence values: 0.42, 0.85, 1.0, "85%".\n\n'
            f"Observable: {observable_json}\n"
            f"Cyberbro engine results: {engine_results_json}"
        )

    def _parse_provider_content(self, content: str, provider: str, model: str) -> AiVerdictResult:
        payload = self._load_json_object(content)
        payload["status"] = AiVerdictStatus.SUCCESS.value
        payload["provider"] = provider
        payload["model"] = model
        return AiVerdictResult.model_validate(payload)

    def _load_json_object(self, content: str) -> dict[str, object]:
        try:
            raw_payload = json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start == -1 or end == -1 or end <= start:
                raise
            raw_payload = json.loads(content[start : end + 1])

        if not isinstance(raw_payload, dict):
            raise TypeError("AI verdict response JSON must be an object.")

        return raw_payload

    def _result(
        self,
        status: AiVerdictStatus,
        summary: str,
        provider: str,
        model: str,
        verdict: AiVerdictValue = AiVerdictValue.UNKNOWN,
        severity: AiVerdictSeverity = AiVerdictSeverity.INFO,
        confidence: int = 0,
    ) -> dict[str, object]:
        result = AiVerdictResult(
            status=status,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            summary=summary,
            provider=provider,
            model=model,
        )
        return result.model_dump(mode="json")

    def create_export_row(self, analysis_result: object) -> dict[str, object]:
        if not isinstance(analysis_result, dict):
            return {
                "ai_verdict_status": "",
                "ai_verdict_verdict": "",
                "ai_verdict_severity": "",
                "ai_verdict_confidence": 0,
                "ai_verdict_summary": "",
                "ai_verdict_rationales": "",
                "ai_verdict_recommendations": "",
                "ai_verdict_provider": "",
                "ai_verdict_model": "",
            }

        return {
            "ai_verdict_status": analysis_result.get("status", ""),
            "ai_verdict_verdict": analysis_result.get("verdict", ""),
            "ai_verdict_severity": analysis_result.get("severity", ""),
            "ai_verdict_confidence": analysis_result.get("confidence", 0),
            "ai_verdict_summary": analysis_result.get("summary", ""),
            "ai_verdict_rationales": ", ".join(
                str(item) for item in analysis_result.get("rationales", [])
            ),
            "ai_verdict_recommendations": ", ".join(
                str(item) for item in analysis_result.get("recommendations", [])
            ),
            "ai_verdict_provider": analysis_result.get("provider", ""),
            "ai_verdict_model": analysis_result.get("model", ""),
        }
