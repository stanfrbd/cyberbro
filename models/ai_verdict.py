from enum import Enum

from pydantic import BaseModel, Field, field_validator

INSUFFICIENT_CONTEXT_MESSAGE = (
    "AI verdict should have multiple engines selected for better results. Use all available "
    "engines for stronger AI-assisted assessment."
)

TECHNICAL_CONTEXT_KEYS: set[str] = {"observable", "type", "reversed_success", "ai_verdict"}


class AiVerdictProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    MICROSOFT_FOUNDRY = "microsoft_foundry"
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    OPENAI_COMPATIBLE = "openai_compatible"


class AiVerdictStatus(str, Enum):
    SUCCESS = "success"
    DISABLED = "disabled"
    CONFIGURATION_ERROR = "configuration_error"
    PROVIDER_ERROR = "provider_error"
    INSUFFICIENT_CONTEXT = "insufficient_context"


class AiVerdictValue(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class AiVerdictSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AiVerdictResult(BaseModel):
    status: AiVerdictStatus
    verdict: AiVerdictValue = AiVerdictValue.UNKNOWN
    severity: AiVerdictSeverity = AiVerdictSeverity.INFO
    confidence: int = Field(default=0, ge=0, le=100)
    summary: str
    rationales: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    provider: str = ""
    model: str = ""

    @field_validator("rationales", "recommendations", mode="before")
    @classmethod
    def coerce_string_list(cls, value: object) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, str) and value:
            return [value]
        return []


class AiVerdictProviderRequest(BaseModel):
    prompt: str
    api_url: str
    api_key: str
    auth_header: str
    api_version: str
    model: str
    max_tokens: int
    timeout: int
    proxies: dict[str, str]
    ssl_verify: bool
