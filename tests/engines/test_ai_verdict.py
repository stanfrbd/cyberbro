import responses

from engines.ai_verdict import INSUFFICIENT_CONTEXT_MESSAGE, AiVerdictEngine
from models.observable import Observable, ObservableType
from utils.config import Secrets


def make_engine(secrets: Secrets) -> AiVerdictEngine:
    return AiVerdictEngine(secrets, {}, True)


def make_context() -> dict[str, object]:
    return {
        "observable": Observable(value="badsite.com", type=ObservableType.FQDN),
        "type": ObservableType.FQDN,
        "virustotal": {"total_malicious": 5, "detection_ratio": "5/90"},
        "abuseipdb": {"risk_score": 80},
    }


def test_ai_verdict_disabled() -> None:
    engine = make_engine(Secrets(ai_verdict_enabled=False))

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "disabled"
    assert result["verdict"] == "unknown"
    assert result["severity"] == "info"


def test_ai_verdict_missing_key_for_openai() -> None:
    secrets = Secrets(ai_verdict_enabled=True, ai_verdict_provider="openai")
    engine = make_engine(secrets)

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "configuration_error"
    assert "API key" in str(result["summary"])


def test_ai_verdict_openai_compatible_requires_url() -> None:
    secrets = Secrets(ai_verdict_enabled=True, ai_verdict_provider="openai_compatible")
    engine = make_engine(secrets)

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "configuration_error"
    assert "API URL" in str(result["summary"])


def test_ai_verdict_insufficient_context() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="openai_compatible",
        ai_verdict_api_url="http://localhost:11434/v1/chat/completions",
    )
    engine = make_engine(secrets)

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN),
        {"ai_verdict": {"status": "success"}},
    )

    assert result["status"] == "insufficient_context"
    assert result["summary"] == INSUFFICIENT_CONTEXT_MESSAGE


@responses.activate
def test_ai_verdict_openai_compatible_success() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="openai_compatible",
        ai_verdict_api_url="http://localhost:11434/v1/chat/completions",
        ai_verdict_model="local-model",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "http://localhost:11434/v1/chat/completions",
        json={
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"verdict":"suspicious","severity":"high","confidence":85,'
                            '"summary":"Multiple engines report suspicious signals.",'
                            '"rationales":["VirusTotal has 5 detections"],'
                            '"recommendations":["Investigate before blocking"]}'
                        )
                    }
                }
            ]
        },
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "success"
    assert result["verdict"] == "suspicious"
    assert result["severity"] == "high"
    assert result["confidence"] == 85
    assert result["provider"] == "openai_compatible"
    assert result["model"] == "local-model"


@responses.activate
def test_ai_verdict_openai_compatible_accepts_base_url() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="openai_compatible",
        ai_verdict_api_url="http://localhost:8000",
        ai_verdict_model="local-model",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "http://localhost:8000/v1/chat/completions",
        json={
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"verdict":"suspicious","severity":"medium","confidence":75,'
                            '"summary":"Signals require review.",'
                            '"rationales":["Engine context has mixed results"],'
                            '"recommendations":["Review manually"]}'
                        )
                    }
                }
            ]
        },
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "success"
    assert result["provider"] == "openai_compatible"


@responses.activate
def test_ai_verdict_ollama_accepts_base_url() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="ollama",
        ai_verdict_api_url="http://localhost:11434",
        ai_verdict_model="llama3.1",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "http://localhost:11434/v1/chat/completions",
        json={
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"verdict":"benign","severity":"low","confidence":80,'
                            '"summary":"No strong malicious evidence.",'
                            '"rationales":["Selected engines are mostly clean"],'
                            '"recommendations":["Monitor only"]}'
                        )
                    }
                }
            ]
        },
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "success"
    assert result["provider"] == "ollama"


@responses.activate
def test_ai_verdict_ollama_accepts_chat_completions_url() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="ollama",
        ai_verdict_api_url="http://localhost:11434/v1/chat/completions",
        ai_verdict_model="llama3.1",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "http://localhost:11434/v1/chat/completions",
        json={
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"verdict":"benign","severity":"low","confidence":80,'
                            '"summary":"No strong malicious evidence.",'
                            '"rationales":["Selected engines are mostly clean"],'
                            '"recommendations":["Monitor only"]}'
                        )
                    }
                }
            ]
        },
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "success"
    assert result["provider"] == "ollama"


@responses.activate
def test_ai_verdict_lm_studio_accepts_v1_base_url() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="lm_studio",
        ai_verdict_api_url="http://localhost:1234/v1",
        ai_verdict_model="local-model",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "http://localhost:1234/v1/chat/completions",
        json={
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"verdict":"benign","severity":"low","confidence":80,'
                            '"summary":"No strong malicious evidence.",'
                            '"rationales":["Selected engines are mostly clean"],'
                            '"recommendations":["Monitor only"]}'
                        )
                    }
                }
            ]
        },
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "success"
    assert result["provider"] == "lm_studio"


@responses.activate
def test_ai_verdict_microsoft_foundry_success_with_api_key_header() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="microsoft_foundry",
        ai_verdict_api_url="https://example-resource.openai.azure.com/openai/v1/chat/completions",
        ai_verdict_api_key="foundry-key",
        ai_verdict_api_version="preview",
        ai_verdict_model="gpt-4o-mini",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "https://example-resource.openai.azure.com/openai/v1/chat/completions?api-version=preview",
        json={
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"verdict":"suspicious","severity":"medium","confidence":65,'
                            '"summary":"Mixed signals require review.",'
                            '"rationales":["One reputation source has detections"],'
                            '"recommendations":["Review before action"]}'
                        )
                    }
                }
            ]
        },
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "success"
    assert result["provider"] == "microsoft_foundry"
    assert responses.calls[0].request.headers["api-key"] == "foundry-key"


@responses.activate
def test_ai_verdict_google_success() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="google",
        ai_verdict_api_key="google-key",
        ai_verdict_model="gemini-2.5-flash",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        json={
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": (
                                    '{"verdict":"benign","severity":"low","confidence":80,'
                                    '"summary":"No meaningful malicious evidence.",'
                                    '"rationales":["Selected engines are mostly clean"],'
                                    '"recommendations":["Monitor only"]}'
                                )
                            }
                        ]
                    }
                }
            ]
        },
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "success"
    assert result["provider"] == "google"
    assert result["verdict"] == "benign"
    assert responses.calls[0].request.headers["x-goog-api-key"] == "google-key"


@responses.activate
def test_ai_verdict_anthropic_success() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="anthropic",
        ai_verdict_api_key="test-key",
        ai_verdict_model="claude-sonnet-4-5",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "https://api.anthropic.com/v1/messages",
        json={
            "content": [
                {
                    "type": "text",
                    "text": (
                        '{"verdict":"benign","severity":"low","confidence":70,'
                        '"summary":"No strong malicious evidence.",'
                        '"rationales":["Only weak signals"],"recommendations":[]}'
                    ),
                }
            ]
        },
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "success"
    assert result["verdict"] == "benign"
    assert result["severity"] == "low"
    assert result["confidence"] == 70
    assert result["provider"] == "anthropic"


@responses.activate
def test_ai_verdict_invalid_json_response() -> None:
    secrets = Secrets(
        ai_verdict_enabled=True,
        ai_verdict_provider="openai_compatible",
        ai_verdict_api_url="http://localhost:11434/v1/chat/completions",
    )
    engine = make_engine(secrets)
    responses.add(
        responses.POST,
        "http://localhost:11434/v1/chat/completions",
        json={"choices": [{"message": {"content": "not json"}}]},
        status=200,
    )

    result = engine.analyze(
        Observable(value="badsite.com", type=ObservableType.FQDN), make_context()
    )

    assert result["status"] == "provider_error"
    assert "invalid JSON" in str(result["summary"])


def test_ai_verdict_export_row_with_data() -> None:
    engine = make_engine(Secrets())

    row = engine.create_export_row(
        {
            "status": "success",
            "verdict": "malicious",
            "severity": "critical",
            "confidence": 95,
            "summary": "Strong malicious evidence.",
            "rationales": ["VirusTotal detections", "Bad ASN match"],
            "recommendations": ["Block observable"],
            "provider": "openai",
            "model": "gpt-4.1-mini",
        }
    )

    assert row["ai_verdict_status"] == "success"
    assert row["ai_verdict_verdict"] == "malicious"
    assert row["ai_verdict_rationales"] == "VirusTotal detections, Bad ASN match"
    assert row["ai_verdict_recommendations"] == "Block observable"


def test_ai_verdict_export_row_without_data() -> None:
    engine = make_engine(Secrets())

    row = engine.create_export_row(None)

    assert row["ai_verdict_status"] == ""
    assert row["ai_verdict_confidence"] == 0
