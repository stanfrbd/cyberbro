## Overview

The **AI Verdict** engine synthesizes results from other Cyberbro engines and sends them to a configured AI provider to produce a consolidated threat assessment for the analyzed observable.

It supports the following observable types: IPv4, IPv6, FQDN, URL, Email, MD5, SHA1, SHA256, Chrome Extension, Bogon.

!!! warning "Context requirement"
    AI Verdict requires **at least two other engine results** to produce a verdict. Running it alone returns an `insufficient_context` status.

---

## How It Works

```
analyze()
  │
  ├─ Check ai_verdict_enabled → disabled (early return)
  ├─ Validate provider name   → configuration_error (early return)
  ├─ Validate provider config → configuration_error (early return)
  ├─ Extract engine results from context
  │     └─ skip technical keys: observable, type, reversed_success, ai_verdict
  │     └─ skip null/empty values
  │     └─ < 2 results → insufficient_context (early return)
  │
  ├─ Build prompt
  │     └─ custom base prompt (ai_verdict_prompt) + observable JSON
  │        + engine results JSON + strict output schema instructions
  │
  ├─ Query AI provider → provider_error on HTTP / parsing failure
  │
  └─ Parse JSON response → AiVerdictResult → return as dict
```

The prompt instructs the model to return **raw JSON only** (no Markdown fences), conforming to a fixed schema. Temperature is set to `0` for determinism.

---

## Providers

| Provider | Key | Notes |
|---|---|---|
| OpenAI | `openai` | Requires API key; uses `https://api.openai.com` |
| Anthropic | `anthropic` | Requires API key; uses Messages API |
| Google | `google` | Requires API key; uses Gemini API |
| Microsoft Foundry | `microsoft_foundry` | Requires API key + API URL; supports `api-version` |
| Ollama | `ollama` | No API key required; local inference |
| LM Studio | `lm_studio` | No API key required; local inference |
| OpenAI-compatible | `openai_compatible` | Any endpoint following the OpenAI `/chat/completions` schema |

OpenAI-compatible providers (Ollama, LM Studio, generic) share a common base that auto-normalizes the API URL to `.../v1/chat/completions`.

---

## Result Schema

| Field | Type | Values |
|---|---|---|
| `status` | enum | `success`, `disabled`, `configuration_error`, `provider_error`, `insufficient_context` |
| `verdict` | enum | `malicious`, `suspicious`, `benign`, `unknown` |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | integer | 0–100 |
| `summary` | string | Short analyst explanation |
| `rationales` | list[string] | Engine-backed justifications |
| `recommendations` | list[string] | Analyst next steps |
| `provider` | string | Provider name used |
| `model` | string | Model name used |

---

## Configuration

All settings are controlled via application secrets / environment variables:

| Setting | Description |
|---|---|
| `ai_verdict_enabled` | Enable/disable the engine |
| `ai_verdict_provider` | Provider key (see table above) |
| `ai_verdict_model` | Model name (e.g. `gpt-4o`, `claude-opus-4-5`) |
| `ai_verdict_api_url` | Base URL (required for self-hosted / Azure providers) |
| `ai_verdict_api_key` | API key |
| `ai_verdict_auth_header` | Custom auth header (default: `Authorization: Bearer`) |
| `ai_verdict_api_version` | API version string (Microsoft Foundry / Azure) |
| `ai_verdict_prompt` | Custom system prompt prepended to every request |
| `ai_verdict_max_tokens` | Max tokens for the model response |
| `ai_verdict_timeout` | HTTP timeout in seconds |

---

## Export Fields

| Column | Description |
|---|---|
| `ai_verdict_status` | Engine status |
| `ai_verdict_verdict` | Threat verdict |
| `ai_verdict_severity` | Severity level |
| `ai_verdict_confidence` | Confidence (0–100) |
| `ai_verdict_summary` | Summary text |
| `ai_verdict_rationales` | Comma-separated rationales |
| `ai_verdict_recommendations` | Comma-separated recommendations |
| `ai_verdict_provider` | Provider used |
| `ai_verdict_model` | Model used |
