# Configure AI Verdict

AI Verdict is disabled by default. Enable it only if you want Cyberbro to send selected engine results to an AI provider for a final analyst-style summary.

## Common variables

```bash
AI_VERDICT_ENABLED=true
AI_VERDICT_PROVIDER=openai
AI_VERDICT_API_URL=
AI_VERDICT_API_KEY=your_key_here
AI_VERDICT_AUTH_HEADER=
AI_VERDICT_API_VERSION=
AI_VERDICT_MODEL=gpt-4.1-mini
AI_VERDICT_PROMPT=You are a senior CTI analyst. Review the Cyberbro engine results and return a concise JSON verdict for the observable.
AI_VERDICT_MAX_TOKENS=1000
AI_VERDICT_TIMEOUT=30
```

Supported providers:

- `openai`
- `anthropic`
- `google`
- `microsoft_foundry`
- `ollama`
- `lm_studio`
- `openai_compatible`

AI Verdict should be used with multiple selected engines. If it is selected alone, Cyberbro returns an `insufficient_context` result.

For OpenAI-compatible providers (`openai`, `ollama`, `lm_studio`, `openai_compatible`), `AI_VERDICT_API_URL` accepts either the full chat completion endpoint or a base URL:

| Input URL | URL used by Cyberbro |
| --- | --- |
| `http://localhost:11434` | `http://localhost:11434/v1/chat/completions` |
| `http://localhost:11434/v1` | `http://localhost:11434/v1/chat/completions` |
| `http://localhost:11434/v1/chat/completions` | unchanged |

If Cyberbro runs in Docker and the AI provider runs on the host machine, do not use `localhost` in `AI_VERDICT_API_URL`: inside Docker, `localhost` means the Cyberbro container. Use `host.docker.internal` instead.

## OpenAI

```bash
AI_VERDICT_PROVIDER=openai
AI_VERDICT_API_KEY=sk-...
AI_VERDICT_MODEL=gpt-4.1-mini
```

Default URL: `https://api.openai.com/v1/chat/completions`.

You may override it with either:

```bash
AI_VERDICT_API_URL=https://api.openai.com
```

or:

```bash
AI_VERDICT_API_URL=https://api.openai.com/v1/chat/completions
```

## Anthropic

```bash
AI_VERDICT_PROVIDER=anthropic
AI_VERDICT_API_KEY=sk-ant-...
AI_VERDICT_MODEL=claude-sonnet-4-5
```

Default URL: `https://api.anthropic.com/v1/messages`.

## Google Gemini

```bash
AI_VERDICT_PROVIDER=google
AI_VERDICT_API_KEY=your_gemini_api_key
AI_VERDICT_MODEL=gemini-2.5-flash
```

Default URL: `https://generativelanguage.googleapis.com/v1beta/models/<model>:generateContent`.

## Microsoft Foundry

Microsoft Foundry can be used with either Azure OpenAI v1 endpoints or Foundry model inference chat completion endpoints.

Azure OpenAI v1 endpoint:

```bash
AI_VERDICT_PROVIDER=microsoft_foundry
AI_VERDICT_API_URL=https://<resource>.openai.azure.com/openai/v1/chat/completions
AI_VERDICT_API_KEY=your_foundry_key
AI_VERDICT_MODEL=<deployment_name>
```

By default, Cyberbro sends the key in the `api-key` header for Microsoft Foundry. If your endpoint uses bearer tokens instead, set:

```bash
AI_VERDICT_AUTH_HEADER=authorization
```

Azure OpenAI deployment route:

```bash
AI_VERDICT_API_URL=https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2025-04-01-preview
```

Foundry model inference route:

```bash
AI_VERDICT_API_URL=https://<resource>.services.ai.azure.com/models/chat/completions
AI_VERDICT_API_VERSION=2024-05-01-preview
AI_VERDICT_MODEL=<model_or_deployment_name>
```

Microsoft Foundry is intentionally not base-URL-normalized by Cyberbro because Foundry/Azure OpenAI deployments can use different routes. Provide the full chat completion URL for your deployment. If `AI_VERDICT_API_VERSION` is set and the URL does not already include `api-version=`, Cyberbro appends it as a query parameter.

## Ollama

```bash
AI_VERDICT_PROVIDER=ollama
AI_VERDICT_MODEL=gemma4:latest
```

Default URL: `http://localhost:11434/v1/chat/completions`.

If Cyberbro runs directly on the same host as Ollama, the default URL is enough. These values are equivalent:

```bash
AI_VERDICT_API_URL=http://localhost:11434
AI_VERDICT_API_URL=http://localhost:11434/v1
AI_VERDICT_API_URL=http://localhost:11434/v1/chat/completions
```

Use the exact model name returned by Ollama, for example `gemma4:latest`, `llama3.1:latest`, or another value from:

```bash
ollama list
```

If Cyberbro runs in Docker and Ollama runs on the host, use:

```bash
AI_VERDICT_API_URL=http://host.docker.internal:11434
```

On Linux, the default `docker-compose.yml` maps `host.docker.internal` to the Docker host with `host-gateway`.

## LM Studio

```bash
AI_VERDICT_PROVIDER=lm_studio
AI_VERDICT_MODEL=local-model
```

Default URL: `http://localhost:1234/v1/chat/completions`.

If Cyberbro runs directly on the same host as LM Studio, these values are equivalent:

```bash
AI_VERDICT_API_URL=http://localhost:1234
AI_VERDICT_API_URL=http://localhost:1234/v1
AI_VERDICT_API_URL=http://localhost:1234/v1/chat/completions
```

If Cyberbro runs in Docker and LM Studio runs on the host, use:

```bash
AI_VERDICT_API_URL=http://host.docker.internal:1234
```

## OpenAI-compatible providers

Use this for vLLM, LocalAI, OpenRouter, Mistral-compatible gateways, LiteLLM, or any custom service that exposes an OpenAI-style `/chat/completions` endpoint.

```bash
AI_VERDICT_PROVIDER=openai_compatible
AI_VERDICT_API_URL=https://your-provider.example/v1/chat/completions
AI_VERDICT_API_KEY=optional_or_required_key
AI_VERDICT_MODEL=your-model-name
```

Base URLs are accepted here too:

```bash
AI_VERDICT_API_URL=http://localhost:8000
```

Cyberbro will call `http://localhost:8000/v1/chat/completions`.
