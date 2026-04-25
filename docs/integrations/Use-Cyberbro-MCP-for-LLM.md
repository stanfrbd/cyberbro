# Using Cyberbro MCP for LLM Integrations

## Overview

Cyberbro MCP is a Model Context Protocol (MCP) server that enables Large Language Models (LLMs) to extract, analyze, and check the reputation of Indicators of Compromise (IoCs) from unstructured input, leveraging multiple threat intelligence sources.

!!! info
    MCP is a standard that allows applications to provide context and functionality to LLMs in a secure, standardized way—similar to a web API, but designed for LLM integrations.

![mcp-cyberbro-demo](https://github.com/user-attachments/assets/99ee5538-c95a-40ca-bff5-3cdf3aa86235)

MCP servers can:

- Expose data through **Resources** (to load information into the LLM's context)
- Provide functionality through **Tools** (to execute code or perform actions)
- Define interaction patterns through **Prompts** (reusable templates for LLM interactions)

This server implements the Tools functionality of MCP, offering a suite of tools for extracting IoCs from text, analyzing them, and checking their reputation across various threat intelligence sources. It allows AI systems like Claude to retrieve, analyze, and act on threat intelligence in real-time.

## Installation

The upstream [`mcp-cyberbro`](https://github.com/stanfrbd/mcp-cyberbro) project supports three common ways to run the MCP server.

### Standalone with `uvx`

```bash
uvx mcp-cyberbro --cyberbro_url http://localhost:5000
```

### Install with `pip`

```bash
pip install mcp-cyberbro
mcp-cyberbro --cyberbro_url http://localhost:5000
```

### Local development

```bash
pip install -e .
mcp-cyberbro --cyberbro_url http://localhost:5000
```

### Docker

The container starts in `streamable-http` mode on port `8000` by default.

```bash
docker run --rm -p 8000:8000 \
    -e CYBERBRO_URL=http://host.docker.internal:5000 \
    ghcr.io/stanfrbd/mcp-cyberbro:latest
```

To force `stdio` transport:

```bash
docker run -i --rm \
    -e CYBERBRO_URL=http://host.docker.internal:5000 \
    ghcr.io/stanfrbd/mcp-cyberbro:latest \
    --transport stdio
```

### Configuration

At minimum, set `CYBERBRO_URL` so the MCP server can reach your Cyberbro instance. The upstream project also supports optional values such as `API_PREFIX`, `SSL_VERIFY`, and transport-related settings like `MCP_TRANSPORT`, `MCP_HOST`, and `MCP_PORT`.

## MCP Client Integration

You can use this server with Claude Desktop, Claude Code, Cursor, OpenAI-compatible MCP clients, or any other MCP client.

Example config using `uvx`:

```json
{
  "mcpServers": {
    "cyberbro": {
      "command": "uvx",
      "args": ["mcp-cyberbro"],
      "env": {
        "CYBERBRO_URL": "http://localhost:5000"
      }
    }
  }
}
```

Example with Docker + `stdio`:

```json
{
  "mcpServers": {
    "cyberbro": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e",
        "CYBERBRO_URL",
        "ghcr.io/stanfrbd/mcp-cyberbro:latest",
        "--transport",
        "stdio"
      ],
      "env": {
        "CYBERBRO_URL": "http://localhost:5000"
      }
    }
  }
}
```

### Usage in VSCode - Example

Create `.vscode/mcp.json`  

```json
{
	"servers": {
		"mcp-cyberbro": {
			"type": "stdio",
			"command": "uvx",
			"args": [
				"mcp-cyberbro"
			],
			"env": {
				"CYBERBRO_URL": "http://127.0.0.1:5000"
			}
		}
	}
}
```

## Key Features

- **Multi-Service Reputation Checks**: Query IPs, domains, hashes, URLs, and Chrome extension IDs across many threat intelligence sources.
- **Integrated Reporting**: Get detailed, exportable reports and analysis history.
- **Platform Integrations**: Supports Microsoft Defender for Endpoint, CrowdStrike, OpenCTI, and more.
- **Advanced Search & Visualization**: Search with Grep.App, check for breaches, and visualize results.
- Beginner-friendly and LLM-ready (no manual UI needed)
- Unique support for Chrome extension IDs and advanced TLD handling

## Available Tools

The MCP server provides the following tools:

| Tool Name                | Description                                                                                  | Arguments                                      |
|--------------------------|----------------------------------------------------------------------------------------------|------------------------------------------------|
| **analyze_observable**   | Extracts and analyzes IoCs from input text using selected engines. Returns analysis ID.      | `text` (string), `engines` (list, optional)    |
| **is_analysis_complete** | Checks if the analysis for a given ID is finished. Returns status.                          | `analysis_id` (string)                         |
| **get_analysis_results** | Retrieves the results of a completed analysis by ID.                                         | `analysis_id` (string)                         |
| **get_engines**          | Lists available analysis engines supported by Cyberbro.                                      | *(none)*                                       |
| **get_web_url**          | Returns the web URL for the Cyberbro instance.                                               | `analysis_id` (string)                         |

## Example Queries

Here are some example queries you can run using the MCP server with an LLM like Claude:

### Getting Indicator Details

```
Cyberbro: Check indicators for target.com
```

```
Can you check this IP reputation with Cyberbro? 192.168.1.1
Use github, google and virustotal engines.
```

```
I want to analyze the domain example.com. What can Cyberbro tell me about it?
Use max 3 engines.
```

```
Analyze these observables with Cyberbro: suspicious-domain.com, 8.8.8.8, and 44d88612fea8a8f36de82e1278abb02f.  
Use all available engines.
```

### Observable Analysis

```
I found this (hash|domain|url|ip|extension)  
Can you submit it for analysis to Cyberbro and analyze the results?
```

These example queries show how Cyberbro leverages LLMs to interpret your intent and automatically select the right MCP tools, allowing you to interact with Cyberbro easily—without needing to make the analysis yourself.

### OSINT investigation

```
Create an OSINT report for the domain example.com using Cyberbro.
Use all available engines and pivot on the results for more information.
Use a maximum of 10 analysis requests.
```

## Resources

- [Cyberbro MCP GitHub](https://github.com/stanfrbd/mcp-cyberbro)
- [Cyberbro](https://github.com/stanfrbd/cyberbro)
- [Model Context Protocol](https://modelcontextprotocol.io)

Licensed under MIT. See the repo for details.
