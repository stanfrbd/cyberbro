# Using Cyberbro MCP for LLM Integrations

## Overview

Cyberbro MCP is a Model Context Protocol (MCP) server that enables Large Language Models (LLMs) to extract, analyze, and check the reputation of Indicators of Compromise (IoCs) from unstructured input, leveraging multiple threat intelligence sources.

!!! info
    MCP is a standard that allows applications to provide context and functionality to LLMs in a secure, standardized way—similar to a web API, but designed for LLM integrations.

![mcp-cyberbro-demo](https://github.com/user-attachments/assets/99ee5538-c95a-40ca-bff5-3cdf3aa86235)

Checkout [Cyberbro](https://github.com/stanfrbd/cyberbro) repository for more information about the platform.

MCP servers can:

- Expose data through **Resources** (to load information into the LLM's context)
- Provide functionality through **Tools** (to execute code or perform actions)
- Define interaction patterns through **Prompts** (reusable templates for LLM interactions)

This server implements the Tools functionality of MCP, offering a suite of tools for extracting IoCs from text, analyzing them, and checking their reputation across various threat intelligence sources. It allows AI systems like Claude to retrieve, analyze, and act on threat intelligence in real-time.

## Key Features

- **Multi-Service Reputation Checks**: Query IPs, domains, hashes, URLs, and Chrome extension IDs across many threat intelligence sources.
- **Integrated Reporting**: Get detailed, exportable reports and analysis history.
- **Platform Integrations**: Supports Microsoft Defender for Endpoint, CrowdStrike, OpenCTI, and more.
- **Advanced Search & Visualization**: Search with Grep.App, check for breaches, and visualize results.
- Beginner-friendly and LLM-ready (no manual UI needed)
- Unique support for Chrome extension IDs and advanced TLD handling

## Installation

### Option 1: Using Docker (Recommended)

1. Export your Cyberbro config as an environment variable:
    ```sh
    export CYBERBRO_URL=http://localhost:5000
    export API_PREFIX=api
    ```
2. Pull the Docker image from GitHub Container Registry:
    ```sh
    docker pull ghcr.io/stanfrbd/mcp-cyberbro:latest
    ```

### Option 2: Local Installation

1. Clone this repository:
    ```sh
    git clone https://github.com/stanfrbd/mcp-cyberbro.git
    cd mcp-cyberbro
    ```
2. Install the required dependencies:
    ```sh
    uv run pip install -r requirements.txt
    ```
3. Set environment variables for MCP configuration **or** provide them as CLI arguments:

    **Option A: Using environment variables**
    ```sh
    export CYBERBRO_URL=http://localhost:5000
    export API_PREFIX=api
    ```

    **Option B: Using CLI arguments**
    ```sh
    uv run mcp-cyberbro-server.py --cyberbro_url http://localhost:5000 --api_prefix api
    ```

4. Start the MCP server:
    ```sh
    uv run mcp-cyberbro-server.py
    ```
    The server will listen for MCP protocol messages on stdin/stdout and use the environment variables as shown in the Claude Desktop configuration example.

#### Optional environment variables

- `SSL_VERIFY`: Set to `false` to disable SSL verification for the Cyberbro URL.
- `API_PREFIX`: Set to a custom prefix for the Cyberbro API.

#### Optional arguments

- `--no_ssl_verify`: Disable SSL verification for the Cyberbro URL.
- `--api_prefix`: Set a custom prefix for the Cyberbro API.

## Integration with Claude Desktop

### Using with Claude Desktop (Docker) - Recommended

!!! warning
    Make sure Docker is installed and running on your machine (e.g., Docker Desktop).

Add to your `claude_desktop_config.json`:

```json
"mcpServers": {
  "cyberbro": {
     "command": "docker",
     "args": [
        "run",
        "-i",
        "--rm",
        "-e",
        "CYBERBRO_URL",
        "-e",
        "API_PREFIX",
        "ghcr.io/stanfrbd/mcp-cyberbro:latest"
     ],
     "env": {
        "CYBERBRO_URL": "http://localhost:5000",
        "API_PREFIX": "api"
     }
  }
}
```

### Using with Claude Desktop (Local)

!!! warning
    While it can be launched with Python directly, use `venv` or `uv` to avoid conflicts with other Python packages.

```json
"mcpServers": {
  "cyberbro": {
     "command": "uv",
     "args": [
        "run",
        "C:\\Users\\path\\to\\mcp-cyberbro-server.py"
     ],
     "env": {
        "CYBERBRO_URL": "http://localhost:5000",
        "API_PREFIX": "api"
     }
  }
}
```

!!! tip
    **Make sure you have exported your Cyberbro config as environment variables** (e.g., `CYBERBRO_URL` and `API_PREFIX`) **before starting Claude Desktop**.

## Using with Other LLMs and MCP Clients

This MCP server can be used with any LLM or MCP client that supports the Model Context Protocol. The server listens for MCP protocol messages on stdin/stdout, making it compatible with various LLMs and clients. It is designed to work best with LLMs that can interpret and execute MCP commands correctly (e.g., Claude Desktop).

Documentation for other LLMs and MCP clients with Open Web UI: https://docs.openwebui.com/openapi-servers/mcp/

It uses an OpenAPI proxy to expose the MCP server as an OpenAPI server, allowing you to interact with it using standard HTTP requests.

### Example of usage with OpenAPI Proxy

!!! tip
    Install `mcpo` via `pip install mcpo` or via `uv`.

1. Create a `config.json` file in the mcp folder:
    ```json
    {
      "mcpServers": {
         "cyberbro": {
            "command": "uv",
            "args": [
              "run",
              "./mcp-cyberbro-server.py"
            ],
            "env": {
              "CYBERBRO_URL": "https://cyberbro.lab.local",
              "API_PREFIX": "api"
            }
         }
      }
    }
    ```
2. Run the MCP server:
    ```sh
    uvx mcpo --config config.json --port 8000
    ```
3. The server will start and listen for requests on port 8000. Access OpenAPI docs at `http://localhost:8000/docs`.

You can configure your MCP client to connect to the server at `http://localhost:8000/cyberbro`. The OpenAPI specification will be available at `http://localhost:8000/cyberbro/openapi.json`.

### Example with Open Web UI

!!! warning
    Use Native function calling and a MCP compatible model (e.g. OpenAI: `gpt-4o`).

![image](https://github.com/user-attachments/assets/3501449c-4153-427c-b927-872de01e73d7)

See: https://docs.openwebui.com/openapi-servers/open-webui#optional-step-4-use-native-function-calling-react-style-tool-use-

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
