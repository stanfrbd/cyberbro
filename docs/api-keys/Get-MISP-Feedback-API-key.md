## How to Get MISP-Feedback Authentication Token

MISP-Feedback is a warninglist verification service that checks observables (IPs, domains, hashes) against MISP warninglists to identify false positives. The service does not require authentication by default, but can be deployed behind a reverse proxy or authentication gateway that uses HTTP Basic Authentication.

## Overview

- **Authentication Type:** Optional HTTP Basic Authentication
- **Default:** No authentication required
- **When Required:** If your MISP-Feedback service is deployed behind a reverse proxy, API gateway, or authentication layer

## Configuration

MISP-Feedback uses two environment variables:

1. **MISP_FEEDBACK_SERVER_URL** - The URL of your MISP-Feedback service (required)
2. **MISP_FEEDBACK_TOKEN** - Authentication token (optional)

## Setting Up Without Authentication

If your MISP-Feedback service is directly accessible without authentication:

1. **Set the Server URL:**
   ```
   MISP_FEEDBACK_SERVER_URL=http://localhost:3000
   ```
   Or for a remote instance:
   ```
   MISP_FEEDBACK_SERVER_URL=https://misp-feedback.example.com
   ```

2. Leave `MISP_FEEDBACK_TOKEN` empty:
   ```
   MISP_FEEDBACK_TOKEN=
   ```

## Setting Up With Authentication

If your MISP-Feedback service is behind an authentication gateway (e.g., reverse proxy, API gateway, SSO provider):

### 1. Obtain Authentication Credentials

Contact your MISP-Feedback service administrator or infrastructure team to obtain your authentication token. This token might be:
- A Bearer token from an OAuth/OIDC provider
- An API key from your API gateway
- A credential from your reverse proxy configuration
- Any other authentication mechanism your deployment uses

### 2. Configure the Token

Set the `MISP_FEEDBACK_TOKEN` environment variable with your authentication token:

```
MISP_FEEDBACK_SERVER_URL=https://misp-feedback.example.com
MISP_FEEDBACK_TOKEN=your_authentication_token_here
```

### 3. How It Works

When a token is configured:
- Cyberbro sends a request with HTTP Basic Authentication
- The token is used as the password component (username is empty)
- The authentication header is sent in the format: `Authorization: Basic base64(":your_token")`

This approach works with most reverse proxies, API gateways, and authentication layers that support HTTP Basic Auth.

## Example Deployments

### Local Development (No Auth)
```
MISP_FEEDBACK_SERVER_URL=http://localhost:3000
MISP_FEEDBACK_TOKEN=
```

### Behind Reverse Proxy (With Auth)
```
MISP_FEEDBACK_SERVER_URL=https://misp-feedback.company.com
MISP_FEEDBACK_TOKEN=abc123def456ghi789
```

### Docker Compose
In your `docker-compose.yml`, you can set these as environment variables:
```yaml
environment:
  - MISP_FEEDBACK_SERVER_URL=http://misp-feedback:3000
  - MISP_FEEDBACK_TOKEN=
```

## Testing Your Configuration

To verify your MISP-Feedback integration is working:

1. In Cyberbro, select the MISP-Feedback engine
2. Analyze an observable (IP, domain, or hash)
3. Check the results for the MISP-Feedback status

## Troubleshooting

- **Connection Refused:** Verify that `MISP_FEEDBACK_SERVER_URL` is correct and the service is running
- **Authentication Failed:** Check that your `MISP_FEEDBACK_TOKEN` is correct if using authentication
- **Empty Results:** The observable may not match any MISP warninglists (this is expected and returns CLEAN status)

!!! note
    The MISP-Feedback service is designed to be deployed privately within your infrastructure. Ensure proper network security and access controls are in place.
