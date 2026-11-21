[Nogon](https://nogon.eu) is a self-hosted search engine that indexes your visited websites and other content you import.

### Getting your Nogon token

Set up your instance using the [Nogon documentation](https://nogon.eu/docs). In single-user mode, configure an access token in Nogon's `config.yml`:

```yaml
app:
  access_token: 'your-token-here'
```

You can also set `NOGON__APP__ACCESS_TOKEN` on the Nogon server. If user handling is enabled, use the personal access token for the account whose index Cyberbro should search.

### Cyberbro configuration

Set both variables in Cyberbro's environment:

```dotenv
NOGON_BASE_URL=https://nogon.example.com
NOGON_TOKEN=your_bearer_token_here
```

Include the path prefix if your instance runs under one. Cyberbro sends the token as a bearer credential and uses the `nogon` engine identifier for API requests and GUI configuration.

This migration is a breaking change. Replace the previous engine identifier and environment settings with the Nogon values above.
