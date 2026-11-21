[Nogon](https://nogon.eu) is a self-hosted, privacy-focused web search engine that indexes your visited websites.

### Getting your Nogon token

You should have already set up your Nogon instance and have an API token ready. 
If not, please refer to the [Nogon documentation](https://nogon.eu/docs)

Basically, in your config.yml, you should have something like this:

```yaml
app:
  access_token: 'your-token-here'
```

or set the `NOGON__APP__ACCESS_TOKEN` environment variable.

### Cyberbro Configuration

Set the following environment variables:

```bash
NOGON_TOKEN=your_bearer_token_here
NOGON_BASE_URL=https://your-nogon-instance.example.com
```

!!! note
    Both `NOGON_TOKEN` and `NOGON_BASE_URL` are required. There is no default public instance.

Use the `NOGON_*` environment variables and the `nogon` engine identifier. Previous `HISTER_*` settings and `hister` identifiers are no longer supported.
