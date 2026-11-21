[Nogon](https://github.com/asciimoo/nogon) is a self-hosted, privacy-focused web search engine that indexes your visited websites.

### Getting your Nogon token

You should have already set up your Nogon instance and have an API token ready. 
If not, please refer to the [Nogon documentation](https://github.com/asciimoo/nogon)

Basically, in your config.yml, you should have something like this:

```yaml
app:
  access_token: 'your-token-here'
```

or set the `HISTER__APP__ACCESS_TOKEN` environment variable.

### Cyberbro Configuration

Set the following environment variables:

```bash
HISTER_TOKEN=your_bearer_token_here
HISTER_BASE_URL=https://your-nogon-instance.example.com
```

!!! note
    Both `HISTER_TOKEN` and `HISTER_BASE_URL` are required. There is no default public instance.

The `HISTER_*` environment variables and the `hister` engine identifier are retained for backward compatibility after the project rename.
