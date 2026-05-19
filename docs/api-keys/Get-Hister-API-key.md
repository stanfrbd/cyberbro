[Hister](https://hister.org) is a self-hosted, privacy-focused web search engine that indexes your visited websites.

### Getting your Hister token

You should have already set up your Hister instance and have an API token ready. 
If not, please refer to the [Hister documentation](https://hister.org/docs/configuration#access-token)

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
HISTER_BASE_URL=https://your-hister-instance.example.com
```

!!! note
    Both `HISTER_TOKEN` and `HISTER_BASE_URL` are required. There is no default public instance.
