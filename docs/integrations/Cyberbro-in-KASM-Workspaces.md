# Cyberbro has now a KASM Workspaces version

!!! info
    Kasm Workspaces is a docker container streaming platform for delivering browser-based access to desktops, applications, and web services.  
    See more on: [https://hub.docker.com/u/kasmweb](https://hub.docker.com/u/kasmweb) for the other images provided.

## Demo

![cyberbro_kasm](https://github.com/user-attachments/assets/c07cf40f-2018-455c-9f37-1c96832e9924)

## Installation

### Images for Cyberbro on DockerHub are built regularly

* Link: https://hub.docker.com/r/stanfrbd/cyberbro

### Configuration of the Workspace in KASM

```
Cores: default
Memory: default
Docker Registry: https://index.docker.io/v1/
Docker image: stanfrbd/cyberbro:latest
Thumnail URL: https://pbs.twimg.com/profile_images/1865474886505742336/Dzn6HiOA_400x400.jpg
Categories: Security
```

### Example of config in the KASM GUI

![image](https://github.com/user-attachments/assets/ae362f5e-c96b-4677-a1c0-4cadfb5b5148)

![image](https://github.com/user-attachments/assets/f6ffb648-e161-4c59-9359-51183b0b0ca0)

## Environment Variables

### Firefox Configuration

* `FIREFOX_APP_ARGS` - Additional arguments to pass to firefox when launched.

### Cyberbro Configuration with optional environment variables

Here is a list of all available environment variables that can be used with examples:

```bash
PROXY_URL=http://127.0.0.1:9000
VIRUSTOTAL=api_key_here
ABUSEIPDB=api_key_here
IPINFO=api_key_here
GOOGLE_SAFE_BROWSING=api_key_here
MDE_TENANT_ID=api_key_here
MDE_CLIENT_ID=api_key_here
MDE_CLIENT_SECRET=api_key_here
SHODAN=api_key_here
OPENCTI_API_KEY=api_key_here
OPENCTI_URL=https://demo.opencti.io
CROWDSTRIKE_CLIENT_ID=client_id_here
CROWDSTRIKE_CLIENT_SECRET=client_secret_here
CROWDSTRIKE_FALCON_BASE_URL=https://falcon.crowdstrike.com
WEBSCOUT=token_here
API_PREFIX=my_api
MAX_FORM_MEMORY_SIZE=1048576
GUI_ENABLED_ENGINES=reverse_dns,rdap,hudsonrock,mde,shodan,opencti,virustotal
CONFIG_PAGE_ENABLED=true
SSL_VERIFY=true
GUI_CACHE_TIMEOUT=1800
API_CACHE_TIMEOUT=86400
```

> Note: if you set `GUI_ENABLED_ENGINES` to `""` then all engines will be enabled in the GUI.  
> By default (even if the variable is not set or enabled), all **free engines** will be enabled in the GUI.

Refer to [https://docs.cyberbro.net/](https://docs.cyberbro.net/) for more information.

You must edit the config in your KASM Cyberbro Workspace settings to add these environment variables, according to [KASM Workspaces documentation examples](https://kasmweb.com/docs/latest/guide/workspaces.html#examples)

![image](https://github.com/user-attachments/assets/33125248-31e8-4315-a772-e0546a8be659)

