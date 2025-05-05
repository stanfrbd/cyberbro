<h1 align="center">Cyberbro</h1>

<p align="center">
<img src="https://github.com/user-attachments/assets/5e5a4406-99c1-47f1-a726-de176baa824c" width="90" /><br />
<b><i>A simple application that extracts your IoCs from garbage input and checks their reputation using multiple services.</i></b>
<br />
<b>🌐 <a href="https://demo.cyberbro.net/">demo.cyberbro.net</a></b><br />

</p>

---

<p align="center">
  <a href="https://github.com/stanfrbd/cyberbro/stargazers">
    <img src="https://img.shields.io/github/stars/stanfrbd/cyberbro?style=social" alt="GitHub stars">
  </a>
  <a href="https://x.com/cyberbro_cti">
    <img src="https://img.shields.io/twitter/follow/cyberbro_cti?style=social" alt="Follow on X/Twitter">
  </a>
  <a href="https://infosec.exchange/@cyberbro">
    <img src="https://img.shields.io/badge/Follow_@cyberbro-23-blue?logo=mastodon" alt="Mastodon">
  </a>
  <a href="https://github.com/stanfrbd/cyberbro/issues">
    <img src="https://img.shields.io/github/issues/stanfrbd/cyberbro" alt="GitHub issues">
  </a>
  <a href="https://github.com/stanfrbd/cyberbro/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/stanfrbd/cyberbro" alt="License">
  </a>
  <a href="https://github.com/stanfrbd/cyberbro/actions/workflows/jobs.yml">
    <img src="https://github.com/stanfrbd/cyberbro/actions/workflows/jobs.yml/badge.svg" alt="example branch parameter">
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.13-blue?logo=python" alt="Python">
  </a>
</p>

---

# About

Inspired by [Cybergordon](https://cybergordon.com/) and [IntelOwl](https://github.com/intelowlproject/IntelOwl).

This project aims to provide a simple and efficient way to check the reputation of your observables using multiple services,
without having to deploy a **complex** solution.

# Demo

## New graph feature

![cyberbro_graph](https://github.com/user-attachments/assets/0b4e46d0-64ad-4950-8520-c5b2f5102206)

## Bulk

![cyberbro_gh](https://github.com/user-attachments/assets/d82a021c-a199-4f07-ab26-7af8e1b650a0)

# Features

* **Effortless Input Handling**: Paste raw logs, IoCs, or fanged IoCs, and let our regex parser do the rest.
* **Multi-Service Reputation Checks**: Verify observables (IP, hash, domain, URL, Chrome extension IDs) across multiple services like OpenCTI, VirusTotal, AbuseIPDB, IPInfo, Spur.us, MDE, Google Safe Browsing, Shodan, Abusix, Phishtank, ThreatFox, URLscan, Github, Google...
* **Detailed Reports**: Generate comprehensive reports with advanced search and filter options.
* **High Performance**: Leverage multithreading for faster processing.
* **Automated Observable Pivoting**: Automatically pivot on domains, URL and IP addresses using reverse DNS and RDAP.
* **Accurate Domain Info**: Retrieve precise domain information from ICANN RDAP (next generation whois).
* **Abuse Contact Lookup**: Accurately find abuse contacts for IPs, URLs, and domains.
* **Export Options**: Export results to CSV and **autofiltered well formatted** Excel files.
* **MDE Integration**: Check if observables are flagged on your Microsoft Defender for Endpoint (MDE) tenant.
* **CrowdStrike Integration**: Check if observables are flagged on your CrowdStrike tenant.
* **OpenCTI Integration**: Get stats (number of incidents, indicators) from OpenCTI and the latest Indicator if available.
* **Proxy Support**: Use a proxy if required.
* **Data Storage**: Store results in a SQLite database.
* **Grep.App**: Search for observables with Grep.App API (fast GitHub searches).
* **Hudson Rock**: Check if an email / domain was part of a data breach or was victim of an infostealer.
* **Analysis History**: Maintain a history of analyses with easy retrieval and search functionality.
* **Graph view**: view your analysis as a graph (experimental)

# What Cyberbro does that others don't

* **Accessible to everyone** from beginners to experts. No gatekeeping here.
* **Chrome extensions IDs lookup**: Retrieve the name of Chrome extensions from ID, and get CTI data about it.
* **Lightweight & Easy Deployment**: Simple to set up and use.
* **Advanced TLD Verification**: Uses `tldextract` to accurately extract root domains, helping RDAP lookups.
* **Pragmatic Information Gathering**: Utilizes GitHub and Google indexed results to catch what other engines might miss.
* **CTI Report Integration**: Leverages IoC.One for IoC-related **CTI reports** in HTML or PDF.
* **EDR Integration**: Integrates with solutions like Microsoft Defender for Endpoint or CrowdStrike to check if observables were seen in YOUR environment.


# Getting Started - TL;DR

> [!TIP]
> If you are lazy, you need Docker. \
> Do a `git clone` ; copy `secrets-sample.json` to `secrets.json` ; `docker compose up` then go to `localhost:5000`. Yep, that's it!

# Getting Started

* To get started, clone the repository

```bash
git clone https://github.com/stanfrbd/cyberbro
cd cyberbro
```

## Edit the config file (mandatory)

```
cp secrets-sample.json secrets.json
```

> [!NOTE]
> Don't have API keys? No problem, just copy the `secrets-sample.json` to `secrets.json` and leave all like this. Be careful if a proxy is used. \
> You will be able to use **all free engines!**

* Fill values (including proxy if needed) in the `secrets.json` file.

```json
{
    "abuseipdb": "token_here",
    "alienvault": "token_here",
    "criminalip_api_key": "token_here",
    "crowdstrike_client_id": "client_id_here",
    "crowdstrike_client_secret": "client_secret_here",
    "google_safe_browsing": "token_here",
    "ipinfo": "token_here",
    "mde_client_id": "client_id_here",
    "mde_client_secret": "client_secret_here",
    "mde_tenant_id": "tenant_here",
    "opencti_api_key": "token_here",
    "opencti_url": "https://demo.opencti.io",
    "proxy_url": "",
    "shodan": "token_here",
    "virustotal": "token_here",
    "webscout": "token_here"
}

```

* Obtain API keys from the official documentation of each service.
* Microsoft Defender for Endpoint (MDE) is a paid service and can be skipped if you don't have an account (unchecked by default).

> [!IMPORTANT]
> You can modify the configuration via the GUI at [http://127.0.0.1:5000/config](http://127.0.0.1:5000/config). \
> This endpoint is disabled by default for security reasons, as it is not protected. \
> To enable it, set `"config_page_enabled":true` in `secrets.json` or use `CONFIG_PAGE_ENABLED=true` as environment variable. \
> **This is not recommended for public or team use, as it exposes your API keys.**

See [Advanced options for deployment](https://github.com/stanfrbd/cyberbro/wiki/4.-Advanced-options-for-deployment) in the wiki to get all custom option.

# Launch the app

## Lazy and easy - use docker

> [!WARNING]
> Make sure you install the `compose` plugin as `docker compose` and not `docker-compose`.

```bash
docker compose up # use -d to run in background and use --build to rebuild the image
```

* Go to http://127.0.0.1:5000 and Enjoy.

> Don't forget to edit the `secrets.json` before building the image.

See [Advanced options for deployment](https://github.com/stanfrbd/cyberbro/wiki/4.-Advanced-options-for-deployment) in the wiki to get all Docker deployment options.

## The old way

* Clone the repository and install the requirements.

You might want to create a [`venv`](https://docs.python.org/3/library/venv.html) before installing the dependencies.

```bash
pip install -r requirements.txt
```

* Run the app with `gunicorn` (clean mode).

```bash
gunicorn -b 0.0.0.0:5000 app:app
```

* Run the app with in development mode.

```bash
python3 app.py
```

# Screenshots

<details>
<summary>See all screenshots</summary>

![image-analysis](https://github.com/user-attachments/assets/1331e340-e95d-4b0a-b487-f13b27f2e24d)

![image-history](https://github.com/user-attachments/assets/859c5f43-6da9-4a6a-8b64-23e5035df8a5)

![image-stats](https://github.com/user-attachments/assets/c4676eb5-b6de-4611-bade-e21d9e10fcf3)

</details>

![image](https://github.com/user-attachments/assets/bfff1355-51a2-496e-98c4-c5f3ea3476c8)
![image](https://github.com/user-attachments/assets/e88dd9fd-3644-42a2-8a47-6ca6d44bf5e7)

> [!CAUTION]
> If you intend to use this in a **production environment**, use well configured **Reverse Proxy** + **WAF** to prevent **security issues**.

# Cyberbro browser extension

<p>
<a href="https://addons.mozilla.org/addon/cyberbro-analyzer/"><img src="https://user-images.githubusercontent.com/585534/107280546-7b9b2a00-6a26-11eb-8f9f-f95932f4bfec.png" alt="Get Cyberbro Analyzer for Firefox"></a>
<a href="https://chromewebstore.google.com/detail/cyberbro-analyzer/nfcfigpaollodajabegcdobhmgaclbbm"><img src="https://user-images.githubusercontent.com/585534/107280622-91a8ea80-6a26-11eb-8d07-77c548b28665.png" alt="Get Cyberbro Analyzer for Chromium"></a>
<a href="https://microsoftedge.microsoft.com/addons/detail/cyberbro-analyzer/lbponbmcggcepflackehgpbceehagiam"><img src="https://user-images.githubusercontent.com/585534/107280673-a5ece780-6a26-11eb-9cc7-9fa9f9f81180.png" alt="Get Cyberbro Analyzer for Microsoft Edge"></a>
</p>

# Cyberbro API

* The API is available at `/api/` and can be accessed via the GUI or command-line.

**There are currently 3 endpoints:**

* `/api/analyze` - Analyze a text and return analysis ID (JSON).
* `/api/is_analysis_complete/<analysis_id>` - Check if the analysis is complete (JSON).
* `/api/results/<analysis_id>` - Retrieve the results of a previous analysis (JSON).

```bash
curl -X POST "http://localhost:5000/api/analyze" -H "Content-Type: application/json" -d '{"text": "20minutes.fr", "engines": ["reverse_dns", "rdap"]}'
```

```json
{
  "analysis_id": "e88de647-b153-4904-91e5-8f5c79174854",
  "link": "/results/e88de647-b153-4904-91e5-8f5c79174854"
}
```

```bash
curl "http://localhost:5000/api/is_analysis_complete/e88de647-b153-4904-91e5-8f5c79174854"
```

```json
{
  "complete": true
}
```

```bash
curl "http://localhost:5000/api/results/e88de647-b153-4904-91e5-8f5c79174854"
```

```json
[
  {
    "observable": "20minutes.fr",
    "rdap": {
      "abuse_contact": "",
      "creation_date": "2001-07-11",
      "expiration_date": "2028-01-08",
      "link": "https://rdap.nic.fr/domain/20minutes.fr",
      "name_servers": [
        "ns-1271.awsdns-30.org",
        "ns-748.awsdns-29.net",
        "ns-16.awsdns-02.com",
        "ns-1958.awsdns-52.co.uk"
      ],
      "organization": "",
      "registrant": "20 MINUTES FRANCE SAS",
      "registrant_email": "0d6621ed24c26f0d32e2c4f76b507da9-679847@contact.gandi.net",
      "registrar": "GANDI",
      "update_date": "2024-11-18"
    },
    "reverse_dns": {
      "reverse_dns": [
        "13.249.9.82",
        "13.249.9.92",
        "13.249.9.83",
        "13.249.9.129"
      ]
    },
    "reversed_success": true,
    "type": "FQDN"
  }
]
```

> [!NOTE]
> The [dedicated wiki page](https://github.com/stanfrbd/cyberbro/wiki/3.-API-usage-and-engine-names) gives all the names of usable engines.

# API and third-party services

* [AbuseIPDB](https://docs.abuseipdb.com/)
* [Abusix](https://abusix.com/)
* [CriminalIP](https://www.criminalip.io/)
* [CrowdStrike](https://www.crowdstrike.com/)
* [Github](https://github.com/)
* [Google Safe Browsing](https://developers.google.com/safe-browsing)
* [Google](https://google.com/)
* [Grep.App](https://grep.app/)
* [Hudson Rock](https://hudsonrock.com/)
* [ICANN](https://lookup.icann.org/)
* [IPinfo](https://ipinfo.io/developers)
* [IPquery](https://ipquery.gitbook.io/ipquery-docs)
* [Ioc.One](https://ioc.one/)
* [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/microsoft-defender-for-endpoint-api)
* [OpenCTI](https://www.opencti.io/)
* [OpenRDAP](https://openrdap.org/api)
* [Phishtank](https://www.phishtank.com/)
* [Shodan](https://developer.shodan.io/)
* [Spur.us](https://spur.us/)
* [ThreatFox](https://threatfox.abuse.ch/api/)
* [URLscan](https://urlscan.io/)
* [VirusTotal](https://developers.virustotal.com/v3.0/reference)
* [WebScout](https://webscout.io/)
* [Alienvault](https://otx.alienvault.com/)

> [!NOTE]
> Any questions? Check the [wiki](https://github.com/stanfrbd/cyberbro/wiki) or raise an [issue](https://github.com/stanfrbd/cyberbro/issues/new) \
> For the advanced config (tuning of `supervisord.conf` before deployment, selection of visible engines, change `/api/` prefix...), check the [dedicated wiki page](https://github.com/stanfrbd/cyberbro/wiki/4.-Advanced-options-for-deployment).

# Special thanks

A huge thank you to all the amazing contributors who made pull requests and helped improve this project:

* [Florian PILLOT](https://github.com/Harukunnn) who reworked engines (refactoring and optimizations).
* [Axel](https://github.com/botlabsDev) who develops [Ioc.One](https://ioc.one/) and added a specific User-Agent allowing scraping of Ioc[.]One.
* [Jon Mark Allen](https://github.com/ubahmapk/) who added a better secret management and tests. He improved code structure too.

Your contributions are greatly appreciated!

# License

```
MIT License

Copyright (c) 2025 stanfrbd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

# Logo

The logo used in this project is free for personal and commercial use and can be found [here](https://www.veryicon.com/icons/object/material_design_icons/web-39.html).
