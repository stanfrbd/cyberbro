## Cyberbro API

* The API is available at `/api/` (or your custom prefix if you have changed it using the advanced options) and can be accessed via the GUI or command-line.

**There are currently 3 endpoints:**

* `/api/analyze` - Analyze a text and return analysis ID (JSON).
* `/api/is_analysis_complete/<analysis_id>` - Check if the analysis is complete (JSON).
* `/api/results/<analysis_id>` - Retrieve the results of a previous analysis (JSON).

```bash
curl -X POST "http://localhost:5000/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "20minutes.fr",
    "engines": ["reverse_dns", "rdap"]
  }'
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

## Note about caching and ignoring cache
* The API results are cached for 24 hours by default. You can change this by modifying the `api_cache_timeout` parameter in the `secrets.json` file or by setting the corresponding environment variable. Refer to this document for more details: [advanced options](https://docs.cyberbro.net/quick-start/Advanced-options-for-deployment).

* You can bypass caching for a specific request by including `"ignore_cache": true` in the data section of your request. Ignoring the cache will force the system to perform the analysis again. For example:

```bash
curl -X POST "http://localhost:5000/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "20minutes.fr",
    "engines": ["reverse_dns", "rdap"],
    "ignore_cache": true
  }'
```

## List of usable engines and their description (just like in the HTML page)

!!! tip
    Use the property `name` for the API.

### Abusix
**Name**: `abusix`  
**Supports**: abuse, free_no_key  
**Explaination**: Checks abuse contact with Abusix for IP, reversed obtained IP for a given domain/URL, free, no API key

### Alienvault
**Name**: `alienvault`   
**Supports**: IP, free API key required  
**Explaination**: Checks Alienvault for IP, domain, URL, hash, free API key required

### AbuseIPDB
**Name**: `abuseipdb`  
**Supports**: risk  
**Explaination**: Checks AbuseIPDB for IP, reversed obtained IP for a given domain/URL, free API key required

### CrowdStrike
**Name**: `crowdstrike`  
**Supports**: hash, IP, domain, URL  
**Explaination**: Checks CrowdStrike for IP, domain, URL, hash, paid API key required with Flacon XDR and Falcon Intelligence licence

### CriminalIP
**Name**: `criminalip`  
**Supports**: IP, free or paid API key required  
**Explaination**: Checks CriminalIP for IP, reversed obtained IP for a given domain / URL, free or paid API key required

### Github
**Name**: `github`  
**Supports**: domain, URL, IP, hash, free_no_key, scraping  
**Explaination**: Get Github grep.app API search results for all types of observable, free, no API key

### Google
**Name**: `google`  
**Supports**: domain, URL, IP, hash, free_no_key, scraping  
**Explaination**: Scraps Google search results for all types of observable, free, no API key

### Google DNS (common records)
**Name**: `google_dns`  
**Supports**: IP, domain, URL  
**Explaination**: Checks Google common DNS records (A, AAAA, CNAME, NS, MX, TXT - including SPF and DMARC, PTR) for IP, domain, URL, free, no API key

### Google Safe Browsing
**Name**: `google_safe_browsing`  
**Supports**: risk, domain, IP  
**Explaination**: Checks Google Safe Browsing, free API key required

### Hudson Rock
**Name**: `hudsonrock`  
**Supports**: domain, URL, email, free_no_key  
**Explaination**: Searches Hudson Rocks results for domains, URL, Email, free, no API key

### Ioc.One (HTML)
**Name**: `ioc_one_html`  
**Supports**: domain, URL, IP, hash, scraping  
**Explaination**: Scraps (can be long) Ioc.One HTML search results for all types of observable, free, no API key

### Ioc.One (PDF)
**Name**: `ioc_one_pdf`  
**Supports**: domain, URL, IP, hash, scraping  
**Explaination**: Scraps (can be long) Ioc.One PDF search results for all types of observable, free, no API key

### IPinfo
**Name**: `ipinfo`  
**Supports**: IP  
**Explaination**: Checks IPinfo for IP, reversed obtained IP for a given domain/URL, free API key required

### IPquery
**Name**: `ipquery`  
**Supports**: default, IP, risk, VPN, proxy, free_no_key  
**Explaination**: Checks IPquery for IP, reversed obtained IP for a given domain/URL, free, no API key

### Microsoft Defender for Endpoint
**Name**: `mde`    
**Supports**: hash, IP, domain, URL  
**Explaination**: Checks Microsoft Defender for Endpoint, paid API info on Azure required

### MISP
**Name**: `misp`  
**Supports**: IP, domain, URL, hash  
**Explaination**: Checks MISP for IP, domain, URL, hash, free API key required

### OpenCTI
**Name**: `opencti`  
**Supports**: domain, URL, IP, hash  
**Explaination**: Searches OpenCTI results for all types of observable, API key required

### Phishtank
**Name**: `phishtank`  
**Supports**: risk, domain, URL, free_no_key  
**Explaination**: Checks Phishtank for domains, URL, free, no API key

### RDAP (ex Whois)
**Name**: `rdap`  
**Supports**: default, abuse, domain, free_no_key  
**Explaination**: Checks RDAP (ex Whois) record for domain, URL, no API key required

### Reverse DNS
**Name**: `reverse_dns`  
**Supports**: default, domain, IP, abuse, free_no_key  
**Explaination**: Performs a reverse DNS lookup for IP, domain, URL (on the Cyberbro machine)

### Shodan
**Name**: `shodan`  
**Supports**: ports, IP  
**Explaination**: Checks Shodan, reversed obtained IP for a given domain/URL, free API key required

### Spur.us
**Name**: `spur`  
**Supports**: VPN, proxy, free_no_key, scraping  
**Explaination**: Scraps Spur.us for IP, reversed obtained IP for a given domain/URL, free, no API key

### ThreatFox
**Name**: `threatfox`  
**Supports**: IP, domain, URL, free_no_key  
**Explaination**: Checks ThreatFox by Abuse.ch for IP, domains, URL, free, no API key

### URLscan
**Name**: `urlscan`  
**Supports**: domain, URL, IP, hash, free_no_key  
**Explaination**: Checks URLscan for all types of observable, free, no API key

### VirusTotal
**Name**: `virustotal`   
**Supports**: hash, risk, IP, domain, URL  
**Explaination**: Checks VirusTotal for IP, domain, URL, hash, free API key required

### WebScout
**Name**: `webscout`  
**Supports**: IP, free or paid API key required  
**Explaination**: Checks WebScout for IP, reversed obtained IP for a given domain / URL, free or paid API key required
