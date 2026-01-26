## Overview

The **Bad ASN Check** engine is a free, no-API-key-required security feature that identifies malicious Autonomous System Numbers (ASNs) associated with IP addresses. It checks if an IP's ASN is listed in known malicious ASN databases and provides risk scoring to help assess the threat level.

This engine is particularly useful for:

- **VPN and Proxy Detection**: Identifies ASNs commonly used by VPN services and anonymization networks
- **Malicious Infrastructure Detection**: Detects ASNs associated with spam, malware distribution, and other malicious activities
- **Risk Assessment**: Provides a calculated risk score (0-100) based on multiple factors
- **Legitimate Provider Abuse Detection**: Distinguishes between inherently malicious ASNs and legitimate cloud/hosting providers that may be abused

!!! tip "No API Key Required"
    This engine is completely free and requires no API key. It works by maintaining a local cache of malicious ASN lists.

## How It Works

### 1. ASN Extraction

The Bad ASN engine requires ASN information from other IP geolocation engines. It extracts ASN data from:

- **ipapi** (recommended - most reliable)
- **ipinfo**
- **ipquery**
- **webscout**

!!! warning "Dependency Requirement"
    You must enable at least one of these engines (ipapi, ipinfo, ipquery, or webscout) for the Bad ASN Check to function. The engine will skip analysis if no ASN data is available.

### 2. Background Service

The Bad ASN engine uses a background service that automatically maintains an up-to-date database of malicious ASNs.

**Background Updater Characteristics:**

- **Update Frequency**: Every 24 hours
- **Initial Update**: Runs immediately when the application starts
- **Thread Type**: Daemon thread (automatically terminates when the application exits)
- **Cache Location**: `data/bad_asn_cache.json`
- **Cache Duration**: 24 hours

**How it works with Gunicorn:**

When running with Gunicorn, the background service is initialized at the module level, ensuring it runs even with multiple workers. The cache freshness check prevents duplicate downloads across workers.

## Data Sources

The engine aggregates data from three authoritative sources:

### 1. Spamhaus ASNDROP

- **Source**: [Spamhaus.org ASNDROP](https://www.spamhaus.org/drop/asndrop.json)
- **Format**: JSONL (JSON Lines)
- **Focus**: ASNs controlled by or associated with spam operations
- **Authority**: Highly authoritative source for spam-related ASNs
- **Data Included**: ASN number, organization name, domain, country code

**Example Entry:**
```json
{
  "asn": "AS12345",
  "asname": "EXAMPLE-AS",
  "domain": "example.com",
  "cc": "RU"
}
```

### 2. Brianhama Bad ASN List

- **Source**: [Brianhama Bad ASN List (GitHub)](https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv)
- **Format**: CSV
- **Focus**: Broad collection of malicious ASNs
- **Data Included**: ASN number, entity name

**Example Entry:**
```csv
"ASN","Entity"
"12345","Example Malicious Entity"
```

### 3. LETHAL-FORENSICS ASN Blacklist

- **Source**: [LETHAL-FORENSICS Microsoft Analyzer Suite](https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/ASN-Blacklist.csv)
- **Format**: CSV
- **Focus**: VPN services and anonymization networks
- **Data Included**: ASN number, organization name, VPN services info, date

**Example Entry:**
```csv
"ASN","OrgName","Info","Date"
"174","Cogent Communications","CyberGhost VPN, Mullvad VPN, PIA VPN, ProtonVPN, Pure VPN","2024-12-17"
```

### Data Merging Strategy

When an ASN appears in multiple lists, the information is combined:

```
Spamhaus ASNDROP (Example AS, example.com, RU) + Brianhama Bad ASN List (Example Entity) + LETHAL-FORENSICS ASN Blacklist (Example Org, VPN Services, 2024-12-17)
```

This provides comprehensive context for security analysts.

## Risk Scoring Algorithm

The engine calculates a risk score from **0 (low risk)** to **100 (critical risk)** based on multiple factors:

!!! info "Algorithm Design"
    The risk scoring algorithm was designed with assistance from Claude (Anthropic) to provide balanced and transparent risk assessment. The scoring factors and weights were calibrated to minimize false positives while maintaining high detection accuracy.

### Base Score
- **50 points**: Base score for being listed in any bad ASN database

### Factor 1: Presence in Multiple Sources
- **+30 points**: Listed in all three sources (very high confidence)
- **+20 points**: Listed in two sources (higher confidence)
- **+10 points**: Listed in Spamhaus only (authoritative source)
- **+8 points**: Listed in LETHAL-FORENSICS only (VPN/anonymization focus)

### Factor 2: Legitimate Provider Detection
- **-30 points**: Identified as a legitimate cloud/hosting provider that can be abused

The engine checks for these known legitimate provider keywords in the ASN description:
- amazon, aws, google, microsoft, azure
- digitalocean, ovh, hetzner, linode, vultr
- cloudflare, oracle, ibm, alibaba, tencent
- rackspace, contabo, scaleway

### Factor 3: High-Risk Country Location
- **+10 points**: ASN registered in a high-risk country

High-risk countries include:
- **RU** (Russia), **CN** (China), **UA** (Ukraine), **IR** (Iran), **KP** (North Korea)
- **MD** (Moldova), **SC** (Seychelles), **BY** (Belarus)
- **PK** (Pakistan), **BD** (Bangladesh), **VN** (Vietnam)
- **BG** (Bulgaria), **RO** (Romania), **IN** (India)
- **HK** (Hong Kong), **TR** (Turkey), **ID** (Indonesia)
- **LT** (Lithuania), **AL** (Albania), **EE** (Estonia)

### Score Bounds
The final score is clamped to ensure it stays within **0-100** range.

### Example Calculations

**Example 1: Malicious ASN**
```
Base: 50
+ Listed in Spamhaus and Brianhama: +20
+ Located in Russia: +10
= Total: 80/100 (High Risk)
Status: malicious
```

**Example 2: Legitimate Provider Abused**
```
Base: 50
+ Listed in LETHAL-FORENSICS only: +8
- Legitimate provider (AWS): -30
= Total: 28/100 (Low-Medium Risk)
Status: potentially_legitimate
```

**Example 3: Critical Risk**
```
Base: 50
+ Listed in all three sources: +30
+ Located in China: +10
= Total: 90/100 (Critical Risk)
Status: malicious
```

## Status Types

The engine returns three possible status values:

### 1. `malicious`
The ASN is listed in bad ASN databases and represents a genuine threat.

**Indicators:**
- Listed in one or more databases
- NOT identified as a legitimate provider
- Higher risk scores

**Example Output:**
```json
{
  "status": "malicious",
  "asn": "12345",
  "risk_score": 80,
  "source": "Spamhaus ASNDROP (...) + Brianhama Bad ASN List (...)",
  "details": "ASN 12345 is listed in bad ASN databases. Risk Score: 80/100. Source: ...",
  "asn_org_name": "Example Malicious Org"
}
```

### 2. `potentially_legitimate`
The ASN is listed BUT belongs to a legitimate cloud/hosting provider that can be abused.

**Indicators:**
- Listed in one or more databases
- Identified as a legitimate provider (AWS, Google, Azure, etc.)
- Lower risk scores due to -30 penalty

**Example Output:**
```json
{
  "status": "potentially_legitimate",
  "asn": "16509",
  "risk_score": 28,
  "source": "LETHAL-FORENSICS ASN Blacklist (Amazon.com Inc., ProtonVPN, 2024-12-17)",
  "details": "ASN 16509 is listed in bad ASN databases BUT this appears to be a legitimate cloud/hosting provider...",
  "legitimate_but_abused": true,
  "asn_org_name": "Amazon.com, Inc."
}
```

!!! info "Legitimate Provider Context"
    When status is `potentially_legitimate`, exercise caution but verify further context. The IP may be legitimate traffic from a cloud provider or may be a malicious actor abusing legitimate infrastructure.

### 3. `unlisted`
The ASN is NOT listed in any bad ASN database.

**Example Output:**
```json
{
  "status": "unlisted",
  "asn": "15169",
  "details": "ASN 15169 is not listed in bad ASN databases"
}
```

!!! warning "Unlisted ≠ Safe"
    An `unlisted` status only means the ASN is not present in the currently monitored bad ASN databases. This does not guarantee the IP is safe or legitimate. The ASN may be:
    
    - A newly created malicious ASN not yet catalogued
    - An ASN used for targeted attacks (not mass campaigns)
    - A compromised legitimate infrastructure not yet blacklisted
    - Updated after the cache's last 24-hour refresh
    
    Always correlate with other engine results (VirusTotal, AbuseIPDB, etc.) for comprehensive analysis.

## Usage

### Via Web Interface

1. Enter an IP address in the search field
2. Enable at least one ASN provider engine (ipapi, ipinfo, ipquery, or webscout)
3. Enable "Bad ASN Check"
4. Submit the analysis

### Via API

```bash
curl -X POST "http://localhost:5000/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "1.2.3.4",
    "engines": ["ipapi", "bad_asn"]
  }'
```

!!! warning "Engine Order"
    The Bad ASN Check engine runs in **Phase 3 (Post-Pivot)** to ensure ASN data from geolocation engines is available. You don't need to worry about execution order - the system handles this automatically.

## GUI Display

### Card View

The card view displays:
- **Status Badge**: Color-coded (Red for malicious, Orange for potentially legitimate, Green for unlisted)
- **Risk Score**: Displayed with matching color
- **ASN Number**: The numeric ASN identifier
- **Organization**: The ASN organization name (from context engines)
- **Source**: Combined source information with all details
- **Details**: Human-readable explanation

**Status Colors:**  
- 🔴 **Red (malicious)**: ASN is listed and represents a genuine threat  
- 🟠 **Orange (potentially_legitimate)**: Legitimate provider potentially abused  
- 🟢 **Green (unlisted)**: ASN is not listed  

### Table View

Compact version showing:
- Status badge with risk score
- ASN number
- Organization (if available)
- Abbreviated source information

## Export

When exporting results to CSV/Excel, the following fields are included:

- `bad_asn_status`: Status value (malicious, potentially_legitimate, unlisted, N/A)
- `bad_asn_asn`: ASN number
- `bad_asn_source`: Combined source information
- `bad_asn_details`: Full details text
- `bad_asn_legitimate_but_abused`: Boolean flag
- `bad_asn_risk_score`: Numeric risk score (0-100)
- `bad_asn_org_name`: Organization name from context

## Troubleshooting

### No ASN Data Available

**Problem**: The engine returns "No ASN data available"

**Solution**: Enable at least one ASN provider engine:
- ipapi (recommended)
- ipinfo
- ipquery
- webscout

### Cache Not Updating

**Problem**: The cache file isn't being updated

**Solutions:**
1. **Check file permissions**: Ensure the `data/` directory is writable
2. **Check network connectivity**: Verify the application can reach external sources
3. **Check proxy settings**: If using a proxy, ensure it's correctly configured
4. **Manual cache update**: Delete `data/bad_asn_cache.json` to force a fresh download
5. **Check logs**: Look for error messages in the application logs

### Proxy Blocking GitHub

**Problem**: Your proxy blocks GitHub raw content URLs

**Solution**: 
- Whitelist the following domains in your proxy:
  - `www.spamhaus.org`
  - `raw.githubusercontent.com`
- Or temporarily disable proxy for these requests (not recommended)

## Performance Considerations

- **Memory Usage**: The cache file typically contains 1000-2000 ASNs, using minimal memory (~500KB-1MB)
- **Disk Usage**: Cache file is typically < 2MB
- **Network Usage**: Downloads occur once every 24 hours, total ~100KB
- **Analysis Speed**: ASN lookup is instantaneous (in-memory dictionary lookup)
- **No Rate Limits**: Since it's a local cache, there are no API rate limits

## Best Practices

1. **Always enable ipapi**: It provides the most reliable ASN data
2. **Review potentially_legitimate results**: Don't automatically dismiss them as safe
3. **Consider context**: Look at other engine results (VirusTotal, AbuseIPDB) for comprehensive analysis
4. **Monitor cache updates**: Check logs to ensure the background updater is working
5. **Use in combination**: Combine with other risk engines for best results

## Security Considerations

### False Positives

**Legitimate Providers**: The engine specifically handles legitimate cloud providers (AWS, Google, Azure, etc.) by flagging them as `potentially_legitimate` rather than `malicious`. Always verify the context.

**VPN Services**: Many VPN services use ASNs from the LETHAL-FORENSICS list. VPN usage alone isn't malicious - consider the broader context.

### False Negatives

**New Malicious ASNs**: The cache updates every 24 hours. Brand new malicious ASNs may not be detected immediately.

**Unlisted ASNs**: An `unlisted` status doesn't guarantee the IP is safe - it just means the ASN isn't in known bad ASN databases.

## Technical Implementation

### Engine Class

```python
class BadASNEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "bad_asn"
    
    @property
    def supported_types(self) -> list[str]:
        return ["IPv4", "IPv6"]
    
    @property
    def execute_after_reverse_dns(self) -> bool:
        return True  # Phase 3: Post-Pivot
```

### Background Service

```python
def background_updater():
    """Updates the bad ASN cache every 24 hours."""
    logger.info("Bad ASN background updater started")
    update_bad_asn_cache()  # Initial update
    
    while True:
        time.sleep(CACHE_MAX_AGE)  # 24 hours
        update_bad_asn_cache()
```

### Cache Structure

```json
{
  "last_updated": 1706281234.567,
  "asns": {
    "12345": "Spamhaus ASNDROP (Example AS, example.com, RU)",
    "67890": "Brianhama Bad ASN List (Example Entity)",
    "174": "LETHAL-FORENSICS ASN Blacklist (Cogent Communications, Multiple VPNs, 2024-12-17)"
  }
}
```

## Future Enhancements

Potential improvements being considered:

- Additional data sources
- Custom ASN blacklist/whitelist support

## Support

For issues, questions, or contributions related to the Bad ASN Check engine:

- **GitHub Issues**: [Report a bug or request a feature](https://github.com/stanfrbd/cyberbro/issues)
- **Discussions**: [Ask questions or share ideas](https://github.com/stanfrbd/cyberbro/discussions)
- **Documentation**: [Main documentation](https://docs.cyberbro.net)

## License

The Bad ASN Check engine is part of Cyberbro and is licensed under the same terms. The data sources have their own licenses:

- **Spamhaus ASNDROP**: [Spamhaus License](https://www.spamhaus.org/organization/dnsbl/)
- **Brianhama Bad ASN List**: [GitHub Repository](https://github.com/brianhama/bad-asn-list)
- **LETHAL-FORENSICS ASN Blacklist**: [Microsoft Analyzer Suite](https://github.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite)
