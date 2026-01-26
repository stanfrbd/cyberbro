"""
Bad ASN Cache Manager
Downloads and maintains a local cache of known malicious ASNs from public blacklists.
"""

import csv
import json
import logging
import time
from pathlib import Path

import requests

from utils.config import get_config

logger = logging.getLogger(__name__)

# Load configuration
secrets = get_config()

# Network configuration
PROXIES = {"https": secrets.proxy_url, "http": secrets.proxy_url}
SSL_VERIFY = secrets.ssl_verify

# Cache file location
CACHE_FILE = Path("data/bad_asn_cache.json")
CACHE_MAX_AGE = 24 * 60 * 60  # 24 hours in seconds

# Data sources
SPAMHAUS_URL = "https://www.spamhaus.org/drop/asndrop.json"
BRIANHAMA_URL = "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"
LETHAL_FORENSICS_URL = "https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/ASN-Blacklist.csv"


def normalize_asn(asn_value: str | int) -> str:
    """
    Normalize ASN to standard format (numeric string without 'AS' prefix).

    Args:
        asn_value: ASN as string or integer (e.g., "AS12345", "12345", 12345)

    Returns:
        Normalized ASN as string (e.g., "12345")
    """
    asn_str = str(asn_value).strip().upper()
    if asn_str.startswith("AS"):
        asn_str = asn_str[2:]
    return asn_str


def download_spamhaus_asndrop() -> dict[str, str]:
    """
    Download and parse Spamhaus ASNDROP list (JSONL format).

    Returns:
        Dictionary mapping ASN (string) to source description
    """
    logger.info("Downloading Spamhaus ASNDROP list...")
    result = {}

    try:
        response = requests.get(SPAMHAUS_URL, proxies=PROXIES, verify=SSL_VERIFY, timeout=30)
        response.raise_for_status()

        # Parse JSONL format (one JSON object per line)
        lines = response.text.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)

                # Skip metadata line
                if entry.get("type") == "metadata":
                    continue

                asn = normalize_asn(entry.get("asn", ""))
                if asn:
                    domain = entry.get("domain", "Unknown")
                    cc = entry.get("cc", "??")
                    asname = entry.get("asname", "Unknown")
                    result[asn] = f"Spamhaus ASNDROP ({asname}, {domain}, {cc})"
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Spamhaus ASNDROP line: {line[:100]}... Error: {e}")
                continue

        logger.info(f"Loaded {len(result)} ASNs from Spamhaus ASNDROP")
    except Exception as e:
        logger.error(f"Failed to download Spamhaus ASNDROP: {e}")

    return result


def download_brianhama_bad_asn() -> dict[str, str]:
    """
    Download and parse Brianhama Bad ASN List (CSV).

    Returns:
        Dictionary mapping ASN (string) to source description
    """
    logger.info("Downloading Brianhama Bad ASN List...")
    result = {}

    try:
        response = requests.get(BRIANHAMA_URL, proxies=PROXIES, verify=SSL_VERIFY, timeout=30)
        response.raise_for_status()

        # Parse CSV
        lines = response.text.splitlines()
        reader = csv.DictReader(lines)

        for row in reader:
            asn = normalize_asn(row.get("ASN", ""))
            entity = row.get("Entity", "Unknown").strip()
            if asn:
                result[asn] = f"Brianhama Bad ASN List ({entity})"

        logger.info(f"Loaded {len(result)} ASNs from Brianhama Bad ASN List")
    except Exception as e:
        logger.error(f"Failed to download Brianhama Bad ASN List: {e}")

    return result


def download_lethal_forensics_asn() -> dict[str, str]:
    """
    Download and parse LETHAL-FORENSICS ASN Blacklist (CSV).

    Returns:
        Dictionary mapping ASN (string) to source description
    """
    logger.info("Downloading LETHAL-FORENSICS ASN Blacklist...")
    result = {}

    try:
        response = requests.get(LETHAL_FORENSICS_URL, proxies=PROXIES, verify=SSL_VERIFY, timeout=30)
        response.raise_for_status()

        # Parse CSV
        lines = response.text.splitlines()
        reader = csv.DictReader(lines)

        for row in reader:
            asn = normalize_asn(row.get("ASN", ""))
            org_name = row.get("OrgName", "Unknown").strip()
            info = row.get("Info", "").strip()
            date = row.get("Date", "").strip()

            if asn:
                # Format the source description with all available information
                description = f"LETHAL-FORENSICS ASN Blacklist ({org_name}"
                if info:
                    description += f", {info}"
                if date:
                    description += f", {date}"
                description += ")"
                result[asn] = description

        logger.info(f"Loaded {len(result)} ASNs from LETHAL-FORENSICS ASN Blacklist")
    except Exception as e:
        logger.error(f"Failed to download LETHAL-FORENSICS ASN Blacklist: {e}")

    return result


def update_bad_asn_cache() -> bool:
    """
    Download all bad ASN lists and merge them into a single cache file.
    Only updates if cache is older than 24 hours or doesn't exist.

    Returns:
        True if cache was updated, False if skipped (cache is fresh)
    """
    # Check if cache exists and is fresh
    if CACHE_FILE.exists():
        file_age = time.time() - CACHE_FILE.stat().st_mtime
        if file_age < CACHE_MAX_AGE:
            logger.info(f"Bad ASN cache is fresh (age: {file_age / 3600:.1f} hours), skipping update")
            return False

    logger.info("Updating Bad ASN cache...")

    # Ensure data directory exists
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Download both sources
    merged_data = {}

    # Spamhaus ASNDROP (priority: has country codes)
    spamhaus_data = download_spamhaus_asndrop()
    merged_data.update(spamhaus_data)

    # Brianhama Bad ASN List (merge intelligently, don't overwrite)
    brianhama_data = download_brianhama_bad_asn()
    for asn, source_description in brianhama_data.items():
        if asn in merged_data:
            # ASN exists in both lists - combine the information
            merged_data[asn] = f"{merged_data[asn]} + {source_description}"
        else:
            # ASN only in Brianhama - add it
            merged_data[asn] = source_description

    # LETHAL-FORENSICS ASN Blacklist (merge intelligently, don't overwrite)
    lethal_forensics_data = download_lethal_forensics_asn()
    for asn, source_description in lethal_forensics_data.items():
        if asn in merged_data:
            # ASN exists in other lists - combine the information
            merged_data[asn] = f"{merged_data[asn]} + {source_description}"
        else:
            # ASN only in LETHAL-FORENSICS - add it
            merged_data[asn] = source_description

    # Save to cache
    cache_data = {"last_updated": time.time(), "asns": merged_data}

    try:
        with CACHE_FILE.open("w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2)
        logger.info(f"Bad ASN cache updated successfully with {len(merged_data)} ASNs")
        return True
    except Exception as e:
        logger.error(f"Failed to save Bad ASN cache: {e}")
        return False


def load_bad_asn_cache() -> dict[str, str]:
    """
    Load the bad ASN cache from disk.

    Returns:
        Dictionary mapping ASN (string) to source description
    """
    if not CACHE_FILE.exists():
        logger.warning("Bad ASN cache file not found, returning empty cache")
        return {}

    try:
        with CACHE_FILE.open(encoding="utf-8") as f:
            cache_data = json.load(f)
            return cache_data.get("asns", {})
    except Exception as e:
        logger.error(f"Failed to load Bad ASN cache: {e}")
        return {}


def check_asn(asn_value: str | int) -> dict | None:
    """
    Check if an ASN is in the bad ASN cache.

    Args:
        asn_value: ASN to check (string or integer)

    Returns:
        Dictionary with status, source, and details if ASN is listed, None otherwise
    """
    asn = normalize_asn(asn_value)
    cache = load_bad_asn_cache()

    if asn in cache:
        return {
            "status": "malicious",
            "source": cache[asn],
            "details": f"ASN {asn} is listed in bad ASN databases",
            "asn": asn,
        }

    return None


def background_updater():
    """
    Background thread function that periodically updates the bad ASN cache.
    Updates once every 24 hours.
    """
    logger.info("Bad ASN background updater started")

    # Initial update on startup
    update_bad_asn_cache()

    # Periodic updates
    while True:
        time.sleep(CACHE_MAX_AGE)  # Sleep for 24 hours
        update_bad_asn_cache()
