import ipaddress
import re
import socket

import tldextract

# List of valid TLDs that can lead to false positives
# Edit this list to add more invalid TLDs or in case of false positives
INVALID_TLD = [
    "doc",
    "xls",
    "xlsb",
    "xlam",
    "xlsm",
    "xlsx",
    "xltm",
    "xml",
    "txt",
    "exe",
    "ppt",
    "pdf",
    "docx",
    "dat",
    "png",
    "yarn",
    "jpg",
    "jpeg",
    "jar",
    "js",
    "gz",
    "pkg",
    "deb",
    "bin",
    "log",
    "csv",
    "sql",
    "tar",
    "apk",
    "bat",
    "py",
    "wsf",
    "vb",
    "gif",
    "ico",
    "tiff",
    "tif",
    "asp",
    "html",
    "htm",
    "css",
    "jsp",
    "php",
    "rss",
    "cpp",
    "pptx",
    "java",
    "ods",
    "bak",
    "cfg",
    "dll",
    "ini",
    "msi",
    "tmp",
    "rtf",
    "vbs",
    "json",
    "scr",
    "class",
    "slk",
    "iqy",
    "http",
    "jse",
    "vbe",
    "ps1",
    "ps",
    "yml",
    "yaml",
    "src",
    "hta",
    "pub",
    "https",
    "sys",
    "eml",
    "cab",
    "dc",
    "cmd",
    "init",
    "lnk",
    "core",
    "docm",
    "hwp",
    "publicvm",
    "iso",
    "crx",
    "config",
]


def identify_observable_type(observable):
    """testing the observable against a set of patterns to identify its type"""
    patterns = {
        "IPv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        "IPv6": r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
        "MD5": r"^[a-fA-F0-9]{32}$",
        "SHA1": r"^[a-fA-F0-9]{40}$",
        "SHA256": r"^[a-fA-F0-9]{64}$",
        "Email": r"^[\w\.-]+@[\w\.-]+\.\w+$",
        "FQDN": r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
        "URL": r"^(https?|ftp)://[^\s/$.?#].[^\s]*$",
        "CHROME_EXTENSION": r"^[a-z]{32}$",
    }

    for type_name, pattern in patterns.items():
        if re.match(pattern, observable):
            return type_name
    return "Unknown"


def extract_observables(text):
    """Extract observables from text, focusing on full URLs with http or https."""
    patterns = {
        "IPv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "MD5": r"\b[a-fA-F0-9]{32}\b",
        "SHA1": r"\b[a-fA-F0-9]{40}\b",
        "SHA256": r"\b[a-fA-F0-9]{64}\b",
        "Email": r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
        # Simplified URL pattern for http(s) only
        # "URL": r"\bhttps?://[^\s/$.?#].[^\s]*\b",
        "URL": r"\bhttps?://[^\s/$.?#].[^\s<>\"'\?,;\]\[\}\{]*",
        "FQDN": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        "CHROME_EXTENSION": r"\b[a-z]{32}\b",
    }

    results = []
    seen = set()

    # Extract URLs first to prevent FQDN overlap
    url_matches = re.findall(patterns["URL"], text)

    # Extract other types of observables from remaining text
    for type_name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        for match in matches:
            # Skip FQDNs if they are already extracted as URLs
            if type_name == "FQDN" and match in str(url_matches):
                continue
            if match not in seen:
                seen.add(match)
                results.append({"value": match, "type": type_name})

    # IPv6 regex pattern provided by https://stackoverflow.com/a/17871737
    # (David M. Syzdek and Benjamin Loison)
    ipv6_regex = re.compile(
        r"""
    (([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|         # 1:2:3:4:5:6:7:8
    ([0-9a-fA-F]{1,4}:){1,7}:|                         # 1:: / 1:2:3:4:5:6:7::
    ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|         # 1::8             1:2:3:4:5:6::8
    ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|  # 1::7:8           1:2:3:4:5::7:8
    ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|  # 1::6:7:8         1:2:3:4::6:7:8
    ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|  # 1::5:6:7:8       1:2:3::5:6:7:8
    ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|  # 1::4:5:6:7:8     1:2::4:5:6:7:8
    [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|       # 1::3:4:5:6:7:8   1::8
    :((:[0-9a-fA-F]{1,4}){1,7}|:)|                     # ::2:3:4:5:6:7:8  ::8       ::
    fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|     # fe80::7:8%eth0   fe80::7:8%1
    ::(ffff(:0{1,4}){0,1}:){0,1}                       # ::255.255.255.255 ::ffff:0:255
    ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}  # IPv4-mapped IPv6
    (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|          # dans IPv6
    ([0-9a-fA-F]{1,4}:){1,4}:                          # 1:2:3:4::255.255.255.255
    ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}  # dans IPv6
    (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))          # dans IPv6
    """,
        re.VERBOSE,
    )

    # Find every IPv6 address in the text
    ipv6_matches = ipv6_regex.findall(text)
    ipv6_addresses = [match[0] for match in ipv6_matches]

    # Add IPv6 at the end
    for ipv6 in ipv6_addresses:
        if ipv6 not in seen:
            seen.add(ipv6)
            results.append({"value": ipv6, "type": "IPv6"})

    # filter invalid TLDs using tldextract and the list of invalid TLDs
    filtered_results = []
    for result in results:
        if result["type"] == "FQDN":
            tld = result["value"].split(".")[-1]
            extracted = tldextract.extract(result["value"])
            if tld in INVALID_TLD or not extracted.suffix:
                continue
        filtered_results.append(result)

    return filtered_results


def is_really_ipv6(value):
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return True
    except OSError:
        return False


def is_bogon(ip):
    return ipaddress.ip_address(ip).is_private
