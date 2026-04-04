import secrets

# Reusable browser fingerprints for services that rate-limit obvious
# automation clients (for example default Python HTTP user agents).
FIREFOX_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
)

ACCEPT_LANGUAGES: tuple[str, ...] = (
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,fr;q=0.6",
)


def random_firefox_user_agent() -> str:
    # Keep UA choice in one place so engines can share the same behavior.
    return secrets.choice(FIREFOX_USER_AGENTS)


def random_browser_accept_language() -> str:
    # Small language variation reduces repetitive request signatures.
    return secrets.choice(ACCEPT_LANGUAGES)


def build_browser_like_headers(origin: str, referer: str) -> dict[str, str]:
    # Builds a browser-like header profile for JSON API calls.
    return {
        "User-Agent": random_firefox_user_agent(),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": random_browser_accept_language(),
        "Referer": referer,
        "Origin": origin,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "DNT": secrets.choice(("0", "1")),
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
