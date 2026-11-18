import logging
import re

import requests
from requests.exceptions import ConnectTimeout, JSONDecodeError, ReadTimeout

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)

_TENANT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)

# Confirmed from live Microsoft OIDC endpoints (tenant_region_scope field).
# Broader codes (NA, SA, EU, AS, OC, AF) are the ones observed in practice;
# granular codes (JP, KR, IN, etc.) exist in tenantidlookup.com's mapping and
# are kept as fallback for sovereign-cloud or future-provisioned tenants.
_REGION_NAMES: dict[str, str] = {
    "NA": "North America",
    "SA": "South America",
    "EU": "European Union",
    "AS": "Asia",
    "OC": "Oceania",
    "AF": "Africa",
    "WW": "Worldwide",
    "USGov": "US Government",
    "USG": "US Government",
    "AP": "Asia Pacific",
    "ME": "Middle East",
    "IN": "India",
    "CN": "China",
    "JP": "Japan",
    "KR": "Korea",
    "CA": "Canada",
    "FR": "France",
    "DE": "Germany",
    "UK": "United Kingdom",
    "US": "United States",
}

MsTenantCheckResult = dict[str, str | bool | list[str] | None]


class MsTenantCheckEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "ms_tenant_check"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.EMAIL

    def _extract_domain(self, observable: Observable) -> str:
        if observable.type is ObservableType.EMAIL:
            return observable.value.split("@")[-1]
        return observable.value

    def _check_mx_records(self, domain: str) -> list[str]:
        try:
            url = "https://dns.google/resolve"
            params: dict[str, str] = {"name": domain, "type": "MX"}
            response = requests.get(
                url, params=params, proxies=self.proxies, verify=self.ssl_verify, timeout=5
            )
            response.raise_for_status()
            data = response.json()
            mx_records: list[str] = []
            for answer in data.get("Answer", []):
                raw = answer.get("data", "").strip().rstrip(".")
                if raw:
                    parts = raw.split()
                    mx_records.append(parts[-1] if len(parts) >= 2 else raw)
            return mx_records
        except Exception as e:
            logger.error("Error querying MX records for '%s': %s", domain, e, exc_info=True)
            return []

    def analyze(self, observable: Observable) -> MsTenantCheckResult | None:
        domain = self._extract_domain(observable)
        oidc_url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"

        try:
            response = requests.get(
                oidc_url, proxies=self.proxies, verify=self.ssl_verify, timeout=10
            )
        except (ReadTimeout, ConnectTimeout):
            logger.info("Timeout while checking MS tenant for '%s'.", observable.value)
            return None
        except Exception as e:
            logger.error(
                "Error checking MS tenant for '%s': %s", observable.value, e, exc_info=True
            )
            return None

        tenant_found = response.status_code == 200
        tenant_id: str | None = None
        tenant_region_scope: str | None = None

        if tenant_found:
            try:
                data = response.json()
                issuer: str = data.get("issuer", "")
                match = _TENANT_ID_RE.search(issuer)
                if match:
                    tenant_id = match.group(0)
                tenant_region_scope = data.get("tenant_region_scope")
            except (JSONDecodeError, ValueError) as e:
                logger.error(
                    "Error parsing openid-configuration for '%s': %s",
                    observable.value,
                    e,
                    exc_info=True,
                )

        mx_records = self._check_mx_records(domain)
        is_office365_mx = any("mail.protection.outlook.com" in mx.lower() for mx in mx_records)
        tenant_region_name: str | None = (
            _REGION_NAMES.get(tenant_region_scope) if tenant_region_scope else None
        )

        return {
            "tenant_found": tenant_found,
            "tenant_id": tenant_id,
            "tenant_region_scope": tenant_region_scope,
            "tenant_region_name": tenant_region_name,
            "mx_records": mx_records,
            "is_office365_mx": is_office365_mx,
            "domain": domain,
        }

    def create_export_row(
        self, analysis_result: MsTenantCheckResult | None
    ) -> dict[str, str | bool | None]:
        if not analysis_result:
            return {
                "ms_tenant_check_found": None,
                "ms_tenant_check_id": None,
                "ms_tenant_check_region": None,
                "ms_tenant_check_is_office365_mx": None,
            }
        return {
            "ms_tenant_check_found": analysis_result.get("tenant_found"),
            "ms_tenant_check_id": analysis_result.get("tenant_id"),
            "ms_tenant_check_region": analysis_result.get("tenant_region_scope"),
            "ms_tenant_check_is_office365_mx": analysis_result.get("is_office365_mx"),
        }
