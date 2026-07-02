import logging
import urllib.parse
from typing import Any

import pycountry
import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableFlag, ObservableType

logger = logging.getLogger(__name__)

_RF_BASE_URL = "https://api.recordedfuture.com/v2"
_IP_FIELDS = "entity,risk,intelCard,sightings,timestamps,location,threatLists"
_DOMAIN_FIELDS = "entity,risk,intelCard,sightings,timestamps,threatLists"
_HASH_FIELDS = "entity,risk,intelCard,sightings,timestamps,fileHashes,hashAlgorithm"
_URL_FIELDS = "entity,risk,intelCard,sightings,timestamps"

_ENTITY_TYPE_MAP: dict[ObservableFlag, tuple[str, str]] = {
    ObservableFlag.IPV4: ("ip", _IP_FIELDS),
    ObservableFlag.IPV6: ("ip", _IP_FIELDS),
    ObservableFlag.FQDN: ("domain", _DOMAIN_FIELDS),
    ObservableFlag.MD5: ("hash", _HASH_FIELDS),
    ObservableFlag.SHA1: ("hash", _HASH_FIELDS),
    ObservableFlag.SHA256: ("hash", _HASH_FIELDS),
    ObservableFlag.URL: ("url", _URL_FIELDS),
}

_IP_TYPES = frozenset({ObservableFlag.IPV4, ObservableFlag.IPV6})
_HASH_TYPES = frozenset({ObservableFlag.MD5, ObservableFlag.SHA1, ObservableFlag.SHA256})


class RecordedFutureEngine(BaseEngine):
    @property
    def name(self):
        return "recorded_future"

    @property
    def supported_types(self) -> ObservableType:
        return (
            ObservableFlag.IPV4
            | ObservableFlag.IPV6
            | ObservableFlag.FQDN
            | ObservableFlag.MD5
            | ObservableFlag.SHA1
            | ObservableFlag.SHA256
            | ObservableFlag.URL
        )

    def analyze(self, observable: Observable) -> dict | None:
        api_key: str = self.secrets.recorded_future_api_key

        if not api_key:
            logger.warning("Recorded Future API key not set")
            return None

        obs_type = observable.type
        mapping = _ENTITY_TYPE_MAP.get(obs_type)

        if mapping is None:
            return None

        entity_type, fields = mapping
        encoded_value = urllib.parse.quote(observable.value, safe="")
        url = f"{_RF_BASE_URL}/{entity_type}/{encoded_value}"
        headers = {"X-RFToken": api_key}
        params = {"fields": fields}

        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()
            json_response = response.json()

            if "data" not in json_response:
                return None

            data = json_response["data"]

            # Parse risk
            risk = data.get("risk") or {}
            risk_score = int(risk.get("score") or 0)
            risk_level = risk.get("criticalityLabel") or ""

            # Sort evidence details by criticality descending, take top 3 rule names
            evidence_details = sorted(
                risk.get("evidenceDetails") or [],
                key=lambda x: x.get("criticality", 0),
                reverse=True,
            )
            rules = [e["rule"] for e in evidence_details[:3] if e.get("rule")]

            # Parse sightings — real API returns a list of sighting objects
            sightings_raw = data.get("sightings") or []
            sightings = len(sightings_raw) if isinstance(sightings_raw, list) else 0

            # Parse timestamps
            timestamps = data.get("timestamps") or {}
            first_seen_raw = timestamps.get("firstSeen") or ""
            last_seen_raw = timestamps.get("lastSeen") or ""
            first_seen = first_seen_raw.split("T")[0] if first_seen_raw else ""
            last_seen = last_seen_raw.split("T")[0] if last_seen_raw else ""

            # Parse threat lists (always [] for URL type per RF API contract)
            threat_lists: list[str] = []
            if obs_type != ObservableFlag.URL:
                threat_lists = [
                    t["name"] for t in (data.get("threatLists") or [])[:3] if t.get("name")
                ]

            # Parse location data (IP types only)
            # Real API nests geo under location.location; country is a plain string
            country = ""
            country_code = ""
            asn = ""
            if obs_type in _IP_TYPES:
                location = data.get("location") or {}
                geo = location.get("location") or {}
                country = geo.get("country") or ""
                if country:
                    try:
                        country_code = pycountry.countries.lookup(country).alpha_2.lower()
                    except LookupError:
                        country_code = ""
                asn_raw = location.get("asn") or ""
                organization = location.get("organization") or ""
                if asn_raw and organization:
                    asn = f"{asn_raw} {organization}"
                elif asn_raw:
                    asn = asn_raw

            # Parse hash algorithm (hash types only)
            hash_algorithm = ""
            if obs_type in _HASH_TYPES:
                hash_algorithm = data.get("hashAlgorithm") or ""

            link = data.get("intelCard") or ""

            return {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "rules": rules,
                "sightings": sightings,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "threat_lists": threat_lists,
                "country": country,
                "country_code": country_code,
                "asn": asn,
                "hash_algorithm": hash_algorithm,
                "link": link,
            }
        except Exception as e:
            logger.error(f"Error querying Recorded Future: {e}")
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                "rf_risk_score": None,
                "rf_risk_level": None,
                "rf_rules": None,
                "rf_sightings": None,
                "rf_first_seen": None,
                "rf_last_seen": None,
                "rf_threat_lists": None,
                "rf_country": None,
                "rf_asn": None,
                "rf_hash_algorithm": None,
            }
        rules = analysis_result.get("rules") or []
        threat_lists = analysis_result.get("threat_lists") or []
        return {
            "rf_risk_score": analysis_result.get("risk_score"),
            "rf_risk_level": analysis_result.get("risk_level"),
            "rf_rules": ", ".join(rules) if rules else None,
            "rf_sightings": analysis_result.get("sightings"),
            "rf_first_seen": analysis_result.get("first_seen"),
            "rf_last_seen": analysis_result.get("last_seen"),
            "rf_threat_lists": ", ".join(threat_lists) if threat_lists else None,
            "rf_country": analysis_result.get("country"),
            "rf_asn": analysis_result.get("asn"),
            "rf_hash_algorithm": analysis_result.get("hash_algorithm"),
        }
