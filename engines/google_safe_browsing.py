import logging
from typing import Any

import requests

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)

GOOGLE_SAFE_BROWSING_V5_URL = "https://safebrowsing.googleapis.com/v5alpha1/urls:search"

THREAT_TYPE_BY_ENUM: dict[int, str] = {
    0: "THREAT_TYPE_UNSPECIFIED",
    1: "MALWARE",
    2: "SOCIAL_ENGINEERING",
    3: "UNWANTED_SOFTWARE",
    4: "POTENTIALLY_HARMFUL_APPLICATION",
}


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    idx = offset

    while idx < len(data):
        byte = data[idx]
        value |= (byte & 0x7F) << shift
        idx += 1

        if (byte & 0x80) == 0:
            return value, idx

        shift += 7
        if shift >= 64:
            raise ValueError("Varint too long")

    raise ValueError("Unexpected end of protobuf while decoding varint")


def _skip_field(data: bytes, wire_type: int, offset: int) -> int:
    if wire_type == 0:
        _, new_offset = _decode_varint(data, offset)
        return new_offset

    if wire_type == 1:
        new_offset = offset + 8
        if new_offset > len(data):
            raise ValueError("Invalid fixed64 field length")
        return new_offset

    if wire_type == 2:
        length, pos = _decode_varint(data, offset)
        new_offset = pos + length
        if new_offset > len(data):
            raise ValueError("Invalid length-delimited field length")
        return new_offset

    if wire_type == 5:
        new_offset = offset + 4
        if new_offset > len(data):
            raise ValueError("Invalid fixed32 field length")
        return new_offset

    raise ValueError(f"Unsupported wire type: {wire_type}")


def _parse_threat_url(threat_message: bytes) -> dict[str, Any]:
    url = ""
    threat_types: list[str] = []
    offset = 0

    while offset < len(threat_message):
        tag, offset = _decode_varint(threat_message, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 2:
            length, pos = _decode_varint(threat_message, offset)
            end = pos + length
            if end > len(threat_message):
                raise ValueError("Invalid threat URL field length")
            url = threat_message[pos:end].decode("utf-8", errors="replace")
            offset = end
            continue

        if field_number == 2 and wire_type == 0:
            enum_value, offset = _decode_varint(threat_message, offset)
            threat_types.append(THREAT_TYPE_BY_ENUM.get(enum_value, f"THREAT_TYPE_{enum_value}"))
            continue

        if field_number == 2 and wire_type == 2:
            packed_length, packed_pos = _decode_varint(threat_message, offset)
            packed_end = packed_pos + packed_length
            if packed_end > len(threat_message):
                raise ValueError("Invalid packed threat types length")

            while packed_pos < packed_end:
                enum_value, packed_pos = _decode_varint(threat_message, packed_pos)
                threat_types.append(
                    THREAT_TYPE_BY_ENUM.get(enum_value, f"THREAT_TYPE_{enum_value}")
                )

            offset = packed_end
            continue

        offset = _skip_field(threat_message, wire_type, offset)

    return {"url": url, "threatTypes": threat_types}


def _parse_v5_protobuf_response(payload: bytes) -> dict[str, Any]:
    threats: list[dict[str, Any]] = []
    offset = 0

    while offset < len(payload):
        tag, offset = _decode_varint(payload, offset)
        field_number = tag >> 3
        wire_type = tag & 0x07

        if field_number == 1 and wire_type == 2:
            length, pos = _decode_varint(payload, offset)
            end = pos + length
            if end > len(payload):
                raise ValueError("Invalid ThreatUrl field length")
            threat = _parse_threat_url(payload[pos:end])
            if threat.get("url") or threat.get("threatTypes"):
                threats.append(threat)
            offset = end
            continue

        if field_number == 2 and wire_type == 2:
            offset = _skip_field(payload, wire_type, offset)
            continue

        offset = _skip_field(payload, wire_type, offset)

    return {"threats": threats}


class GoogleSafeBrowsingEngine(BaseEngine):
    @property
    def name(self):
        return "google_safe_browsing"

    @property
    def supported_types(self) -> ObservableType:
        return ObservableType.FQDN | ObservableType.IPV4 | ObservableType.IPV6 | ObservableType.URL

    def analyze(self, observable: Observable) -> dict[str, Any] | None:
        api_key = self.secrets.google_safe_browsing

        if not api_key:
            logger.error("Missing Google Safe Browsing API key for '%s'", observable.value)
            return None

        try:
            lookup_url = ""
            match observable.type:
                case ObservableType.URL:
                    lookup_url = observable.value
                case ObservableType.FQDN | ObservableType.IPV4 | ObservableType.IPV6:
                    lookup_url = f"http://{observable.value}"
                case _:
                    return None

            response = requests.get(
                GOOGLE_SAFE_BROWSING_V5_URL,
                params={"key": api_key, "urls": lookup_url},
                headers={"User-Agent": "cyberbro/1.0"},
                proxies=self.proxies,
                verify=self.ssl_verify,
                timeout=5,
            )
            response.raise_for_status()

            response_content_type = response.headers.get("content-type", "")
            if "application/x-protobuf" in response_content_type:
                data = _parse_v5_protobuf_response(response.content)
            else:
                data = response.json()

            threats: list[dict[str, Any]] = (
                data.get("threats", []) if isinstance(data, dict) else []
            )

            if threats:
                return {
                    "threat_found": "Threat found",
                    "details": threats,
                    "threat_types": sorted(
                        {
                            threat_type
                            for threat in threats
                            for threat_type in threat.get("threatTypes", [])
                        }
                    ),
                }
            return {
                "threat_found": "No threat found",
                "details": None,
                "threat_types": [],
            }

        except Exception as e:
            logger.error(
                "Error while querying Google Safe Browsing for '%s': %s",
                observable.value,
                e,
                exc_info=True,
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        if not analysis_result:
            return {
                "gsb_threat": None,
                "gsb_threat_types": None,
                "gsb_matched_urls": None,
            }

        threat_types = analysis_result.get("threat_types")
        if isinstance(threat_types, list):
            threat_types_export = ", ".join(threat_types) if threat_types else None
        else:
            threat_types_export = None

        details = analysis_result.get("details")
        matched_urls: list[str] = []
        if isinstance(details, list):
            for item in details:
                if isinstance(item, dict):
                    url = item.get("url")
                    if isinstance(url, str) and url:
                        matched_urls.append(url)

        return {
            "gsb_threat": analysis_result.get("threat_found"),
            "gsb_threat_types": threat_types_export,
            "gsb_matched_urls": ", ".join(matched_urls) if matched_urls else None,
        }
