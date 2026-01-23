import logging
from collections.abc import Mapping

import querycontacts
from typing_extensions import override

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class AbusixEngine(BaseEngine):
    @property
    @override
    def name(self):
        return "abusix"

    @property
    @override
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    @override
    def execute_after_reverse_dns(self):
        # IP-only engine, runs after potential IP pivot
        return True

    @override
    def analyze(self, observable_value: str, observable_type: str) -> dict[str, str] | None:
        try:
            results = querycontacts.ContactFinder().find(observable_value)
            if not results:
                logger.warning(
                    "No contact information returned for observable: %s",
                    observable_value,
                )
                return None

            return {"abuse": results[0]}
        except Exception as e:
            logger.error(
                "Error querying Abusix for observable '%s': %s",
                observable_value,
                e,
                exc_info=True,
            )
            return None

    @classmethod
    @override
    def create_export_row(cls, analysis_result: Mapping) -> dict:
        return {"abusix_abuse": analysis_result.get("abuse") if analysis_result else None}
