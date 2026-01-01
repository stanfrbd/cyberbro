import logging
from typing import Any, Optional

import querycontacts

from models.base_engine import BaseEngine

logger = logging.getLogger(__name__)


class AbusixEngine(BaseEngine):
    @property
    def name(self):
        return "abusix"

    @property
    def supported_types(self):
        return ["IPv4", "IPv6"]

    @property
    def execute_after_reverse_dns(self):
        # IP-only engine, runs after potential IP pivot
        return True

    def analyze(self, observable_value: str, observable_type: str) -> Optional[dict[str, str]]:
        try:
            results = querycontacts.ContactFinder().find(observable_value)
            if not results:
                logger.warning("No contact information returned for observable: %s", observable_value)
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

    def create_export_row(self, analysis_result: Any) -> dict:
        return {"abusix_abuse": analysis_result.get("abuse") if analysis_result else None}
