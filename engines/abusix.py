import logging
from typing import Any

import querycontacts

from models.base_engine import BaseEngine
from models.observable import Observable, ObservableType

logger = logging.getLogger(__name__)


class AbusixEngine(BaseEngine):
    @property
    def name(self):
        return "abusix"

    @property
    def supported_types(self):
        return ObservableType.IPV4 | ObservableType.IPV6

    @property
    def execute_after_reverse_dns(self):
        # IP-only engine, runs after potential IP pivot
        return True

    def analyze(self, observable: Observable) -> dict[str, str] | None:
        try:
            results = querycontacts.ContactFinder().find(observable.value)
            if not results:
                logger.warning(
                    "No contact information returned for observable: %s", observable.value
                )
                return None

            return {"abuse": results[0]}
        except Exception as e:
            logger.error(
                "Error querying Abusix for observable '%s': %s",
                observable.value,
                e,
                exc_info=True,
            )
            return None

    def create_export_row(self, analysis_result: Any) -> dict:
        return {"abusix_abuse": analysis_result.get("abuse") if analysis_result else None}
