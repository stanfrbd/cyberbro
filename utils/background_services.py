import logging
import threading

from utils.bad_asn_manager import background_updater

logger = logging.getLogger(__name__)


def initialize_background_services() -> None:
    """
    Initialize background services for the application.

    This function starts daemon threads for long-running background tasks:
    - Bad ASN database updater: Periodically updates malicious ASN lists from
      external sources (Spamhaus ASNDROP, Brianhama Bad ASN database).

    These threads are marked as daemon threads, so they will automatically
    terminate when the main application exits.
    """
    # Start Bad ASN background updater thread
    # This maintains up-to-date lists of malicious ASNs for IP reputation checks
    bad_asn_thread = threading.Thread(target=background_updater, daemon=True, name="BadASNUpdater")
    bad_asn_thread.start()
    logger.info("Bad ASN background updater thread started")
