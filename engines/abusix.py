import logging
from typing import Optional

import querycontacts

logger = logging.getLogger(__name__)


def query_abusix(observable: str) -> Optional[dict[str, str]]:
    """
    Queries the Abusix service for contact information related to the given observable.

    Args:
        observable (str): The observable (e.g., IP address, domain) to query.

    Returns:
        dict: A dictionary with the key "abuse", containing the returned contact info
              (e.g., abuse email address). For example:
                  {
                      "abuse": "abuse@example.com"
                  }
        None: If an error occurs or no contact information is found.
    """
    try:
        results = querycontacts.ContactFinder().find(observable)
        if not results:
            logger.warning("No contact information returned for observable: %s", observable)
            return None

        # We assume the first item in 'results' is the most relevant contact
        return {"abuse": results[0]}

    except Exception as e:
        logger.error(
            "Error querying Abusix for observable '%s': %s",
            observable,
            e,
            exc_info=True,
        )

    # Return None if any error or unexpected scenario occurred
    return None
