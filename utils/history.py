"""Helper functions for the history page with pagination and search."""

import time

from models.analysis_result import AnalysisResult


def validate_history_params(page: int, per_page: int, search_type: str, time_range: str) -> tuple[int, int, str, str]:
    """Validate and sanitize history page parameters.

    Args:
        page: Current page number
        per_page: Results per page
        search_type: Type of search (observable, engine, id)
        time_range: Time range filter (7d, 30d, all)

    Returns:
        Tuple of validated (page, per_page, search_type, time_range)
    """
    page = max(1, page)
    per_page = 20 if per_page < 1 or per_page > 100 else per_page
    search_type = search_type if search_type in ["observable", "engine", "id"] else "observable"
    time_range = time_range if time_range in ["7d", "30d", "all"] else "7d"
    return page, per_page, search_type, time_range


def apply_time_range_filter(base_query, time_range: str):
    """Apply time range filter to the base query.

    Args:
        base_query: SQLAlchemy query object
        time_range: Time range filter (7d, 30d, all)

    Returns:
        Filtered query object
    """
    if time_range == "all":
        return base_query

    current_time = time.time()
    days = 7 if time_range == "7d" else 30
    cutoff_time = current_time - (days * 24 * 60 * 60)
    return base_query.filter(AnalysisResult.end_time >= cutoff_time)


def apply_search_filter(base_query, search_query: str, search_type: str):
    """Apply search filter to the base query for non-observable searches.

    Args:
        base_query: SQLAlchemy query object
        search_query: Search query string
        search_type: Type of search (id or engine)

    Returns:
        Filtered query object
    """
    if not search_query or search_type == "observable":
        return base_query

    if search_type == "id":
        return base_query.filter(AnalysisResult.id.ilike(f"%{search_query}%"))
    if search_type == "engine":
        return base_query.filter(AnalysisResult.selected_engines.ilike(f"%{search_query}%"))

    return base_query


def filter_by_observable(results: list, search_query: str) -> list:
    """Filter results by observable value (in-memory search).

    Args:
        results: List of AnalysisResult objects
        search_query: Search query string

    Returns:
        Filtered list of results
    """
    search_lower = search_query.lower()
    return [result for result in results if any(search_lower in str(item.get("observable", "")).lower() for item in result.results if item is not None and isinstance(item, dict))]


def calculate_pagination_metadata(page: int, per_page: int, total_count: int) -> dict:
    """Calculate pagination metadata.

    Args:
        page: Current page number
        per_page: Results per page
        total_count: Total number of results

    Returns:
        Dict with total_pages, has_prev, has_next
    """
    total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
    return {"total_pages": total_pages, "has_prev": page > 1, "has_next": page < total_pages}
