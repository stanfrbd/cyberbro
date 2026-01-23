from collections import Counter
from datetime import datetime

from models.analysis_result import AnalysisResult, db


def get_analysis_stats() -> dict:
    # Calculate the timestamp for 30 days ago
    now = datetime.now().timestamp()
    thirty_days_ago = now - 30 * 24 * 60 * 60

    # Query: only analyses from the last 30 days, ordered by start_time desc, limit 1000
    recent_analyses: list[AnalysisResult] = (
        db.session.query(AnalysisResult)
        .filter(AnalysisResult.start_time >= thirty_days_ago)
        .order_by(AnalysisResult.start_time.desc())
        .limit(1000)
        .all()
    )
    last_30_days_analyses_count: int = (
        db.session.query(db.func.count(AnalysisResult.id))
        .filter(AnalysisResult.start_time >= thirty_days_ago)
        .scalar()
    )
    total_analyses: int = db.session.query(db.func.count(AnalysisResult.id)).scalar()
    observables_set: set = set()
    engines_set: set = set()
    observable_type_counter: Counter = Counter()
    engine_counter: Counter = Counter()
    observable_counter: Counter = Counter()

    for analysis in recent_analyses:
        for result in analysis.results:
            observable: str = result.get("observable") if result else "Unknown"
            observable_type: str = result.get("type") if result else "Unknown"
            observables_set.add(observable)
            observable_type_counter[observable_type] += 1
            observable_counter[observable] += 1

        engine_counter += Counter(analysis.selected_engines)
        for engine in analysis.selected_engines:
            engines_set.add(engine)

    return {
        "total_analyses_count": total_analyses,
        "last_30_days_analyses_count": last_30_days_analyses_count,
        "unique_observables_count": len(observables_set),
        "unique_observables": list(observables_set),
        "unique_engines_count": len(engines_set),
        "unique_engines": list(engines_set),
        "observable_type_count": observable_type_counter,
        "engine_count": engine_counter,
        "observable_count": observable_counter,
    }
