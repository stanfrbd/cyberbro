from datetime import datetime

from models.analysis_result import AnalysisResult, db


def get_analysis_stats():
    # Calculate the timestamp for 30 days ago
    now = datetime.now().timestamp()
    thirty_days_ago = now - 30 * 24 * 60 * 60

    # Query: only analyses from the last 30 days, ordered by start_time desc, limit 1000
    recent_analyses = (
        db.session.query(AnalysisResult)
        .filter(AnalysisResult.start_time >= thirty_days_ago)
        .order_by(AnalysisResult.start_time.desc())
        .limit(1000)
        .all()
    )
    last_30_days_analyses_count = (
        db.session.query(db.func.count(AnalysisResult.id))
        .filter(AnalysisResult.start_time >= thirty_days_ago)
        .scalar()
    )
    total_analyses = db.session.query(db.func.count(AnalysisResult.id)).scalar()
    observables_set = set()
    engines_set = set()
    observable_type_counter = {}
    engine_counter = {}
    observable_counter = {}

    for analysis in recent_analyses:
        for result in analysis.results:
            observable = result.get("observable") if result else "Unknown"
            observable_type = result.get("type") if result else "Unknown"
            observables_set.add(observable)
            observable_type_counter[observable_type] = (
                observable_type_counter.get(observable_type, 0) + 1
            )
            observable_counter[observable] = observable_counter.get(observable, 0) + 1

        for engine in analysis.selected_engines:
            engines_set.add(engine)
            engine_counter[engine] = engine_counter.get(engine, 0) + 1

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
