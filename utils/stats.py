from models.analysis_result import AnalysisResult, db


def get_analysis_stats():
    analyses = db.session.query(AnalysisResult).all()
    num_analyses = len(analyses)

    unique_observables = set()
    unique_engines = set()
    observable_type_count = {}
    engine_count = {}
    observable_count = {}

    for analysis in analyses:
        for result in analysis.results:
            observable = result.get("observable") if result else "Unknown"
            observable_type = result.get("type") if result else "Unknown"
            unique_observables.add(observable)
            if observable_type in observable_type_count:
                observable_type_count[observable_type] += 1
            else:
                observable_type_count[observable_type] = 1

            if observable in observable_count:
                observable_count[observable] += 1
            else:
                observable_count[observable] = 1

        for engine in analysis.selected_engines:
            unique_engines.add(engine)
            if engine in engine_count:
                engine_count[engine] += 1
            else:
                engine_count[engine] = 1

    return {
        "num_analyses": num_analyses,
        "num_unique_observables": len(unique_observables),
        "unique_observables": list(unique_observables),
        "num_unique_engines": len(unique_engines),
        "unique_engines": list(unique_engines),
        "observable_type_count": observable_type_count,
        "engine_count": engine_count,
        "observable_count": observable_count,
    }
