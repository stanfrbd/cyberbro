from models.analysis_result import AnalysisResult, db


def save_analysis_result(analysis_result: AnalysisResult):
    db.session.add(analysis_result)
    db.session.commit()


def get_analysis_result(analysis_id: str):
    return db.session.query(AnalysisResult).filter_by(id=analysis_id).first()
