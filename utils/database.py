from models.analysis_result import AnalysisResult, db


def save_analysis_result(analysis_result):
    db.session.add(analysis_result)
    db.session.commit()


def get_analysis_result(analysis_id):
    return db.session.query(AnalysisResult).filter_by(id=analysis_id).first()
