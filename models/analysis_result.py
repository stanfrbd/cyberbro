from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class AnalysisResult(db.Model):
    id: str = db.Column(db.String, primary_key=True)
    results: dict = db.Column(db.JSON, nullable=False)
    start_time: float = db.Column(db.Float, nullable=False)
    end_time: float = db.Column(db.Float, nullable=True)  # Permettre les valeurs NULL
    start_time_string: str = db.Column(db.String, nullable=False)
    end_time_string: str = db.Column(db.String, nullable=True)  # Permettre les valeurs NULL
    analysis_duration_string: str = db.Column(
        db.String, nullable=True
    )  # Permettre les valeurs NULL
    analysis_duration: float = db.Column(db.Float, nullable=True)  # Permettre les valeurs NULL
    selected_engines: dict = db.Column(db.JSON, nullable=False)
    in_progress: bool = db.Column(db.Boolean, default=True)
