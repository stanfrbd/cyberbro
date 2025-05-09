from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class AnalysisResult(db.Model):
    id = db.Column(db.String, primary_key=True)
    results = db.Column(db.JSON, nullable=False)
    start_time = db.Column(db.Float, nullable=False)
    end_time = db.Column(db.Float, nullable=True)  # Permettre les valeurs NULL
    start_time_string = db.Column(db.String, nullable=False)
    end_time_string = db.Column(db.String, nullable=True)  # Permettre les valeurs NULL
    analysis_duration_string = db.Column(db.String, nullable=True)  # Permettre les valeurs NULL
    analysis_duration = db.Column(db.Float, nullable=True)  # Permettre les valeurs NULL
    selected_engines = db.Column(db.JSON, nullable=False)
    in_progress = db.Column(db.Boolean, default=True)
