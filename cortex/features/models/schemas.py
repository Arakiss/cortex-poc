from pydantic import BaseModel
from typing import Dict


class SurveyAnalysis(BaseModel):
    satisfaction_score: str
    daily_active_users: str
    main_pain_point: str
    feature_requests: Dict[str, str]
    summary: str


class AnalysisReport(BaseModel):
    title: str
    overview: str
    key_metrics: Dict[str, str]
    pain_points: Dict[str, str]
    feature_requests: Dict[str, str]
    recommendations: list[str]
