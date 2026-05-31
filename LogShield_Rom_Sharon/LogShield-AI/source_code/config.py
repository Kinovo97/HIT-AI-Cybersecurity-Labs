from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
RESULTS_DIR = PROJECT_DIR / "results"
ASSETS_DIR = PROJECT_DIR / "assets"
DATASET_PATH = DATA_DIR / "login_logs.csv"
MODEL_PATH = MODEL_DIR / "logshield_isolation_forest.joblib"
TOP_ALERTS_PATH = RESULTS_DIR / "top_suspicious_events.csv"
METRICS_PATH = RESULTS_DIR / "metrics.txt"
METRICS_JSON_PATH = RESULTS_DIR / "metrics.json"
CLASSIFICATION_REPORT_PATH = RESULTS_DIR / "classification_report.txt"
CONFUSION_MATRIX_PATH = ASSETS_DIR / "confusion_matrix.png"
SCORE_DISTRIBUTION_PATH = ASSETS_DIR / "score_distribution.png"
FEATURE_PATTERNS_PATH = ASSETS_DIR / "feature_patterns.png"

FEATURES = [
    "failed_attempts_10m",
    "unique_usernames_10m",
    "login_hour",
    "geo_risk_score",
    "ip_reputation_score",
    "login_velocity_1h",
    "success_ratio_1h",
    "device_change_flag",
]
