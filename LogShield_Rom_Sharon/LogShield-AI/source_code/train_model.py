"""Train the LogShield AI anomaly detection model."""

from __future__ import annotations

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from config import DATASET_PATH, FEATURES, MODEL_DIR, MODEL_PATH


def train_model() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError("Dataset was not found. Run: python generate_dataset.py")

    df = pd.read_csv(DATASET_PATH)
    missing = [col for col in FEATURES + ["is_anomaly"] if col not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    # Isolation Forest is trained only on normal behavior so anomalies remain unseen during training.
    x_train = df.loc[df["is_anomaly"] == 0, FEATURES]

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IsolationForest(n_estimators=250, contamination=0.03, random_state=42)),
    ])
    model.fit(x_train)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to: {MODEL_PATH}")
    print(f"Training rows: {len(x_train)} | Features: {len(FEATURES)}")


if __name__ == "__main__":
    train_model()
