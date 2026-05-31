"""Evaluate the LogShield AI model, export metrics and update presentation-ready charts."""

from __future__ import annotations

import json

import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from config import (
    ASSETS_DIR,
    CLASSIFICATION_REPORT_PATH,
    CONFUSION_MATRIX_PATH,
    DATASET_PATH,
    FEATURE_PATTERNS_PATH,
    FEATURES,
    METRICS_JSON_PATH,
    METRICS_PATH,
    MODEL_PATH,
    RESULTS_DIR,
    SCORE_DISTRIBUTION_PATH,
    TOP_ALERTS_PATH,
)


def _save_confusion_matrix(cm) -> None:
    display = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Normal", "Anomaly"])
    display.plot(values_format="d")
    plt.title("Confusion Matrix")
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PATH, dpi=200)
    plt.close()


def _save_score_distribution(df: pd.DataFrame) -> None:
    normal_scores = df.loc[df["is_anomaly"] == 0, "anomaly_score"]
    anomaly_scores = df.loc[df["is_anomaly"] == 1, "anomaly_score"]
    plt.figure(figsize=(8, 4.5))
    plt.hist(normal_scores, bins=40, alpha=0.8, label="Legitimate")
    plt.hist(anomaly_scores, bins=40, alpha=0.8, label="Anomalous")
    plt.title("Anomaly Score Distribution")
    plt.xlabel("Anomaly score (higher = more suspicious)")
    plt.ylabel("Events")
    plt.legend()
    plt.tight_layout()
    plt.savefig(SCORE_DISTRIBUTION_PATH, dpi=200)
    plt.close()


def _save_feature_patterns(df: pd.DataFrame) -> None:
    selected = [
        "failed_attempts_10m",
        "unique_usernames_10m",
        "geo_risk_score",
        "ip_reputation_score",
        "login_velocity_1h",
    ]
    grouped = df.groupby("is_anomaly")[selected].mean().rename(index={0: "Normal", 1: "Anomaly"})
    grouped.T.plot(kind="bar", figsize=(9, 4.8))
    plt.title("Average Feature Patterns")
    plt.ylabel("Average value")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(FEATURE_PATTERNS_PATH, dpi=200)
    plt.close()


def evaluate_model() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError("Dataset was not found. Run: python generate_dataset.py")
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Model was not found. Run: python train_model.py")

    df = pd.read_csv(DATASET_PATH)
    model = joblib.load(MODEL_PATH)

    x = df[FEATURES]
    y_true = df["is_anomaly"]
    raw_pred = model.predict(x)
    y_pred = pd.Series(raw_pred).map({1: 0, -1: 1})
    anomaly_score = -model.decision_function(x)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    cm = confusion_matrix(y_true, y_pred)
    report_text = classification_report(y_true, y_pred, target_names=["Normal", "Anomaly"], zero_division=0)
    report_dict = classification_report(y_true, y_pred, target_names=["Normal", "Anomaly"], output_dict=True, zero_division=0)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

    output = df.copy()
    output["predicted_anomaly"] = y_pred.values
    output["anomaly_score"] = anomaly_score
    output.sort_values("anomaly_score", ascending=False).head(25).to_csv(TOP_ALERTS_PATH, index=False)

    metrics_text = (
        "LogShield AI - Evaluation Metrics\n"
        "=================================\n"
        f"Accuracy:  {accuracy:.3f}\n"
        f"Precision: {precision:.3f}\n"
        f"Recall:    {recall:.3f}\n"
        f"F1 Score:  {f1:.3f}\n\n"
        "Confusion Matrix [Normal, Anomaly]:\n"
        f"{cm}\n\n"
        "Classification Report:\n"
        f"{report_text}\n"
    )
    METRICS_PATH.write_text(metrics_text, encoding="utf-8")

    metrics_json = {
        "project": "LogShield AI",
        "model": "Isolation Forest",
        "dataset": {
            "total_rows": int(len(df)),
            "normal_rows": int((df["is_anomaly"] == 0).sum()),
            "anomaly_rows": int((df["is_anomaly"] == 1).sum()),
        },
        "metrics": {
            "accuracy": round(float(accuracy), 3),
            "precision": round(float(precision), 3),
            "recall": round(float(recall), 3),
            "f1_score": round(float(f1), 3),
        },
        "confusion_matrix": {
            "labels": ["Normal", "Anomaly"],
            "matrix": cm.astype(int).tolist(),
            "true_normal_pred_normal": int(cm[0, 0]),
            "true_normal_pred_anomaly": int(cm[0, 1]),
            "true_anomaly_pred_normal": int(cm[1, 0]),
            "true_anomaly_pred_anomaly": int(cm[1, 1]),
        },
        "classification_report": report_dict,
    }
    METRICS_JSON_PATH.write_text(json.dumps(metrics_json, indent=4), encoding="utf-8")

    classification_report_text = (
        "LogShield AI - Updated Classification Report\n"
        "============================================\n\n"
        "Model: Isolation Forest\n"
        f"Total rows: {len(df)}\n"
        f"Normal rows: {(df['is_anomaly'] == 0).sum()}\n"
        f"Anomaly rows: {(df['is_anomaly'] == 1).sum()}\n\n"
        "Evaluation Metrics\n"
        "------------------\n"
        f"Accuracy:  {accuracy:.3f}\n"
        f"Precision: {precision:.3f}\n"
        f"Recall:    {recall:.3f}\n"
        f"F1 Score:  {f1:.3f}\n\n"
        "Confusion Matrix [Normal, Anomaly]\n"
        "----------------------------------\n"
        f"{cm}\n\n"
        "Classification Report\n"
        "---------------------\n"
        f"{report_text}"
    )
    CLASSIFICATION_REPORT_PATH.write_text(classification_report_text, encoding="utf-8")

    chart_df = output.copy()
    _save_confusion_matrix(cm)
    _save_score_distribution(chart_df)
    _save_feature_patterns(chart_df)

    print(metrics_text)
    print(f"Top suspicious events saved to: {TOP_ALERTS_PATH}")
    print(f"Metrics JSON saved to: {METRICS_JSON_PATH}")
    print(f"Classification report saved to: {CLASSIFICATION_REPORT_PATH}")
    print(f"Charts saved to: {ASSETS_DIR}")


if __name__ == "__main__":
    evaluate_model()
