"""Run LogShield AI inference for a single login event or for the dataset."""

from __future__ import annotations

import argparse

import joblib
import pandas as pd

from config import DATASET_PATH, FEATURES, MODEL_PATH


def enrich_with_mitre_intelligence(row: pd.Series) -> dict[str, str]:
    """Map suspicious behavior to MITRE ATT&CK context."""
    if row["unique_usernames_10m"] >= 8:
        scenario = "Credential Stuffing"
    else:
        scenario = "Brute Force"

    return {
        "Scenario": scenario,
        "Tactic": "Credential Access (TA0006)",
        "Technique": "Brute Force (T1110)",
        "Severity": "High" if row["failed_attempts_10m"] >= 15 or row["ip_reputation_score"] >= 80 else "Medium",
        "Recommended_Action": "Block or rate-limit the source IP, require MFA reset, and investigate related accounts.",
    }


def predict_single_event(args: argparse.Namespace) -> None:
    model = joblib.load(MODEL_PATH)
    event = pd.DataFrame([{
        "failed_attempts_10m": args.failed,
        "unique_usernames_10m": args.users,
        "login_hour": args.hour,
        "geo_risk_score": args.geo_risk,
        "ip_reputation_score": args.ip_reputation,
        "login_velocity_1h": args.velocity,
        "success_ratio_1h": args.success_ratio,
        "device_change_flag": args.device_change,
    }])

    prediction = model.predict(event[FEATURES])[0]
    score = -model.decision_function(event[FEATURES])[0]

    print("LogShield AI - Single Event Analysis")
    print("-" * 45)
    print(event.to_string(index=False))
    print(f"\nAnomaly score: {score:.4f}")

    if prediction == -1:
        mitre = enrich_with_mitre_intelligence(event.iloc[0])
        print("Decision: SUSPICIOUS / ANOMALY")
        print(f"Scenario: {mitre['Scenario']}")
        print(f"MITRE ATT&CK Tactic: {mitre['Tactic']}")
        print(f"MITRE ATT&CK Technique: {mitre['Technique']}")
        print(f"Severity: {mitre['Severity']}")
        print(f"Recommended Action: {mitre['Recommended_Action']}")
    else:
        print("Decision: NORMAL")


def predict_dataset() -> None:
    model = joblib.load(MODEL_PATH)
    df = pd.read_csv(DATASET_PATH)
    raw_pred = model.predict(df[FEATURES])
    df["predicted_anomaly"] = [1 if p == -1 else 0 for p in raw_pred]
    df["anomaly_score"] = -model.decision_function(df[FEATURES])
    anomalies = df[df["predicted_anomaly"] == 1].sort_values("anomaly_score", ascending=False)

    print(f"Pipeline complete. Detected {len(anomalies)} suspicious login events.")
    print("Top 5 suspicious events:")
    for _, row in anomalies.head(5).iterrows():
        mitre = enrich_with_mitre_intelligence(row)
        print("-" * 60)
        print(f"Event: {row['event_id']} | User: {row['username']} | IP: {row['source_ip']}")
        print(f"Failed attempts: {row['failed_attempts_10m']} | Users from IP: {row['unique_usernames_10m']} | Hour: {row['login_hour']}")
        print(f"Score: {row['anomaly_score']:.4f} | Severity: {mitre['Severity']} | {mitre['Technique']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LogShield AI anomaly detection inference")
    parser.add_argument("--dataset", action="store_true", help="Run inference on the full dataset")
    parser.add_argument("--failed", type=int, default=20, help="Failed attempts in the last 10 minutes")
    parser.add_argument("--users", type=int, default=3, help="Unique usernames tried from the same source in the last 10 minutes")
    parser.add_argument("--hour", type=int, default=2, help="Login hour, 0-23")
    parser.add_argument("--geo-risk", type=float, default=80, help="Geographic risk score, 0-100")
    parser.add_argument("--ip-reputation", type=float, default=90, help="IP reputation risk score, 0-100")
    parser.add_argument("--velocity", type=float, default=100, help="Login velocity in the last hour")
    parser.add_argument("--success-ratio", type=float, default=0.05, help="Login success ratio in the last hour")
    parser.add_argument("--device-change", type=int, choices=[0, 1], default=1, help="1 if this is a new device, otherwise 0")
    return parser.parse_args()


def main() -> None:
    if not MODEL_PATH.exists():
        raise FileNotFoundError("Model was not found. Run: python train_model.py")

    args = parse_args()
    if args.dataset:
        predict_dataset()
    else:
        predict_single_event(args)


if __name__ == "__main__":
    main()
