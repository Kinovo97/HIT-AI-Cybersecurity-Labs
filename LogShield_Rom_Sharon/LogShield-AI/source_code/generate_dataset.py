"""Generate a synthetic login-log dataset for LogShield AI.

The dataset contains normal login activity and several attack-like scenarios:
- Brute Force
- Credential Stuffing
- Suspicious off-hours login activity

The generated columns match the features used by train_model.py,
evaluate_model.py and main.py.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from config import DATA_DIR, DATASET_PATH


def _normal_activity(n: int, rng: np.random.Generator) -> pd.DataFrame:
    return pd.DataFrame({
        "source_ip": [f"10.{rng.integers(1, 255)}.{rng.integers(1, 255)}.{rng.integers(1, 255)}" for _ in range(n)],
        "username": [f"user_{rng.integers(100, 999)}" for _ in range(n)],
        "failed_attempts_10m": rng.choice([0, 1, 2, 3], size=n, p=[0.70, 0.20, 0.08, 0.02]),
        "unique_usernames_10m": rng.choice([1, 2, 3], size=n, p=[0.82, 0.15, 0.03]),
        "login_hour": rng.choice(list(range(7, 23)), size=n),
        "geo_risk_score": rng.normal(18, 8, size=n).clip(0, 100).round(2),
        "ip_reputation_score": rng.normal(20, 10, size=n).clip(0, 100).round(2),
        "login_velocity_1h": rng.normal(8, 5, size=n).clip(0, 200).round(2),
        "success_ratio_1h": rng.normal(0.86, 0.10, size=n).clip(0, 1).round(3),
        "device_change_flag": rng.choice([0, 1], size=n, p=[0.92, 0.08]),
        "is_anomaly": 0,
        "scenario": "legitimate_login_activity",
    })


def _brute_force(n: int, rng: np.random.Generator) -> pd.DataFrame:
    df = _normal_activity(n, rng)
    df["failed_attempts_10m"] = rng.integers(15, 50, size=n)
    df["unique_usernames_10m"] = rng.integers(1, 5, size=n)
    df["login_hour"] = rng.choice([0, 1, 2, 3, 4], size=n)
    df["geo_risk_score"] = rng.normal(70, 12, size=n).clip(0, 100).round(2)
    df["ip_reputation_score"] = rng.normal(78, 10, size=n).clip(0, 100).round(2)
    df["login_velocity_1h"] = rng.normal(95, 25, size=n).clip(0, 200).round(2)
    df["success_ratio_1h"] = rng.normal(0.08, 0.05, size=n).clip(0, 1).round(3)
    df["device_change_flag"] = rng.choice([0, 1], size=n, p=[0.35, 0.65])
    df["is_anomaly"] = 1
    df["scenario"] = "brute_force_T1110"
    return df


def _credential_stuffing(n: int, rng: np.random.Generator) -> pd.DataFrame:
    df = _normal_activity(n, rng)
    df["failed_attempts_10m"] = rng.integers(8, 25, size=n)
    df["unique_usernames_10m"] = rng.integers(8, 30, size=n)
    df["login_hour"] = rng.choice([0, 1, 2, 3, 4, 5, 22, 23], size=n)
    df["geo_risk_score"] = rng.normal(65, 15, size=n).clip(0, 100).round(2)
    df["ip_reputation_score"] = rng.normal(82, 9, size=n).clip(0, 100).round(2)
    df["login_velocity_1h"] = rng.normal(120, 30, size=n).clip(0, 220).round(2)
    df["success_ratio_1h"] = rng.normal(0.15, 0.07, size=n).clip(0, 1).round(3)
    df["device_change_flag"] = rng.choice([0, 1], size=n, p=[0.25, 0.75])
    df["is_anomaly"] = 1
    df["scenario"] = "credential_stuffing_T1110"
    return df


def generate_dataset(normal: int = 2400, brute_force: int = 180, credential_stuffing: int = 180, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    df = pd.concat([
        _normal_activity(normal, rng),
        _brute_force(brute_force, rng),
        _credential_stuffing(credential_stuffing, rng),
    ], ignore_index=True)
    df.insert(0, "event_id", [f"EVT-{i:05d}" for i in range(1, len(df) + 1)])
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)
    print(f"Dataset saved to: {DATASET_PATH}")
    print(f"Rows: {len(df)} | Normal: {(df.is_anomaly == 0).sum()} | Anomaly: {(df.is_anomaly == 1).sum()}")
    return df


if __name__ == "__main__":
    generate_dataset()
