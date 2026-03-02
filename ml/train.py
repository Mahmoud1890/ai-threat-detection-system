#!/usr/bin/env python3
"""
Phase 2 — ML Anomaly Detection
Train a supervised classifier on BETH dataset to detect suspicious syscall behavior.

Training label : sus  (available in training data)
Evaluation label: evil (available in test data only)
"""

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import LabelEncoder

TRAIN_PATH = "data/raw/labelled_training_data.csv"
VAL_PATH   = "data/raw/labelled_validation_data.csv"
TEST_PATH  = "data/raw/labelled_testing_data.csv"
MODEL_PATH = "models/detector.joblib"

FEATURES = [
    "eventName",
    "processName",
    "processId",
    "parentProcessId",
    "userId",
    "returnValue",
    "argsNum",
    "is_root",
    "failed_syscall",
    "is_unknown_user",
    "is_unknown_process",
    "connect_count",
]


def engineer_features(
    df: pd.DataFrame,
    encoders: dict = None,
    fit: bool = False,
    normal_users: set = None,
    normal_processes: set = None,
) -> tuple:
    df = df.copy()

    # Basic binary features
    df["is_root"]        = (df["userId"] == 0).astype(int)
    df["failed_syscall"] = (df["returnValue"] < 0).astype(int)

    # Unknown user/process — never seen in normal training rows
    df["is_unknown_user"]    = (~df["userId"].isin(normal_users)).astype(int)
    df["is_unknown_process"] = (~df["processName"].astype(str).isin(normal_processes)).astype(int)

    # Per-process connect call count — captures port scanning / C2 beaconing
    connect_counts = (
        df[df["eventName"] == "connect"]
        .groupby("processId")
        .size()
        .rename("connect_count")
    )
    df = df.join(connect_counts, on="processId")
    df["connect_count"] = df["connect_count"].fillna(0).astype(int)

    if fit:
        encoders = {}
        for col in ("eventName", "processName"):
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
    else:
        for col in ("eventName", "processName"):
            le = encoders[col]
            df[col] = df[col].astype(str).map(
                lambda x, le=le: le.transform([x])[0] if x in le.classes_ else -1
            )

    return df[FEATURES], encoders


def load(path: str) -> pd.DataFrame:
    print(f"Loading {path} ...")
    return pd.read_csv(path)


def main():
    # ── Load ──────────────────────────────────────────────────────────────────
    train = load(TRAIN_PATH)
    val   = load(VAL_PATH)
    test  = load(TEST_PATH)

    # ── Feature engineering ───────────────────────────────────────────────────
    print("Engineering features ...")

    # Compute normal baselines from training data (sus=0 rows only)
    normal_rows     = train[train["sus"] == 0]
    normal_users    = set(normal_rows["userId"].unique())
    normal_processes = set(normal_rows["processName"].astype(str).unique())

    X_train, encoders = engineer_features(
        train, fit=True,
        normal_users=normal_users, normal_processes=normal_processes,
    )
    y_train = train["sus"]

    X_val, _ = engineer_features(
        val, encoders=encoders,
        normal_users=normal_users, normal_processes=normal_processes,
    )
    y_val = val["sus"]

    X_test, _ = engineer_features(
        test, encoders=encoders,
        normal_users=normal_users, normal_processes=normal_processes,
    )
    y_test_evil = test["evil"]

    # ── Train ─────────────────────────────────────────────────────────────────
    print("Training Random Forest ...")
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train)

    # ── Validate ──────────────────────────────────────────────────────────────
    print("\n=== Validation (sus labels) ===")
    y_val_pred = model.predict(X_val)
    print(classification_report(y_val, y_val_pred, target_names=["normal", "suspicious"]))

    # ── Evaluate on test (evil labels) ────────────────────────────────────────
    print("=== Test (evil labels) ===")
    y_test_pred = model.predict(X_test)
    print(classification_report(y_test_evil, y_test_pred, target_names=["normal", "evil"]))
    print(f"ROC-AUC: {roc_auc_score(y_test_evil, model.predict_proba(X_test)[:, 1]):.4f}")

    # ── Feature importance ────────────────────────────────────────────────────
    print("\n=== Feature Importance ===")
    importances = sorted(
        zip(FEATURES, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for name, score in importances:
        print(f"  {name:<20} {score:.4f}")

    # ── Save ──────────────────────────────────────────────────────────────────
    joblib.dump({
        "model": model,
        "encoders": encoders,
        "normal_users": normal_users,
        "normal_processes": normal_processes,
    }, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
