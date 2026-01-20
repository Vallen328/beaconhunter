import pandas as pd
import numpy as np

from pathlib import Path
import joblib

from src.features import (
    add_timing_features,
    add_port_features,
    add_process_features,
    add_geoip_features
)

DATA_PATH = Path("data/beacon_events_eval_unlabeled.csv")
ARTIFACTS_DIR = Path("artifacts/")

SUP_MODEL_PATH = ARTIFACTS_DIR / "supervised_detector.joblib"
UNSUP_MODEL_PATH = ARTIFACTS_DIR / "unsupervised_detector.joblib"


def load_data(path):
    """
    Load live (unlabeled) event data.
    """
    df = pd.read_csv(path)
    return df


def engineer_features(df):
    """
    Apply the same feature engineering used during training.
    """
    df_feat = df.copy()

    df_feat = add_timing_features(df_feat)
    df_feat = add_port_features(df_feat)
    df_feat = add_process_features(df_feat)
    df_feat = add_geoip_features(df_feat)

    return df_feat



def load_models():
    """
    Load trained supervised and unsupervised models.
    """
    sup_model = joblib.load(SUP_MODEL_PATH)
    unsup_model = joblib.load(UNSUP_MODEL_PATH)

    return sup_model, unsup_model

def prepare_features_for_scoring(df):
    """
    Apply the same missing-value handling as training (inference-safe).
    """
    df_clean = df.copy()

    numeric_features = [
        'inter_event_seconds',
        'bytes_out',
        'bytes_in',
        'timing_distance_from_60s',
        'is_rare_port',
        'process_risk_score',
        'geoip_risk_bucket',
        'signed_binary'
    ]

    categorical_features = [
        'protocol',
        'user'
    ]

    # Numeric: fill with median (computed on live batch)
    for col in numeric_features:
        df_clean[col] = df_clean[col].fillna(df_clean[col].median())

    # Categorical: fill UNKNOWN
    for col in categorical_features:
        df_clean[col] = df_clean[col].fillna("UNKNOWN")

    return df_clean




def score_events(df, sup_model, unsup_model):
    """
    Compute supervised score, anomaly score, and final risk score.
    """
    df_scored = df.copy()

    # Supervised probability score
    supervised_scores = sup_model.predict_proba(df_scored)[:, 1]

    # Unsupervised anomaly score (higher = more anomalous)
    raw_anomaly_scores = unsup_model.decision_function(df_scored)
    anomaly_scores = -raw_anomaly_scores

    # Normalize anomaly scores to [0, 1]
    min_score = anomaly_scores.min()
    max_score = anomaly_scores.max()

    if max_score > min_score:
        anomaly_scores = (anomaly_scores - min_score) / (max_score - min_score)
    else:
        anomaly_scores = np.zeros_like(anomaly_scores)

    # Fusion
    ALPHA = 0.7
    final_risk = ALPHA * supervised_scores + (1 - ALPHA) * anomaly_scores
    final_risk = np.clip(final_risk, 0.0, 1.0)

    # Attach scores
    df_scored["supervised_score"] = supervised_scores
    df_scored["anomaly_score"] = anomaly_scores
    df_scored["final_risk"] = final_risk

    return df_scored



def aggregate_by_host(df_scored):
    """
    Aggregate event-level scores into host-level prioritization.
    """
    host_agg = (
        df_scored
        .groupby("host_id")
        .agg(
            event_count=("event_id", "count"),
            mean_risk=("final_risk", "mean"),
            max_risk=("final_risk", "max")
        )
        .reset_index()
        .sort_values("max_risk", ascending=False)
    )

    return host_agg



def main():
    df = load_data(DATA_PATH)
    df = engineer_features(df)

    df = prepare_features_for_scoring(df)

    sup_model, unsup_model = load_models()

    df_scored = score_events(df, sup_model, unsup_model)

    host_agg = aggregate_by_host(df_scored)

    print("\nTop 5 hosts by max risk:")
    print(host_agg.head(5))

if __name__ == "__main__":
    main()
