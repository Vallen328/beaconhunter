import pandas as pd
import numpy as np

from pathlib import Path
import joblib

from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from src.features import (
    add_timing_features,
    add_port_features,
    add_process_features,
    add_geoip_features
)

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)
from sklearn.ensemble import IsolationForest

DATA_PATH = Path("data/beacon_events_train.csv")
ARTIFACTS_DIR = Path("artifacts/")
RANDOM_STATE = 42

def load_data(path):
    """
    Load raw training data
    """
    df = pd.read_csv(path)
    return df

def prepare_features(df):
    """
    Select features and target label.
    Handle missing values if needed.
    Return X, y.
    """
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

    target_col = 'label'

    required_cols = numeric_features + categorical_features + [target_col]
    missing_cols = [c for c in required_cols if c not in df.columns]

    if missing_cols:
        raise ValueError(
            f"Missing required feature columns: {missing_cols}. "
            "Have you run feature engineering before training?"
        )

    df_clean = df.copy()

    for col in numeric_features:
        median_value = df_clean[col].median()
        df_clean[col] = df_clean[col].fillna(median_value)

    for col in categorical_features:
        df_clean[col] = df_clean[col].fillna('UNKNOWN')

    feature_cols = numeric_features + categorical_features

    X = df_clean[feature_cols]
    y = df_clean[target_col]

    return X, y

def build_preprocessor():
    """
    Build and return preprocessing pipeline.
    """
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

    numeric_transformer = Pipeline(
        steps=[
            ('scaler', StandardScaler())
        ]
    )

    categorical_transformer = OneHotEncoder(
        handle_unknown='ignore'
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numeric_features),
            ('cat', categorical_transformer, categorical_features)
        ]
    )

    return preprocessor

def train_supervised_model(X_train, y_train, preprocessor):
    """
    Train supervised classifier.
    """
    clf = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=RANDOM_STATE
    )

    supervised_pipeline = Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("clf", clf)
        ]
    )

    supervised_pipeline.fit(X_train, y_train)

    return supervised_pipeline

def train_unsupervised_model(X_train_benign, preprocessor):
    """
    Train unsupervised anomaly detection model.
    """
    iforest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=RANDOM_STATE
    )

    unsupervised_pipeline = Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("iforest", iforest)
        ]
    )

    unsupervised_pipeline.fit(X_train_benign)

    return unsupervised_pipeline

def compute_final_risk(supervised_scores, anomaly_scores):
    """
    Combine supervised and unsupervised scores
    into a final risk score.
    """
    ALPHA = 0.7
    final_risk = ALPHA * supervised_scores + (1 - ALPHA) * anomaly_scores
    final_risk = np.clip(final_risk, 0.0, 1.0)

    return final_risk

def save_artifacts(preprocessor, sup_model, unsup_model):
    """
    Persist trained artifacts to disk.
    """
    ARTIFACTS_DIR.mkdir(exist_ok=True)

    joblib.dump(
        sup_model,
        ARTIFACTS_DIR / "supervised_detector.joblib"
    )

    joblib.dump(
        unsup_model,
        ARTIFACTS_DIR / "unsupervised_detector.joblib"
    )

def main():
    df = load_data(DATA_PATH)
    df = add_timing_features(df)
    df = add_port_features(df)
    df = add_process_features(df)
    df = add_geoip_features(df)
    X, y = prepare_features(df)
    preprocessor = build_preprocessor()
    X_train, X_val, y_train, y_val = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y
    )
    sup_model = train_supervised_model(
        X_train, y_train, preprocessor
    )
    y_proba = sup_model.predict_proba(X_val)[:, 1]

    THRESHOLD = 0.7
    y_pred = (y_proba >= THRESHOLD).astype(int)

    precision = precision_score(y_val, y_pred)
    recall = recall_score(y_val, y_pred)
    f1 = f1_score(y_val, y_pred)
    roc_auc = roc_auc_score(y_val, y_proba)

    X_train_benign = X_train[y_train == 0]

    unsup_model = train_unsupervised_model(
        X_train_benign,
        preprocessor
    )

    raw_anomaly_scores = unsup_model.decision_function(X_val)

    anomaly_scores = -raw_anomaly_scores

    min_score = anomaly_scores.min()
    max_score = anomaly_scores.max()

    anomaly_scores = (anomaly_scores - min_score) / (max_score - min_score)

    final_risk = compute_final_risk(y_proba, anomaly_scores)

    save_artifacts(preprocessor, sup_model, unsup_model)

    print("\nUnsupervised anomaly score summary:")
    print(pd.Series(anomaly_scores).describe())

    print("\nMean anomaly score by label:")
    print(pd.Series(anomaly_scores).groupby(y_val).mean())


    print("Supervised model validation metrics:")
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1-score:  {f1:.3f}")
    print(f"ROC-AUC:   {roc_auc:.3f}")

    print("\nFinal risk score summary:")
    print(pd.Series(final_risk).describe())

    print("\nMean final risk by label:")
    print(pd.Series(final_risk).groupby(y_val).mean())
    


if __name__ == "__main__":
    main()