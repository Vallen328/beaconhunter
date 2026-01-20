import pandas as pd
import tempfile
from pathlib import Path

from src.train_detector import (
    load_data,
    prepare_features,
)

from src.features import (
    add_timing_features,
    add_port_features,
    add_process_features,
    add_geoip_features,
)

from src.score_live_events import (
    engineer_features,
    prepare_features_for_scoring,
    score_events,
    load_models,
)

def test_feature_engineering_columns():
    # Minimal synthetic row
    df = pd.DataFrame([{
        "event_id": "EVT-1",
        "host_id": "HOST-1",
        "timestamp": "2025-01-01T00:00:00Z",
        "dst_port": 443,
        "inter_event_seconds": 60.0,
        "proc_name": "powershell.exe",
        "country_code": "RU",
        "bytes_out": 120,
        "bytes_in": 80,
        "protocol": "https",
        "user": "alice",
        "signed_binary": 0,
    }])

    df = add_timing_features(df)
    df = add_port_features(df)
    df = add_process_features(df)
    df = add_geoip_features(df)

    expected_columns = [
        "timing_distance_from_60s",
        "is_rare_port",
        "process_risk_score",
        "geoip_risk_bucket",
    ]

    for col in expected_columns:
        assert col in df.columns

def test_train_pipeline_smoke(tmp_path):
    df = pd.DataFrame([
        {
            "event_id": "EVT-1",
            "host_id": "HOST-1",
            "timestamp": "2025-01-01T00:00:00Z",
            "dst_port": 443,
            "inter_event_seconds": 60.0,
            "proc_name": "powershell.exe",
            "country_code": "RU",
            "bytes_out": 100,
            "bytes_in": 50,
            "protocol": "https",
            "user": "alice",
            "signed_binary": 0,
            "label": 1,
        },
        {
            "event_id": "EVT-2",
            "host_id": "HOST-2",
            "timestamp": "2025-01-01T00:01:00Z",
            "dst_port": 443,
            "inter_event_seconds": 120.0,
            "proc_name": "chrome.exe",
            "country_code": "US",
            "bytes_out": 5000,
            "bytes_in": 10000,
            "protocol": "https",
            "user": "bob",
            "signed_binary": 1,
            "label": 0,
        },
    ])

    csv_path = tmp_path / "tiny_train.csv"
    df.to_csv(csv_path, index=False)

    df_loaded = load_data(csv_path)

    df_loaded = add_timing_features(df_loaded)
    df_loaded = add_port_features(df_loaded)
    df_loaded = add_process_features(df_loaded)
    df_loaded = add_geoip_features(df_loaded)

    X, y = prepare_features(df_loaded)

    assert len(X) == 2
    assert len(y) == 2

def test_score_live_events_sanity():
    df = pd.DataFrame([
        {
            "event_id": "EVT-100",
            "host_id": "HOST-X",
            "timestamp": "2025-02-01T12:00:00Z",
            "dst_port": 443,
            "inter_event_seconds": 60.0,
            "proc_name": "cmd.exe",
            "country_code": "CN",
            "bytes_out": 120,
            "bytes_in": 60,
            "protocol": "https",
            "user": "system",
            "signed_binary": 0,
        }
    ])

    df = engineer_features(df)
    df = prepare_features_for_scoring(df)

    sup_model, unsup_model = load_models()

    df_scored = score_events(df, sup_model, unsup_model)

    assert "final_risk" in df_scored.columns
    assert 0.0 <= df_scored["final_risk"].iloc[0] <= 1.0


