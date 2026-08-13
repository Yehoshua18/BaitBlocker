from pathlib import Path

import pandas as pd

from baitblocker.ml.model_training import (
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    extract_url_features,
    predict_url,
    train_logistic_regression,
)


def _make_row(index: int, label: int) -> dict:
    base = {name: 0.0 for name in FEATURE_COLUMNS}
    base["NumDots"] = 1 + (index % 3)
    base["UrlLength"] = 30 + index * 7
    base["HostnameLength"] = 12 + index
    base["PathLength"] = 3 + index
    base["NumDash"] = float(index % 2)
    base["NoHttps"] = float(label)
    base["IpAddress"] = float(label)
    base["NumSensitiveWords"] = float(1 + label)
    base["RandomString"] = float(label)
    base[LABEL_COLUMN] = label
    return base


def test_extract_url_features_basic_counts() -> None:
    features = extract_url_features("http://secure-login.example.com/account/verify?id=123")

    assert features["NoHttps"] == 1.0
    assert features["SubdomainLevel"] >= 1.0
    assert features["NumQueryComponents"] == 1.0
    assert features["NumSensitiveWords"] >= 2.0


def test_train_and_predict_smoke(tmp_path: Path) -> None:
    rows = [_make_row(i, 1 if i % 2 else 0) for i in range(20)]
    csv_path = tmp_path / "mini_phishing.csv"
    model_path = tmp_path / "phishing_model.joblib"
    metrics_path = tmp_path / "metrics.json"

    pd.DataFrame(rows).to_csv(csv_path, index=False)

    train_result = train_logistic_regression(
        csv_path=csv_path,
        model_path=model_path,
        metrics_path=metrics_path,
        test_size=0.25,
        random_state=7,
    )

    assert model_path.exists()
    assert metrics_path.exists()
    assert train_result["metrics"]["feature_count"] == len(FEATURE_COLUMNS)

    prediction = predict_url("http://192.168.0.1/login/verify", model_path=model_path)

    assert isinstance(prediction["is_phishing"], bool)
    assert 0.0 <= prediction["phishing_probability"] <= 1.0
    assert 0.0 <= prediction["safe_probability"] <= 1.0

