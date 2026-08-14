"""
Unit tests for:
  - src/baitblocker/ml/features.py    (extract_url_features and helpers)
  - src/baitblocker/ml/model_training.py (train_logistic_regression, load_model, predict_url)
"""

import json
from pathlib import Path

import pandas as pd
import pytest

from src.baitblocker.ml.model_training import (
    DEFAULT_PHISHING_THRESHOLD,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    extract_url_features,
    load_model,
    predict_url,
    train_logistic_regression,
)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _make_row(index: int, label: int) -> dict:
    """Build one synthetic CSV row that is linearly separable by label."""
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


@pytest.fixture()
def tiny_dataset(tmp_path: Path) -> Path:
    """Write a 30-row CSV (balanced labels) to a temp directory."""
    rows = [_make_row(i, i % 2) for i in range(30)]
    p = tmp_path / "tiny_phishing.csv"
    pd.DataFrame(rows).to_csv(p, index=False)
    return p


@pytest.fixture()
def trained_model(tmp_path: Path, tiny_dataset: Path):
    """Train on the tiny dataset and return (result_dict, model_path)."""
    model_path = tmp_path / "model.joblib"
    result = train_logistic_regression(
        csv_path=tiny_dataset,
        model_path=model_path,
        metrics_path=tmp_path / "metrics.json",
        test_size=0.25,
        random_state=0,
    )
    return result, model_path


# ────────────────────────────────────────────────────────────────────────────
# Feature Extraction Tests
# ────────────────────────────────────────────────────────────────────────────

class TestExtractUrlFeatures:

    def test_returns_all_feature_columns(self):
        feats = extract_url_features("https://example.com")
        assert set(feats.keys()) == set(FEATURE_COLUMNS)

    def test_all_values_are_floats(self):
        feats = extract_url_features("https://example.com/path?q=1")
        for key, val in feats.items():
            assert isinstance(val, float), f"{key} is not a float: {val!r}"

    def test_https_sets_no_https_to_zero(self):
        feats = extract_url_features("https://example.com")
        assert feats["NoHttps"] == 0.0

    def test_http_sets_no_https_to_one(self):
        feats = extract_url_features("http://example.com")
        assert feats["NoHttps"] == 1.0

    def test_ip_address_detected(self):
        feats = extract_url_features("http://192.168.1.1/admin")
        assert feats["IpAddress"] == 1.0

    def test_regular_hostname_not_flagged_as_ip(self):
        feats = extract_url_features("https://google.com")
        assert feats["IpAddress"] == 0.0

    def test_at_symbol_detected(self):
        feats = extract_url_features("http://user@evil.com/path")
        assert feats["AtSymbol"] == 1.0

    def test_tilde_detected(self):
        feats = extract_url_features("http://evil.com/~admin")
        assert feats["TildeSymbol"] == 1.0

    def test_num_dots_in_hostname(self):
        feats = extract_url_features("http://sub.domain.example.com")
        assert feats["NumDots"] == 3.0

    def test_subdomain_level_for_plain_domain(self):
        feats = extract_url_features("https://example.com")
        assert feats["SubdomainLevel"] == 0.0

    def test_subdomain_level_with_one_subdomain(self):
        feats = extract_url_features("https://login.example.com")
        assert feats["SubdomainLevel"] == 1.0

    def test_path_level_counts_slashes(self):
        feats = extract_url_features("https://example.com/a/b/c")
        assert feats["PathLevel"] == 3.0

    def test_query_components_counted(self):
        feats = extract_url_features("https://example.com/p?a=1&b=2&c=3")
        assert feats["NumQueryComponents"] == 3.0

    def test_num_dash_in_url(self):
        feats = extract_url_features("http://pay-pal-verify.com/account-check")
        assert feats["NumDash"] == 3.0

    def test_num_dash_in_hostname_only(self):
        feats = extract_url_features("http://pay-pal.com/safe-path")
        assert feats["NumDashInHostname"] == 1.0

    def test_num_numeric_chars(self):
        feats = extract_url_features("http://example.com/page123?id=456")
        assert feats["NumNumericChars"] == 6.0

    def test_double_slash_in_path(self):
        feats = extract_url_features("http://evil.com//redirect")
        assert feats["DoubleSlashInPath"] == 1.0

    def test_https_in_hostname_flag(self):
        feats = extract_url_features("http://https-secure.evil.com")
        assert feats["HttpsInHostname"] == 1.0

    def test_domain_in_paths_flag(self):
        feats = extract_url_features("http://evil.com/paypal/login")
        # domain_label = "evil", "evil" not in path "paypal/login" → 0
        assert feats["DomainInPaths"] == 0.0

    def test_random_string_detected(self):
        # Token "ab3cd4ef" has both alpha and digit, length ≥ 8
        feats = extract_url_features("http://ab3cd4ef.com")
        assert feats["RandomString"] == 1.0

    def test_random_string_not_triggered_on_plain_hostname(self):
        feats = extract_url_features("http://youtube.com")
        assert feats["RandomString"] == 0.0

    def test_sensitive_keywords_in_url(self):
        # "login" and "verify" are seeded keywords
        feats = extract_url_features("http://example.com/login/verify")
        assert feats["NumSensitiveWords"] >= 1.0

    def test_scheme_less_url_normalized(self):
        # scheme-less should be treated as http (NoHttps=1)
        feats = extract_url_features("example.com")
        assert feats["NoHttps"] == 1.0

    def test_url_length_increases_with_longer_url(self):
        short = extract_url_features("http://a.com")
        long = extract_url_features("http://a.com/" + "x" * 100)
        assert long["UrlLength"] > short["UrlLength"]

    def test_percent_encoding_counted(self):
        feats = extract_url_features("http://evil.com/path%20with%20spaces")
        assert feats["NumPercent"] == 2.0


# ────────────────────────────────────────────────────────────────────────────
# Model Training Tests
# ────────────────────────────────────────────────────────────────────────────

class TestTrainLogisticRegression:

    def test_model_artifact_is_saved(self, trained_model):
        _, model_path = trained_model
        assert model_path.exists()

    def test_metrics_file_is_saved_and_valid_json(self, tmp_path, tiny_dataset):
        metrics_path = tmp_path / "m.json"
        train_logistic_regression(
            csv_path=tiny_dataset,
            model_path=tmp_path / "model.joblib",
            metrics_path=metrics_path,
            test_size=0.25,
            random_state=1,
        )
        data = json.loads(metrics_path.read_text())
        for key in ("accuracy", "precision", "recall", "f1", "roc_auc", "train_size", "test_size", "feature_count"):
            assert key in data, f"Missing metrics key: {key}"

    def test_metrics_values_are_in_valid_range(self, trained_model):
        result, _ = trained_model
        m = result["metrics"]
        for key in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            assert 0.0 <= m[key] <= 1.0, f"{key}={m[key]} out of [0, 1]"

    def test_feature_count_matches_columns(self, trained_model):
        result, _ = trained_model
        assert result["metrics"]["feature_count"] == len(FEATURE_COLUMNS)

    def test_train_size_and_test_size_match_split(self, trained_model, tiny_dataset):
        result, _ = trained_model
        df = pd.read_csv(tiny_dataset)
        total = len(df)
        assert result["metrics"]["train_size"] + result["metrics"]["test_size"] == total

    def test_return_dict_contains_paths(self, trained_model):
        result, model_path = trained_model
        assert result["model_path"] == str(model_path)
        assert result["metrics_path"] is not None

    def test_missing_columns_raises_value_error(self, tmp_path):
        bad_csv = tmp_path / "bad.csv"
        pd.DataFrame({"OnlyOneCol": [1, 2, 3]}).to_csv(bad_csv, index=False)
        with pytest.raises(ValueError, match="missing required columns"):
            train_logistic_regression(
                csv_path=bad_csv,
                model_path=tmp_path / "model.joblib",
                test_size=0.25,
            )

    def test_no_metrics_path_writes_no_file(self, tmp_path, tiny_dataset):
        model_path = tmp_path / "model_nm.joblib"
        result = train_logistic_regression(
            csv_path=tiny_dataset,
            model_path=model_path,
            metrics_path=None,
            test_size=0.25,
        )
        assert result["metrics_path"] is None

    def test_determinism_with_same_random_state(self, tmp_path, tiny_dataset):
        def _train(seed):
            return train_logistic_regression(
                csv_path=tiny_dataset,
                model_path=tmp_path / f"model_{seed}.joblib",
                metrics_path=None,
                test_size=0.25,
                random_state=seed,
            )["metrics"]["accuracy"]

        assert _train(42) == _train(42)


# ────────────────────────────────────────────────────────────────────────────
# predict_url Tests
# ────────────────────────────────────────────────────────────────────────────

class TestPredictUrl:

    def test_output_keys_present(self, trained_model):
        _, model_path = trained_model
        result = predict_url("http://example.com", model_path=model_path)
        for key in ("url", "is_phishing", "phishing_probability", "safe_probability", "features", "feature_contributions"):
            assert key in result, f"Missing key: {key}"

    def test_probabilities_sum_to_one(self, trained_model):
        _, model_path = trained_model
        result = predict_url("http://example.com", model_path=model_path)
        total = round(result["phishing_probability"] + result["safe_probability"], 4)
        assert total == 1.0, f"Probabilities sum to {total}, expected 1.0"

    def test_phishing_probability_in_unit_interval(self, trained_model):
        _, model_path = trained_model
        result = predict_url("http://192.168.0.1/login/verify", model_path=model_path)
        assert 0.0 <= result["phishing_probability"] <= 1.0
        assert 0.0 <= result["safe_probability"] <= 1.0

    def test_is_phishing_is_bool(self, trained_model):
        _, model_path = trained_model
        result = predict_url("https://google.com", model_path=model_path)
        assert isinstance(result["is_phishing"], bool)

    def test_features_dict_has_all_columns(self, trained_model):
        _, model_path = trained_model
        result = predict_url("https://example.com", model_path=model_path)
        assert set(result["features"].keys()) == set(FEATURE_COLUMNS)

    def test_feature_contributions_has_all_columns(self, trained_model):
        _, model_path = trained_model
        result = predict_url("https://example.com", model_path=model_path)
        assert set(result["feature_contributions"].keys()) == set(FEATURE_COLUMNS)

    def test_contribution_values_are_floats(self, trained_model):
        _, model_path = trained_model
        result = predict_url("https://example.com", model_path=model_path)
        for k, v in result["feature_contributions"].items():
            assert isinstance(v, float), f"Contribution for {k} is not float: {v!r}"

    def test_custom_threshold_respected(self, trained_model):
        """If threshold is set to 0 all URLs are phishing; at 1.0 none are."""
        _, model_path = trained_model
        always = predict_url("https://google.com", model_path=model_path, phishing_threshold=0.0)
        never = predict_url("https://google.com", model_path=model_path, phishing_threshold=1.0)
        assert always["is_phishing"] is True
        assert never["is_phishing"] is False

    def test_default_threshold_is_applied(self, trained_model):
        _, model_path = trained_model
        result = predict_url("https://google.com", model_path=model_path)
        expected = result["phishing_probability"] >= DEFAULT_PHISHING_THRESHOLD
        assert result["is_phishing"] == expected

    def test_url_normalised_in_output(self, trained_model):
        _, model_path = trained_model
        result = predict_url("google.com", model_path=model_path)
        assert result["url"].startswith("http://") or result["url"].startswith("https://")

    def test_suspicious_url_higher_prob_than_benign(self, trained_model):
        """A URL with IP address + login path should outscore a clean domain."""
        _, model_path = trained_model
        suspicious = predict_url("http://192.168.1.5/login/verify", model_path=model_path)
        benign = predict_url("https://example.com", model_path=model_path)
        assert suspicious["phishing_probability"] >= benign["phishing_probability"]

    def test_load_model_returns_pipeline_and_columns(self, trained_model):
        _, model_path = trained_model
        artifact = load_model(model_path)
        assert "model" in artifact
        assert "feature_columns" in artifact
        assert artifact["feature_columns"] == FEATURE_COLUMNS
