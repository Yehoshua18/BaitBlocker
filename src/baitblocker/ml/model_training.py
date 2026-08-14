"""Train and use a logistic regression model for phishing URL detection."""

import json
from pathlib import Path
from typing import Any, Dict, Optional
import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from ..ml.features import extract_url_features, _normalize_url, FEATURE_COLUMNS


LABEL_COLUMN = "CLASS_LABEL"

DEFAULT_DATASET_PATH = Path(__file__).with_name("PhishingData.csv")
DEFAULT_MODEL_PATH = Path(__file__).with_name("phishing_logreg_model.joblib")
DEFAULT_METRICS_PATH = Path(__file__).with_name("phishing_logreg_metrics.json")
DEFAULT_PHISHING_THRESHOLD = 0.6


def _normalize_labels(y_raw: pd.Series) -> pd.Series:
	# The dataset commonly uses {-1, 1};
	# map positive values to phishing=1 to be applicable for logistic regression
	if set(pd.Series(y_raw).dropna().unique()).issubset({-1, 0, 1}):
		return (y_raw.astype(float) > 0).astype(int) # Any positive number=phishing
	return y_raw.astype(int) # The labels consist of more than {-1, 0, 1} which should happen in logistical regression


def train_logistic_regression(
	csv_path: Path = DEFAULT_DATASET_PATH,
	model_path: Path = DEFAULT_MODEL_PATH,
	metrics_path: Optional[Path] = DEFAULT_METRICS_PATH,
	test_size: float = 0.2,
	random_state: int = 42,
) -> Dict[str, Any]:
	"""Train logistic regression on PhishingData.csv and persist the trained model."""
	csv_path = Path(csv_path)
	model_path = Path(model_path)
	if metrics_path is not None:
		metrics_path = Path(metrics_path)

	dataset = pd.read_csv(csv_path)
	required_columns = set(FEATURE_COLUMNS + [LABEL_COLUMN])
	missing_columns = sorted(required_columns - set(dataset.columns))
	if missing_columns:
		raise ValueError("Dataset is missing required columns: {}".format(missing_columns))

	X = dataset[FEATURE_COLUMNS]
	y = _normalize_labels(dataset[LABEL_COLUMN])

	X_train, X_test, y_train, y_test = train_test_split(
		X,
		y,
		test_size=test_size,
		random_state=random_state,
		stratify=y,
	)

	pipeline = Pipeline(
		steps=[
			("scaler", StandardScaler()),
			(
				"classifier",
				LogisticRegression(
					max_iter=2000,
					class_weight="balanced",
					solver="liblinear",
					random_state=random_state,
				),
			),
		]
	)

	pipeline.fit(X_train, y_train)
	predictions = pipeline.predict(X_test)
	probabilities = pipeline.predict_proba(X_test)[:, 1]

	# Use functions from sklearn to determine whether the model is efficient
	metrics = {
		"accuracy": float(accuracy_score(y_test, predictions)),
		"precision": float(precision_score(y_test, predictions, zero_division=0)),
		"recall": float(recall_score(y_test, predictions, zero_division=0)),
		"f1": float(f1_score(y_test, predictions, zero_division=0)),
		"roc_auc": float(roc_auc_score(y_test, probabilities)),
		"train_size": int(len(X_train)),
		"test_size": int(len(X_test)),
		"feature_count": int(len(FEATURE_COLUMNS)),
	}

	artifact = {
		"model": pipeline,
		"feature_columns": FEATURE_COLUMNS,
		"label_column": LABEL_COLUMN,
		"positive_label": 1,
	}
	model_path.parent.mkdir(parents=True, exist_ok=True)
	joblib.dump(artifact, model_path)

	if metrics_path is not None:
		metrics_path.parent.mkdir(parents=True, exist_ok=True)
		metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

	return {
		"model_path": str(model_path),
		"metrics_path": str(metrics_path) if metrics_path is not None else None,
		"metrics": metrics,
	}


def load_model(model_path: Path = DEFAULT_MODEL_PATH) -> Dict[str, Any]:
	"""Load a persisted phishing logistic regression model artifact."""
	return joblib.load(Path(model_path))


def predict_url(
	url: str,
	model_path: Path = DEFAULT_MODEL_PATH,
	phishing_threshold: float = DEFAULT_PHISHING_THRESHOLD,
) -> Dict[str, Any]:
	"""Predict whether a URL is phishing using the trained model and return confidence scores."""
	artifact = load_model(model_path)
	model = artifact["model"]
	feature_columns = artifact["feature_columns"]

	feature_values = extract_url_features(url)
	frame = pd.DataFrame([[feature_values[name] for name in feature_columns]], columns=feature_columns)

	phishing_probability = float(model.predict_proba(frame)[0][1])
	safe_probability = float(1.0 - phishing_probability)
	is_phishing = bool(phishing_probability >= phishing_threshold)

	# Compute per-feature signed contributions: (scaled_value * coefficient).
	# Positive = pushes toward phishing, negative = pushes toward safe.
	scaler = model.named_steps["scaler"]
	classifier = model.named_steps["classifier"]
	scaled = (frame.values[0] - scaler.mean_) / scaler.scale_
	contributions = {
		name: round(float(scaled[i] * classifier.coef_[0][i]), 4)
		for i, name in enumerate(feature_columns)
	}

	return {
		"url": _normalize_url(url),
		"is_phishing": is_phishing,
		"phishing_probability": round(phishing_probability, 4),
		"safe_probability": round(safe_probability, 4),
		"features": feature_values,
		"feature_contributions": contributions,
	}


