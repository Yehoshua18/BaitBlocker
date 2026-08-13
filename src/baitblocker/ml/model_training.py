"""Train and use a logistic regression model for phishing URL detection."""

import argparse
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from ..db.matcher import KeywordScanner

LABEL_COLUMN = "CLASS_LABEL"

# These lexical features are available in PhishingData.csv and can be computed directly from a URL.
FEATURE_COLUMNS = [
	"NumDots",
	"SubdomainLevel",
	"PathLevel",
	"UrlLength",
	"NumDash",
	"NumDashInHostname",
	"AtSymbol",
	"TildeSymbol",
	"NumUnderscore",
	"NumPercent",
	"NumQueryComponents",
	"NumAmpersand",
	"NumHash",
	"NumNumericChars",
	"NoHttps",
	"RandomString",
	"IpAddress",
	"DomainInSubdomains",
	"DomainInPaths",
	"HttpsInHostname",
	"HostnameLength",
	"PathLength",
	"QueryLength",
	"DoubleSlashInPath",
	"NumSensitiveWords",
]

# Using Bait Blocker's already existing database of suspicious keywords
keyword_scanner = KeywordScanner()

DEFAULT_DATASET_PATH = Path(__file__).with_name("PhishingData.csv")
DEFAULT_MODEL_PATH = Path(__file__).with_name("phishing_logreg_model.joblib")
DEFAULT_METRICS_PATH = Path(__file__).with_name("phishing_logreg_metrics.json")

# To make parsing easier
def _normalize_url(url: str) -> str:
	normalized = url.strip()
	if not normalized.startswith(("http://", "https://")):
		normalized = "https://" + normalized
	return normalized

# Quick check if a hostname looks like an IP address
def _hostname_looks_like_ip(hostname: str) -> int:
	if not hostname:
		return 0
	try:
		ipaddress.ip_address(hostname.strip("[]"))
		return 1
	except ValueError:
		return 0

# If a token in a URL has both letters and digits, it is most likely a random string
def _has_random_token(hostname: str, path: str) -> int:
	text = "{} {}".format(hostname, path)
	tokens = re.findall(r"[a-z0-9]{8,}", text.lower())
	for token in tokens:
		has_alpha = any(ch.isalpha() for ch in token)
		has_digit = any(ch.isdigit() for ch in token)
		if has_alpha and has_digit:
			return 1
	return 0

# More suspicious words = more likely to be phishing
def _count_sensitive_words(parts: Iterable[str]) -> int:
	return len(keyword_scanner.scan_url(" ".join(parts))["matches"])


def extract_url_features(url: str) -> Dict[str, float]:
	"""Create lexical features for a URL compatible with the logistic regression model."""

	# Step 1: parsing using our normalized url
	normalized = _normalize_url(url)
	parsed = urlparse(normalized)
	hostname = parsed.hostname or ""
	hostname_lower = hostname.lower()
	path = parsed.path or ""
	query = parsed.query or ""
	full_url = parsed.geturl()


	# Step 2 : Extract the registrable domain label (the "brand" token before the public suffix)
	# so downstream features like DomainInSubdomains/DomainInPaths can detect reuse.
	# For multi-part country-code suffixes (e.g., example.co.uk, example.com.au, example.uk.co),
	# use the token before the last two suffix labels.
	domain_label = ""
	host_parts = [part for part in hostname_lower.split(".") if part]
	if len(host_parts) >= 2:
		common_second_level_suffixes = {"co", "com", "org", "net", "gov", "ac", "edu"}
		uses_compound_cc_suffix = len(host_parts) >= 3 and len(host_parts[-1]) == 2 and (
			len(host_parts[-2]) == 2 or host_parts[-2] in common_second_level_suffixes
		)
		domain_label = host_parts[-3] if uses_compound_cc_suffix else host_parts[-2]


	# Step 3: Split hostname + path into lowercase alphanumeric tokens for keyword scanning.
	words = re.findall(r"[a-z0-9]+", (hostname_lower + " " + path.lower()))

	# Step 4: Create feature dictionary
	features = {
		"NumDots": float(hostname_lower.count(".")),
		"SubdomainLevel": float(max(len(host_parts) - 2, 0)),
		"PathLevel": float(path.count("/") if path else 0),
		"UrlLength": float(len(full_url)),
		"NumDash": float(full_url.count("-")),
		"NumDashInHostname": float(hostname_lower.count("-")),
		"AtSymbol": float("@" in full_url),
		"TildeSymbol": float("~" in full_url),
		"NumUnderscore": float(full_url.count("_")),
		"NumPercent": float(full_url.count("%")),
		"NumQueryComponents": float(len([q for q in query.split("&") if q]) if query else 0),
		"NumAmpersand": float(full_url.count("&")),
		"NumHash": float(full_url.count("#")),
		"NumNumericChars": float(sum(ch.isdigit() for ch in full_url)),
		"NoHttps": float(parsed.scheme != "https"),
		"RandomString": float(_has_random_token(hostname_lower, path)),
		"IpAddress": float(_hostname_looks_like_ip(hostname_lower)),
		"DomainInSubdomains": float(bool(domain_label and "." in hostname_lower and domain_label in ".".join(host_parts[:-2]))),
		"DomainInPaths": float(bool(domain_label and domain_label in path.lower())),
		"HttpsInHostname": float("https" in hostname_lower),
		"HostnameLength": float(len(hostname_lower)),
		"PathLength": float(len(path)),
		"QueryLength": float(len(query)),
		"DoubleSlashInPath": float("//" in path),
		"NumSensitiveWords": float(_count_sensitive_words(words)),
	}
	return features


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


def predict_url(url: str, model_path: Path = DEFAULT_MODEL_PATH) -> Dict[str, Any]:
	"""Predict whether a URL is phishing using the trained model and return confidence scores."""
	artifact = load_model(model_path)
	model = artifact["model"]
	feature_columns = artifact["feature_columns"]

	feature_values = extract_url_features(url)
	frame = pd.DataFrame([[feature_values[name] for name in feature_columns]], columns=feature_columns)

	phishing_probability = float(model.predict_proba(frame)[0][1])
	is_phishing = bool(phishing_probability >= 0.5)
	return {
		"url": _normalize_url(url),
		"is_phishing": is_phishing,
		"phishing_probability": round(phishing_probability, 4),
		"safe_probability": round(1.0 - phishing_probability, 4),
		"features": feature_values,
	}


def _build_arg_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Train and run phishing logistic regression model")
	subparsers = parser.add_subparsers(dest="command", required=True)

	train_parser = subparsers.add_parser("train", help="Train logistic regression from CSV")
	train_parser.add_argument("--csv-path", default=str(DEFAULT_DATASET_PATH), help="Path to training CSV")
	train_parser.add_argument("--model-path", default=str(DEFAULT_MODEL_PATH), help="Path to save .joblib model")
	train_parser.add_argument("--metrics-path", default=str(DEFAULT_METRICS_PATH), help="Path to save metrics JSON")
	train_parser.add_argument("--test-size", type=float, default=0.2, help="Validation split ratio")
	train_parser.add_argument("--random-state", type=int, default=42, help="Random seed")

	predict_parser = subparsers.add_parser("predict", help="Predict if a URL is phishing")
	predict_parser.add_argument("url", help="URL to evaluate")
	predict_parser.add_argument("--model-path", default=str(DEFAULT_MODEL_PATH), help="Path to .joblib model")

	return parser


def main() -> None:
	parser = _build_arg_parser()
	args = parser.parse_args()

	if args.command == "train":
		result = train_logistic_regression(
			csv_path=Path(args.csv_path),
			model_path=Path(args.model_path),
			metrics_path=Path(args.metrics_path) if args.metrics_path else None,
			test_size=args.test_size,
			random_state=args.random_state,
		)
		print(json.dumps(result, indent=2))
		return

	if args.command == "predict":
		result = predict_url(args.url, model_path=Path(args.model_path))
		print(json.dumps(result, indent=2))
		return


if __name__ == "__main__":
	main()

# TODO: Add unit tests for feature extraction, model training, and prediction functions.
# TODO: Split responsibilities into - extraction, training and prediction
# TODO: integrate into FastAPI for final calculation