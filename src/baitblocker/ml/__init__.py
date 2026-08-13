"""Machine learning utilities for phishing URL detection."""

from .model_training import extract_url_features, load_model, predict_url, train_logistic_regression

__all__ = [
    "extract_url_features",
    "load_model",
    "predict_url",
    "train_logistic_regression",
]

