# Phishing Logistic Regression Model

This module trains a logistic regression classifier on `PhishingData.csv` and predicts whether a URL is phishing.

## Quick start

```powershell
python -m baitblocker.ml.model_training train
python -m baitblocker.ml.model_training predict "http://192.168.0.10/verify-account"
```

## Notes

- Training uses lexical URL features that can be extracted directly from a URL string.
- The trained model is saved to `phishing_logreg_model.joblib` by default.
- Evaluation metrics are written to `phishing_logreg_metrics.json` by default.
- The dataset was taken from [Kaggle](https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning/data) and contains 10,000 samples (5,000 phishing and 5,000 safe) with 40 features each.

