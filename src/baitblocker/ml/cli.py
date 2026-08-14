import argparse
import json
from pathlib import Path
from ..ml.model_training import train_logistic_regression, predict_url, DEFAULT_DATASET_PATH, DEFAULT_MODEL_PATH, DEFAULT_METRICS_PATH

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
