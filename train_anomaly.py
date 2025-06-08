import argparse
import pandas as pd
from agent.anomaly import AnomalyDetector
from agent.config import Config

def main():
    parser = argparse.ArgumentParser(
        description="Train anomaly detection model from CSV data"
    )
    parser.add_argument(
        "--data-file", required=True,
        help="Path to CSV file with numeric features (rows of feature vectors)"
    )
    parser.add_argument(
        "--save-path", default=None,
        help="Optional path to save trained model override"
    )
    args = parser.parse_args()

    # Load data
    df = pd.read_csv(args.data_file)
    X = df.values

    # Load config and detector
    cfg = Config.load()
    detector = AnomalyDetector(
        model_path=cfg.anomaly.get('model_path'),
        contamination=cfg.anomaly.get('contamination')
    )

    # Train and save
    model_path = detector.train(X, save_path=args.save_path)
    print(f"Model trained and saved to: {model_path}")

if __name__ == "__main__":
    main()