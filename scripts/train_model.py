#!/usr/bin/env python3
"""
AISS ML Model Trainer
Trains a GradientBoostingClassifier on synthetic request feature data and
exports it to ONNX format for use by the Go agent's tier3 scorer.

Usage:
    pip install scikit-learn skl2onnx onnx numpy
    python scripts/train_model.py --output /etc/aiss/ml/aiss_model.onnx

Feature order (must match tier3/scorer_onnx.go featureVector):
  0  method_encoded      1  uri_length          2  query_length
  3  header_count        4  body_length         5  uri_entropy
  6  query_entropy       7  body_entropy        8  special_char_ratio
  9  encoded_char_count  10 double_encoded      11 null_bytes
  12 unicode_escape      13 has_base64_body     14 param_count
  15 excessive_params    16 ua_length           17 ua_is_scanner
  18 ua_empty            19 ua_suspicious       20 unusual_method
  21 has_proxy_headers
"""

import argparse
import os
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

try:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    HAS_SKL2ONNX = True
except ImportError:
    HAS_SKL2ONNX = False
    print("WARNING: skl2onnx not installed — ONNX export will be skipped")


FEATURE_NAMES = [
    "method_encoded", "uri_length", "query_length", "header_count",
    "body_length", "uri_entropy", "query_entropy", "body_entropy",
    "special_char_ratio", "encoded_char_count", "double_encoded",
    "null_bytes", "unicode_escape", "has_base64_body", "param_count",
    "excessive_params", "ua_length", "ua_is_scanner", "ua_empty",
    "ua_suspicious", "unusual_method", "has_proxy_headers",
]
N_FEATURES = len(FEATURE_NAMES)


def generate_samples(n_benign: int = 10_000, n_malicious: int = 2_000):
    """Generate synthetic training data mimicking real request distributions."""
    rng = np.random.default_rng(42)

    # Benign requests
    benign = np.zeros((n_benign, N_FEATURES))
    benign[:, 0]  = rng.choice([0, 1, 2], n_benign)        # method: GET/POST/PUT
    benign[:, 1]  = rng.integers(5, 200, n_benign)          # uri_length
    benign[:, 2]  = rng.integers(0, 50, n_benign)           # query_length
    benign[:, 3]  = rng.integers(3, 15, n_benign)           # header_count
    benign[:, 4]  = rng.integers(0, 5000, n_benign)         # body_length
    benign[:, 5]  = rng.uniform(1.5, 3.5, n_benign)         # uri_entropy
    benign[:, 6]  = rng.uniform(0, 2.5, n_benign)           # query_entropy
    benign[:, 7]  = rng.uniform(0, 3.5, n_benign)           # body_entropy
    benign[:, 8]  = rng.uniform(0, 0.05, n_benign)          # special_char_ratio
    benign[:, 9]  = rng.integers(0, 5, n_benign)            # encoded_char_count
    # rest stay near 0

    # Malicious requests — exaggerate anomaly features
    mal = np.zeros((n_malicious, N_FEATURES))
    mal[:, 0]  = rng.choice([0, 1, 3, 7], n_malicious)      # unusual methods too
    mal[:, 1]  = rng.integers(200, 3000, n_malicious)        # long URIs
    mal[:, 2]  = rng.integers(50, 800, n_malicious)          # large query strings
    mal[:, 3]  = rng.integers(2, 30, n_malicious)
    mal[:, 4]  = rng.integers(0, 50000, n_malicious)         # large bodies
    mal[:, 5]  = rng.uniform(3.5, 5.5, n_malicious)         # high uri entropy
    mal[:, 6]  = rng.uniform(3.0, 5.5, n_malicious)         # high query entropy
    mal[:, 7]  = rng.uniform(4.0, 6.0, n_malicious)         # high body entropy
    mal[:, 8]  = rng.uniform(0.1, 0.5, n_malicious)         # many special chars
    mal[:, 9]  = rng.integers(10, 100, n_malicious)          # many %XX sequences
    mal[:, 10] = rng.choice([0, 1], n_malicious, p=[0.4, 0.6])  # double encoding
    mal[:, 11] = rng.choice([0, 1], n_malicious, p=[0.6, 0.4])  # null bytes
    mal[:, 12] = rng.choice([0, 1], n_malicious, p=[0.5, 0.5])  # unicode escapes
    mal[:, 13] = rng.choice([0, 1], n_malicious, p=[0.4, 0.6])  # base64 body
    mal[:, 14] = rng.integers(0, 50, n_malicious)            # many params
    mal[:, 15] = rng.choice([0, 1], n_malicious, p=[0.3, 0.7])  # excessive params
    mal[:, 16] = rng.integers(0, 200, n_malicious)           # ua length
    mal[:, 17] = rng.choice([0, 1], n_malicious, p=[0.3, 0.7])  # scanner UA
    mal[:, 18] = rng.choice([0, 1], n_malicious, p=[0.7, 0.3])  # empty UA
    mal[:, 19] = rng.choice([0, 1], n_malicious, p=[0.4, 0.6])  # suspicious UA
    mal[:, 20] = rng.choice([0, 1], n_malicious, p=[0.6, 0.4])  # unusual method
    mal[:, 21] = rng.choice([0, 1], n_malicious, p=[0.6, 0.4])  # proxy headers

    X = np.vstack([benign, mal]).astype(np.float32)
    y = np.array([0] * n_benign + [1] * n_malicious, dtype=np.int32)
    return X, y


def train_and_export(output_path: str) -> None:
    print("Generating training data...")
    X, y = generate_samples()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print(f"Training on {len(X_train)} samples ({y_train.sum()} malicious)...")
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GradientBoostingClassifier(
            n_estimators=200,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
        )),
    ])
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))

    if not HAS_SKL2ONNX:
        print("\nskl2onnx not available — model trained but not exported to ONNX.")
        print("Install with: pip install skl2onnx onnx")
        return

    print(f"\nExporting to ONNX: {output_path}")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    initial_type = [("features", FloatTensorType([None, N_FEATURES]))]
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset=17,
        options={GradientBoostingClassifier: {"zipmap": False}},
    )

    # Override output to return probability of class 1 (malicious)
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print(f"Model saved to {output_path}")
    print(f"Model size: {os.path.getsize(output_path) / 1024:.1f} KB")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AISS anomaly detection model")
    parser.add_argument("--output", default="/etc/aiss/ml/aiss_model.onnx",
                        help="Output path for the ONNX model")
    parser.add_argument("--n-benign",    type=int, default=10_000)
    parser.add_argument("--n-malicious", type=int, default=2_000)
    args = parser.parse_args()
    train_and_export(args.output)
