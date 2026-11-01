import csv
import json
import math
from pathlib import Path

import joblib
import numpy as np
from django.conf import settings
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

FEATURES = [
    "duration_seconds",
    "bytes_src_to_dst",
    "bytes_dst_to_src",
    "failed_connections",
    "connection_frequency",
    "service_anomaly_score",
]

LABEL_MAP = {"normal": 0, "suspicious": 1}
MODEL_DIR = Path(settings.BASE_DIR) / "ml_models"
DATA_FILE = Path(settings.BASE_DIR) / "data" / "demo_network_data.csv"
MODEL_PATH = MODEL_DIR / "demo_model.joblib"
METADATA_PATH = MODEL_DIR / "demo_model_metadata.json"


def ensure_demo_data() -> Path:
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Demo training data not found at {DATA_FILE}.")
    return DATA_FILE


def read_demo_dataset():
    data_path = ensure_demo_data()
    rows = []
    with data_path.open("r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        required = FEATURES + ["label"]
        missing = [field for field in required if field not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(
                "Training dataset is missing required columns: " + ", ".join(missing)
            )
        for row in reader:
            feature_values = {}
            for field in FEATURES:
                try:
                    feature_values[field] = float(row[field])
                except (TypeError, ValueError):
                    raise ValueError(f"Value for {field} in the training data is invalid: {row.get(field)}")
                if not math.isfinite(feature_values[field]) or feature_values[field] < 0:
                    raise ValueError(f"Value for {field} must be a finite, non-negative number.")
            if feature_values["service_anomaly_score"] > 1:
                raise ValueError("Values for service_anomaly_score must be between 0 and 1.")
            label = row.get("label", "").strip().lower()
            if label not in LABEL_MAP:
                raise ValueError(f"Invalid label '{label}' in training dataset. Use 'normal' or 'suspicious'.")
            rows.append({**feature_values, "label": label})
    if not rows:
        raise ValueError("Training dataset is empty.")
    return rows


def normalise_feature_map(feature_map):
    normalised = {}
    for name in FEATURES:
        if name not in feature_map:
            raise ValueError(f"Missing required feature '{name}' for detection input.")
        try:
            normalised[name] = float(feature_map[name])
        except (TypeError, ValueError):
            raise ValueError(f"Feature '{name}' must be numeric.")
        if not math.isfinite(normalised[name]) or normalised[name] < 0:
            raise ValueError(f"Feature '{name}' must be a finite, non-negative number.")
    if normalised["service_anomaly_score"] > 1:
        raise ValueError("Feature 'service_anomaly_score' must be between 0 and 1.")
    return normalised


def _validate_model(model):
    if not hasattr(model, "predict") or not hasattr(model, "predict_proba"):
        raise ValueError("The saved model does not provide the required prediction methods.")
    if getattr(model, "n_features_in_", None) != len(FEATURES):
        raise ValueError("The saved model does not match the current feature schema.")
    if set(getattr(model, "classes_", [])) != set(LABEL_MAP.values()):
        raise ValueError("The saved model does not contain both expected classification labels.")
    model_features = getattr(model, "feature_names_in_", None)
    if model_features is not None and list(model_features) != FEATURES:
        raise ValueError("The saved model feature order does not match the current feature schema.")
    return model


def get_model_status():
    available = MODEL_PATH.exists() and METADATA_PATH.exists()
    status = {
        "available": available,
        "mode": "machine_learning" if available else "simulation",
        "model_path": str(MODEL_PATH),
        "metadata_path": str(METADATA_PATH),
        "feature_names": FEATURES,
        "error": None,
    }
    if not available:
        status["error"] = "No trained model is available. Run 'python manage.py train_demo_model' to create it."
        return status

    try:
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
        if metadata.get("feature_names") != FEATURES:
            raise ValueError("The model metadata feature order does not match the current feature schema.")
        _validate_model(joblib.load(MODEL_PATH))
        status["algorithm"] = metadata.get("algorithm", "RandomForestClassifier")
        status["metrics"] = metadata.get("metrics", {})
    except Exception as exc:  # Loading a corrupt local pickle can raise different exception types.
        status["available"] = False
        status["mode"] = "simulation"
        status["error"] = f"The saved model could not be validated: {exc}"
    return status


def train_demo_model():
    rows = read_demo_dataset()
    X = np.array([[row[field] for field in FEATURES] for row in rows], dtype=float)
    y = np.array([LABEL_MAP[row["label"]] for row in rows], dtype=int)

    class_counts = np.bincount(y, minlength=len(LABEL_MAP))
    if len(np.unique(y)) < 2 or np.any(class_counts < 2):
        raise ValueError("The training data must include at least two examples of both normal and suspicious activity.")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y if len(np.unique(y)) > 1 else None,
    )

    model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1_score": float(f1_score(y_test, predictions, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    metadata = {
        "algorithm": "RandomForestClassifier",
        "feature_names": FEATURES,
        "metrics": metrics,
        "training_rows": len(rows),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metrics


def load_demo_model():
    if not MODEL_PATH.exists():
        return None
    try:
        model = _validate_model(joblib.load(MODEL_PATH))
    except Exception as exc:  # pragma: no cover - defensive fallback
        raise ValueError(f"Could not load the trained model: {exc}") from exc
    return model


def risk_level_for_score(score):
    if score >= 0.75:
        return "critical"
    if score >= 0.55:
        return "high"
    if score >= 0.3:
        return "medium"
    return "low"


def risk_from_prediction(predicted_label, confidence):
    if predicted_label == "suspicious":
        confidence_score = float(confidence)
        return risk_level_for_score(confidence_score)
    return "low"


def predict_with_model(feature_map):
    model = load_demo_model()
    if model is None:
        raise ValueError("No trained model is available. Use the train_demo_model command or run the app in simulation mode.")
    normalised = normalise_feature_map(feature_map)
    array = np.array([[normalised[name] for name in FEATURES]], dtype=float)
    predicted_index = int(model.predict(array)[0])
    probabilities = model.predict_proba(array)[0]
    prediction_text = "suspicious" if predicted_index == LABEL_MAP["suspicious"] else "normal"
    predicted_class_index = list(model.classes_).index(predicted_index)
    probability = float(probabilities[predicted_class_index])
    risk = risk_from_prediction(prediction_text, probability)
    if prediction_text == "normal":
        explanation = "The analysed traffic pattern remains consistent with typical activity for the demonstration model."
        recommendation = "Continue monitoring and compare with historical baselines."
    else:
        explanation = (
            "The model identified a traffic profile associated with suspicious or anomalous network behaviour. "
            "This is a detection signal rather than proof of wrongdoing."
        )
        recommendation = "Escalate the event for review and determine whether additional network evidence is required."
    return {
        "label": prediction_text,
        "severity": risk,
        "confidence": probability,
        "explanation": explanation,
        "recommendation": recommendation,
    }


def simulate_prediction(feature_map):
    values = normalise_feature_map(feature_map)
    risk_score = 0
    if values["duration_seconds"] > 180:
        risk_score += 1
    if values["bytes_src_to_dst"] > 2_000_000:
        risk_score += 1
    if values["bytes_dst_to_src"] > 1_500_000:
        risk_score += 1
    if values["failed_connections"] >= 3:
        risk_score += 2
    if values["connection_frequency"] > 60:
        risk_score += 1
    if values["service_anomaly_score"] >= 0.65:
        risk_score += 1

    label = "suspicious" if risk_score >= 3 else "normal"
    confidence = min(0.94, 0.58 + (risk_score * 0.08)) if label == "suspicious" else max(0.52, 0.74 - (risk_score * 0.1))
    severity = risk_level_for_score(confidence)
    if label == "normal":
        explanation = "The simulated network profile fell within the routine baseline range and did not trigger the suspicious indicator threshold."
        recommendation = "No incident is created automatically, but the trend should remain monitored."
    else:
        explanation = "The simulation flagged the activity as potentially suspicious due to abnormal duration, data transfer, failed connection attempts, or service anomaly indicators."
        recommendation = "Create or review an incident record for additional investigation and escalation."
    return {
        "label": label,
        "severity": severity,
        "confidence": float(confidence),
        "explanation": explanation,
        "recommendation": recommendation,
    }


def determine_detection_result(feature_map):
    model_status = get_model_status()
    if model_status["available"]:
        try:
            result = predict_with_model(feature_map)
            return {"mode": "machine_learning", **result}
        except Exception as exc:
            result = simulate_prediction(feature_map)
            return {"mode": "simulation", "warning": str(exc), **result}
    result = simulate_prediction(feature_map)
    if model_status["error"]:
        return {"mode": "simulation", "warning": model_status["error"], **result}
    return {"mode": "simulation", **result}


def build_demo_examples():
    return {
        "baseline_guest_traffic": {
            "duration_seconds": 38,
            "bytes_src_to_dst": 125000,
            "bytes_dst_to_src": 82000,
            "failed_connections": 0,
            "connection_frequency": 18,
            "service_anomaly_score": 0.12,
        },
        "repeated_probe_scan": {
            "duration_seconds": 410,
            "bytes_src_to_dst": 3_450_000,
            "bytes_dst_to_src": 2_100_000,
            "failed_connections": 6,
            "connection_frequency": 76,
            "service_anomaly_score": 0.82,
        },
        "slow_web_session": {
            "duration_seconds": 96,
            "bytes_src_to_dst": 480000,
            "bytes_dst_to_src": 520000,
            "failed_connections": 1,
            "connection_frequency": 31,
            "service_anomaly_score": 0.24,
        },
    }
