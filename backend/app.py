"""
Phishing URL Detector — Flask API
Loads a trained Random Forest model and exposes a /analyze endpoint.
"""
import os
import json
import pickle
import logging
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS

from features import extract_features, extract_feature_dict, URLFeatures

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "model.pkl")
META_PATH  = os.path.join(os.path.dirname(__file__), "model", "meta.json")

model = None
meta  = {}

# ── Model loading ──────────────────────────────────────────────────────────────

def load_or_train():
    global model, meta
    if os.path.exists(MODEL_PATH) and os.path.exists(META_PATH):
        logger.info("Loading pre-trained model...")
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        with open(META_PATH) as f:
            meta = json.load(f)
        logger.info(f"Model loaded (ROC AUC: {meta.get('roc_auc', 'N/A')})")
    else:
        logger.info("No model found — training now...")
        from train import train as run_training
        model, meta = run_training()


# ── Risk scoring ───────────────────────────────────────────────────────────────

def risk_label(score: float) -> str:
    if score >= 0.75:
        return "PHISHING"
    if score >= 0.45:
        return "SUSPICIOUS"
    return "SAFE"

def risk_color(score: float) -> str:
    if score >= 0.75:
        return "#ff4d4d"
    if score >= 0.45:
        return "#fbbf24"
    return "#4ade80"

def top_features(url: str, n: int = 8) -> list[dict]:
    """Return top N most important triggered features for this URL."""
    if not meta.get("feature_importances"):
        return []

    feat_dict   = extract_feature_dict(url)
    importances = meta["feature_importances"]

    scored = []
    for name, value in feat_dict.items():
        importance = importances.get(name, 0)
        # Weight by both importance and feature activation
        activation = min(abs(float(value)), 1.0) if isinstance(value, (int, float)) else 0
        scored.append({
            "name": name,
            "value": value,
            "importance": round(importance, 4),
            "contribution": round(importance * (activation + 0.1), 4),
        })

    scored.sort(key=lambda x: x["contribution"], reverse=True)
    return scored[:n]


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.post("/api/analyze")
def analyze():
    if model is None:
        return jsonify({"error": "Model not ready yet — please try again in 30 seconds"}), 503

    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "Missing 'url' field"}), 400

    url = data["url"].strip()
    if len(url) > 2000:
        return jsonify({"error": "URL too long (max 2000 chars)"}), 400

    try:
        features_obj = extract_features(url)
        X = [features_obj.to_list()]
        prob = model.predict_proba(X)[0]
        phish_score = float(prob[1])

        return jsonify({
            "url": url,
            "phishing_probability": round(phish_score, 4),
            "risk_score": round(phish_score * 100, 1),
            "label": risk_label(phish_score),
            "color": risk_color(phish_score),
            "top_features": top_features(url),
            "all_features": extract_feature_dict(url),
            "model_auc": meta.get("roc_auc"),
        })
    except Exception as e:
        logger.error(f"Analysis error for {url}: {e}")
        return jsonify({"error": str(e)}), 500


@app.get("/api/model/info")
def model_info():
    return jsonify({
        "ready": model is not None,
        "roc_auc": meta.get("roc_auc"),
        "training_samples": meta.get("training_samples"),
        "feature_count": len(meta.get("feature_names", [])),
        "top_features": sorted(
            meta.get("feature_importances", {}).items(),
            key=lambda x: x[1], reverse=True
        )[:10],
    })


@app.get("/health")
def health():
    return jsonify({"status": "ok", "model_ready": model is not None})


# ── Startup ────────────────────────────────────────────────────────────────────

_loader = threading.Thread(target=load_or_train, daemon=True)
_loader.start()

if __name__ == "__main__":
    _loader.join()  # wait for model on direct run
    app.run(host="0.0.0.0", port=5001, debug=False)
