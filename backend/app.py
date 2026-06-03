"""
Phishing URL Detector — Flask API
"""
import os
import json
import pickle
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS

from features import extract_features, extract_feature_dict, URLFeatures

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "model.pkl")
META_PATH  = os.path.join(BASE_DIR, "model", "meta.json")

model = None
meta  = {}

def load_or_train():
    global model, meta
    os.makedirs(os.path.join(BASE_DIR, "model"), exist_ok=True)
    if os.path.exists(MODEL_PATH) and os.path.exists(META_PATH):
        try:
            logger.info(f"Loading model from {MODEL_PATH}")
            with open(MODEL_PATH, "rb") as f:
                model = pickle.load(f)
            with open(META_PATH) as f:
                meta = json.load(f)
            logger.info(f"Model loaded — ROC AUC: {meta.get('roc_auc')}")
            return
        except Exception as e:
            logger.error(f"Failed to load model: {e} — retraining")
            model = None
            for p in [MODEL_PATH, META_PATH]:
                if os.path.exists(p):
                    os.remove(p)
    logger.info("Training model now...")
    from train import train as run_training
    model, meta = run_training()
    logger.info("Training complete")

# Load synchronously at import time — works correctly with gunicorn --preload
load_or_train()

def risk_label(score):
    if score >= 0.75: return "PHISHING"
    if score >= 0.45: return "SUSPICIOUS"
    return "SAFE"

def risk_color(score):
    if score >= 0.75: return "#ff4d4d"
    if score >= 0.45: return "#fbbf24"
    return "#4ade80"

def top_features(url, n=8):
    if not meta.get("feature_importances"):
        return []
    feat_dict   = extract_feature_dict(url)
    importances = meta["feature_importances"]
    scored = []
    for name, value in feat_dict.items():
        importance = importances.get(name, 0)
        activation = min(abs(float(value)), 1.0)
        scored.append({
            "name": name, "value": value,
            "importance": round(importance, 4),
            "contribution": round(importance * (activation + 0.1), 4),
        })
    scored.sort(key=lambda x: x["contribution"], reverse=True)
    return scored[:n]

@app.post("/api/analyze")
def analyze():
    if model is None:
        return jsonify({"error": "Model not ready — please try again"}), 503
    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "Missing 'url' field"}), 400
    url = data["url"].strip()
    try:
        X = [extract_features(url).to_list()]
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
        logger.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.get("/api/model/info")
def model_info():
    return jsonify({
        "ready": model is not None,
        "model_exists": os.path.exists(MODEL_PATH),
        "roc_auc": meta.get("roc_auc"),
        "training_samples": meta.get("training_samples"),
        "feature_count": len(meta.get("feature_names", [])),
    })

@app.get("/health")
def health():
    return jsonify({"status": "ok", "model_ready": model is not None})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)