"""
Phishing URL Detector — Flask API
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

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "model.pkl")
META_PATH  = os.path.join(BASE_DIR, "model", "meta.json")

model = None
meta  = {}
model_status = "initializing"

def load_or_train():
    global model, meta, model_status
    try:
        os.makedirs(os.path.join(BASE_DIR, "model"), exist_ok=True)
        if os.path.exists(MODEL_PATH) and os.path.exists(META_PATH):
            logger.info(f"Model file found — loading from {MODEL_PATH}")
            model_status = "loading"
            try:
                with open(MODEL_PATH, "rb") as f:
                    model = pickle.load(f)
                with open(META_PATH) as f:
                    meta = json.load(f)
                model_status = "ready"
                logger.info(f"Model loaded successfully — ROC AUC: {meta.get('roc_auc')}")
                return
            except Exception as e:
                logger.error(f"Failed to load model: {e} — will retrain")
                model = None
                # Delete corrupt files
                if os.path.exists(MODEL_PATH):
                    os.remove(MODEL_PATH)
                if os.path.exists(META_PATH):
                    os.remove(META_PATH)

        logger.info("No valid model found — training now...")
        model_status = "training"
        from train import train as run_training
        model, meta = run_training()
        model_status = "ready"
        logger.info("Training complete — model ready")

    except Exception as e:
        model_status = f"error: {str(e)}"
        logger.error(f"load_or_train failed: {e}")

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
        return jsonify({"error": f"Model not ready yet ({model_status}) — please try again in 30 seconds"}), 503
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
        "status": model_status,
        "model_path": MODEL_PATH,
        "model_exists": os.path.exists(MODEL_PATH),
        "roc_auc": meta.get("roc_auc"),
        "training_samples": meta.get("training_samples"),
        "feature_count": len(meta.get("feature_names", [])),
    })

@app.get("/health")
def health():
    return jsonify({"status": "ok", "model_ready": model is not None, "model_status": model_status})

# Start loading model in background thread
_loader = threading.Thread(target=load_or_train, daemon=True)
_loader.start()

if __name__ == "__main__":
    _loader.join()
    app.run(host="0.0.0.0", port=5001, debug=False)