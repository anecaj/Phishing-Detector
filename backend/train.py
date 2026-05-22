"""
Train the phishing detection model.
Data sources — all completely free, no signup required:
  - Phishing: OpenPhish public feed (https://openphish.com/feed.txt)
  - Legitimate: Tranco top-1M list (https://tranco-list.eu)
  - Fallback dataset bundled in data/ if downloads fail
Run: python train.py
"""
import os
import json
import pickle
import logging
import random
import requests
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from features import extract_features, URLFeatures

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MODEL_PATH   = os.path.join(os.path.dirname(__file__), "model", "model.pkl")
META_PATH    = os.path.join(os.path.dirname(__file__), "model", "meta.json")
DATA_DIR     = os.path.join(os.path.dirname(__file__), "data")

# ── Bundled fallback URLs (used if downloads fail) ─────────────────────────────

FALLBACK_PHISHING = [
    "http://192.168.1.1/login/paypal/verify",
    "http://secure-paypal-login.tk/account/confirm",
    "http://amazon-verify-account.ml/signin",
    "http://appleid.apple.com.phishing-site.ru/login",
    "http://microsoft.update-now.xyz/security/alert",
    "http://bankofamerica-secure.info/online/login",
    "http://login-facebook.suspicious-domain.com/auth",
    "http://paypal.com.account-suspended.tk/resolve",
    "http://netflix-billing-update.ml/payment/card",
    "http://google-account-verify.xyz/signin/confirm",
    "http://wellsfargo.secure-login.tk/banking",
    "http://irs-tax-refund-claim.ml/gov/refund",
    "http://fedex-tracking-update.xyz/package/track",
    "http://instagram-verify-account.tk/auth/login",
    "http://steam-free-items.ml/trade/offer",
    "http://secure-login-chase.xyz/online/banking",
    "http://dhl-package-delivery.tk/tracking/update",
    "http://coinbase-wallet-verify.ml/account/secure",
    "http://amazon.com.signin-account.xyz/ap/signin",
    "http://apple-id-locked.tk/iforgot/appleid",
    "http://update-your-account.paypal.suspicious.com/verify",
    "http://login.microsoftonline.com.phish.xyz/auth",
    "http://ebay-suspended-account.ml/signin/recovery",
    "http://usps-package-hold.tk/tracking/package",
    "http://crypto-free-bitcoin.xyz/claim/now",
    "http://account-alert-wells.ml/fargo/secure",
    "http://dropbox-share-file.tk/view/document",
    "http://linkedin-security-alert.xyz/verify/account",
    "http://zoom-meeting-invite.ml/j/meeting/join",
    "http://office365-password-expire.xyz/login/renew",
    "http://194.165.16.11/paypal/login",
    "http://172.16.254.1/bank/secure/login",
    "http://secure@evil-phish.com/login",
    "http://legitimate-looking.com//redirect//evil.com",
    "http://update-account.win/microsoft/login",
    "http://free-gift-card-amazon.gq/claim",
    "http://bit.ly.suspicious-redirect.tk/go",
    "http://verify-now.account-amazon.ml/signin",
    "http://credential-harvest.xyz/office365",
    "http://password-reset-urgent.tk/gmail/reset",
    "http://tax-refund-irs-gov.ml/refund/2024",
    "http://covid-relief-payment.xyz/apply/now",
    "http://bank-security-update.tk/verify/identity",
    "http://prize-winner-notification.ml/claim",
    "http://urgent-account-action.xyz/required",
    "http://confirm-shipping-address.tk/amazon",
    "http://two-factor-disabled-alert.ml/enable",
    "http://suspicious-login-detected.xyz/verify",
    "http://limited-time-offer-free.tk/get",
    "http://account-deactivated-soon.ml/reactivate",
]

FALLBACK_LEGIT = [
    "https://www.google.com/search?q=python",
    "https://www.github.com/features",
    "https://stackoverflow.com/questions",
    "https://www.amazon.com/electronics",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/iphone",
    "https://www.wikipedia.org/wiki/Python",
    "https://www.reddit.com/r/programming",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.linkedin.com/in/profile",
    "https://www.netflix.com/browse",
    "https://www.twitter.com/home",
    "https://www.facebook.com/marketplace",
    "https://www.instagram.com/explore",
    "https://www.paypal.com/myaccount",
    "https://www.ebay.com/deals",
    "https://www.walmart.com/grocery",
    "https://www.nytimes.com/news",
    "https://www.bbc.com/news",
    "https://www.cnn.com/world",
    "https://www.espn.com/nfl",
    "https://www.weather.com/forecast",
    "https://www.imdb.com/movies",
    "https://www.spotify.com/us/home",
    "https://www.dropbox.com/files",
    "https://www.zoom.us/meeting",
    "https://www.slack.com/workspace",
    "https://www.notion.so/workspace",
    "https://www.figma.com/files",
    "https://www.trello.com/boards",
    "https://docs.python.org/3/library",
    "https://developer.mozilla.org/en-US/docs",
    "https://www.w3schools.com/python",
    "https://www.coursera.org/courses",
    "https://www.udemy.com/courses",
    "https://arxiv.org/abs/2301.00001",
    "https://www.nature.com/articles",
    "https://www.sciencedirect.com/journal",
    "https://www.forbes.com/technology",
    "https://www.techcrunch.com/startups",
    "https://www.wired.com/security",
    "https://www.cloudflare.com/solutions",
    "https://www.aws.amazon.com/s3",
    "https://azure.microsoft.com/services",
    "https://cloud.google.com/products",
    "https://www.heroku.com/home",
    "https://www.digitalocean.com/products",
    "https://www.stripe.com/payments",
    "https://www.twilio.com/messaging",
    "https://www.sendgrid.com/solutions",
]


# ── Data loading ───────────────────────────────────────────────────────────────

def fetch_openphish(max_urls: int = 300) -> list[str]:
    """Fetch phishing URLs from OpenPhish public feed (no key needed)."""
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=15)
        resp.raise_for_status()
        urls = [u.strip() for u in resp.text.splitlines() if u.strip().startswith("http")]
        logger.info(f"OpenPhish: fetched {len(urls)} URLs")
        return urls[:max_urls]
    except Exception as e:
        logger.warning(f"OpenPhish fetch failed: {e} — using fallback data")
        return []


def fetch_tranco_legit(max_domains: int = 300) -> list[str]:
    """Fetch top legitimate domains from Tranco list."""
    try:
        import io, zipfile
        resp = requests.get(
            "https://tranco-list.eu/top-1m.csv.zip",
            timeout=30, stream=True
        )
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            with z.open(z.namelist()[0]) as f:
                lines = f.read().decode().splitlines()
        domains = []
        for line in lines[:max_domains]:
            parts = line.split(",")
            if len(parts) >= 2:
                domains.append(f"https://www.{parts[1].strip()}")
        logger.info(f"Tranco: fetched {len(domains)} legitimate domains")
        return domains
    except Exception as e:
        logger.warning(f"Tranco fetch failed: {e} — using fallback data")
        return []


def load_bundled_data():
    """Load from bundled text files in data/ directory."""
    phishing, legit = [], []
    phish_file = os.path.join(DATA_DIR, "phishing_urls.txt")
    legit_file  = os.path.join(DATA_DIR, "legit_urls.txt")
    if os.path.exists(phish_file):
        with open(phish_file) as f:
            phishing = [l.strip() for l in f if l.strip()]
    if os.path.exists(legit_file):
        with open(legit_file) as f:
            legit = [l.strip() for l in f if l.strip()]
    return phishing, legit


# ── Training ───────────────────────────────────────────────────────────────────

def build_dataset() -> tuple[list, list]:
    """
    Assemble URL dataset from live sources with fallback to bundled data.
    Returns (urls, labels) where label 1=phishing, 0=legit.
    """
    phishing_urls = fetch_openphish(400)
    legit_urls    = fetch_tranco_legit(400)

    bundled_phish, bundled_legit = load_bundled_data()

    # Merge and deduplicate
    phishing_urls = list(set(phishing_urls + bundled_phish + FALLBACK_PHISHING))
    legit_urls    = list(set(legit_urls    + bundled_legit + FALLBACK_LEGIT))

    random.shuffle(phishing_urls)
    random.shuffle(legit_urls)

    # Balance dataset
    n = min(len(phishing_urls), len(legit_urls))
    phishing_urls = phishing_urls[:n]
    legit_urls    = legit_urls[:n]

    urls   = phishing_urls + legit_urls
    labels = [1] * len(phishing_urls) + [0] * len(legit_urls)

    logger.info(f"Dataset: {len(phishing_urls)} phishing + {len(legit_urls)} legit = {len(urls)} total")
    return urls, labels


def extract_all_features(urls: list[str]) -> np.ndarray:
    X = []
    for url in urls:
        try:
            f = extract_features(url)
            X.append(f.to_list())
        except Exception:
            X.append([0] * len(URLFeatures.feature_names()))
    return np.array(X, dtype=float)


def train():
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    logger.info("Building dataset...")
    urls, labels = build_dataset()

    logger.info("Extracting features...")
    X = extract_all_features(urls)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    report = classification_report(y_test, y_pred, target_names=["Legit", "Phishing"])
    auc    = roc_auc_score(y_test, y_prob)
    logger.info(f"\n{report}\nROC AUC: {auc:.4f}")

    # Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    logger.info(f"Model saved to {MODEL_PATH}")

    # Save metadata
    feature_importances = dict(zip(
        URLFeatures.feature_names(),
        model.feature_importances_.tolist()
    ))
    meta = {
        "feature_names": URLFeatures.feature_names(),
        "feature_importances": feature_importances,
        "n_estimators": model.n_estimators,
        "roc_auc": round(auc, 4),
        "training_samples": len(urls),
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    logger.info(f"Metadata saved to {META_PATH}")
    return model, meta


if __name__ == "__main__":
    train()
