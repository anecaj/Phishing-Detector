# PhishGuard — ML-Powered Phishing URL Detector

Analyzes URLs in real time using a Random Forest classifier trained on 25+ lexical features.
No API keys required — all data sources are free and public.

**Live demo:** `https://anecaj.github.io/Phishing-Detector/`
**Backend API:** `https://phishing-detector-api.onrender.com`

---

## Stack

| Layer    | Tech                                      |
|----------|-------------------------------------------|
| ML Model | scikit-learn Random Forest (200 trees)    |
| Backend  | Python, Flask                             |
| Frontend | React, Vite                               |
| Data     | OpenPhish + Tranco Top-1M (free, no keys) |
| Hosting  | Render.com + GitHub Pages                 |

---

## Features Extracted (25+)

- URL / domain / path / query length
- Dot, hyphen, underscore, digit counts
- Shannon entropy (domain, path, full URL)
- Subdomain depth, path depth, query params
- Phishing keyword detection
- IP-address domain, @ symbol, port presence
- HTTPS usage, encoded chars, uncommon TLD
- Punycode detection

---

## Local Development

### Backend
```bash
cd backend
pip install -r requirements.txt
python train.py       # trains model (~30 seconds)
python app.py         # starts API on port 5001
```

### Frontend
```bash
cd frontend
npm install
npm run dev           # starts on port 5173
```

---

## Deploy

### Backend → Render.com
1. New Web Service → connect repo → Root Directory: `backend`
2. Build command auto-runs `python train.py` before starting
3. Free tier — no payment required

### Frontend → GitHub Pages
1. Settings → Pages → Source: GitHub Actions
2. Add secret `VITE_API_URL` = your Render URL + `/api`
3. Push to main — auto-deploys
