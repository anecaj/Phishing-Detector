import { useState, useEffect } from "react";
import axios from "axios";
import RiskGauge from "./components/RiskGauge";
import FeatureBreakdown from "./components/FeatureBreakdown";
import HistoryLog from "./components/HistoryLog";

const API = import.meta.env.VITE_API_URL || "/api";

const EXAMPLE_URLS = [
  "https://www.github.com/features",
  "http://paypal.com.account-verify.tk/login",
  "https://stackoverflow.com/questions",
  "http://192.168.1.1/banking/signin/verify",
  "https://www.google.com/search?q=python",
  "http://secure-apple-id-locked.xyz/iforgot",
];

const css = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #060912; color: #e2e8f0; font-family: 'DM Sans', sans-serif; }
  ::selection { background: #f59e0b33; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: #0d1117; }
  ::-webkit-scrollbar-thumb { background: #2d3748; border-radius: 4px; }

  @keyframes pulse-ring {
    0% { transform: scale(0.95); opacity: 0.8; }
    50% { transform: scale(1.02); opacity: 0.4; }
    100% { transform: scale(0.95); opacity: 0.8; }
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .fade-in { animation: fadeIn 0.3s ease forwards; }

  .url-input {
    width: 100%;
    background: #0d1117;
    border: 1.5px solid #1e2530;
    border-radius: 10px;
    padding: 16px 20px;
    font-size: 14px;
    color: #e2e8f0;
    font-family: 'Space Mono', monospace;
    outline: none;
    transition: border-color 0.2s;
  }
  .url-input:focus { border-color: #f59e0b; }
  .url-input::placeholder { color: #374151; }

  .scan-btn {
    padding: 14px 32px;
    background: linear-gradient(135deg, #f59e0b, #ef4444);
    border: none;
    border-radius: 10px;
    color: #000;
    font-weight: 700;
    font-size: 14px;
    font-family: 'Space Mono', monospace;
    cursor: pointer;
    letter-spacing: 0.05em;
    transition: opacity 0.2s, transform 0.1s;
    white-space: nowrap;
  }
  .scan-btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
  .scan-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  .card {
    background: #0d1117;
    border: 1px solid #1e2530;
    border-radius: 14px;
    padding: 24px;
  }

  .example-pill {
    font-size: 11px;
    padding: 4px 10px;
    border-radius: 99px;
    border: 1px solid #1e2530;
    background: transparent;
    color: #6b7280;
    cursor: pointer;
    font-family: 'Space Mono', monospace;
    transition: all 0.15s;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 200px;
  }
  .example-pill:hover { border-color: #f59e0b; color: #f59e0b; }
`;

export default function App() {
  const [url, setUrl]         = useState("");
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");
  const [modelReady, setModelReady] = useState(null);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    checkModel();
  }, []);

  async function checkModel() {
    try {
      const res = await axios.get(`${API}/model/info`);
      setModelReady(res.data.ready);
      if (!res.data.ready) setTimeout(checkModel, 5000);
    } catch { setModelReady(false); }
  }

  async function analyze(targetUrl) {
    const scanUrl = targetUrl || url;
    if (!scanUrl.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await axios.post(`${API}/analyze`, { url: scanUrl.trim() });
      setResult(res.data);
      setHistory((h) => [res.data, ...h.filter((i) => i.url !== res.data.url)].slice(0, 8));
    } catch (e) {
      setError(e.response?.data?.error || "Analysis failed — is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  function handleKey(e) {
    if (e.key === "Enter") analyze();
  }

  const resultBg = result
    ? result.label === "PHISHING"   ? "rgba(255,77,77,0.04)"
    : result.label === "SUSPICIOUS" ? "rgba(251,191,36,0.04)"
    : "rgba(74,222,128,0.04)"
    : undefined;

  const resultBorder = result
    ? result.label === "PHISHING"   ? "1px solid rgba(255,77,77,0.2)"
    : result.label === "SUSPICIOUS" ? "1px solid rgba(251,191,36,0.2)"
    : "1px solid rgba(74,222,128,0.2)"
    : undefined;

  return (
    <>
      <style>{css}</style>
      <div style={{ minHeight: "100vh", padding: "0 20px 60px" }}>

        {/* Header */}
        <header style={{ maxWidth: 900, margin: "0 auto", padding: "32px 0 40px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: "linear-gradient(135deg, #f59e0b, #ef4444)",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18,
            }}>🎣</div>
            <span style={{ fontFamily: "Space Mono", fontSize: 20, fontWeight: 700, color: "#f1f5f9" }}>
              PhishGuard
            </span>
            <span style={{ fontSize: 11, color: "#374151", fontFamily: "Space Mono" }}>v1.0</span>
            {modelReady === false && (
              <span style={{ fontSize: 11, color: "#f59e0b", fontFamily: "Space Mono", marginLeft: 8 }}>
                ⚡ Model loading...
              </span>
            )}
            {modelReady === true && (
              <span style={{ fontSize: 11, color: "#4ade80", fontFamily: "Space Mono", marginLeft: 8 }}>
                ● Model ready
              </span>
            )}
          </div>
          <p style={{ fontSize: 13, color: "#4a5568", maxWidth: 500 }}>
            ML-powered phishing URL detection. Paste any URL to get an instant risk score with feature-level explanation.
          </p>
        </header>

        <main style={{ maxWidth: 900, margin: "0 auto" }}>

          {/* Input */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
              <input
                className="url-input"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={handleKey}
                placeholder="https://suspicious-site.xyz/login/verify"
              />
              <button className="scan-btn" onClick={() => analyze()} disabled={loading || !url.trim()}>
                {loading ? "Scanning..." : "Scan →"}
              </button>
            </div>

            {/* Example URLs */}
            <div>
              <span style={{ fontSize: 11, color: "#374151", fontFamily: "Space Mono", marginRight: 8 }}>
                TRY:
              </span>
              <div style={{ display: "inline-flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                {EXAMPLE_URLS.map((u) => (
                  <button key={u} className="example-pill" onClick={() => { setUrl(u); analyze(u); }}>
                    {u.replace(/^https?:\/\//, "")}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {error && (
            <div style={{ background: "rgba(255,77,77,0.08)", border: "1px solid rgba(255,77,77,0.2)", borderRadius: 10, padding: "12px 16px", marginBottom: 16, fontSize: 13, color: "#ff4d4d" }}>
              {error}
            </div>
          )}

          {/* Result */}
          {result && (
            <div className="fade-in card" style={{ background: resultBg, border: resultBorder, marginBottom: 16 }}>
              <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 32 }}>

                {/* Gauge */}
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                  <RiskGauge
                    score={result.risk_score}
                    label={result.label}
                    color={result.color}
                  />
                  <div style={{ fontSize: 11, color: "#4a5568", textAlign: "center", marginTop: 8, fontFamily: "Space Mono" }}>
                    Model AUC: {result.model_auc}
                  </div>
                </div>

                {/* Details */}
                <div>
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 11, color: "#4a5568", fontFamily: "Space Mono", marginBottom: 4 }}>SCANNED URL</div>
                    <div style={{ fontSize: 13, color: "#9ca3af", fontFamily: "Space Mono", wordBreak: "break-all", lineHeight: 1.5 }}>
                      {result.url}
                    </div>
                  </div>
                  <FeatureBreakdown features={result.top_features} allFeatures={result.all_features} />
                </div>
              </div>
            </div>
          )}

          {/* History */}
          {history.length > 0 && (
            <div className="card">
              <HistoryLog history={history} onSelect={(item) => { setUrl(item.url); setResult(item); }} />
            </div>
          )}
        </main>
      </div>
    </>
  );
}
