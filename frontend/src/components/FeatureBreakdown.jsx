const FEATURE_LABELS = {
  url_length: "URL Length",
  domain_length: "Domain Length",
  path_length: "Path Length",
  query_length: "Query String Length",
  tld_length: "TLD Length",
  num_dots: "Number of Dots",
  num_hyphens: "Number of Hyphens",
  num_underscores: "Underscores",
  num_digits: "Digit Count",
  num_special_chars: "Special Characters",
  num_subdomains: "Subdomain Count",
  num_params: "Query Parameters",
  path_depth: "Path Depth",
  num_phishing_keywords: "Phishing Keywords",
  digit_ratio: "Digit Ratio",
  letter_ratio: "Letter Ratio",
  special_char_ratio: "Special Char Ratio",
  domain_entropy: "Domain Entropy",
  path_entropy: "Path Entropy",
  url_entropy: "URL Entropy",
  is_https: "Uses HTTPS",
  has_ip: "IP Address as Domain",
  has_at_symbol: "Has @ Symbol",
  has_double_slash_redirect: "Double Slash Redirect",
  has_port: "Explicit Port",
  has_encoded_chars: "Encoded Characters (%)",
  uncommon_tld: "Uncommon TLD",
  has_punycode: "Punycode Domain",
};

const FEATURE_DESCRIPTIONS = {
  num_phishing_keywords: "URL contains words commonly used in phishing (login, verify, secure, etc.)",
  has_ip: "Domain is an IP address — legitimate sites use domain names",
  has_at_symbol: "@ in URL can redirect to a malicious host",
  domain_entropy: "High randomness in domain name — often indicates generated domains",
  num_subdomains: "Many subdomains used to mimic legitimate sites (paypal.evil.com)",
  has_double_slash_redirect: "Double slash in path can indicate redirect tricks",
  uncommon_tld: "Unusual top-level domain (.tk, .ml, .xyz) favored by attackers",
  has_port: "Explicit port number in URL is uncommon for legitimate sites",
  url_length: "Very long URLs are often used to hide malicious destination",
  num_hyphens: "Hyphens used to mimic legitimate domains (pay-pal.com)",
};

export default function FeatureBreakdown({ features, allFeatures }) {
  if (!features || features.length === 0) return null;

  const maxContrib = Math.max(...features.map((f) => f.contribution), 0.001);

  return (
    <div>
      <div style={{ fontSize: 11, color: "#6b7280", fontFamily: "Space Mono", marginBottom: 14, letterSpacing: "0.08em" }}>
        TOP CONTRIBUTING FEATURES
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {features.map((feat) => {
          const pct = (feat.contribution / maxContrib) * 100;
          const label = FEATURE_LABELS[feat.name] || feat.name;
          const desc  = FEATURE_DESCRIPTIONS[feat.name];
          const isFlag = typeof feat.value === "number" && (feat.value === 0 || feat.value === 1)
            && feat.name.startsWith("has_") || feat.name.startsWith("is_") || feat.name === "uncommon_tld" || feat.name === "has_punycode";
          const triggered = feat.value > 0;

          return (
            <div key={feat.name} title={desc || ""}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4, alignItems: "baseline" }}>
                <span style={{ fontSize: 12, color: triggered ? "#e2e8f0" : "#4a5568", fontFamily: "DM Sans" }}>
                  {label}
                </span>
                <span style={{ fontSize: 11, color: "#6b7280", fontFamily: "Space Mono" }}>
                  {typeof feat.value === "number"
                    ? (Number.isInteger(feat.value) ? feat.value : feat.value.toFixed(3))
                    : feat.value}
                </span>
              </div>
              <div style={{ height: 4, background: "#1e2530", borderRadius: 99, overflow: "hidden" }}>
                <div style={{
                  width: `${pct}%`, height: "100%", borderRadius: 99,
                  background: triggered ? "linear-gradient(90deg, #f59e0b, #ef4444)" : "#2d3748",
                  transition: "width 0.6s ease",
                }} />
              </div>
              {desc && (
                <div style={{ fontSize: 10, color: "#4a5568", marginTop: 3, lineHeight: 1.4 }}>{desc}</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
