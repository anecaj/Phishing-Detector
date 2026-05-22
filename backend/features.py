"""
URL Feature Extraction for Phishing Detection.
All features derived purely from the URL string — no external API calls needed.
"""
import re
import math
import urllib.parse
from dataclasses import dataclass, field, asdict

# Known suspicious keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure", "update",
    "account", "password", "credential", "banking", "confirm", "billing",
    "suspend", "unusual", "unauthorized", "alert", "paypal", "amazon",
    "microsoft", "apple", "google", "facebook", "instagram", "netflix",
    "validate", "recover", "unlock", "limited", "urgent", "click", "free",
    "winner", "prize", "offer", "discount", "deal",
]

# Common legitimate TLDs (longer/unusual TLDs are suspicious)
COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "io", "co", "uk", "de",
    "fr", "jp", "au", "ca", "us", "info",
}


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address."""
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    return bool(ip_pattern.match(domain))


@dataclass
class URLFeatures:
    # Length-based
    url_length: int = 0
    domain_length: int = 0
    path_length: int = 0
    query_length: int = 0
    tld_length: int = 0

    # Count-based
    num_dots: int = 0
    num_hyphens: int = 0
    num_underscores: int = 0
    num_digits: int = 0
    num_special_chars: int = 0
    num_subdomains: int = 0
    num_params: int = 0
    path_depth: int = 0
    num_phishing_keywords: int = 0

    # Ratio-based
    digit_ratio: float = 0.0
    letter_ratio: float = 0.0
    special_char_ratio: float = 0.0

    # Entropy
    domain_entropy: float = 0.0
    path_entropy: float = 0.0
    url_entropy: float = 0.0

    # Binary flags
    is_https: int = 0
    has_ip: int = 0
    has_at_symbol: int = 0
    has_double_slash_redirect: int = 0
    has_port: int = 0
    has_encoded_chars: int = 0
    uncommon_tld: int = 0
    has_punycode: int = 0

    def to_list(self) -> list:
        return list(asdict(self).values())

    @classmethod
    def feature_names(cls) -> list[str]:
        return list(cls.__dataclass_fields__.keys())


def extract_features(url: str) -> URLFeatures:
    """
    Extract all phishing-detection features from a URL.
    Returns a URLFeatures dataclass instance.
    """
    f = URLFeatures()

    # Ensure URL has a scheme for parsing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return f

    full_url   = url.lower()
    domain     = parsed.netloc.lower()
    path       = parsed.path.lower()
    query      = parsed.query.lower()
    scheme     = parsed.scheme.lower()

    # Strip port from domain if present
    domain_no_port = domain.split(":")[0]

    # TLD extraction
    parts = domain_no_port.split(".")
    tld = parts[-1] if parts else ""

    # ── Length features ────────────────────────────────────────────────────────
    f.url_length    = len(full_url)
    f.domain_length = len(domain_no_port)
    f.path_length   = len(path)
    f.query_length  = len(query)
    f.tld_length    = len(tld)

    # ── Count features ─────────────────────────────────────────────────────────
    f.num_dots        = full_url.count(".")
    f.num_hyphens     = full_url.count("-")
    f.num_underscores = full_url.count("_")
    f.num_digits      = sum(c.isdigit() for c in full_url)
    f.num_special_chars = sum(
        1 for c in full_url if not c.isalnum() and c not in "./-_:?=&#%@+"
    )
    # Subdomains: everything before the registrable domain
    f.num_subdomains = max(0, len(parts) - 2)
    f.num_params     = len(urllib.parse.parse_qs(query))
    f.path_depth     = len([p for p in path.split("/") if p])

    # Phishing keywords
    f.num_phishing_keywords = sum(
        1 for kw in PHISHING_KEYWORDS if kw in full_url
    )

    # ── Ratio features ─────────────────────────────────────────────────────────
    url_len = max(len(full_url), 1)
    f.digit_ratio       = f.num_digits / url_len
    f.letter_ratio      = sum(c.isalpha() for c in full_url) / url_len
    f.special_char_ratio = f.num_special_chars / url_len

    # ── Entropy features ───────────────────────────────────────────────────────
    f.domain_entropy = shannon_entropy(domain_no_port)
    f.path_entropy   = shannon_entropy(path)
    f.url_entropy    = shannon_entropy(full_url)

    # ── Binary flags ───────────────────────────────────────────────────────────
    f.is_https                 = int(scheme == "https")
    f.has_ip                   = int(is_ip_address(domain_no_port))
    f.has_at_symbol            = int("@" in full_url)
    f.has_double_slash_redirect = int("//" in path)
    f.has_port                 = int(bool(parsed.port))
    f.has_encoded_chars        = int("%" in full_url)
    f.uncommon_tld             = int(tld not in COMMON_TLDS)
    f.has_punycode             = int("xn--" in domain_no_port)

    return f


def extract_feature_dict(url: str) -> dict:
    """Return features as a labeled dict for API responses."""
    f = extract_features(url)
    return asdict(f)
