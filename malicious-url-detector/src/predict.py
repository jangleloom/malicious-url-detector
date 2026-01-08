from urllib.parse import urlparse
from pathlib import Path
import pandas as pd
from joblib import load

from components import extract_components

# Get the project root directory (2 levels up from this file)
PROJECT_ROOT = Path(__file__).parent.parent.parent

MODEL_PATH = PROJECT_ROOT / "models" / "logistic_regression_model.joblib"
WHITELIST_PATH = PROJECT_ROOT / "config" / "whitelist.txt"
PLATFORM_PATH = PROJECT_ROOT / "config" / "platform_hosts.txt"


def load_domain_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return set(lines)


TRUSTED_DOMAINS = load_domain_set(WHITELIST_PATH)
PLATFORM_HOSTS = load_domain_set(PLATFORM_PATH)


def normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return url


def get_hostname(url: str) -> str:
    host = urlparse(normalize_url(url)).hostname
    return (host or "").lower()


def suffix_match(hostname: str, domain_set: set[str]) -> bool:
    return any(hostname == d or hostname.endswith("." + d) for d in domain_set)


def score_url(url: str) -> dict:
    hostname = get_hostname(url)

    # --- Tier checks ---
    is_trusted = suffix_match(hostname, TRUSTED_DOMAINS)
    is_platform = suffix_match(hostname, PLATFORM_HOSTS)

    # Tier 1: Hard Whitelist
    if is_trusted and not is_platform:
        return {
            "url": url,
            "hostname": hostname,
            "tier": "trusted",
            "prob_malicious": 0.0,
            "risk_score": 5,
            "verdict": "LOW RISK",
        }

    # --- ML scoring ---
    bundle = load(MODEL_PATH)
    model = bundle["model"]
    columns = bundle["columns"]

    feats = extract_components(url)
    numeric_feats = {k: v for k, v in feats.items() if isinstance(v, (int, float))}
    X = pd.DataFrame([numeric_feats]).reindex(columns=columns, fill_value=0)

    p_mal = float(model.predict_proba(X)[0][1])

    # Tier 2: platform-hosted soft allow (reduce risk, don't hard override)
    # Platform hosts are often used by both legitimate and malicious users 
    if is_platform:
        # reduce but not to 0: keeps some safety
        p_mal = p_mal ** 3
    

    # Scale down extreme probabilities
    if p_mal > 0.95:
        p_mal = 0.95  # Cap at 95%
    elif p_mal < 0.05:
        p_mal = 0.05  # Floor at 5%

    risk_score = int(round(p_mal * 100))

    if risk_score >= 80:
        verdict = "HIGH RISK"
    elif risk_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    tier = "platform" if is_platform else "normal"


    return {
        "url": url,
        "hostname": hostname,
        "tier": tier,
        "prob_malicious": p_mal,
        "risk_score": risk_score,
        "verdict": verdict,
    }

def main():
    while True:
        url = input("Enter URL to check (or 'exit' to quit): ").strip()
        if url.lower() == 'exit':
            break
        result = score_url(url)
        print(f"\nURL: {result['url']}", flush=True)
        print(f"Hostname: {result['hostname']}", flush=True)
        print(f"Tier: {result['tier']}", flush=True)
        print(f"Probability Malicious: {result['prob_malicious']:.4f}", flush=True)
        print(f"Risk Score: {result['risk_score']}/100", flush=True)
        print(f"Verdict: {result['verdict']}\n", flush=True)
        
if __name__ == "__main__":
    main()