import re 
from urllib.parse import urlparse
import tldextract
import math

# Helper function to count occurrences of a character in a string
def count_char(s: str, ch: str) -> int:
    return s.count(ch)

KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "accounts", "auth", "authentication", "token",
    "password", "support", "update", "billing"
    ]

def extract_components(url: str) -> dict:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    
    # Normalize components to lowercase
    # Add default scheme so urlparse works correctly
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # ----- Extract hostname -----
    # Network location can include @ and ports 
    # Remove anything before @ (user info), then remove :port
    # E.g. user@evil.com:8080 -> evil.com
    hostport = netloc.split('@')[-1]
    hostname = hostport.split(':')[0]

    # ----- Create components dictionary -----
    components = {}

    # Check if HTTPS is used
    # URL length - use log to reduce sensitivity to absolute length
    # Hostname length ie. very long hostnames with deep subdomains 
    # Path length ie. long paths can be suspicious
    # Query length ie. long queries contain a lot of parameters 

    components["is_https"] = 1 if scheme == "https" else 0
    components["url_len"] = math.log1p(len(url))  # log(1 + len) to avoid log(0)
    components["hostname_len"] = math.log1p(len(hostname))
    components["path_len"] = math.log1p(len(path))
    components["query_len"] = len(query)  # Keep query length raw since it's usually 0

    # Check if hostname is an IP address ie. common phishing tactic
    is_ip = 1 if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname) else 0
    components["is_ip"] = is_ip

    # Special character count 
    # @ and % are often used in phishing URLs 
    # Many . often means many subdomains 
    # Note: / count removed - too many false positives on legitimate deep URLs
    for ch in ['-', '@', '?', '%', '.', '=', '_', '&']:
        components[f"count_{ch}"] = count_char(url, ch)


    # Check for presence of suspicious keywords in URL
    combined = hostname + " " + path + " " + query
    # Split by non-alphanumeric characters to avoid partial matches
    tokens = re.split(r"[^a-z0-9]+", combined) 
    # Remove empty strings from tokens
    tokens = [t for t in tokens if t]
    token_set = set(tokens)
    # Match keywords against tokens
    for keyword in KEYWORDS:
        components[f"keyword_{keyword}"] = 1 if keyword in token_set else 0

    # Subdomain depth and registered domain extraction using tldextract
    ext = tldextract.extract(hostname)
    subdomain_depth = 0 if not ext.subdomain else len(ext.subdomain.split("."))
    components["subdomain_depth"] = subdomain_depth
    
    # Check if TLD is common (helps reduce false positives for legitimate sites)
    suffix = ext.suffix.lower()
    tld_is_common = 1 if suffix in {"com", "org", "net", "edu", "gov", "io"} else 0
    components["tld_is_common"] = tld_is_common

    return components


    
