from src.components import extract_components
import json

# Test URLs - mix of legitimate and suspicious
test_urls = [
    # Legitimate URLs
    "https://www.google.com",
    "https://github.com/user/repo",
    "https://www.amazon.com/product?id=123",
    
    # Suspicious URLs
    "http://login-paypal-verify.suspicious-domain.com/secure/update?token=abc",
    "http://192.168.1.1/admin/login",
    "http://accounts-google.verify-login.tk/signin?redirect=home",
    "http://www.paypa1.com/login",  # Typosquatting (l -> 1)
    "http://secure-account-verification-required.long-suspicious-domain.com/update/password?session=12345&redirect=true",
]

print("=" * 80)
print("URL DETECTOR TEST")
print("=" * 80)

for i, url in enumerate(test_urls, 1):
    print(f"\n[{i}] Testing: {url}")
    print("-" * 80)
    
    features = extract_components(url)
    
    # Print key suspicious indicators
    print(f"  HTTPS: {'Yes' if features['is_https'] else 'No'}")
    print(f"  IP Address: {'Yes' if features['is_ip'] else 'No'}")
    print(f"  URL Length: {features['url_len']}")
    print(f"  Hostname Length: {features['hostname_len']}")
    print(f"  Subdomain Depth: {features['subdomain_depth']}")
    print(f"  Registered Domain: {features['registered_domain']}")
    
    # Check for suspicious keywords
    keywords_found = [k.replace('keyword_', '') for k, v in features.items() 
                     if k.startswith('keyword_') and v == 1]
    if keywords_found:
        print(f"  Suspicious Keywords: {', '.join(keywords_found)}")
    
    # Check for special characters
    special_chars = {
        '@': features['count_@'],
        '-': features['count_-'],
        '.': features['count_.']
    }
    print(f"  Special Chars: @ ({special_chars['@']}), - ({special_chars['-']}), . ({special_chars['.']})") 
    
    # Simple risk score (basic heuristic)
    risk_score = 0
    if not features['is_https']: risk_score += 2
    if features['is_ip']: risk_score += 3
    if features['url_len'] > 75: risk_score += 2
    if features['subdomain_depth'] > 2: risk_score += 2
    if len(keywords_found) > 0: risk_score += len(keywords_found)
    if features['count_-'] > 3: risk_score += 1
    
    print(f"  Risk Score: {risk_score}/10 {'⚠️ SUSPICIOUS' if risk_score >= 5 else '✓ Looks OK'}")

print("\n" + "=" * 80)
print("Test complete!")
print("=" * 80)
