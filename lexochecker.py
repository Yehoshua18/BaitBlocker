import math
from urllib.parse import urlparse
import ipaddress

# Suspicious keywords often crammed into paths/subdomains to fool users
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "secure", "banking", "update",
    "account", "wallet", "paypal", "netflix", "amazon", "apple"
}

# High-risk top level domains frequently used in malicious infrastructure
HIGH_RISK_TLDS = {".xyz", ".top", ".club", ".work", ".live", ".gq", ".tk", ".cf"}


def calculate_entropy(string: str) -> float:
    """
    Calculates Shannon Entropy to measure string randomness.
    High entropy means high unpredictability (often indicating generated/malicious strings).
    """
    if not string:
        return 0.0 #no unique characters
    probabilities = [float(string.count(c)) / len(string) for c in set(string)] #how many times each character appears in the string
    return -sum(p * math.log2(p) for p in probabilities) #the formula to calculate shannon's entropy


def assess_url_risk(url: str) -> dict:
    """
    Lexicographically evaluates a URL and returns a risk score profile.
    """
    # Clean up basic spacing/lowercase to avoid simple evasion tricks
    url = url.strip().lower()

    # Force a scheme if missing so urlparse works properly
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        # Extract netloc (domain + port) and path
        hostname = parsed.hostname or ""
        path = parsed.path
    except Exception:
        return {"verdict": "MALFORMED", "risk_score": 1.0, "reasons": ["Failed to parse URL structure"]}

    risk_score = 0.0
    reasons = []

    # 1. Length Checks (Malicious URLs often hide payloads or subdomains in long strings)
    if len(url) > 75:
        risk_score += 0.15
        reasons.append("Excessive total URL length")
    if len(hostname) > 30:
        risk_score += 0.15
        reasons.append("Excessive domain length")

    # 2. Structural/Character Checks
    # Count special characters in the domain (excluding standard dots)
    hyphen_count = hostname.count("-")
    digit_count = sum(c.isdigit() for c in hostname)

    if hyphen_count > 2:
        risk_score += 0.2
        reasons.append(f"High number of hyphens in domain ({hyphen_count})")
    if digit_count > 3:
        risk_score += 0.2
        reasons.append(f"High density of numbers in domain ({digit_count})")

    # 3. Keyword Squatting (Brand names or bait words in paths/subdomains)
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in url]
    # Check if they are trying to trick the user (e.g., 'paypal' is present but it's not the actual brand domain)
    if found_keywords:
        # Simple safeguard: if the brand is inside the string but doesn't map to the core domain
        risk_score += 0.25 * len(found_keywords)
        reasons.append(f"Suspicious keywords detected: {found_keywords}")

    # 4. TLD Risk Assessment
    if any(hostname.endswith(tld) for tld in HIGH_RISK_TLDS):
        risk_score += 0.3
        reasons.append("Uses a statistically high-risk top-level domain (TLD)")

    # 5. IP Address Check (Direct IP URLs are overwhelmingly malicious/scams)
    # We strip brackets [] because urlparse preserves them around IPv6 hostnames
    clean_host = hostname.strip("[]")
    try:
        # If this succeeds, the hostname is a valid raw IPv4 or IPv6 address
        ip_obj = ipaddress.ip_address(clean_host)
        risk_score += 0.6
        reasons.append(f"Host is a raw IP address ({ip_obj.version}) instead of a domain name")
    except ValueError:
        # If a ValueError is thrown, it's a standard text domain (like google.com), so we move on safely
        pass

    # 6. Entropy Check (Looks for randomly generated strings)
    entropy = calculate_entropy(hostname)
    if entropy > 4.2:  # 4.2+ is heavily random for typical commercial domain names
        risk_score += 0.2
        reasons.append(f"High domain character randomness (Entropy: {entropy:.2f})")

    # Normalize score between 0.0 and 1.0 (0% - 100%)
    final_score = min(round(risk_score, 2), 1.0)

    # Determine general verdict threshold
    if final_score >= 0.6:
        verdict = "HIGH_RISK"
    elif final_score >= 0.3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": final_score,
        "reasons": reasons
    }


# --- Quick Test ---
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=python",
        "http://secure-login-paypal-update-account.xyz/index.php",
        "http://192.168.1.1/login",
        "https://amzn-security-verification-check.com"
    ]

    for t_url in test_urls:
        res = assess_url_risk(t_url)
        print(
            f"URL: {res['url']}\nVerdict: {res['verdict']} ({res['risk_score']})\nReasons: {res['reasons']}\n{'-' * 40}")