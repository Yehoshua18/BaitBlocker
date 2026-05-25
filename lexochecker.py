import math
from typing import List
from urllib.parse import urlparse
import ipaddress
from database import get_brands
from rapidfuzz.distance import Levenshtein

from matcher import KeywordScanner

# Suspicious keywords often crammed into paths/subdomains to fool users
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "secure", "banking", "update",
    "account", "wallet", "paypal", "netflix", "amazon", "apple"
}

keyword_scanner = KeywordScanner()

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


def detect_mutations(input_domain: str, known_brands: List[str]) -> List[dict]:
    """
    Compares the input against trusted brands using Levenshtein distance.
    Filters out exact matches and flags close mutations.
    """
    detected = []
    input_clean = input_domain.lower().strip()

    for brand in known_brands:
        brand_clean = brand.lower().strip()

        # Exact match means they are visiting the legitimate domain
        if input_clean == brand_clean:
            continue

        # Calculate how many single-character edits separate the strings
        distance = Levenshtein.distance(input_clean, brand_clean)

        # An edit distance of 1 or 2 characters indicates a severe typosquatting risk
        if 0 < distance <= 2:
            # Simple confidence inverse calculation for metric output
            confidence = 100.0 if distance == 1 else 75.0

            detected.append({
                "impersonated_brand": brand,
                "edit_distance": distance,
                "confidence_score": confidence
            })

    return detected

async def assess_url_risk(url: str) -> dict:
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
    subdomain_count = len(hostname.split(".")) - 2

    if subdomain_count >= 3:
        risk_score += 0.2
        reasons.append(f"Suspicious sub-segmenting detected ({subdomain_count} routing layers)")

    if hyphen_count > 2:
        risk_score += 0.2
        reasons.append(f"High number of hyphens in domain ({hyphen_count})")
    if digit_count > 3:
        risk_score += 0.2
        reasons.append(f"High density of numbers in domain ({digit_count})")

    # 3. Keyword Squatting (Brand names or bait words in paths/subdomains)
    db_scan_results = keyword_scanner.scan_url(url)
    if db_scan_results["matches"]:
        risk_score += 0.25 * len(db_scan_results["matches"])
        reasons.append(f"Blacklisted keywords found: {db_scan_results['matches']}")
    '''
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in url]
    # Check if they are trying to trick the user (e.g., 'paypal' is present but it's not the actual brand domain)
    if found_keywords:
        # Simple safeguard: if the brand is inside the string but doesn't map to the core domain
        risk_score += 0.25 * len(found_keywords)
        reasons.append(f"Suspicious keywords detected: {found_keywords}")
    '''

    # 4. Typosquatting (similar to existing brand names)

    # Fallback/Safety valve if your database table is empty during testing
    brands = get_brands()
    if not brands:
        brands = ["google", "paypal", "microsoft", "netflix"]

    # 4.2. Run the algorithmic distance evaluation
    # Extract just the core name label before the TLD dot (e.g., "g00gle.com" -> "g00gle")
    clean_host_label = hostname.split(".")[0] if hostname else ""
    matches = detect_mutations(clean_host_label, brands)
    if len(matches) > 0:
        risk_score += 0.3 * len(matches)
        reasons.append(f"Suspicious mutation detected: {matches}")

    # 5. TLD Risk Assessment
    if any(hostname.endswith(tld) for tld in HIGH_RISK_TLDS):
        risk_score += 0.3
        reasons.append("Uses a statistically high-risk top-level domain (TLD)")

    # 6. IP Address Check (Direct IP URLs are overwhelmingly malicious/scams)
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

    # 7. Entropy Check (Looks for randomly generated strings)
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