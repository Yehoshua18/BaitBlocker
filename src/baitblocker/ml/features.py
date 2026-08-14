""" Extract relevant features from a url and transfer them into a dictionary for the logistic regression model. """

import ipaddress
import re
from urllib.parse import urlparse
from typing import Iterable, Dict
from ..db.matcher import KeywordScanner

# These lexical features are available in PhishingData.csv and can be computed directly from a URL.
FEATURE_COLUMNS = [
	"NumDots",
	"SubdomainLevel",
	"PathLevel",
	"UrlLength",
	"NumDash",
	"NumDashInHostname",
	"AtSymbol",
	"TildeSymbol",
	"NumUnderscore",
	"NumPercent",
	"NumQueryComponents",
	"NumAmpersand",
	"NumHash",
	"NumNumericChars",
	"NoHttps",
	"RandomString",
	"IpAddress",
	"DomainInSubdomains",
	"DomainInPaths",
	"HttpsInHostname",
	"HostnameLength",
	"PathLength",
	"QueryLength",
	"DoubleSlashInPath",
	"NumSensitiveWords",
]

# Using Bait Blocker's already existing database of suspicious keywords
keyword_scanner = KeywordScanner()

# To make parsing easier
def _normalize_url(url: str) -> str:
	normalized = url.strip()
	if not normalized.startswith(("http://", "https://")):
		# Keep scheme-less inputs compatible with the training feature distribution.
		normalized = "http://" + normalized
	return normalized

# Quick check if a hostname looks like an IP address
def _hostname_looks_like_ip(hostname: str) -> int:
	if not hostname:
		return 0
	try:
		ipaddress.ip_address(hostname.strip("[]"))
		return 1
	except ValueError:
		return 0

# If a token in a URL has both letters and digits, it is most likely a random string
def _has_random_token(hostname: str, path: str) -> int:
	text = "{} {}".format(hostname, path)
	tokens = re.findall(r"[a-z0-9]{8,}", text.lower())
	for token in tokens:
		has_alpha = any(ch.isalpha() for ch in token)
		has_digit = any(ch.isdigit() for ch in token)
		if has_alpha and has_digit:
			return 1
	return 0

# More suspicious words = more likely to be phishing
def _count_sensitive_words(parts: Iterable[str]) -> int:
	return len(keyword_scanner.scan_url(" ".join(parts))["matches"])


def extract_url_features(url: str) -> Dict[str, float]:
	"""Create lexical features for a URL compatible with the logistic regression model."""

	# Step 1: parsing using our normalized url
	normalized = _normalize_url(url)
	parsed = urlparse(normalized)
	hostname = parsed.hostname or ""
	hostname_lower = hostname.lower()
	path = parsed.path or ""
	query = parsed.query or ""
	full_url = parsed.geturl()


	# Step 2 : Extract the registrable domain label (the "brand" token before the public suffix)
	# so downstream features like DomainInSubdomains/DomainInPaths can detect reuse.
	# For multipart country-code suffixes (e.g., example.co.uk, example.com.au, example.uk.co),
	# use the token before the last two suffix labels.
	domain_label = ""
	host_parts = [part for part in hostname_lower.split(".") if part]
	if len(host_parts) >= 2:
		common_second_level_suffixes = {"co", "com", "org", "net", "gov", "ac", "edu"}
		uses_compound_cc_suffix = len(host_parts) >= 3 and len(host_parts[-1]) == 2 and (
			len(host_parts[-2]) == 2 or host_parts[-2] in common_second_level_suffixes
		)
		domain_label = host_parts[-3] if uses_compound_cc_suffix else host_parts[-2]


	# Step 3: Split hostname + path into lowercase alphanumeric tokens for keyword scanning.
	words = re.findall(r"[a-z0-9]+", (hostname_lower + " " + path.lower()))

	# Step 4: Create feature dictionary
	features = {
		"NumDots": float(hostname_lower.count(".")),
		"SubdomainLevel": float(max(len(host_parts) - 2, 0)),
		"PathLevel": float(path.count("/") if path else 0),
		"UrlLength": float(len(full_url)),
		"NumDash": float(full_url.count("-")),
		"NumDashInHostname": float(hostname_lower.count("-")),
		"AtSymbol": float("@" in full_url),
		"TildeSymbol": float("~" in full_url),
		"NumUnderscore": float(full_url.count("_")),
		"NumPercent": float(full_url.count("%")),
		"NumQueryComponents": float(len([q for q in query.split("&") if q]) if query else 0),
		"NumAmpersand": float(full_url.count("&")),
		"NumHash": float(full_url.count("#")),
		"NumNumericChars": float(sum(ch.isdigit() for ch in full_url)),
		"NoHttps": float(parsed.scheme != "https"),
		"RandomString": float(_has_random_token(hostname_lower, path)),
		"IpAddress": float(_hostname_looks_like_ip(hostname_lower)),
		"DomainInSubdomains": float(bool(domain_label and "." in hostname_lower and domain_label in ".".join(host_parts[:-2]))),
		"DomainInPaths": float(bool(domain_label and domain_label in path.lower())),
		"HttpsInHostname": float("https" in hostname_lower),
		"HostnameLength": float(len(hostname_lower)),
		"PathLength": float(len(path)),
		"QueryLength": float(len(query)),
		"DoubleSlashInPath": float("//" in path),
		"NumSensitiveWords": float(_count_sensitive_words(words)),
	}
	return features