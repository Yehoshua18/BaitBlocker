import whois
from datetime import datetime
import whois.parser


def perform_whois_lookup(domain_or_url: str) -> dict:
    """
    Performs a WHOIS lookup on a domain or URL and extracts key dates.
    Returns a normalized dictionary.
    """
    # Clean the input to just the domain if a full URL is passed
    domain = domain_or_url.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        # Query the WHOIS server
        w = whois.whois(domain)

        # WHOIS data can return a single datetime object OR a list of them.
        # This helper ensures we always get the earliest/primary date.
        def normalize_date(date_input):
            if isinstance(date_input, list):
                return date_input[0]
            return date_input

        creation_date = normalize_date(w.creation_date)
        expiration_date = normalize_date(w.expiration_date)

        # Calculate domain age in days if creation date exists
        age_days = None
        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days

        return {
            "status": "SUCCESS",
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "expiration_date": expiration_date.isoformat() if expiration_date else None,
            "age_days": age_days,
            "country": w.country,
            "raw": str(w)  # Fallback to raw text if needed
        }

    except whois.parser.PywhoisError:
        # Thrown if the domain is not registered or cannot be found
        return {"status": "NOT_FOUND", "domain": domain, "error": "Domain not registered."}
    except Exception as e:
        # Thrown for network timeouts or socket errors
        return {"status": "ERROR", "domain": domain, "error": str(e)}

