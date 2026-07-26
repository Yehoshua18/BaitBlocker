import re
from database import get_all_keywords, init_db, get_by_type


class KeywordScanner:
    def __init__(self):
        # Initialize database and populate cache
        init_db()
        self.refresh_cache()

    def refresh_cache(self):
        """Loads keywords from DB into memory and pre-compiles regex structures."""
        raw_keywords = get_all_keywords()
        self.keyword_weights = {kw: weight for kw, weight in raw_keywords}

        if not self.keyword_weights:
            self.compiled_regex = None
            return

        # Escapes special characters and creates an alternation pattern: \b(login|signin|verify)\b
        escaped_kws = [re.escape(kw) for kw in self.keyword_weights.keys()]
        pattern_str = rf"(\b|[-._\/])({'|'.join(escaped_kws)})(\b|[-._\/])"
        self.compiled_regex = re.compile(pattern_str, re.IGNORECASE)

    def scan_url(self, url: str) -> dict:
        """Scans a target URL against the loaded keyword database."""
        if not self.compiled_regex:
            return {"score": 0.0, "matches": []}

        # Find all structural overlapping matches inside the target string
        matches = self.compiled_regex.findall(url.lower())

        # Extract the captured keyword token from the matching groups
        # regex captures: (left_boundary, target_keyword, right_boundary)
        found_keywords = list({match[1] for match in matches})

        # Calculate a combined running threat matrix score capped at 1.0
        total_score = min(1.0, sum(self.keyword_weights.get(kw, 0.25) for kw in found_keywords))

        return {
            "score": round(total_score, 2),
            "matches": found_keywords,
            "verdict": "SUSPICIOUS" if total_score >= 0.5 else "CLEAN"
        }

    def scan_for_keywords_by_type(self, url: str, type: str) -> dict:
        """Scans a target URL against the loaded keyword database."""
        if not self.compiled_regex:
            return {"score": 0.0, "matches": []}

        # Find all structural overlapping matches inside the target string
        matches = self.compiled_regex.findall(url.lower())

        # Extract the captured keyword token from the matching groups
        # regex captures: (left_boundary, target_keyword, right_boundary)
        found_keywords = list({match[1] for match in matches})
        found_keywords_by_type = list(set(found_keywords) & set(get_by_type(type)))

        # Calculate a combined running threat matrix score capped at 1.0
        total_score = min(1.0, sum(self.keyword_weights.get(kw, 0.25) for kw in found_keywords_by_type))

        return {
            "score": round(total_score, 2),
            "matches": found_keywords_by_type,
            "verdict": "SUSPICIOUS" if total_score >= 0.5 else "CLEAN"
        }