"""Core logic for BaitBlocker (local analysis and helpers)."""

from .local_analysis import assess_url_risk
from .emailchecker import check_email, TextPhishingAssessment

__all__ = ["assess_url_risk", "check_email", "TextPhishingAssessment"]

