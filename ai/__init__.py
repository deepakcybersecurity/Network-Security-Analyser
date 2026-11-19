"""Aegis AI Security Analyst package.

Provides automated post-scan security exposure evaluation, prioritized
remediation guidance, and beginner-friendly explanations while strictly
preserving Aegis's deterministic risk engine classifications.
"""

from .analyzer import AIAnalystError, analyze_scan

__all__ = ["analyze_scan", "AIAnalystError"]
