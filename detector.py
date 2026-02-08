# detector.py
"""
Cloak - Detection & Effectiveness Module
Simulates signature-based detection and evaluates transformation effectiveness.
"""

import re

# Example signatures (expand as needed)
SIGNATURES = [
    r"/bin/sh",
    r"os\.system",
    r"powershell",
    r"cmd\.exe",
]

def detect(payload: str) -> bool:
    """Return True if payload matches any signature."""
    for sig in SIGNATURES:
        if re.search(sig, payload):
            return True
    return False

def effectiveness(original: str, transformed: str) -> str:
    """
    Compare detection results for original vs transformed payloads.
    Return a human-readable effectiveness verdict.
    """
    detected_original = detect(original)
    detected_transformed = detect(transformed)

    if detected_original and not detected_transformed:
        return "SUCCESS — Transformation bypassed detection."
    elif detected_original and detected_transformed:
        return "FAIL — Transformation did not evade detection."
    elif not detected_original and not detected_transformed:
        return "NEUTRAL — Both original and transformed bypassed."
    else:
        return "UNEXPECTED — Transformed was detected while original was not."
