# report.py
"""
Cloak - Reporting Module
Generates structured reports comparing original vs. transformed payloads.
"""

from pathlib import Path
import hashlib
import datetime

RESULTS_DIR = Path("results")

def save_output(content: str):
    """Save report content into results/ directory with unique filename."""
    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.txt"
    (RESULTS_DIR / filename).write_text(content)
    return filename

def generate_report(original: str, transformed: str,
                    detected_original: bool, detected_transformed: bool) -> str:
    """Generate a structured report with hashes, detection outcomes, and effectiveness analysis."""
    report = []
    report.append("=== Cloak Report ===")
    report.append(f"Timestamp: {datetime.datetime.now().isoformat()}")
    report.append("")
    report.append(f"Original Payload: {original}")
    report.append(f"Original SHA256: {hashlib.sha256(original.encode()).hexdigest()}")
    report.append(f"Transformed Payload Preview: {transformed[:60]}")
    report.append(f"Transformed SHA256: {hashlib.sha256(transformed.encode()).hexdigest()}")
    report.append("")
    report.append(f"Original Detection: {'DETECTED' if detected_original else 'BYPASSED'}")
    report.append(f"Transformed Detection: {'DETECTED' if detected_transformed else 'BYPASSED'}")

    # Effectiveness analysis
    if detected_original and not detected_transformed:
        report.append("Effectiveness: SUCCESS — Transformation bypassed detection.")
    elif detected_original and detected_transformed:
        report.append("Effectiveness: FAIL — Transformation did not evade detection.")
    elif not detected_original and not detected_transformed:
        report.append("Effectiveness: NEUTRAL — Both original and transformed bypassed.")
    else:
        report.append("Effectiveness: UNEXPECTED — Transformed was detected while original was not.")

    return "\n".join(report)
