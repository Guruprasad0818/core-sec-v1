"""
Minimal report uploader that ingests a ZAP JSON report and computes a simple risk score.
If score >= threshold it prints a simulated ticket creation payload.
"""
import os
import json
import sys
from typing import Dict


def compute_risk_from_zap(report: Dict) -> float:
    # Simplified heuristic: average alert risk where risk: "High"=1.0, "Medium"=0.6, "Low"=0.2, "Informational"=0.0
    mapping = {"High": 1.0, "Medium": 0.6, "Low": 0.2, "Informational": 0.0}
    alerts = report.get("site", [])
    if not alerts:
        return 0.0
    scores = []
    for site in alerts:
        for alert in site.get("alerts", []):
            r = alert.get("risk", "Informational")
            scores.append(mapping.get(r, 0.0))
    if not scores:
        return 0.0
    return sum(scores) / len(scores)


def upload_report(path: str, threshold: float = 0.7):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as f:
        report = json.load(f)
    score = compute_risk_from_zap(report)
    payload = {
        "summary": f"DAST findings (score={score:.2f})",
        "risk": score,
        "attachments": [os.path.basename(path)],
    }
    if score >= threshold:
        # Placeholder for ticket creation (Jira/GitHub). Print JSON to stdout for now.
        print(json.dumps({"action": "create_ticket", "payload": payload}, indent=2))
        return True
    else:
        print(json.dumps({"action": "no_ticket", "payload": payload}, indent=2))
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: report_uploader.py <zap-report.json> [threshold]")
        sys.exit(2)
    path = sys.argv[1]
    th = float(sys.argv[2]) if len(sys.argv) > 2 else 0.7
    ok = upload_report(path, th)
    sys.exit(0 if ok else 1)
