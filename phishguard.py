#!/usr/bin/env python3
"""PhishGuard: explainable, offline email-text risk indicators."""
import argparse
import json
import re
from pathlib import Path

RULES = [
    ("urgent_language", re.compile(r"\b(urgent|immediately|act now|within 24 hours|suspended)\b", re.I), 2,
     "Urgent or pressure-based language"),
    ("credential_request", re.compile(r"\b(password|verify your account|login details|credentials)\b", re.I), 3,
     "Possible request for credentials or account verification"),
    ("payment_pressure", re.compile(r"\b(gift card|wire transfer|payment required|bank details)\b", re.I), 3,
     "Payment or financial-information language"),
    ("link_present", re.compile(r"https?://|www\.", re.I), 1,
     "Contains a web link; inspect its destination independently"),
    ("shortened_link", re.compile(r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl)/", re.I), 2,
     "Contains a URL-shortening domain"),
    ("suspicious_attachment", re.compile(r"\.(?:exe|scr|js|vbs|iso|hta)\b", re.I), 3,
     "Mentions a potentially risky attachment extension"),
]

def inspect(text):
    indicators=[]; score=0
    for name,pattern,weight,description in RULES:
        if pattern.search(text):
            score+=weight
            indicators.append({"rule":name,"weight":weight,"description":description})
    level="LOW" if score<=2 else "MEDIUM" if score<=5 else "HIGH"
    return {"risk_score":score,"risk_level":level,"indicators":indicators,
            "disclaimer":"Heuristic screening only. Validate context and sender separately."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input",required=True,help="Path to a plain-text email sample")
    p.add_argument("--out",default="phishguard-report.json")
    a=p.parse_args()
    text=Path(a.input).read_text(encoding="utf-8",errors="replace")
    report=inspect(text)
    Path(a.out).write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(f"Risk: {report['risk_level']} (score {report['risk_score']})")
    for item in report["indicators"]: print(f"- {item['description']}")
    print(f"Report saved to {a.out}")

if __name__=="__main__": main()
