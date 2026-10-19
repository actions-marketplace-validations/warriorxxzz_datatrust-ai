import re
from datatrust_ai.normalizer import normalize_digits
from datatrust_ai.patterns.nepal import NEPAL_PATTERNS
from datatrust_ai.patterns.india import INDIA_PATTERNS
from datatrust_ai.patterns.global_ids import GLOBAL_PATTERNS
from datatrust_ai.validators import is_valid_luhn, is_valid_verhoeff

SEVERITY = {
    "NP_CITIZENSHIP": "HIGH",
    "NP_NID": "HIGH",
    "NP_PAN": "HIGH",
    "NP_PASSPORT": "HIGH",
    "NP_PHONE_MOBILE": "MEDIUM",
    "NP_PHONE_LANDLINE": "LOW",
    "IN_AADHAAR": "HIGH",
    "IN_PAN": "HIGH",
    "IN_UPI": "MEDIUM",
    "IN_IFSC": "LOW",
    "IN_PHONE_MOBILE": "MEDIUM",
    "CREDIT_CARD": "HIGH",
    "AWS_KEY": "HIGH",
    "OPENAI_KEY": "HIGH",
    "GITHUB_PAT": "HIGH",
    "GOOGLE_API": "HIGH",
    "PRIVATE_KEY": "HIGH",
    "EMAIL": "LOW",
    "IPV4": "LOW",
}

ALL_PATTERNS = {**NEPAL_PATTERNS, **INDIA_PATTERNS, **GLOBAL_PATTERNS}

def scan_text(text: str) -> dict:
    normalized = normalize_digits(text)
    findings = []

    for name, pattern in ALL_PATTERNS.items():
        for match in re.finditer(pattern, normalized):
            value = match.group()
            
            if name == "CREDIT_CARD" and not is_valid_luhn(value):
                continue
            if name == "IN_AADHAAR" and not is_valid_verhoeff(value):
                continue

            findings.append({
                "type": name,
                "severity": SEVERITY.get(name, "LOW"),
                "start": match.start(),
                "end": match.end(),
            })

    findings.sort(key=lambda x: (x["end"] - x["start"]), reverse=True)
    filtered = []
    for f in findings:
        overlap = False
        for existing in filtered:
            if max(f["start"], existing["start"]) < min(f["end"], existing["end"]):
                overlap = True
                break
        if not overlap:
            filtered.append(f)

    filtered.sort(key=lambda x: x["start"])

    if any(f["severity"] == "HIGH" for f in filtered):
        risk = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in filtered):
        risk = "MEDIUM"
    elif filtered:
        risk = "LOW"
    else:
        risk = "NONE"

    return {"risk": risk, "findings": filtered}
