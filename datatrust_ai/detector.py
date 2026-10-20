import re
import base64
from datatrust_ai.normalizer import normalize_digits
from datatrust_ai.patterns.nepal import NEPAL_PATTERNS
from datatrust_ai.patterns.india import INDIA_PATTERNS
from datatrust_ai.patterns.global_ids import GLOBAL_PATTERNS
from datatrust_ai.validators import is_valid_luhn, is_valid_verhoeff, calculate_shannon_entropy

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    NLP_AVAILABLE = True
except ImportError:
    NLP_AVAILABLE = False

SEVERITY = {
    "NP_CITIZENSHIP": "HIGH", "NP_NID": "HIGH", "NP_PAN": "HIGH", "NP_PASSPORT": "HIGH",
    "NP_PHONE_MOBILE": "MEDIUM", "NP_PHONE_LANDLINE": "LOW",
    "IN_AADHAAR": "HIGH", "IN_PAN": "HIGH", "IN_UPI": "MEDIUM", "IN_IFSC": "LOW", "IN_PHONE_MOBILE": "MEDIUM",
    "CREDIT_CARD": "HIGH", "AWS_KEY": "HIGH", "OPENAI_KEY": "HIGH", "GITHUB_PAT": "HIGH", "GOOGLE_API": "HIGH", "PRIVATE_KEY": "HIGH",
    "EMAIL": "LOW", "IPV4": "LOW", "HIGH_ENTROPY": "HIGH", "PROMPT_INJECTION": "HIGH",
    "NLP_PERSON": "MEDIUM", "NLP_GPE": "MEDIUM"
}

ALL_PATTERNS = {**NEPAL_PATTERNS, **INDIA_PATTERNS, **GLOBAL_PATTERNS}

PROMPT_PATTERNS = [
    r"(?i)ignore (all )?previous instructions",
    r"(?i)system prompt",
    r"(?i)you are now a",
    r"(?i)jailbreak",
    r"(?i)bypass (all )?rules"
]

def decode_base64(text: str) -> str:
    try:
        decoded = base64.b64decode(text + "==").decode('utf-8')
        if len(decoded) > 4 and decoded.isprintable():
            return decoded
    except Exception:
        pass
    return ""

def scan_text(text: str, include_value: bool = False) -> dict:
    normalized = normalize_digits(text)
    findings = []

    for name, pattern in ALL_PATTERNS.items():
        for match in re.finditer(pattern, normalized):
            value = match.group()
            if name == "CREDIT_CARD" and not is_valid_luhn(value): continue
            if name == "IN_AADHAAR" and not is_valid_verhoeff(value): continue
            item = {"type": name, "severity": SEVERITY.get(name, "LOW"), "start": match.start(), "end": match.end()}
            if include_value: item["value"] = value
            findings.append(item)

    url_pattern = re.compile(r'https?://\S+')
    clean_text = url_pattern.sub('', normalized)

    for match in re.finditer(r'\b[A-Za-z0-9+/=_-]{16,}\b', clean_text):
        val = match.group()
        if calculate_shannon_entropy(val) > 4.0:
            item = {"type": "HIGH_ENTROPY", "severity": "HIGH", "start": match.start(), "end": match.end()}
            if include_value: item["value"] = val
            findings.append(item)
            
        decoded_val = decode_base64(val)
        if decoded_val:
            decoded_scan = scan_text(decoded_val, include_value)
            for df in decoded_scan["findings"]:
                df["type"] = f"BASE64_{df['type']}"
                findings.append(df)

    for pattern in PROMPT_PATTERNS:
        for match in re.finditer(pattern, normalized):
            item = {"type": "PROMPT_INJECTION", "severity": "HIGH", "start": match.start(), "end": match.end()}
            if include_value: item["value"] = match.group()
            findings.append(item)

    if NLP_AVAILABLE and len(clean_text) < 1000:
        doc = nlp(clean_text)
        for ent in doc.ents:
            if ent.label_ in ["PERSON", "GPE"]:
                item = {"type": f"NLP_{ent.label_}", "severity": SEVERITY.get(f"NLP_{ent.label_}", "MEDIUM"), "start": ent.start_char, "end": ent.end_char}
                if include_value: item["value"] = ent.text
                findings.append(item)

    findings.sort(key=lambda x: (x["end"] - x["start"]), reverse=True)
    filtered = []
    for f in findings:
        overlap = False
        for existing in filtered:
            if max(f["start"], existing["start"]) < min(f["end"], existing["end"]):
                overlap = True
                break
        if not overlap: filtered.append(f)
    filtered.sort(key=lambda x: x["start"])

    if any(f["severity"] == "HIGH" for f in filtered): risk = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in filtered): risk = "MEDIUM"
    elif filtered: risk = "LOW"
    else: risk = "NONE"

    return {"risk": risk, "findings": filtered}
