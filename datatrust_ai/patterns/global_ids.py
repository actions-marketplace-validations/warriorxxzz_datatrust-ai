GLOBAL_PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]?){13,19}\b",
    "IPV4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "AWS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
    "OPENAI_KEY": r"\bsk-[a-zA-Z0-9]{20,}\b",
    "GITHUB_PAT": r"\bghp_[a-zA-Z0-9]{36}\b",
    "GOOGLE_API": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
}
