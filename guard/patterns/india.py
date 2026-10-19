INDIA_PATTERNS = {
    # Aadhaar
    "IN_AADHAAR": r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b",
    
    # PAN
    "IN_PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    
    # IFSC Code
    "IN_IFSC": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    
    # UPI ID
    "IN_UPI": r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b",
    
    # Indian Mobile
    "IN_PHONE_MOBILE": r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b",
}
