import sys
from datatrust_ai.detector import scan_text

FRIENDLY_NAMES = {
    "NP_CITIZENSHIP": "Nepal Citizenship Number",
    "NP_NID": "National ID (NID)",
    "NP_PAN": "Nepal PAN Number",
    "NP_PASSPORT": "Nepal Passport Number",
    "NP_PHONE_MOBILE": "Nepal Mobile Number",
    "NP_PHONE_LANDLINE": "Nepal Landline Number",
    "IN_AADHAAR": "India Aadhaar Number",
    "IN_PAN": "India PAN Card",
    "IN_UPI": "India UPI ID",
    "IN_IFSC": "India IFSC Code",
    "IN_PHONE_MOBILE": "India Mobile Number",
    "CREDIT_CARD": "Credit Card Number",
    "EMAIL": "Email Address",
    "IPV4": "IP Address"
}

def print_result(text: str):
    result = scan_text(text)
    risk = result["risk"]
    findings = result["findings"]
    
    print("\n" + "="*45)
    
    if risk == "NONE":
        print("✅ Looks Safe!")
        print("No personal information was found.")
        print("="*45 + "\n")
        return
        
    print("🛑 WARNING: Personal Info Detected!")
    print("="*45)
    print("It looks like you are about to share:\n")
    
    detected_types = set()
    for item in findings:
        friendly_name = FRIENDLY_NAMES.get(item['type'], item['type'])
        detected_types.add(friendly_name)
        
    for info in detected_types:
        print(f"  🔴 {info}")
        
    print("\n⚠️  Please be careful! Once you send this, ")
    print("    the AI will remember it. We recommend ")
    print("    removing these details before sending.")
    print("="*45 + "\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: datatrust \"Your text here\"")
        print("Example: datatrust \"My phone is 9841234567\"")
        return
        
    text = " ".join(sys.argv[1:])
    print_result(text)

if __name__ == "__main__":
    main()
