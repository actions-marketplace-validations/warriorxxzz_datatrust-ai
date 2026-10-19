DEVANAGARI = "०१२३४५६७८९"
ARABIC_INDIC = "٠١٢٣٤٥٦٧٨٩"

_TRANSLATION = str.maketrans(
    DEVANAGARI + ARABIC_INDIC,
    "0123456789" * 2
)

def normalize_digits(text: str) -> str:
    """Convert Devanagari/Arabic-Indic digits to ASCII digits."""
    return text.translate(_TRANSLATION)
