# Mathematical validation algorithms

def is_valid_luhn(card_number: str) -> bool:
    """Validates a credit card number using the Luhn algorithm."""
    # Remove spaces and hyphens
    digits = [int(d) for d in str(card_number) if d.isdigit()]
    
    # Reverse the digits
    digits = digits[::-1]
    
    total = 0
    for i, digit in enumerate(digits):
        if i % 2 == 1: # Double every second digit
            doubled = digit * 2
            total += doubled if doubled < 10 else doubled - 9
        else:
            total += digit
            
    return total % 10 == 0

def is_valid_verhoeff(aadhaar_number: str) -> bool:
    """Validates an Aadhaar number using the Verhoeff algorithm."""
    # Verhoeff tables
    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

    # Clean the number
    c = [int(x) for x in str(aadhaar_number) if x.isdigit()]
    
    # Reverse and process
    c.reverse()
    check = 0
    for i, digit in enumerate(c):
        check = d[check][p[i % 8][digit]]
        
    return check == 0
