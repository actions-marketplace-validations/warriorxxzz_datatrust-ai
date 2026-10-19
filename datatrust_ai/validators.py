import math

def is_valid_luhn(card_number: str) -> bool:
    digits = [int(d) for d in str(card_number) if d.isdigit()]
    digits = digits[::-1]
    total = 0
    for i, digit in enumerate(digits):
        if i % 2 == 1:
            doubled = digit * 2
            total += doubled if doubled < 10 else doubled - 9
        else:
            total += digit
    return total % 10 == 0

def is_valid_verhoeff(aadhaar_number: str) -> bool:
    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],[1, 2, 3, 4, 0, 6, 7, 8, 9, 5],[2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],[4, 0, 1, 2, 3, 9, 5, 6, 7, 8],[5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],[7, 6, 5, 9, 8, 2, 1, 0, 4, 3],[8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],[1, 5, 7, 6, 2, 8, 3, 0, 9, 4],[5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],[9, 4, 5, 3, 1, 2, 6, 8, 7, 0],[4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],[7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]
    c = [int(x) for x in str(aadhaar_number) if x.isdigit()]
    c.reverse()
    check = 0
    for i, digit in enumerate(c):
        check = d[check][p[i % 8][digit]]
    return check == 0

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy
