import unittest
from datatrust_ai.detector import scan_text

class TestDataTrustDetector(unittest.TestCase):

    def test_nepal_citizenship(self):
        text = "Mero citizenship 12-01-78-12345 cha"
        result = scan_text(text)
        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["findings"][0]["type"], "NP_CITIZENSHIP")

    def test_devanagari_support(self):
        text = "मेरो नागरिकता १२-०१-७८-१२३४५ छ"
        result = scan_text(text)
        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["findings"][0]["type"], "NP_CITIZENSHIP")

    def test_valid_credit_card(self):
        # This passes the Luhn algorithm
        text = "My card is 4532 0151 1283 0366"
        result = scan_text(text)
        self.assertEqual(result["risk"], "HIGH")
        self.assertEqual(result["findings"][0]["type"], "CREDIT_CARD")

    def test_fake_credit_card(self):
        # This fails the Luhn algorithm
        text = "My card is 1234 5678 9012 3456"
        result = scan_text(text)
        self.assertEqual(result["risk"], "NONE")
        self.assertEqual(len(result["findings"]), 0)

    def test_safe_text(self):
        text = "Hello, how are you doing today?"
        result = scan_text(text)
        self.assertEqual(result["risk"], "NONE")

if __name__ == "__main__":
    unittest.main()
