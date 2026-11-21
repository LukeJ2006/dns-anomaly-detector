import unittest

from detector import clean, rule_high_entropy, rule_long_names, shannon_entropy


class TestEntropy(unittest.TestCase):
    def test_repeated_letter_scores_zero(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_empty_string_scores_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_normal_word_scores_low(self):
        self.assertAlmostEqual(shannon_entropy("google"), 1.92, places=2)

    def test_random_string_scores_high(self):
        self.assertGreater(shannon_entropy("x7kq9zp2mw4t"), 3.5)


class TestRules(unittest.TestCase):
    def test_clean_strips_trailing_dot(self):
        self.assertEqual(clean(b"www.google.com."), "www.google.com")

    def test_long_name_is_flagged(self):
        long_domain = "a" * 60 + ".example.com"
        findings = rule_long_names([long_domain, "google.com"], 50)
        self.assertEqual([f["domain"] for f in findings], [long_domain])

    def test_random_label_is_flagged(self):
        findings = rule_high_entropy(["x7kq9zp2mw4t.test", "www.google.com"], 3.5)
        self.assertEqual([f["domain"] for f in findings], ["x7kq9zp2mw4t.test"])


if __name__ == "__main__":
    unittest.main()