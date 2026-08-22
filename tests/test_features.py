import unittest

import features as feat


class TestValidateUrlInput(unittest.TestCase):
    def test_empty_input_invalid(self):
        ok, reason = feat.validate_url_input("")
        self.assertFalse(ok)

    def test_whitespace_only_invalid(self):
        ok, reason = feat.validate_url_input("   ")
        self.assertFalse(ok)

    def test_garbage_text_invalid(self):
        ok, reason = feat.validate_url_input("asdkjhaskjdh")
        self.assertFalse(ok)

    def test_url_with_space_invalid(self):
        ok, reason = feat.validate_url_input("https://exa mple.com")
        self.assertFalse(ok)

    def test_too_long_invalid(self):
        ok, reason = feat.validate_url_input("https://example.com/" + "a" * 3000)
        self.assertFalse(ok)

    def test_valid_https_url(self):
        ok, reason = feat.validate_url_input("https://example.com")
        self.assertTrue(ok)

    def test_valid_bare_domain(self):
        ok, reason = feat.validate_url_input("example.com")
        self.assertTrue(ok)

    def test_valid_ip_address(self):
        ok, reason = feat.validate_url_input("http://192.168.1.1/login")
        self.assertTrue(ok)

    def test_valid_subdomain(self):
        ok, reason = feat.validate_url_input("mail.google.com")
        self.assertTrue(ok)


class TestFeatureExtraction(unittest.TestCase):
    def test_feature_vector_length_matches_models(self):
        features = feat.extract_features("https://example.com")
        self.assertEqual(len(features), 18)
        self.assertEqual(len(features), len(feat.FEATURE_NAMES))

    def test_https_flag(self):
        f_https = feat.extract_features("https://example.com")
        f_http = feat.extract_features("http://example.com")
        self.assertEqual(f_https[7], 1)
        self.assertEqual(f_http[7], 0)

    def test_ip_address_flag(self):
        f_ip = feat.extract_features("http://192.168.1.1/login")
        f_domain = feat.extract_features("http://example.com")
        self.assertEqual(f_ip[8], 1)
        self.assertEqual(f_domain[8], 0)

    def test_suspicious_tld_flag(self):
        f_xyz = feat.extract_features("http://freestuff.xyz")
        f_com = feat.extract_features("http://freestuff.com")
        self.assertEqual(f_xyz[17], 1)
        self.assertEqual(f_com[17], 0)


class TestSuspiciousScore(unittest.TestCase):
    def test_clean_url_low_score(self):
        self.assertEqual(feat.suspicious_score("https://example.com"), 0)

    def test_multiple_indicators_raise_score(self):
        score = feat.suspicious_score("http://192.168.1.1/login/verify/secure/account.xyz")
        self.assertGreaterEqual(score, 3)


class TestImpersonation(unittest.TestCase):
    def test_flags_brand_without_real_domain(self):
        result = feat.detect_impersonation("http://paypal-login-secure.com")
        self.assertIsNotNone(result)
        self.assertIn("Paypal", result)

    def test_does_not_flag_real_domain(self):
        result = feat.detect_impersonation("https://www.paypal.com/signin")
        self.assertIsNone(result)

    def test_does_not_flag_unrelated_url(self):
        result = feat.detect_impersonation("https://example.com")
        self.assertIsNone(result)


class TestTrustedDomain(unittest.TestCase):
    def test_trusted_domain_true(self):
        self.assertTrue(feat.is_trusted_domain("https://www.google.com/search"))

    def test_subdomain_of_trusted_true(self):
        self.assertTrue(feat.is_trusted_domain("https://mail.google.com"))

    def test_untrusted_domain_false(self):
        self.assertFalse(feat.is_trusted_domain("https://totally-not-google.com"))


if __name__ == "__main__":
    unittest.main()
