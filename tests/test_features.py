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

    def test_userinfo_at_host_url_is_valid_not_rejected(self):
        """Regression test for a real bug found via testing: a URL using
        the classic 'trusted-looking@actual-host' obfuscation trick
        (valid syntax per RFC 3986's userinfo component) was being
        rejected outright as 'invalid input' because the hostname-shape
        regex doesn't allow '@' -- silently discarding a genuine
        phishing indicator instead of flagging it. The real host (after
        the @) must still look like a real hostname; the URL itself must
        not be thrown out."""
        ok, reason = feat.validate_url_input("https://user@malicious-payments.tk/login")
        self.assertTrue(ok, reason)

    def test_userinfo_at_host_with_invalid_real_host_still_rejected(self):
        """The fix must not become a blanket bypass -- if the ACTUAL host
        (after the @) doesn't look like a real hostname (here: no dot at
        all), it's still correctly rejected."""
        ok, reason = feat.validate_url_input("https://user@localhost")
        self.assertFalse(ok)


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

    def test_at_symbol_in_host_raises_score(self):
        """Regression test: '@' in the host is a real, explainable
        phishing indicator (the classic userinfo-obfuscation trick) --
        it must contribute to the score, not just silently exist as an
        unexplained raw ML feature."""
        self.assertGreater(
            feat.suspicious_score("https://user@malicious-payments.tk/login"),
            feat.suspicious_score("https://malicious-payments.tk/login"),
        )

    def test_at_symbol_explained_in_indicators(self):
        indicators = feat.explain_indicators("https://user@malicious-payments.tk/login")
        self.assertTrue(any("@" in i for i in indicators))


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

    def test_flags_real_domain_embedded_as_decoy_prefix(self):
        """Regression test for a real bypass found via testing: a classic
        phishing pattern embeds the real brand domain as a decoy prefix
        before the actual (unrelated) domain -- e.g.
        www.paypal.com.security-check-update.info is NOT paypal.com, it's
        security-check-update.info. The old substring check against the
        whole URL missed this because "paypal.com" is literally present
        somewhere in the string, even though it isn't the actual domain."""
        result = feat.detect_impersonation("https://www.paypal.com.security-check-update.info/signin")
        self.assertIsNotNone(result)
        self.assertIn("Paypal", result)


class TestTrustedDomain(unittest.TestCase):
    def test_trusted_domain_true(self):
        self.assertTrue(feat.is_trusted_domain("https://www.google.com/search"))

    def test_subdomain_of_trusted_true(self):
        self.assertTrue(feat.is_trusted_domain("https://mail.google.com"))

    def test_untrusted_domain_false(self):
        self.assertFalse(feat.is_trusted_domain("https://totally-not-google.com"))

    def test_user_content_hosting_subdomain_not_trusted(self):
        """Regression test for a real false negative found via testing:
        sites.google.com is Google's free, open user-content publishing
        platform -- anyone can host a page there, including phishing
        pages -- yet it technically ends with '.google.com' and was
        being blanket-trusted. Unlike Google's own first-party services
        (mail/docs/drive/accounts.google.com), it must not inherit trust."""
        self.assertFalse(feat.is_trusted_domain("https://sites.google.com/site/anything/"))

    def test_other_first_party_google_subdomains_still_trusted(self):
        """The exclusion must be narrow -- it should not accidentally
        strip trust from Google's own legitimate services."""
        for sub in ("docs.google.com", "drive.google.com", "accounts.google.com"):
            with self.subTest(sub=sub):
                self.assertTrue(feat.is_trusted_domain(f"https://{sub}/"))


if __name__ == "__main__":
    unittest.main()
