import unittest
from unittest.mock import patch, MagicMock

import model_utils as mu


class TestModelLoading(unittest.TestCase):
    def test_real_models_load_successfully(self):
        """These are the actual model.pkl / nn_model.pkl shipped in this
        repo -- a real load, not a mock."""
        models = mu.load_models()
        self.assertTrue(models.available, f"Models failed to load: {models.load_error}")
        self.assertIsNone(models.load_error)

    def test_missing_model_file_reported_honestly(self):
        with patch("model_utils.MODEL_PATH", "/nonexistent/model.pkl"):
            models = mu.load_models()
        self.assertFalse(models.available)
        self.assertIn("not found", models.load_error.lower())

    def test_corrupted_model_file_reported_honestly(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"not a real pickle file")
            path = f.name
        try:
            with patch("model_utils.MODEL_PATH", path):
                models = mu.load_models()
            self.assertFalse(models.available)
            self.assertIsNotNone(models.load_error)
        finally:
            os.unlink(path)


class TestScanUrlPipeline(unittest.TestCase):
    def setUp(self):
        self.models = mu.load_models()
        self.assertTrue(self.models.available, "Real models must load for these tests")

    def test_invalid_input_never_reaches_model(self):
        result = mu.scan_url("not a url at all !!", self.models)
        self.assertEqual(result.status, mu.STATUS_INVALID_INPUT)
        self.assertIsNone(result.label)

    def test_empty_input_invalid(self):
        result = mu.scan_url("", self.models)
        self.assertEqual(result.status, mu.STATUS_INVALID_INPUT)

    def test_known_safe_domain(self):
        result = mu.scan_url("https://www.google.com", self.models)
        self.assertEqual(result.status, mu.STATUS_OK)
        self.assertEqual(result.label, mu.LABEL_SAFE)

    def test_impersonation_detected_without_needing_models(self):
        result = mu.scan_url("http://paypal-login-secure-verify.com", self.models)
        self.assertEqual(result.status, mu.STATUS_OK)
        self.assertEqual(result.label, mu.LABEL_IMPERSONATING)
        self.assertIsNotNone(result.impersonation_notice)

    def test_ip_based_suspicious_url_is_phish_or_flagged(self):
        result = mu.scan_url("http://192.168.5.5/login/verify/secure/account.xyz", self.models)
        self.assertEqual(result.status, mu.STATUS_OK)
        # Heavily-loaded suspicious URL should not be reported Safe.
        self.assertIn(result.label, (mu.LABEL_PHISH, mu.LABEL_IMPERSONATING))

    def test_result_status_never_ok_with_none_label(self):
        result = mu.scan_url("https://example.com", self.models)
        if result.status == mu.STATUS_OK:
            self.assertIsNotNone(result.label)

    def test_models_unavailable_degrades_gracefully_not_safe_by_default(self):
        empty = mu.ModelBundle(load_error="simulated failure")
        # A heavily suspicious URL must not become "Safe" just because
        # the ML layer is down.
        result = mu.scan_url("http://192.168.5.5/login/verify/secure/account.xyz", empty)
        self.assertEqual(result.status, mu.STATUS_MODELS_UNAVAILABLE)
        self.assertTrue(result.heuristic_only)
        self.assertEqual(result.label, mu.LABEL_PHISH)

    def test_models_unavailable_clean_url_reports_safe_but_labeled_heuristic(self):
        empty = mu.ModelBundle(load_error="simulated failure")
        result = mu.scan_url("https://example.com", empty)
        self.assertEqual(result.status, mu.STATUS_MODELS_UNAVAILABLE)
        self.assertTrue(result.heuristic_only)
        self.assertEqual(result.label, mu.LABEL_SAFE)

    def test_model_scoring_exception_is_analysis_failed_not_safe(self):
        broken_gb = MagicMock()
        broken_gb.predict_proba.side_effect = RuntimeError("simulated model crash")
        broken_models = mu.ModelBundle(
            gb_model=broken_gb, nn_model=self.models.nn_model, scaler=self.models.scaler,
        )
        result = mu.scan_url("https://example.com", broken_models)
        self.assertEqual(result.status, mu.STATUS_ANALYSIS_FAILED)
        self.assertIsNone(result.label)


class TestModelSubdomainBiasRegression(unittest.TestCase):
    """Regression tests for a real, severe false-positive bug found via
    direct empirical testing (not assumed from reading the code): the
    trained models had learned that a bare apex domain (no subdomain --
    e.g. github.com, stackoverflow.com, reddit.com) was an almost-perfect
    predictor of phishing, purely because 99.9% of the "legitimate"
    examples in the training data had a subdomain (nearly all formatted
    as https://www.X.com) versus only ~45% of phishing examples --
    confirmed directly by measuring the training data's own subdomain
    distribution. This flipped genuinely benign, extremely common
    real-world URLs to "Phish" with 90%+ model confidence, from BOTH the
    gradient boosting and neural net components independently. Fixed by
    retraining on a rebalanced dataset (same class counts, same labels --
    a random 55% of legitimate examples that had a subdomain were
    rewritten to bare-apex-domain form, breaking the spurious
    correlation) -- not a scoring-pipeline patch, since the bias lived in
    the trained models themselves."""

    def setUp(self):
        self.models = mu.load_models()
        self.assertTrue(self.models.available, self.models.load_error)

    def test_bare_apex_domain_legitimate_sites_are_safe(self):
        """These are real, well-known, entirely benign sites that
        deliberately don't use a 'www.' subdomain -- all were previously
        misclassified as Phish with 90%+ confidence."""
        bare_domain_sites = [
            "https://github.com/torvalds/linux",
            "https://stackoverflow.com/questions/tagged/python",
            "https://reddit.com/r/programming",
            "https://news.ycombinator.com",
        ]
        for url in bare_domain_sites:
            with self.subTest(url=url):
                result = mu.scan_url(url, self.models)
                self.assertEqual(result.label, mu.LABEL_SAFE, f"{url} still misclassified")

    def test_bare_apex_domain_does_not_mask_genuine_phishing(self):
        """The fix must not have overcorrected -- a bare apex domain
        that actually IS suspicious (IP address, phishing keywords, or a
        suspicious TLD) must still be flagged, with or without a
        subdomain present."""
        suspicious_bare = [
            "https://192.168.1.1/login/verify-account",
            "https://amaz0n-account-update.ml/secure/verify",
        ]
        for url in suspicious_bare:
            with self.subTest(url=url):
                result = mu.scan_url(url, self.models)
                self.assertIn(result.label, (mu.LABEL_PHISH, mu.LABEL_IMPERSONATING))

    def test_adding_an_arbitrary_subdomain_no_longer_flips_the_verdict(self):
        """Direct proof the bias is gone: previously, ANY subdomain at
        all (not specifically 'www') flipped a bare-domain site's score
        from ~0.92 to ~0.01. Both forms of the same legitimate site must
        now agree."""
        bare = mu.scan_url("https://github.com/torvalds/linux", self.models)
        with_sub = mu.scan_url("https://app.github.com/torvalds/linux", self.models)
        self.assertEqual(bare.label, with_sub.label)
        self.assertEqual(bare.label, mu.LABEL_SAFE)


class TestHttpSchemeRegression(unittest.TestCase):
    """Regression tests for the reported bug: https://testphp.vulnweb.com/
    and http://testphp.vulnweb.com/ -- the SAME site, differing only in
    scheme -- were classified Safe and Phish respectively. Traced to a
    training-data bias (99.99% of legitimate examples used HTTPS versus
    only 6.2% of phishing examples, confirmed by directly measuring
    data/url_dataset.csv), which made is_https alone a ~94%-accurate
    predictor in training; flipping ONLY the scheme swung the hybrid
    score from ~0.01 to ~0.99. Fixed by retraining on a rebalanced
    dataset (same row counts, same class balance -- legitimate examples'
    HTTPS rate reduced to ~90%, phishing examples' raised to ~20%) plus
    adding a genuine three-tier classification (Safe/Suspicious/Phish)
    so a URL with weak, ambiguous evidence resolves honestly rather than
    being forced into a confident guess."""

    def setUp(self):
        self.models = mu.load_models()
        self.assertTrue(self.models.available, self.models.load_error)

    def test_vulnerable_test_site_never_confidently_labeled_phish(self):
        """A deliberately-vulnerable security-testing site is not a
        phishing site -- neither scheme variant should produce a
        confident 'Phish' verdict from URL structure alone."""
        for url in ("https://testphp.vulnweb.com/", "http://testphp.vulnweb.com/"):
            with self.subTest(url=url):
                result = mu.scan_url(url, self.models)
                self.assertNotEqual(result.label, mu.LABEL_PHISH)

    def test_scheme_alone_no_longer_causes_an_extreme_score_swing(self):
        """Direct proof the bias is substantially reduced: the SAME
        hostname/path scored ~0.01 (https) vs ~0.99 (http) before the
        fix -- a ~0.98 swing from one bit. It must now be far smaller."""
        https_result = mu.scan_url("https://testphp.vulnweb.com/", self.models)
        http_result = mu.scan_url("http://testphp.vulnweb.com/", self.models)
        swing = abs(https_result.hybrid_score - http_result.hybrid_score)
        self.assertLess(swing, 0.6, f"Scheme alone still swings the score by {swing:.3f}")

    def test_missing_https_produces_a_separate_security_note_not_phishing_evidence(self):
        result = mu.scan_url("http://testphp.vulnweb.com/", self.models)
        self.assertIsNotNone(result.security_note)
        self.assertIn("not encrypted", result.security_note.lower())

    def test_https_produces_no_security_note(self):
        result = mu.scan_url("https://testphp.vulnweb.com/", self.models)
        self.assertIsNone(result.security_note)

    def test_ambiguous_url_resolves_to_suspicious_not_a_forced_binary_guess(self):
        """The core design fix: genuinely ambiguous evidence must not be
        forced into a confident Safe or Phish guess."""
        result = mu.scan_url("http://testphp.vulnweb.com/", self.models)
        self.assertEqual(result.label, mu.LABEL_SUSPICIOUS)

    def test_genuinely_suspicious_http_url_still_reaches_phish(self):
        """The fix must not make HTTP URLs blanket-safe -- genuine red
        flags (IP address, phishing keywords) must still reach Phish
        regardless of scheme."""
        result = mu.scan_url("http://192.168.1.1/login/verify-account", self.models)
        self.assertEqual(result.label, mu.LABEL_PHISH)


class TestExplanationSystem(unittest.TestCase):
    """Regression tests for a real audit finding: the Streamlit UI's
    "Why this result?" section was still calling the old flat
    feat.explain_indicators() -- a simple list of every rule that
    happened to fire, with no regard for whether that signal was
    actually decisive -- even though a much better, tiered,
    classification-aware mu.build_explanation() already existed
    elsewhere in the codebase and was never wired in. A bare 'login'
    keyword was being shown as if it were meaningful evidence, for every
    classification including Safe. Fixed by wiring build_explanation()
    into app.py and adding this dedicated coverage, since nothing
    exercised it before."""

    def setUp(self):
        self.models = mu.load_models()
        self.assertTrue(self.models.available, self.models.load_error)

    def test_impersonation_explanation_matches_the_specific_brand_and_domain(self):
        """The exact worked example from the audit report."""
        result = mu.scan_url("https://google-login.com", self.models)
        self.assertEqual(result.label, mu.LABEL_IMPERSONATING)
        exp = mu.build_explanation(result)
        self.assertEqual(len(exp.strong), 2)
        self.assertTrue(any("Google" in s and "brand name" in s for s in exp.strong))
        self.assertTrue(any("google.com" in s for s in exp.strong))
        self.assertTrue(any("login" in s.lower() for s in exp.supporting))
        self.assertIn("Google", exp.summary)

    def test_legitimate_login_url_never_shows_login_keyword_as_reasoning(self):
        """The core principle: a login keyword on a genuinely trusted
        domain must never appear as if it were suspicious evidence."""
        result = mu.scan_url("https://accounts.google.com/login", self.models)
        self.assertEqual(result.label, mu.LABEL_SAFE)
        exp = mu.build_explanation(result)
        self.assertEqual(exp.strong, [])
        self.assertEqual(exp.supporting, [])
        self.assertIn("known, established", exp.summary)

    def test_clean_safe_url_has_no_fabricated_indicators(self):
        result = mu.scan_url("https://www.google.com/", self.models)
        exp = mu.build_explanation(result)
        self.assertEqual(exp.strong, [])
        self.assertEqual(exp.supporting, [])

    def test_ip_based_phish_shows_ip_as_the_strong_indicator_not_keywords(self):
        result = mu.scan_url("http://192.168.1.1/login/verify-account", self.models)
        self.assertEqual(result.label, mu.LABEL_PHISH)
        exp = mu.build_explanation(result)
        self.assertEqual(len(exp.strong), 1)
        self.assertIn("IP address", exp.strong[0])
        # Keywords are real evidence too, but demoted to supporting --
        # never presented as if they alone justified the verdict.
        self.assertTrue(len(exp.supporting) >= 1)

    def test_combination_only_phish_is_honestly_labeled_as_a_combination(self):
        """Regression test for the task's core principle: when NO single
        rule is independently decisive, the explanation must say so
        honestly -- never present one of the several weak, contributing
        keywords as if it alone were the reason."""
        result = mu.scan_url(
            "https://accounts.login.verify.update.secure.example-payments.tk/", self.models,
        )
        self.assertEqual(result.label, mu.LABEL_PHISH)
        exp = mu.build_explanation(result)
        self.assertEqual(len(exp.strong), 1)
        self.assertIn("combination", exp.strong[0].lower())
        self.assertNotIn("login", exp.strong[0].lower())

    def test_pure_model_score_phish_does_not_fabricate_a_specific_rule(self):
        """Direct unit test of the honesty-preserving branch: when the
        classification comes purely from the trained model's own
        assessment (no explicit rule fired), the explanation must say
        exactly that -- never invent a specific-sounding reason that
        didn't actually drive the verdict."""
        fake_result = mu.ScanResult(
            status=mu.STATUS_OK, url="https://some-weird-structure-example.com/",
            label=mu.LABEL_PHISH, indicator_score=0, trusted_domain=False,
            hybrid_score=0.91, is_https=True,
        )
        exp = mu.build_explanation(fake_result)
        self.assertEqual(len(exp.strong), 1)
        self.assertIn("91%", exp.strong[0])
        self.assertIn("model", exp.summary.lower())

    def test_suspicious_explanation_communicates_ambiguity_not_certainty(self):
        result = mu.scan_url("http://testphp.vulnweb.com/", self.models)
        self.assertEqual(result.label, mu.LABEL_SUSPICIOUS)
        exp = mu.build_explanation(result)
        self.assertEqual(exp.strong, [])
        self.assertTrue(
            "not clearly" in exp.summary.lower() or "inconclusive" in exp.summary.lower()
            or "does not clearly" in exp.summary.lower()
        )

    def test_no_raw_model_internals_ever_appear_in_any_explanation_text(self):
        """Requirement: never expose feature indices, model names, or
        implementation details -- only meaningful security language."""
        urls = [
            "https://google-login.com", "https://accounts.google.com/login",
            "https://www.google.com/", "http://testphp.vulnweb.com/",
            "https://testphp.vulnweb.com/", "http://192.168.1.1/login/verify-account",
        ]
        banned_substrings = ("feature_", "gb_model", "nn_model", "RandomForest",
                              "GradientBoosting", "MLPClassifier", "predict_proba")
        for url in urls:
            result = mu.scan_url(url, self.models)
            exp = mu.build_explanation(result)
            all_text = " ".join(exp.strong + exp.supporting + exp.informational + [exp.summary])
            for banned in banned_substrings:
                self.assertNotIn(banned, all_text, f"{url}: leaked internal detail '{banned}'")


if __name__ == "__main__":
    unittest.main()
