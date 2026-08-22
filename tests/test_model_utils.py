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


if __name__ == "__main__":
    unittest.main()
