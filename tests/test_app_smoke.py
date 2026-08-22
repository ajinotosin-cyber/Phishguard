"""
End-to-end smoke test using Streamlit's official AppTest harness. Drives
app.py itself, not just the underlying modules.
"""
import os
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

import model_utils as mu

APP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


class TestAppSmoke(unittest.TestCase):
    def test_app_boots_with_real_models(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        self.assertFalse(at.exception, f"App raised on default load: {at.exception}")

    def test_scan_safe_url_end_to_end(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.text_input[0].set_value("https://www.google.com")
        at.button[0].click().run(timeout=30)
        self.assertFalse(at.exception)
        body = " ".join(m.value for m in at.markdown)
        self.assertIn("Safe Website", body)

    def test_scan_phishing_like_url_end_to_end(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.text_input[0].set_value("http://192.168.5.5/login/verify/secure/account.xyz")
        at.button[0].click().run(timeout=30)
        self.assertFalse(at.exception)
        body = " ".join(m.value for m in at.markdown)
        self.assertIn("Phishing Website", body)

    def test_scan_impersonation_url_end_to_end(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.text_input[0].set_value("http://paypal-login-secure-verify.com")
        at.button[0].click().run(timeout=30)
        self.assertFalse(at.exception)
        body = " ".join(m.value for m in at.markdown)
        self.assertIn("Impersonation Website", body)

    def test_invalid_input_shows_invalid_state_not_a_verdict(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.text_input[0].set_value("not a url !!")
        at.button[0].click().run(timeout=30)
        self.assertFalse(at.exception)
        body = " ".join(m.value for m in at.markdown)
        self.assertIn("Invalid Input", body)
        self.assertNotIn("Safe Website", body)
        self.assertNotIn("Phishing Website", body)

    def test_empty_input_shows_warning(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.button[0].click().run(timeout=30)
        self.assertFalse(at.exception)
        self.assertTrue(len(at.warning) >= 1)

    def test_models_unavailable_does_not_crash_and_is_labeled(self):
        broken_bundle = mu.ModelBundle(load_error="simulated missing model files")
        with patch("model_utils.load_models", return_value=broken_bundle):
            at = AppTest.from_file(APP_PATH)
            at.run(timeout=30)
            self.assertFalse(at.exception, f"App crashed with models unavailable: {at.exception}")
            warnings = " ".join(w.value for w in at.warning)
            self.assertIn("unavailable", warnings.lower())

            at.text_input[0].set_value("https://www.google.com")
            at.button[0].click().run(timeout=30)
            self.assertFalse(at.exception)


if __name__ == "__main__":
    unittest.main()
