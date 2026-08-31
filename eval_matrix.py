"""
Comprehensive evaluation matrix for the PhishGuard audit. Not part of
the permanent pytest suite (see tests/test_model_utils.py's
TestModelSubdomainBiasRegression / TestHttpSchemeRegression for the
permanent regression tests) -- this is the one-off diagnostic run
requested to produce a full URL / expected / predicted / pass-fail
table across legitimate, security-testing, phishing-like, and
malformed URLs.
"""
import model_utils as mu
import features as feat

models = mu.load_models()

# (url, expected_labels (any of these counts as pass), category)
CASES = [
    # ---- LEGITIMATE ----
    ("https://www.google.com/", ("Safe",), "Legitimate"),
    ("https://www.microsoft.com/", ("Safe",), "Legitimate"),
    ("https://www.apple.com/", ("Safe",), "Legitimate"),
    ("https://www.github.com/", ("Safe",), "Legitimate"),
    ("https://www.wikipedia.org/", ("Safe",), "Legitimate"),
    ("https://example.com/", ("Safe", "Suspicious"), "Legitimate"),
    ("http://neverssl.com/", ("Safe", "Suspicious"), "Legitimate HTTP"),
    ("https://docs.python.org/3/library/re.html", ("Safe",), "Legitimate, long path"),
    ("https://en.wikipedia.org/wiki/Phishing?action=history", ("Safe",), "Legitimate, query params"),
    ("https://shop.example-store.com/product/12345-blue-widget", ("Safe", "Suspicious"), "Legitimate, hyphens+digits"),

    # ---- SECURITY / TESTING (the core reported bug) ----
    ("https://testphp.vulnweb.com/", ("Safe", "Suspicious"), "Vulnerable-but-legitimate test site"),
    ("http://testphp.vulnweb.com/", ("Safe", "Suspicious"), "Vulnerable-but-legitimate test site"),

    # ---- PHISHING-LIKE ----
    ("http://192.168.1.1/login/verify-account", ("Phish", "Suspicious"), "IP-based hostname"),
    ("http://198.51.100.24/secure/login.php?verify=1", ("Phish", "Suspicious"), "IP-based hostname"),
    ("https://paypal-secure-login-verify.xyz/account/update", ("Phish", "Impersonating"), "Suspicious TLD + keywords"),
    ("https://amaz0n-account-update.ml/secure/verify", ("Phish", "Impersonating"), "Suspicious TLD + keywords"),
    ("https://accounts.login.verify.update.secure.example-payments.tk/", ("Phish", "Suspicious"), "Excessive subdomains"),
    ("http://secure-paypal.com.verify-account.ga/login", ("Phish", "Impersonating"), "Deceptive domain"),
    ("https://www.paypal.com.security-check-update.info/signin", ("Phish", "Impersonating"), "Brand impersonation pattern"),
    ("http://apple.com-signin-verify.cf/account", ("Phish", "Impersonating"), "Brand impersonation pattern"),
    ("https://user@malicious-payments.tk/login", ("Phish", "Suspicious"), "@ symbol obfuscation"),
    ("https://bit.ly-account-verify.tk/secure/login?redirect=update", ("Phish", "Suspicious"), "Shortener-lookalike + keywords"),
    ("https://facebook-login-secure.xyz/account/verify/update", ("Phish", "Impersonating"), "Brand impersonation pattern"),

    # ---- MALFORMED / INVALID ----
    ("not a url at all", None, "Malformed"),
    ("http://", None, "Malformed"),
    ("   ", None, "Malformed"),
    ("", None, "Malformed"),
    ("https://" + "a" * 3000, None, "Malformed (too long)"),
]

print(f"{'URL':<70} {'Expected':<28} {'Predicted':<14} {'Pass':<6} Indicators")
print("=" * 160)

results = []
for url, expected, category in CASES:
    r = mu.scan_url(url, models)
    if expected is None:
        passed = r.status == mu.STATUS_INVALID_INPUT
        predicted = f"[{r.status}]"
    else:
        passed = r.label in expected
        predicted = r.label

    indicators = feat.explain_indicators(url) if expected is not None else []
    ind_str = "; ".join(indicators) if indicators else "(none)"
    exp_str = "/".join(expected) if expected else "INVALID_INPUT"
    pred_str = str(predicted) if predicted is not None else "(no label)"

    results.append((url, category, exp_str, pred_str, passed, ind_str,
                     getattr(r, "hybrid_score", None), getattr(r, "indicator_score", None)))
    print(f"{url[:68]:<70} {exp_str:<28} {pred_str:<14} {'PASS' if passed else 'FAIL':<6} {ind_str}")

print()
total = len(results)
passed_count = sum(1 for r in results if r[4])
print(f"TOTAL: {passed_count}/{total} passed")
print()
print("FAILURES:")
for r in results:
    if not r[4]:
        print(f"  {r[0]}  (category={r[1]}, expected={r[2]}, got={r[3]}, hybrid={r[6]}, indicator_score={r[7]})")
