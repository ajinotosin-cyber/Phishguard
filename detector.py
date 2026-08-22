"""
detector.py
-----------
Standalone terminal CLI for PhishGuard, kept as a genuinely useful
alternative to the Streamlit UI for quick command-line scans. Uses the
same shared features.py / model_utils.py pipeline as app.py, so results
are identical between the CLI and the web app -- no separate, drifting
copy of the feature-extraction or scoring logic.

Run with:
    python detector.py

Previously this script duplicated the entire feature-extraction function
and loaded the models at MODULE level with an unguarded interactive input()
loop -- meaning simply `import detector` (e.g. to reuse a helper function)
would hang the importing process waiting on stdin. That's fixed: importing
this module now does nothing except define functions; the interactive
loop only runs when the script is executed directly.
"""

from __future__ import annotations

import model_utils as mu


def format_result(result: mu.ScanResult) -> str:
    lines = ["", "================ RESULT ================"]

    if result.status == mu.STATUS_INVALID_INPUT:
        lines.append(f"Invalid input: {result.error_message}")
        return "\n".join(lines)

    if result.status == mu.STATUS_ANALYSIS_FAILED:
        lines.append(f"Analysis failed: {result.error_message}")
        return "\n".join(lines)

    lines.append(f"URL        : {result.url}")
    lines.append(f"Prediction : {result.label}")
    if result.heuristic_only:
        lines.append("Note       : heuristics-only mode (ML models unavailable)")
    if result.impersonation_notice:
        lines.append(f"Note       : {result.impersonation_notice}")
    lines.append(f"Indicator score: {result.indicator_score}")

    import features as feat
    indicators = feat.explain_indicators(result.url)
    lines.append("\nIndicators:")
    if indicators:
        for item in indicators:
            lines.append(f" • {item}")
    else:
        lines.append(" • No major phishing indicators detected.")

    lines.append("=" * 40)
    return "\n".join(lines)


def run_cli():
    models = mu.load_models()

    print("=" * 60)
    print("      PHISHGUARD HYBRID PHISHING DETECTOR")
    print("=" * 60)
    if not models.available:
        print(f"\n⚠️  ML models unavailable ({models.load_error}).")
        print("    Running in heuristics-only mode.\n")

    while True:
        raw = input("\nEnter URL (or type 'exit'): ").strip()
        if raw.lower() == "exit":
            print("\nThank you for using PhishGuard.")
            break

        result = mu.scan_url(raw, models)
        print(format_result(result))


if __name__ == "__main__":
    run_cli()
