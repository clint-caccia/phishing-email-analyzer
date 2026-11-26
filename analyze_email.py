#!/usr/bin/env python3
"""Analyze one or more .eml files for phishing indicators.

Examples:
    python analyze_email.py samples/
    python analyze_email.py suspicious.eml --json results.json --iocs iocs.csv
"""

import argparse
import glob
import os
import sys

from phish_analyzer.checks import run_checks
from phish_analyzer.parse import parse_eml
from phish_analyzer.report import text_report, to_dict, write_iocs_csv, write_json


def collect(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.eml"))))
        else:
            files.append(p)
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description="Score .eml files for phishing red flags.")
    parser.add_argument("paths", nargs="+", help=".eml files or folders of them")
    parser.add_argument("--json", help="write full results to this JSON file")
    parser.add_argument("--iocs", help="write extracted indicators to this CSV file")
    args = parser.parse_args(argv)

    files = collect(args.paths)
    if not files:
        print("No .eml files found.", file=sys.stderr)
        return 1

    results = []
    for path in files:
        try:
            email = parse_eml(path)
        except (OSError, ValueError) as err:
            print(f"Skipping {path}: {err}", file=sys.stderr)
            continue
        findings = run_checks(email)
        print(text_report(path, email, findings))
        print()
        results.append(to_dict(path, email, findings))

    print("=" * 64)
    print("SUMMARY")
    for r in sorted(results, key=lambda r: -r["score"]):
        print(f"  {r['score']:>3}  {r['verdict']:<16} {os.path.basename(r['file'])}")

    if args.json:
        write_json(results, args.json)
        print(f"\nWrote results to {args.json}")
    if args.iocs:
        write_iocs_csv(results, args.iocs)
        print(f"Wrote indicators to {args.iocs}")

    return 2 if any(r["verdict"] == "LIKELY PHISHING" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
