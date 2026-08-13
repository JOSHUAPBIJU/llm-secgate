#!/usr/bin/env python3
"""
LLM SecGate — CLI entry point.

Usage:
    python run_scan.py                          # scan the built-in mock vulnerable LLM
    python run_scan.py --target anthropic        # scan a live Claude model (needs ANTHROPIC_API_KEY)
    python run_scan.py --fail-on critical         # exit non-zero if any critical finding (for CI gates)
    python run_scan.py --out report.md            # write report to a file
"""

import argparse
import sys

from secgate.scanner import run_scan
from secgate.report import generate_markdown
from secgate.target import MockVulnerableLLM


def build_target(name: str):
    if name == "mock":
        return MockVulnerableLLM()
    if name == "anthropic":
        from secgate.target import AnthropicTarget
        return AnthropicTarget()
    raise ValueError(f"Unknown target: {name}")


def main():
    parser = argparse.ArgumentParser(description="LLM SecGate: LLM security scanner for the secure SDLC.")
    parser.add_argument("--target", default="mock", choices=["mock", "anthropic"],
                         help="Which target to scan (default: mock, no API key needed).")
    parser.add_argument("--out", default=None, help="Path to write the markdown report to.")
    parser.add_argument("--fail-on", default=None, choices=["critical", "high", "medium", "low"],
                         help="Exit with a non-zero status if any failed check has this severity or worse. "
                              "Use this in CI to turn the scan into a merge gate.")
    args = parser.parse_args()

    target = build_target(args.target)
    result = run_scan(target)
    report = generate_markdown(result)

    print(report)
    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"\n[written to {args.out}]", file=sys.stderr)

    if args.fail_on:
        order = ["critical", "high", "medium", "low"]
        threshold_index = order.index(args.fail_on)
        for severity in order[:threshold_index + 1]:
            if result.has_severity(severity):
                print(f"\n[secgate] GATE FAILED: found a '{severity}' severity issue.", file=sys.stderr)
                sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
