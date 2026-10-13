#!/usr/bin/env python3
"""
LLM SecGate — CLI entry point.

Usage:
    python run_scan.py                          # scan the built-in mock vulnerable LLM
    python run_scan.py --target hardened        # scan a refusing target (expected PASS)
    python run_scan.py --target anthropic       # scan a live Claude model (needs ANTHROPIC_API_KEY)
    python run_scan.py --fail-on critical       # exit non-zero if any critical finding (for CI gates)
    python run_scan.py --out report.md          # write report to a file
"""

import argparse
import os
import sys

from secgate.scanner import run_scan
from secgate.report import generate_markdown
from secgate.target import MockVulnerableLLM, HardenedMockLLM

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def build_target(name: str):
    """Return a target instance. Network-backed targets are imported lazily
    so the offline run needs no SDK and no API key."""
    if name == "mock":
        return MockVulnerableLLM()
    if name == "hardened":
        return HardenedMockLLM()
    if name == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit(
                "[secgate] ANTHROPIC_API_KEY is not set.\n"
                "          Set it, or run without --target to scan the offline mock."
            )
        from secgate.target import AnthropicTarget
        return AnthropicTarget()
    raise ValueError(f"Unknown target: {name}")


def main():
    parser = argparse.ArgumentParser(
        description="LLM SecGate: LLM security scanner for the secure SDLC."
    )
    parser.add_argument(
        "--target", default="mock", choices=["mock", "hardened", "anthropic"],
        help="Which target to scan (default: mock, no API key needed).",
    )
    parser.add_argument(
        "--out", default=None,
        help="Path to write the markdown report to.",
    )
    parser.add_argument(
        "--fail-on", default=None, choices=SEVERITY_ORDER,
        help="Exit with a non-zero status if any failed check has this severity "
             "or worse. Use this in CI to turn the scan into a merge gate.",
    )
    args = parser.parse_args()

    try:
        target = build_target(args.target)
    except Exception as exc:
        sys.exit(f"[secgate] could not initialise target '{args.target}': {exc}")

    result = run_scan(target)
    report = generate_markdown(result)

    print(report)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(report)
        except OSError as exc:
            sys.exit(f"[secgate] could not write report to {args.out}: {exc}")
        print(f"\n[written to {args.out}]", file=sys.stderr)

    if args.fail_on:
        threshold_index = SEVERITY_ORDER.index(args.fail_on)
        for severity in SEVERITY_ORDER[:threshold_index + 1]:
            if result.has_severity(severity):
                print(
                    f"\n[secgate] GATE FAILED: found a '{severity}' severity issue.",
                    file=sys.stderr,
                )
                sys.exit(1)
        print("\n[secgate] GATE PASSED: no findings at or above "
              f"'{args.fail_on}' severity.", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
