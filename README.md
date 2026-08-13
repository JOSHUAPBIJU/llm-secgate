# LLM SecGate

A lightweight LLM security scanner built as an **SSDLC security gate**, with every
finding mapped to the specific **NIS2 Article 21** risk-management measure it relates to.

Runs fully offline against a deliberately vulnerable mock LLM, no API key required,
so anyone can clone this and run it in under a minute. It also supports pointing
at a real Claude model via the Anthropic API.

## Why this project

Most "AI security" demos stop at "look, I can jailbreak a chatbot." This one tries
to answer the next questions a security team actually asks:

1. **Where does this catch belong in the development pipeline?** → wired up as a
   GitHub Actions gate that fails a pull request when a critical vulnerability is found,
   the same way a SAST or DAST scanner would.
2. **What regulatory obligation does this actually connect to?** → every OWASP LLM
   Top 10 category the scanner tests for is mapped to the specific NIS2 Article 21(2)
   measure(s) an in-scope organization would need to evidence.

## Architecture

```
llm-secgate/
├── secgate/
│   ├── payloads.py       # attack payload library, tagged by OWASP LLM Top 10 category
│   ├── target.py         # pluggable targets: offline mock LLM + live Anthropic adapter
│   ├── scanner.py         # runs payloads against a target, scores results
│   ├── nis2_mapping.py    # OWASP LLM Top 10 category -> NIS2 Article 21 measure
│   └── report.py          # generates the markdown report
├── tests/
│   └── test_scanner.py    # pytest suite (part of the SSDLC test stage)
├── .github/workflows/
│   └── llm-security-gate.yml   # CI: run tests + scan on every PR, block merge on critical findings
├── run_scan.py             # CLI entry point
└── sample_report.md        # example output from a run against the mock target
```

## What it tests for

Payloads currently cover 5 categories from the OWASP Top 10 for LLM Applications (2026):

| Category | What it probes |
|---|---|
| LLM01 Prompt Injection | Direct instruction override, fake "developer mode" jailbreaks |
| LLM02 Sensitive Information Disclosure | System prompt / credential exfiltration |
| LLM03 Excessive Agency | Destructive or financial actions taken without authorization |
| LLM05 Improper Output Handling | Unsanitized output that could enable injection/XSS downstream |
| LLM09 Misinformation | Model confirming a dangerous, false factual claim |

Each finding is scored by severity and rolled up into a 0-100 risk score, and any
`critical` finding fails the CI gate by default.

## Running it

```bash
pip install -r requirements.txt

# scan the built-in vulnerable mock target (no API key needed)
python run_scan.py

# scan a live Claude model instead (needs ANTHROPIC_API_KEY set)
python run_scan.py --target anthropic

# use it as a CI gate: exits non-zero if any critical finding is present
python run_scan.py --fail-on critical

# write the report to a file
python run_scan.py --out scan_report.md
```

Run the tests:

```bash
pytest -q
```

## NIS2 mapping (Article 21(2))

| Code | Measure |
|---|---|
| (a) | Risk analysis and information system security policies |
| (b) | Incident handling |
| (c) | Business continuity, backup management, disaster recovery, crisis management |
| (d) | Supply chain security |
| (e) | Security in system acquisition, development and maintenance, incl. vulnerability handling/disclosure |
| (f) | Policies to assess effectiveness of risk management measures |
| (g) | Basic cyber hygiene practices and cybersecurity training |
| (h) | Policies on cryptography and encryption |
| (i) | Human resources security, access control, asset management |
| (j) | Multi-factor/continuous authentication, secured communications |

See `secgate/nis2_mapping.py` for the exact category-to-measure mapping used.

## Extending it

- Add new payloads in `secgate/payloads.py` (just needs a prompt + a detector function).
- Add a new target by implementing a class with a `.send(prompt) -> str` method in `secgate/target.py`.
- Extend `OWASP_TO_NIS2` in `secgate/nis2_mapping.py` as you add coverage for more categories
  (LLM04 Data/Model Poisoning, LLM06 Excessive Consumption, LLM07 System Prompt Leakage, etc.).

## Notes / limitations

This is a portfolio-scale demo, not a production scanner. Detection here uses
simple keyword/regex heuristics for clarity and zero-dependency reproducibility.
A production version would likely use an LLM-as-judge for more nuanced detection,
a larger and continuously updated payload library, and integration with a real
ticketing/GRC system for the NIS2 evidence trail.

## License

MIT
