"""Generates a markdown security + compliance report from a ScanResult."""

from .nis2_mapping import measures_for

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def generate_markdown(result) -> str:
    lines = []
    lines.append("# LLM SecGate Scan Report\n")
    lines.append(f"**Target:** `{result.target_name}`  ")
    lines.append(f"**Scanned at:** {result.timestamp}  ")
    lines.append(f"**Payloads run:** {len(result.findings)}  ")
    lines.append(f"**Failed checks:** {len(result.failed)}  ")
    lines.append(f"**Risk score:** {result.risk_score()}/100\n")

    gate_status = "FAIL" if result.has_severity("critical") else "PASS"
    lines.append(f"**SSDLC Security Gate:** `{gate_status}` "
                  f"({'blocks merge, critical vulnerability found' if gate_status == 'FAIL' else 'no critical findings, merge allowed'})\n")

    lines.append("## Findings\n")
    lines.append("| ID | Category | Severity | Result | Description |")
    lines.append("|----|----------|----------|--------|--------------|")
    for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
        status = "FAIL" if f.vulnerable else "pass"
        lines.append(f"| {f.payload_id} | {f.category} {f.category_name} | {f.severity} | {status} | {f.description} |")

    lines.append("\n## Failed checks — detail\n")
    if not result.failed:
        lines.append("None. No vulnerable behavior detected for the payloads in this run.\n")
    else:
        for f in result.failed:
            lines.append(f"### {f.payload_id} — {f.category_name} ({f.severity})")
            lines.append(f"- **Prompt sent:** `{f.prompt}`")
            lines.append(f"- **Target response:** `{f.response}`")
            lines.append(f"- **Why this matters:** {f.description}")
            lines.append("")

    lines.append("## NIS2 Article 21 compliance mapping\n")
    lines.append("Each failed check below maps to specific NIS2 risk-management measures "
                  "that an in-scope organization would need to evidence as part of Article 21.\n")
    seen_categories = {f.category: f.category_name for f in result.failed}
    if not seen_categories:
        lines.append("No compliance gaps identified from this run.\n")
    else:
        for cat, name in seen_categories.items():
            lines.append(f"**{cat} — {name}**")
            for code, desc in measures_for(cat):
                lines.append(f"- Article 21(2)({code}): {desc}")
            lines.append("")

    return "\n".join(lines)
