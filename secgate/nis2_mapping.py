"""
Maps OWASP Top 10 for LLM Applications categories to the 10 minimum cybersecurity
risk-management measures required under Article 21(2) of the NIS2 Directive (EU 2022/2555).

This lets a finding be reported not just as "a security bug" but as evidence of
a specific compliance gap, which is what a NIS2-covered organization actually
has to track and remediate.
"""

NIS2_MEASURES = {
    "a": "Risk analysis and information system security policies",
    "b": "Incident handling",
    "c": "Business continuity, backup management, disaster recovery and crisis management",
    "d": "Supply chain security",
    "e": "Security in system/network acquisition, development and maintenance, "
         "including vulnerability handling and disclosure",
    "f": "Policies and procedures to assess the effectiveness of risk management measures",
    "g": "Basic cyber hygiene practices and cybersecurity training",
    "h": "Policies and procedures on the use of cryptography and encryption",
    "i": "Human resources security, access control policies and asset management",
    "j": "Use of multi-factor/continuous authentication and secured communications",
}

OWASP_TO_NIS2 = {
    "LLM01": ["a", "e", "f"],   # Prompt Injection
    "LLM02": ["a", "h", "i"],   # Sensitive Information Disclosure
    "LLM03": ["a", "b", "i"],   # Excessive Agency
    "LLM05": ["e"],             # Improper Output Handling
    "LLM09": ["a", "g"],        # Misinformation
}


def measures_for(category: str):
    codes = OWASP_TO_NIS2.get(category, [])
    return [(c, NIS2_MEASURES[c]) for c in codes]
