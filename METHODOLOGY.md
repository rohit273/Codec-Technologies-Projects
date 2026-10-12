# Methodology

1. **Authorize and scope:** document assets, approved sources, purpose, data owner, retention, and escalation path.
2. **Collect:** import approved provider exports or internal reports. No marketplace crawler is included.
3. **Normalize:** map each record to source/date/title/text and optional ID/reference URL.
4. **Minimize data:** redact supported password/token-like patterns before reporting; this is heuristic, not complete DLP.
5. **Match:** case-insensitive matching against configured organizations, domains, products, and keywords.
6. **Extract indicators:** identify common URLs/domains and syntactically valid IPv4 addresses; do not resolve or contact them.
7. **Prioritize:** use the documented deterministic score and deduplicate by SHA-256 fingerprint.
8. **Validate:** analyst checks source credibility, context, false positives, and incident relevance.
9. **Report:** export JSON/CSV and apply access/retention policy.
10. **Evaluate:** use labeled synthetic records to measure precision, recall, redaction coverage, and duplicate handling.
