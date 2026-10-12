# Dark Web Threat Monitoring System

A defensive OSINT prototype for finding organization-specific indicators in **authorized threat-intelligence feeds and supplied exports**. It normalizes records, redacts credential-like strings, matches a watchlist, assigns explainable triage priority, and exports JSON/CSV.

**Scope:** This version does not crawl dark-web marketplaces, access illegal content, collect passwords, or verify leaked credentials. Use approved exports and synthetic data. Any Tor/onion source requires separate authorization and an approved connector.

## Features
- JSON, JSONL, and CSV input
- Organization/domain/product/keyword watchlists
- URL, domain, and valid IPv4 extraction
- Credential-like pattern redaction
- Explainable priority scoring and duplicate suppression
- JSON and CSV reports; synthetic sample; unit tests

## Requirements
Python 3.10+. Core uses only the standard library.

## Quick start
Windows:
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python src\monitor.py --input data\sample_feed.json --config config\watchlist.json --out reports\demo
```
Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
python src/monitor.py --input data/sample_feed.json --config config/watchlist.json --out reports/demo
```
Run tests: `python -m unittest discover -s tests -v`

Outputs: `report.json`, `report.csv`.

## Methodology
1. Define authorized scope, assets, data sources, retention, and escalation contacts.
2. Import an approved feed/export; do not crawl or interact with criminal marketplaces.
3. Normalize records, redact credential-like values, and match the configured watchlist.
4. Extract basic indicators and calculate a transparent score.
5. Review findings manually, validate context, and record false positives.
6. Export findings for analyst triage; do not treat matches as proof of compromise.

## Scoring
+3 organization/domain/product match; +2 if URL/domain/IP found; +2 credential-like pattern detected; +1 high-risk keyword. Capped at 8. High >=6, medium >=3, otherwise low. This is a triage aid, not a calibrated risk probability.

## Security and limitations
Use only authorized data. Do not test or share leaked credentials. Redaction is heuristic and not a complete DLP control. No marketplace crawler, Tor automation, external API, semantic NLP, or ML model is included. Production use needs access control, secure storage, retention controls, source validation, monitoring, and analyst workflow integration.

## Repository map
`src/monitor.py` · `config/watchlist.json` · `data/sample_feed.json` · `docs/` · `tests/` · `reports/`
