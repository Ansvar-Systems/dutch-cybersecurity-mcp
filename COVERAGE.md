# Coverage

This MCP provides access to publicly available data from **NCSC-NL** (Nationaal Cyber Security Centrum — the Dutch National Cyber Security Centre).

## Data Sources

| Source | URL | Format |
|--------|-----|--------|
| NCSC-NL Guidance Documents | https://www.ncsc.nl/documenten | HTML (scraped) |
| NCSC-NL Security Advisories | https://advisories.ncsc.nl/csaf/v2/ | CSAF v2 JSON |

## Document Coverage

### Guidance Series

| Series | Description |
|--------|-------------|
| ICT-beveiligingsrichtlijnen | ICT security guidelines for specific technologies and topics |
| BIO | Baseline Informatiebeveiliging Overheid — mandatory security baseline for Dutch government |
| NIS2 | NCSC-NL guidance supporting NIS2 Directive compliance |
| NCSC-NL | General NCSC-NL publications, factsheets, and whitepapers |

### Advisory Types

| Type | Description |
|------|-------------|
| Security advisories | Vulnerability notifications with severity, affected products, and CVE references |

## Update Frequency

Data is ingested on-demand using `scripts/ingest-ncsc-nl.ts`. No automated ingestion schedule is currently configured; run the ingest script manually to pull the latest publications.

## Limitations

- Full text is extracted from HTML and may not perfectly reproduce the original formatting.
- Advisory data is sourced from the CSAF v2 feed; advisories older than the feed retention window may not be present.
- This MCP does not cover classified or restricted NCSC-NL publications.
