# Tools

All tools are prefixed `nl_cyber_`.

## nl_cyber_search_guidance

Full-text search across NCSC-NL guidance documents.

**Input**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `patch management`, `network security`) |
| `type` | string | no | Filter by document type: `guidance`, `framework`, `technical`, `board` |
| `series` | string | no | Filter by series: `ICT-beveiligingsrichtlijnen`, `BIO`, `NCSC-NL`, `NIS2` |
| `status` | string | no | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | no | Maximum results (default 20, max 100) |

**Returns** `results[]` with matching guidance records and `count`.

---

## nl_cyber_get_guidance

Retrieve a specific guidance document by its reference code.

**Input**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | NCSC-NL reference (e.g., `NCSC-NL-ICT-2023`, `NCSC-NL-BIO-2023`) |

**Returns** Full guidance record including `full_text`, `_citation`, and `_meta`.

---

## nl_cyber_search_advisories

Full-text search across NCSC-NL security advisories.

**Input**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | Search query (e.g., `ransomware`, `zero-day`, `supply chain`) |
| `severity` | string | no | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | no | Maximum results (default 20, max 100) |

**Returns** `results[]` with matching advisory records and `count`.

---

## nl_cyber_get_advisory

Retrieve a specific security advisory by its reference code.

**Input**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | yes | NCSC-NL advisory reference (e.g., `NCSC-NL-ADV-2024-001`) |

**Returns** Full advisory record including CVE references, affected products, `_citation`, and `_meta`.

---

## nl_cyber_list_frameworks

List all NCSC-NL frameworks and guidance series covered in this MCP.

**Input** None.

**Returns** `frameworks[]` with id, name, description, and document count.

---

## nl_cyber_list_sources

List the upstream data sources used to populate this MCP.

**Input** None.

**Returns** Array of source objects with URL, data types, and update frequency.

---

## nl_cyber_check_data_freshness

Check the most recent dates in the database for guidance and advisories.

**Input** None.

**Returns** `guidance_latest_date`, `advisory_latest_date`, and `checked_at` timestamp.

---

## nl_cyber_about

Return metadata about this MCP server.

**Input** None.

**Returns** Server name, version, description, data source, coverage summary, and tool list.

---

## Response metadata

Every response includes a `_meta` block:

```json
{
  "_meta": {
    "disclaimer": "Data sourced from NCSC-NL ...",
    "copyright": "© NCSC-NL ...",
    "source_url": "https://www.ncsc.nl/"
  }
}
```

Single-document responses (`get_guidance`, `get_advisory`) also include a `_citation` block for deterministic citation pipelines.
