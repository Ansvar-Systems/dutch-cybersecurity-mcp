/**
 * Citation metadata for the deterministic citation pipeline.
 *
 * Provides structured identifiers (canonical_ref, display_text, aliases)
 * that the platform's entity linker uses to match references in agent
 * responses to MCP tool results — without relying on LLM formatting.
 *
 * This is the UNIVERSAL template — works for all MCP types (law, sector,
 * agriculture, domain). Each MCP adapts the builder call to its own
 * field names.
 *
 * See: docs/guides/law-mcp-golden-standard.md Section 4.9c
 */

export interface CitationMetadata {
  canonical_ref: string;
  display_text: string;
  aliases?: string[];
  source_url?: string;
  lookup: {
    tool: string;
    args: Record<string, string>;
  };
  // Source-attribution contract per the Source Attribution Standard.
  // Declared upstream in sources.yml and in the fleet manifest's attribution block.
  // Every served item MUST carry these fields so the gateway can verify upstream
  // source rights at fan-out time (see scripts/audit-source-legitimacy.py).
  publisher?: string;
  license?: string;
  retrieved_at?: string;
}

/**
 * Source attribution constant for this MCP. Mirrors sources.yml and the fleet
 * manifest's attribution block. Hardcoded here because dutch-cybersecurity-mcp
 * has exactly one upstream publisher; adding a second source requires extending
 * to a per-item lookup.
 *
 * publisher: bare hostname matching infrastructure/policy/source-authority-registry.yml
 * license:   SPDX code from infrastructure/attribution-licenses.json (CC0-1.0 entry
 *            confirms commercial_allowed=true, safe_for_public_ghcr=true)
 */
export const SOURCE_ATTRIBUTION = {
  publisher: "ncsc.nl",
  license: "CC0-1.0",
  base_url: "https://www.ncsc.nl/",
} as const;

/**
 * Build a minimal source-attribution stub for items in a search result list.
 * Returns the publisher / license / source_url / retrieved_at subset.
 *
 * Used for search_* tool responses where building the full entity-linker
 * citation (canonical_ref / display_text / aliases / lookup) per item would
 * be expensive. The gateway's source-rights verification only requires the
 * three attribution fields; the entity-linker citation is built lazily on
 * follow-up get_* calls.
 *
 * @param sourceUrl  Optional item-level URL. If absent, falls back to the
 *                   publisher base URL (per the 2026-05-16 known-gap noted in
 *                   sources.yml; closes once the DB schema captures per-item URLs).
 */
export function buildItemAttribution(sourceUrl?: string | null): {
  publisher: string;
  license: string;
  source_url: string;
  retrieved_at: string;
} {
  return {
    publisher: SOURCE_ATTRIBUTION.publisher,
    license: SOURCE_ATTRIBUTION.license,
    source_url: sourceUrl || SOURCE_ATTRIBUTION.base_url,
    retrieved_at: new Date().toISOString(),
  };
}

/**
 * Build citation metadata for any retrieval tool response.
 *
 * @param canonicalRef  Primary reference the entity linker matches against
 *                      (e.g., "SFS 2018:218", "GDPR Article 33", "CVE-2024-1234")
 * @param displayText   How the reference appears in prose
 *                      (e.g., "34 § SFS 2018:218", "Article 33 of GDPR")
 * @param toolName      The MCP tool name (e.g., "get_provision", "get_article")
 * @param toolArgs      The tool arguments for verification lookup
 * @param sourceUrl     Official portal URL (optional)
 * @param aliases       Alternative names the LLM might use (optional)
 */
export function buildCitation(
  canonicalRef: string,
  displayText: string,
  toolName: string,
  toolArgs: Record<string, string>,
  sourceUrl?: string | null,
  aliases?: string[],
): CitationMetadata {
  // Source-attribution fields are always populated from SOURCE_ATTRIBUTION; the
  // Source Attribution Standard requires every served item to carry them. The
  // source_url falls back to publisher base URL when item-level URL is absent.
  return {
    canonical_ref: canonicalRef,
    display_text: displayText,
    ...(aliases && aliases.length > 0 && { aliases }),
    source_url: sourceUrl || SOURCE_ATTRIBUTION.base_url,
    lookup: {
      tool: toolName,
      args: toolArgs,
    },
    publisher: SOURCE_ATTRIBUTION.publisher,
    license: SOURCE_ATTRIBUTION.license,
    retrieved_at: new Date().toISOString(),
  };
}

/**
 * Build citation metadata for a law MCP get_provision response.
 *
 * Handles Swedish-style YYYY:NNN statute IDs, chapter:section notation,
 * and short-name aliases. Other jurisdictions adapt field names.
 *
 * @param documentId     DB identifier (e.g., "2018:218", "LOV-2018-06-15-38")
 * @param documentTitle  Full title of the law
 * @param provisionRef   Provision reference (e.g., "34", "3:12")
 * @param inputDocId     The document_id argument as passed by the caller
 * @param inputSection   The section argument as passed by the caller
 * @param sourceUrl      Official portal URL (optional)
 * @param shortName      Short name / alias (optional)
 */
export function buildProvisionCitation(
  documentId: string,
  documentTitle: string,
  provisionRef: string,
  inputDocId: string,
  inputSection: string,
  sourceUrl?: string | null,
  shortName?: string | null,
): CitationMetadata {
  // Build canonical_ref — detect common statute ID formats
  let canonicalRef: string;
  if (documentId.match(/^\d{4}:\d+$/)) {
    // Swedish SFS format: "2018:218" → "SFS 2018:218"
    canonicalRef = `SFS ${documentId}`;
  } else if (documentId.match(/^LOV-\d{4}/)) {
    // Norwegian Lovdata format
    canonicalRef = documentId;
  } else {
    canonicalRef = documentTitle || documentId;
  }

  // Build display_text with provision reference
  let displayText: string;
  if (provisionRef && provisionRef.includes(':')) {
    // Chapter:section format (e.g., "3:12" → "3 kap. 12 §")
    const [ch, sec] = provisionRef.split(':');
    displayText = `${ch} kap. ${sec} § ${canonicalRef}`;
  } else if (provisionRef) {
    displayText = `§ ${provisionRef} ${canonicalRef}`;
  } else {
    displayText = canonicalRef;
  }

  // Build aliases
  const aliases: string[] = [];
  if (shortName) aliases.push(shortName);
  if (documentId !== canonicalRef) aliases.push(documentId);
  if (documentTitle && documentTitle !== canonicalRef) aliases.push(documentTitle);

  return {
    canonical_ref: canonicalRef,
    display_text: displayText,
    ...(aliases.length > 0 && { aliases }),
    ...(sourceUrl && { source_url: sourceUrl }),
    lookup: {
      tool: 'get_provision',
      args: { document_id: inputDocId, section: inputSection },
    },
  };
}

/**
 * Build citation for a sector regulator decision/regulation.
 *
 * @param reference      Decision/regulation reference (e.g., "FFFS 2024:1")
 * @param title          Full title
 * @param toolName       Tool name (e.g., "se_dp_get_decision")
 * @param toolArgs       Tool arguments
 * @param authority      Issuing authority (e.g., "IMY", "FI")
 * @param sourceUrl      Official URL (optional)
 */
export function buildRegulationCitation(
  reference: string,
  title: string,
  toolName: string,
  toolArgs: Record<string, string>,
  authority?: string | null,
  sourceUrl?: string | null,
): CitationMetadata {
  const canonicalRef = reference;
  const displayText = title || reference;
  const aliases: string[] = [];
  if (authority) aliases.push(`${authority}: ${reference}`);

  return {
    canonical_ref: canonicalRef,
    display_text: displayText,
    ...(aliases.length > 0 && { aliases }),
    ...(sourceUrl && { source_url: sourceUrl }),
    lookup: { tool: toolName, args: toolArgs },
  };
}
