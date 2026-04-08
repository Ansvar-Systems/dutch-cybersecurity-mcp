#!/usr/bin/env node

/**
 * Dutch Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying NCSC-NL (Nationaal Cyber Security Centrum)
 * guidance documents, Cyber Essentials, CAF, 10 Steps to Cyber Security,
 * and security advisories.
 *
 * Tool prefix: nl_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
  getDataFreshness,
} from "./db.js";
import { buildCitation } from "./citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "dutch-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "nl_cyber_search_guidance",
    description:
      "Full-text search across NCSC guidance documents. Covers ICT-beveiligingsrichtlijnen, Baseline Informatiebeveiliging Overheid (BIO), NIS2 guidance, and technical publications. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'patch management', 'network security', 'incident response')",
        },
        type: {
          type: "string",
          enum: ["guidance", "framework", "technical", "board"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["ICT-beveiligingsrichtlijnen", "BIO", "NCSC-NL", "NIS2"],
          description: "Filter by NCSC series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "nl_cyber_get_guidance",
    description:
      "Get a specific NCSC guidance document by reference (e.g., 'NCSC-NL-ICT-2023', 'NCSC-NL-BIO-2023', 'NCSC-NL-AP-2024').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "NCSC-NL document reference (e.g., 'NCSC-NL-ICT-2023', 'NCSC-NL-BIO-2023')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "nl_cyber_search_advisories",
    description:
      "Search NCSC-NL security advisories and vulnerability notifications. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'ransomware', 'zero-day', 'supply chain')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "nl_cyber_get_advisory",
    description:
      "Get a specific NCSC security advisory by reference (e.g., 'NCSC-NL-ADV-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "NCSC advisory reference (e.g., 'NCSC-NL-ADV-2024-001')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "nl_cyber_list_frameworks",
    description:
      "List all NCSC-NL frameworks and guidance series covered in this MCP, including ICT-beveiligingsrichtlijnen, Baseline Informatiebeveiliging Overheid (BIO), and NIS2 guidance.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "nl_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "nl_cyber_list_sources",
    description:
      "List the data sources used by this MCP server, including URLs, data types, and update frequency.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "nl_cyber_check_data_freshness",
    description:
      "Check when the data in this MCP was last updated. Returns the most recent dates for guidance documents and security advisories.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["guidance", "framework", "technical", "board"]).optional(),
  series: z.enum(["ICT-beveiligingsrichtlijnen", "BIO", "NCSC-NL", "NIS2"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helpers -----------------------------------------------------------------

const META = {
  disclaimer:
    "Data sourced from NCSC-NL (Nationaal Cyber Security Centrum). Verify against official sources before acting on this information.",
  copyright:
    "© NCSC-NL. Content reproduced for informational purposes under NCSC-NL terms of use.",
  source_url: "https://www.ncsc.nl/",
};

function textContent(data: unknown) {
  const payload = typeof data === "object" && data !== null
    ? { ...data as Record<string, unknown>, _meta: META }
    : data;
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(payload, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "nl_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({
          query: parsed.query,
          type: parsed.type,
          series: parsed.series,
          status: parsed.status,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "nl_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        const d = doc as unknown as Record<string, unknown>;
        return textContent({
          ...d,
          _citation: buildCitation(
            String(d["reference"] ?? parsed.reference),
            String(d["title"] ?? d["reference"] ?? parsed.reference),
            "nl_cyber_get_guidance",
            { reference: parsed.reference },
            d["url"] != null ? String(d["url"]) : undefined,
          ),
        });
      }

      case "nl_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "nl_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        const adv = advisory as unknown as Record<string, unknown>;
        return textContent({
          ...adv,
          _citation: buildCitation(
            String(adv["reference"] ?? parsed.reference),
            String(adv["title"] ?? adv["reference"] ?? parsed.reference),
            "nl_cyber_get_advisory",
            { reference: parsed.reference },
            adv["url"] != null ? String(adv["url"]) : undefined,
          ),
        });
      }

      case "nl_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "nl_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "NCSC-NL (Nationaal Cyber Security Centrum) MCP server. Provides access to NCSC guidance including Cyber Essentials, 10 Steps to Cyber Security, Cyber Assessment Framework (CAF), and security advisories.",
          data_source: "NCSC-NL (https://www.ncsc.nl/)",
          coverage: {
            guidance: "ICT-beveiligingsrichtlijnen, Baseline Informatiebeveiliging Overheid (BIO), NIS2 guidance",
            advisories: "NCSC-NL security advisories and vulnerability notifications",
            frameworks: "ICT-beveiligingsrichtlijnen, BIO, NIS2",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      case "nl_cyber_list_sources": {
        return textContent({
          sources: [
            {
              id: "ncsc-nl-guidance",
              name: "NCSC-NL Guidance Documents",
              url: "https://www.ncsc.nl/documenten",
              types: ["guidance", "framework", "technical", "board"],
              update_frequency: "as published by NCSC-NL",
            },
            {
              id: "ncsc-nl-advisories",
              name: "NCSC-NL Security Advisories (CSAF v2)",
              url: "https://advisories.ncsc.nl/csaf/v2/",
              types: ["advisory"],
              update_frequency: "as published by NCSC-NL",
            },
          ],
          ingest_script: "scripts/ingest-ncsc-nl.ts",
        });
      }

      case "nl_cyber_check_data_freshness": {
        const freshness = getDataFreshness();
        return textContent(freshness);
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
