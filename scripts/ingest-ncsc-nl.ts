/**
 * NCSC-NL Ingestion Crawler
 *
 * Scrapes the NCSC-NL (Dutch National Cyber Security Centre) website and
 * populates the SQLite database with real cybersecurity advisories and
 * guidance documents.
 *
 * Data sources:
 *   - Advisories: CSAF v2 feed at advisories.ncsc.nl/csaf/v2/
 *     (machine-readable JSON, ~800 advisories across 2024-2026)
 *   - Advisory index: advisories.ncsc.nl/advisories.json
 *     (list feed with severity metadata)
 *   - Guidance: ncsc.nl/documenten (publications, factsheets, guidelines)
 *     scraped via HTML parsing
 *
 * Usage:
 *   npx tsx scripts/ingest-ncsc-nl.ts
 *   npx tsx scripts/ingest-ncsc-nl.ts --dry-run
 *   npx tsx scripts/ingest-ncsc-nl.ts --resume
 *   npx tsx scripts/ingest-ncsc-nl.ts --force
 *   npx tsx scripts/ingest-ncsc-nl.ts --advisories-only
 *   npx tsx scripts/ingest-ncsc-nl.ts --guidance-only
 *   npx tsx scripts/ingest-ncsc-nl.ts --max-advisories 50
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import * as cheerio from "cheerio";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["NCSCNL_DB_PATH"] ?? "data/ncsc-nl.db";
const STATE_FILE = join(dirname(DB_PATH), ".ingest-state.json");
const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 3000;
const REQUEST_TIMEOUT_MS = 30_000;

const CSAF_BASE = "https://advisories.ncsc.nl/csaf/v2";
const ADVISORIES_INDEX = "https://advisories.ncsc.nl/advisories.json";
const NCSC_BASE = "https://www.ncsc.nl";

// Known guidance publication URLs on ncsc.nl.
// The ncsc.nl publications section uses a Next.js SPA that loads content
// dynamically, so direct scraping of listing pages is unreliable. Instead
// we maintain a curated list of known publication URLs and scrape each one.
// This list should be extended as new publications are discovered.
const GUIDANCE_URLS: string[] = [
  // ICT security guidelines
  "/documenten/publicaties/2021/januari/19/ict-beveiligingsrichtlijnen-voor-transport-layer-security-2.1",
  "/documenten/publicaties/2022/juli/guidelines-for-quantum-safe-transport-layer-encryption/guidelines-for-quantum-safe-transport-layer-encryption",
  "/documenten/publicaties/2024/september/27/basisprincipes",
  "/documenten/publicaties/2022/oktober/10/basismaatregelen-voor-cybersecurity-van-iacs",
  "/documenten/publicaties/2024/oktober/08/checklist-registreren",
  // Factsheets
  "/documenten/factsheets/2019/juni/01/factsheet-tls-interceptie",
  "/documenten/factsheets/2024/juli/15/hoe-krijg-ik-grip-op-mijn-security-controls",
  "/documenten/factsheets/2024/juli/15/hoe-breng-ik-mijn-dreigingen-in-kaart",
  // Thematic pages with substantive content
  "/basisprincipes/overzicht",
  "/cyberbeveiligingswet-nis2/bereid-je-voor",
  "/ot/aan-de-slag-met-het-beveiligen-van-otiacs",
  "/risicomanagement",
  "/incidenten-en-herstellen",
];

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const resume = args.includes("--resume");
const force = args.includes("--force");
const advisoriesOnly = args.includes("--advisories-only");
const guidanceOnly = args.includes("--guidance-only");

function getArgValue(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

const maxAdvisories = parseInt(getArgValue("--max-advisories") ?? "0", 10) || 0;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.log(`[${ts}] ${msg}`);
}

function warn(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.warn(`[${ts}] WARN: ${msg}`);
}

function error(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.error(`[${ts}] ERROR: ${msg}`);
}

// ---------------------------------------------------------------------------
// State persistence (for --resume)
// ---------------------------------------------------------------------------

interface IngestState {
  advisoriesCompleted: string[];   // list of advisory IDs already ingested
  guidanceCompleted: string[];     // list of guidance URLs already ingested
  lastRun: string;
}

function loadState(): IngestState {
  if (existsSync(STATE_FILE)) {
    try {
      return JSON.parse(readFileSync(STATE_FILE, "utf-8")) as IngestState;
    } catch {
      warn(`Failed to parse state file ${STATE_FILE}, starting fresh`);
    }
  }
  return { advisoriesCompleted: [], guidanceCompleted: [], lastRun: "" };
}

function saveState(state: IngestState): void {
  state.lastRun = new Date().toISOString();
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let lastRequestTime = 0;

async function rateLimitedFetch(url: string, retries = MAX_RETRIES): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  lastRequestTime = Date.now();

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const resp = await fetch(url, {
        signal: controller.signal,
        headers: {
          "User-Agent": "ansvar-ncsc-nl-mcp-crawler/1.0 (contact: hello@ansvar.ai)",
          "Accept": "application/json, text/html, */*",
        },
      });

      clearTimeout(timeout);

      if (resp.status === 429) {
        const retryAfter = parseInt(resp.headers.get("Retry-After") ?? "10", 10);
        warn(`Rate limited (429) on ${url}, waiting ${retryAfter}s`);
        await sleep(retryAfter * 1000);
        continue;
      }

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      }

      return resp;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (attempt < retries) {
        const backoff = RETRY_BACKOFF_MS * attempt;
        warn(`Attempt ${attempt}/${retries} failed for ${url}: ${msg}. Retrying in ${backoff}ms...`);
        await sleep(backoff);
      } else {
        throw new Error(`All ${retries} attempts failed for ${url}: ${msg}`);
      }
    }
  }

  // Unreachable, but TypeScript requires it.
  throw new Error(`Fetch failed for ${url}`);
}

async function fetchJson<T>(url: string): Promise<T> {
  const resp = await rateLimitedFetch(url);
  return (await resp.json()) as T;
}

async function fetchText(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  return await resp.text();
}

// ---------------------------------------------------------------------------
// CSAF advisory types
// ---------------------------------------------------------------------------

interface CsafDocument {
  document: {
    title: string;
    lang?: string;
    tracking: {
      id: string;
      version: string;
      status: string;
      initial_release_date: string;
      current_release_date: string;
    };
    notes?: Array<{
      category: string;
      text: string;
      title?: string;
    }>;
    distribution?: {
      tlp?: { label: string };
    };
    aggregate_severity?: {
      text: string;
    };
    references?: Array<{
      url: string;
      summary?: string;
      category?: string;
    }>;
  };
  product_tree?: {
    branches?: CsafBranch[];
  };
  vulnerabilities?: Array<{
    cve?: string;
    notes?: Array<{ category: string; text: string }>;
    product_status?: {
      known_affected?: string[];
    };
    scores?: Array<{
      cvss_v3?: {
        baseScore: number;
        baseSeverity: string;
        vectorString: string;
      };
      products?: string[];
    }>;
    cwe?: {
      id: string;
      name: string;
    };
    threats?: Array<{
      category: string;
      details: string;
    }>;
  }>;
}

interface CsafBranch {
  category: string;
  name: string;
  branches?: CsafBranch[];
  product?: {
    name: string;
    product_id: string;
  };
}

// Advisory index entry from advisories.json: [id, version, title, timestamp, probability, impact]
type AdvisoryIndexEntry = [string, string, string, string, number, number];

// ---------------------------------------------------------------------------
// CSAF parsing
// ---------------------------------------------------------------------------

const SEVERITY_MAP: Record<number, string> = {
  0: "low",
  1: "medium",
  2: "high",
};

function extractProducts(branch: CsafBranch | undefined, results: string[] = []): string[] {
  if (!branch) return results;
  if (branch.product) {
    results.push(branch.product.name);
  }
  if (branch.branches) {
    for (const child of branch.branches) {
      extractProducts(child, results);
    }
  }
  return results;
}

function extractAllProducts(tree: CsafDocument["product_tree"]): string[] {
  if (!tree?.branches) return [];
  const products: string[] = [];
  for (const branch of tree.branches) {
    extractProducts(branch, products);
  }
  return products;
}

function extractCves(doc: CsafDocument): string[] {
  if (!doc.vulnerabilities) return [];
  const cves: string[] = [];
  for (const vuln of doc.vulnerabilities) {
    if (vuln.cve) cves.push(vuln.cve);
  }
  return cves;
}

function extractNoteByCategory(doc: CsafDocument, category: string): string {
  if (!doc.document.notes) return "";
  const note = doc.document.notes.find((n) => n.category === category);
  return note?.text ?? "";
}

/**
 * Determine severity from the CSAF document. Checks aggregate_severity first,
 * then falls back to the highest CVSS score in the vulnerabilities array.
 */
function determineSeverity(doc: CsafDocument): string {
  // Check aggregate_severity
  const agg = doc.document.aggregate_severity?.text?.toLowerCase();
  if (agg && ["critical", "high", "medium", "low"].includes(agg)) {
    return agg;
  }

  // Fall back to highest CVSS base score
  let maxScore = 0;
  if (doc.vulnerabilities) {
    for (const vuln of doc.vulnerabilities) {
      if (vuln.scores) {
        for (const score of vuln.scores) {
          if (score.cvss_v3 && score.cvss_v3.baseScore > maxScore) {
            maxScore = score.cvss_v3.baseScore;
          }
        }
      }
    }
  }

  if (maxScore >= 9.0) return "critical";
  if (maxScore >= 7.0) return "high";
  if (maxScore >= 4.0) return "medium";
  if (maxScore > 0) return "low";
  return "medium"; // default if no score data
}

/**
 * Build the full_text field by concatenating all note texts from the CSAF
 * document plus CVE/CVSS details.
 */
function buildFullText(doc: CsafDocument): string {
  const parts: string[] = [];

  // Title
  parts.push(doc.document.title);
  parts.push("");

  // Notes (description, summary, details, etc.)
  if (doc.document.notes) {
    for (const note of doc.document.notes) {
      // Skip the legal disclaimer — it's identical across all advisories
      if (note.category === "legal_disclaimer") continue;
      if (note.title) {
        parts.push(`${note.title}:`);
      }
      parts.push(note.text);
      parts.push("");
    }
  }

  // Vulnerability details
  if (doc.vulnerabilities && doc.vulnerabilities.length > 0) {
    parts.push("Kwetsbaarheden:");
    for (const vuln of doc.vulnerabilities) {
      const cveLine = vuln.cve ?? "Onbekend";
      let scorePart = "";
      if (vuln.scores) {
        for (const s of vuln.scores) {
          if (s.cvss_v3) {
            scorePart = ` (CVSS ${s.cvss_v3.baseScore} ${s.cvss_v3.baseSeverity})`;
            break;
          }
        }
      }
      const cwePart = vuln.cwe ? ` — ${vuln.cwe.id}: ${vuln.cwe.name}` : "";
      parts.push(`- ${cveLine}${scorePart}${cwePart}`);

      // Vulnerability-level notes
      if (vuln.notes) {
        for (const n of vuln.notes) {
          parts.push(`  ${n.text}`);
        }
      }
    }
    parts.push("");
  }

  // References
  if (doc.document.references && doc.document.references.length > 0) {
    parts.push("Referenties:");
    for (const ref of doc.document.references) {
      parts.push(`- ${ref.url}${ref.summary ? ` (${ref.summary})` : ""}`);
    }
  }

  return parts.join("\n").trim();
}

// ---------------------------------------------------------------------------
// Advisory ingestion (CSAF feed)
// ---------------------------------------------------------------------------

async function ingestAdvisories(
  db: Database.Database,
  state: IngestState,
): Promise<number> {
  log("Fetching advisory index from advisories.ncsc.nl...");

  // Step 1: Fetch the lightweight index for severity metadata
  const indexEntries = await fetchJson<AdvisoryIndexEntry[]>(ADVISORIES_INDEX);
  log(`Advisory index contains ${indexEntries.length} entries`);

  // Build a map from advisory ID to its index metadata (probability + impact)
  const indexMap = new Map<string, { probability: number; impact: number }>();
  for (const entry of indexEntries) {
    const [id, , , , probability, impact] = entry;
    if (id) {
      indexMap.set(id, { probability: probability ?? 1, impact: impact ?? 1 });
    }
  }

  // Step 2: Fetch the CSAF index to get all available advisory file paths
  log("Fetching CSAF index...");
  const csafIndexText = await fetchText(`${CSAF_BASE}/index.txt`);
  const csafPaths = csafIndexText
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && line.endsWith(".json"));

  log(`CSAF index contains ${csafPaths.length} advisory files`);

  // Filter out already-completed advisories when resuming
  const completedSet = new Set(state.advisoriesCompleted);
  let pending = csafPaths.filter((p) => {
    const id = extractIdFromPath(p);
    return !completedSet.has(id);
  });

  if (resume && pending.length < csafPaths.length) {
    log(`Resuming: ${csafPaths.length - pending.length} advisories already ingested, ${pending.length} remaining`);
  }

  // Apply --max-advisories limit
  if (maxAdvisories > 0 && pending.length > maxAdvisories) {
    log(`Limiting to ${maxAdvisories} advisories (of ${pending.length} pending)`);
    pending = pending.slice(0, maxAdvisories);
  }

  const insertAdvisory = db.prepare(`
    INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  let ingested = 0;
  let failed = 0;

  for (let i = 0; i < pending.length; i++) {
    const csafPath = pending[i]!;
    const advisoryId = extractIdFromPath(csafPath);
    const url = `${CSAF_BASE}/${csafPath}`;

    try {
      const csafDoc = await fetchJson<CsafDocument>(url);

      const title = csafDoc.document.title;
      const date = csafDoc.document.tracking.current_release_date?.slice(0, 10) ?? null;
      const products = extractAllProducts(csafDoc.product_tree);
      const cves = extractCves(csafDoc);
      const summary = extractNoteByCategory(csafDoc, "summary")
        || extractNoteByCategory(csafDoc, "description")
        || title;
      const fullText = buildFullText(csafDoc);

      // Determine severity from CSAF data; fall back to index metadata
      let severity = determineSeverity(csafDoc);
      const indexMeta = indexMap.get(advisoryId);
      if (indexMeta && severity === "medium") {
        // Use the higher of probability/impact from the index
        const maxLevel = Math.max(indexMeta.probability, indexMeta.impact);
        severity = SEVERITY_MAP[maxLevel] ?? "medium";
      }

      if (dryRun) {
        log(`[DRY-RUN] Would insert advisory ${advisoryId}: ${title} (${severity}, ${cves.length} CVEs, ${products.length} products)`);
      } else {
        insertAdvisory.run(
          advisoryId,
          title,
          date,
          severity,
          products.length > 0 ? JSON.stringify(products) : null,
          summary,
          fullText,
          cves.length > 0 ? JSON.stringify(cves) : null,
        );
        state.advisoriesCompleted.push(advisoryId);
      }

      ingested++;

      if (ingested % 25 === 0) {
        log(`Progress: ${ingested}/${pending.length} advisories ingested (${failed} failed)`);
        if (!dryRun) saveState(state);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      error(`Failed to ingest ${advisoryId}: ${msg}`);
      failed++;
    }
  }

  if (!dryRun) saveState(state);

  log(`Advisory ingestion complete: ${ingested} ingested, ${failed} failed`);
  return ingested;
}

function extractIdFromPath(csafPath: string): string {
  // "2026/ncsc-2026-0099.json" -> "NCSC-2026-0099"
  const filename = csafPath.split("/").pop() ?? csafPath;
  return filename.replace(".json", "").toUpperCase();
}

// ---------------------------------------------------------------------------
// Guidance ingestion (HTML scraping)
// ---------------------------------------------------------------------------

/**
 * Extract the publication date from the URL path.
 * NCSC publication URLs follow the pattern:
 *   /documenten/publicaties/YYYY/maand/DD/slug
 *   /documenten/factsheets/YYYY/maand/DD/slug
 *
 * Dutch month names map: januari=01, februari=02, ..., december=12
 */
const DUTCH_MONTHS: Record<string, string> = {
  januari: "01",
  februari: "02",
  maart: "03",
  april: "04",
  mei: "05",
  juni: "06",
  juli: "07",
  augustus: "08",
  september: "09",
  oktober: "10",
  november: "11",
  december: "12",
};

function extractDateFromUrl(urlPath: string): string | null {
  // Match /YYYY/month/DD/ in the URL path
  const match = urlPath.match(/\/(\d{4})\/([\w]+)\/(\d{1,2})\//);
  if (!match) return null;
  const [, year, monthStr, day] = match;
  if (!year || !monthStr || !day) return null;
  const month = DUTCH_MONTHS[monthStr.toLowerCase()];
  if (!month) return null;
  return `${year}-${month}-${day.padStart(2, "0")}`;
}

/**
 * Determine the document type from the URL path.
 */
function extractTypeFromUrl(urlPath: string): string {
  if (urlPath.includes("/factsheets/")) return "factsheet";
  if (urlPath.includes("/publicaties/") && urlPath.includes("richtlijn")) return "guideline";
  if (urlPath.includes("/publicaties/")) return "publication";
  return "guidance";
}

/**
 * Generate a stable reference ID from the URL path.
 */
function generateReference(urlPath: string): string {
  // Take the last segment of the URL as the slug
  const segments = urlPath.split("/").filter((s) => s.length > 0);
  const slug = segments[segments.length - 1] ?? "unknown";
  // Prefix with NCSC-NL-PUB- and truncate slug to 60 chars
  const cleanSlug = slug
    .replace(/[^a-z0-9-]/gi, "-")
    .replace(/-+/g, "-")
    .slice(0, 60)
    .replace(/-$/, "");
  return `NCSC-NL-PUB-${cleanSlug}`.toUpperCase();
}

/**
 * Determine the series/framework from the page content or URL.
 */
function detectSeries(urlPath: string, title: string): string | null {
  const lower = (urlPath + " " + title).toLowerCase();
  if (lower.includes("tls") || lower.includes("transport-layer-security")) return "TLS-richtlijnen";
  if (lower.includes("basisprincip")) return "Basisprincipes";
  if (lower.includes("nis2") || lower.includes("cyberbeveiligingswet")) return "NIS2";
  if (lower.includes("iacs") || lower.includes("ot/")) return "OT/IACS";
  if (lower.includes("risicomanagement")) return "Risicomanagement";
  if (lower.includes("incident")) return "Incidenten";
  if (lower.includes("quantum")) return "Cryptografie";
  return null;
}

async function scrapeGuidancePage(
  urlPath: string,
): Promise<{
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string | null;
  summary: string | null;
  full_text: string;
  topics: string | null;
  status: string;
} | null> {
  const url = urlPath.startsWith("http") ? urlPath : `${NCSC_BASE}${urlPath}`;

  const html = await fetchText(url);
  const $ = cheerio.load(html);

  // Extract title from <title> tag or first <h1>
  let title = $("h1").first().text().trim();
  if (!title) {
    title = $("title").text().trim().replace(/\s*\|.*$/, "").replace(/^NCSC\s*-\s*/, "");
  }
  if (!title) {
    warn(`No title found for ${urlPath}, skipping`);
    return null;
  }

  // Extract meta description as summary
  const metaDesc =
    $('meta[name="description"]').attr("content")?.trim() ??
    $('meta[property="og:description"]').attr("content")?.trim() ??
    null;

  // Extract main content text.
  // ncsc.nl uses Next.js; the main content is usually inside <main> or
  // elements with role="main". We strip navigation, footer, and scripts.
  $("nav, footer, script, style, noscript, header, [role='banner']").remove();

  // Grab all paragraph and list text from the main body
  const contentParts: string[] = [];
  $("main p, main li, main h2, main h3, main h4, [role='main'] p, [role='main'] li, [role='main'] h2, [role='main'] h3, article p, article li, article h2, article h3").each((_, el) => {
    const text = $(el).text().trim();
    if (text.length > 0) {
      contentParts.push(text);
    }
  });

  // If <main> extraction yielded nothing, fall back to body text
  if (contentParts.length === 0) {
    $("body p, body li, body h2, body h3").each((_, el) => {
      const text = $(el).text().trim();
      if (text.length > 20) {
        contentParts.push(text);
      }
    });
  }

  const fullText = contentParts.join("\n\n");
  if (fullText.length < 50) {
    warn(`Insufficient content for ${urlPath} (${fullText.length} chars), skipping`);
    return null;
  }

  // Try to find an English title from alternate link tags
  const enLink = $('link[hreflang="en"]').attr("href");
  let titleEn: string | null = null;
  if (enLink) {
    // We do not fetch the English page to respect rate limits.
    // The alternate link presence is enough to note that an English version exists.
    titleEn = null;
  }

  // Detect topics from the content
  const topics = detectTopics(fullText, title, urlPath);

  return {
    reference: generateReference(urlPath),
    title,
    title_en: titleEn,
    date: extractDateFromUrl(urlPath),
    type: extractTypeFromUrl(urlPath),
    series: detectSeries(urlPath, title),
    summary: metaDesc,
    full_text: fullText,
    topics: topics.length > 0 ? JSON.stringify(topics) : null,
    status: "current",
  };
}

/**
 * Extract topic keywords from the content.
 */
function detectTopics(fullText: string, title: string, urlPath: string): string[] {
  const combined = (fullText + " " + title + " " + urlPath).toLowerCase();
  const topicMap: Record<string, string> = {
    "nis2": "NIS2",
    "cyberbeveiligingswet": "Cyberbeveiligingswet",
    "tls": "TLS",
    "transport layer security": "TLS",
    "kwantum": "quantum-cryptografie",
    "quantum": "quantum-cryptografie",
    "ransomware": "ransomware",
    "phishing": "phishing",
    "wachtwoord": "authenticatie",
    "authenticatie": "authenticatie",
    "multi-factor": "MFA",
    "tweestapsverificatie": "MFA",
    "back-up": "back-up",
    "netwerksegmentatie": "netwerksegmentatie",
    "patch": "patch-management",
    "cloud": "cloud",
    "logging": "logging",
    "monitoring": "monitoring",
    "iacs": "OT/IACS",
    "operationele technologie": "OT/IACS",
    "risicomanagement": "risicomanagement",
    "incident": "incident-response",
    "toeleveringsketen": "supply-chain",
    "supply chain": "supply-chain",
    "basisprincip": "basisprincipes",
    "webapplicatie": "webapplicaties",
    "encryptie": "cryptografie",
    "versleutel": "cryptografie",
    "ddos": "DDoS",
    "zero-day": "zero-day",
    "zeroday": "zero-day",
    "vulnerability": "kwetsbaarheden",
    "kwetsbaarh": "kwetsbaarheden",
    "meldplicht": "meldplicht",
  };

  const found = new Set<string>();
  for (const [keyword, topic] of Object.entries(topicMap)) {
    if (combined.includes(keyword)) {
      found.add(topic);
    }
  }

  return [...found].slice(0, 10);
}

async function ingestGuidance(
  db: Database.Database,
  state: IngestState,
): Promise<number> {
  log("Starting guidance ingestion from ncsc.nl...");

  const completedSet = new Set(state.guidanceCompleted);
  const pending = GUIDANCE_URLS.filter((u) => !completedSet.has(u));

  if (resume && pending.length < GUIDANCE_URLS.length) {
    log(`Resuming: ${GUIDANCE_URLS.length - pending.length} guidance pages already ingested, ${pending.length} remaining`);
  }

  // Also try to discover additional guidance URLs from the main documents page
  const discoveredUrls = await discoverGuidanceUrls();
  for (const url of discoveredUrls) {
    if (!pending.includes(url) && !completedSet.has(url)) {
      pending.push(url);
    }
  }

  log(`${pending.length} guidance pages to process`);

  const insertGuidance = db.prepare(`
    INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES
      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  let ingested = 0;
  let failed = 0;

  for (const urlPath of pending) {
    try {
      const doc = await scrapeGuidancePage(urlPath);
      if (!doc) {
        warn(`Skipped ${urlPath} (no extractable content)`);
        state.guidanceCompleted.push(urlPath);
        continue;
      }

      if (dryRun) {
        log(`[DRY-RUN] Would insert guidance ${doc.reference}: ${doc.title} (${doc.type})`);
      } else {
        insertGuidance.run(
          doc.reference,
          doc.title,
          doc.title_en,
          doc.date,
          doc.type,
          doc.series,
          doc.summary,
          doc.full_text,
          doc.topics,
          doc.status,
        );
        state.guidanceCompleted.push(urlPath);
      }

      ingested++;
      log(`Ingested guidance: ${doc.title}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      error(`Failed to ingest guidance from ${urlPath}: ${msg}`);
      failed++;
    }
  }

  if (!dryRun) saveState(state);

  log(`Guidance ingestion complete: ${ingested} ingested, ${failed} failed`);
  return ingested;
}

/**
 * Try to discover additional guidance URLs from the NCSC documents listing.
 * The ncsc.nl documents page uses dynamic rendering, so we attempt to parse
 * whatever HTML is available and extract links to publication pages.
 */
async function discoverGuidanceUrls(): Promise<string[]> {
  const discovered: string[] = [];

  // Try multiple paginated pages
  for (let page = 1; page <= 5; page++) {
    try {
      const url = `${NCSC_BASE}/documenten?pagina=${page}`;
      const html = await fetchText(url);
      const $ = cheerio.load(html);

      // Look for links to publication and factsheet pages
      $("a[href]").each((_, el) => {
        const href = $(el).attr("href");
        if (!href) return;

        // Match publication and factsheet URL patterns
        if (
          href.match(/\/documenten\/(publicaties|factsheets)\/\d{4}\//) ||
          href.match(/\/binaries\/ncsc\/documenten\//)
        ) {
          // Only include HTML pages, not PDFs
          if (!href.endsWith(".pdf") && !href.includes("/binaries/")) {
            const clean = href.startsWith("http")
              ? new URL(href).pathname
              : href;
            discovered.push(clean);
          }
        }
      });
    } catch {
      // Dynamic pages may not render; this is expected
      break;
    }
  }

  if (discovered.length > 0) {
    log(`Discovered ${discovered.length} additional guidance URLs from document listings`);
  }

  return [...new Set(discovered)];
}

// ---------------------------------------------------------------------------
// Framework seeding
// ---------------------------------------------------------------------------

function seedFrameworks(db: Database.Database): void {
  log("Seeding framework metadata...");

  const frameworks = [
    {
      id: "bio",
      name: "Baseline Informatiebeveiliging Overheid (BIO)",
      name_en: "Baseline Information Security Government",
      description: "Het verplichte normenkader voor informatiebeveiliging voor alle Nederlandse overheidsorganisaties, gebaseerd op ISO 27001/27002. Vervangt de voormalige BIR, BIG, IBI en BIWA.",
    },
    {
      id: "tls-richtlijnen",
      name: "ICT-beveiligingsrichtlijnen voor TLS",
      name_en: "ICT Security Guidelines for TLS",
      description: "Technische richtlijnen voor de configuratie van Transport Layer Security (TLS) protocollen, bedoeld voor gebruik bij inkoop, inrichting of beoordeling van TLS-configuraties op servers.",
    },
    {
      id: "nis2",
      name: "NIS2 / Cyberbeveiligingswet (Cbw)",
      name_en: "NIS2 / Dutch Cybersecurity Act",
      description: "Het Nederlandse implementatiekader voor de Europese NIS2-richtlijn. Definieert verplichtingen voor essentieel en belangrijk aangemerkte entiteiten op het gebied van cybersecurity en incidentmelding.",
    },
    {
      id: "basisprincipes",
      name: "5 Basisprincipes van Digitale Weerbaarheid",
      name_en: "5 Basic Principles of Digital Resilience",
      description: "De vijf basisprincipes van het NCSC-NL en DTC voor digitale veiligheid: risicos in kaart brengen, veilig gedrag bevorderen, systemen beschermen, toegang beheren en voorbereiden op incidenten.",
    },
    {
      id: "ot-iacs",
      name: "Basismaatregelen voor OT/IACS Cybersecurity",
      name_en: "Basic Measures for OT/IACS Cybersecurity",
      description: "Richtlijnen voor de beveiliging van operationele technologie (OT) en industriele automatiserings- en controlesystemen (IACS), gebaseerd op IEC 62443 en het ISA-95 referentiemodel.",
    },
    {
      id: "webapplicaties",
      name: "ICT-beveiligingsrichtlijnen voor Webapplicaties",
      name_en: "ICT Security Guidelines for Web Applications",
      description: "Technische beveiligingsrichtlijnen voor ontwikkelaars en beheerders van webapplicaties, gebaseerd op de OWASP Top 10 en andere geaccepteerde standaarden.",
    },
  ];

  const insert = db.prepare(
    "INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, 0)",
  );

  const tx = db.transaction(() => {
    for (const f of frameworks) {
      insert.run(f.id, f.name, f.name_en, f.description);
    }
  });
  tx();

  // Update document_count based on actual guidance rows linked to each series
  const updateCount = db.prepare(
    "UPDATE frameworks SET document_count = (SELECT count(*) FROM guidance WHERE series = ?) WHERE id = ?",
  );

  const seriesMapping: Record<string, string> = {
    "bio": "BIO",
    "tls-richtlijnen": "TLS-richtlijnen",
    "nis2": "NIS2",
    "basisprincipes": "Basisprincipes",
    "ot-iacs": "OT/IACS",
    "webapplicaties": "ICT-beveiligingsrichtlijnen",
  };

  for (const [id, series] of Object.entries(seriesMapping)) {
    updateCount.run(series, id);
  }

  log(`Seeded ${frameworks.length} frameworks`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  log("=== NCSC-NL Ingestion Crawler ===");
  log(`Database: ${DB_PATH}`);
  log(`Flags: ${[
    dryRun ? "--dry-run" : "",
    resume ? "--resume" : "",
    force ? "--force" : "",
    advisoriesOnly ? "--advisories-only" : "",
    guidanceOnly ? "--guidance-only" : "",
    maxAdvisories > 0 ? `--max-advisories ${maxAdvisories}` : "",
  ].filter(Boolean).join(" ") || "(none)"}`);

  // Ensure data directory exists
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
    log(`Created data directory: ${dir}`);
  }

  // Handle --force: delete existing DB
  if (force && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    log(`Deleted existing database at ${DB_PATH}`);
  }

  // Load resume state
  const state = resume ? loadState() : { advisoriesCompleted: [], guidanceCompleted: [], lastRun: "" };
  if (resume && state.lastRun) {
    log(`Resuming from previous run at ${state.lastRun}`);
  }

  // Open database
  let db: Database.Database;
  if (dryRun) {
    // In dry-run mode, use an in-memory database for schema validation
    db = new Database(":memory:");
  } else {
    db = new Database(DB_PATH);
  }
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);

  if (!dryRun) {
    log(`Database initialized at ${DB_PATH}`);
  }

  const startTime = Date.now();
  let totalAdvisories = 0;
  let totalGuidance = 0;

  try {
    // Ingest advisories (CSAF feed)
    if (!guidanceOnly) {
      totalAdvisories = await ingestAdvisories(db, state);
    }

    // Ingest guidance (HTML scraping)
    if (!advisoriesOnly) {
      totalGuidance = await ingestGuidance(db, state);
    }

    // Seed/update framework metadata
    if (!dryRun) {
      seedFrameworks(db);
    }

    // Final summary
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    if (!dryRun) {
      const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
      const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
      const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

      log("");
      log("=== Ingestion Summary ===");
      log(`  Advisories ingested this run: ${totalAdvisories}`);
      log(`  Guidance ingested this run:   ${totalGuidance}`);
      log(`  Elapsed: ${elapsed}s`);
      log("");
      log("=== Database Totals ===");
      log(`  Advisories:  ${advisoryCount}`);
      log(`  Guidance:    ${guidanceCount}`);
      log(`  Frameworks:  ${frameworkCount}`);
      log(`  Database:    ${DB_PATH}`);
    } else {
      log("");
      log("=== Dry Run Summary ===");
      log(`  Advisories found: ${totalAdvisories}`);
      log(`  Guidance found:   ${totalGuidance}`);
      log(`  Elapsed: ${elapsed}s`);
      log("  No data was written.");
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    error(`Fatal error: ${msg}`);
    if (!dryRun) saveState(state);
    process.exit(1);
  } finally {
    db.close();
  }

  log("Done.");
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  error(`Unhandled error: ${msg}`);
  process.exit(1);
});
