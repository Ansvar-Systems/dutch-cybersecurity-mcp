/**
 * Seed the NCSC-NL database with sample guidance documents, advisories, and
 * frameworks for testing.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["NCSCNL_DB_PATH"] ?? "data/ncsc-nl.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

if (force && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);

console.log(`Database initialised at ${DB_PATH}`);

// --- Frameworks --------------------------------------------------------------

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

const frameworks: FrameworkRow[] = [
  {
    id: "bio",
    name: "Baseline Informatiebeveiliging Overheid (BIO)",
    name_en: "Baseline Information Security Government",
    description: "De Baseline Informatiebeveiliging Overheid (BIO) is het basisnormenkader voor informatiebeveiliging binnen de gehele Nederlandse overheid. De BIO is gebaseerd op ISO 27001/27002 en vervangt de verschillende basisregelingen voor Rijk, provincies, gemeenten en waterschappen.",
    document_count: 2,
  },
  {
    id: "ict-richtlijnen",
    name: "ICT-beveiligingsrichtlijnen voor webapplicaties",
    name_en: "ICT Security Guidelines for Web Applications",
    description: "De NCSC-NL ICT-beveiligingsrichtlijnen voor webapplicaties bevatten concrete technische maatregelen voor het beveiligen van webapplicaties. Ze zijn onderverdeeld in richtlijnen voor authenticatie, sessiemanagement, invoervalidatie en meer.",
    document_count: 1,
  },
  {
    id: "nis2",
    name: "NIS2 Implementatiekader voor Nederland",
    name_en: "NIS2 Implementation Framework for the Netherlands",
    description: "Het Nederlandse implementatiekader voor de Europese NIS2-richtlijn. Definieert welke organisaties onder de richtlijn vallen, welke maatregelen zij moeten nemen en hoe incidenten gemeld moeten worden aan het NCSC-NL.",
    document_count: 1,
  },
];

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);

for (const f of frameworks) {
  insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
}

console.log(`Inserted ${frameworks.length} frameworks`);

// --- Guidance ----------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

const guidance: GuidanceRow[] = [
  {
    reference: "NCSC-NL-BIO-2023",
    title: "Baseline Informatiebeveiliging Overheid (BIO) 2023",
    title_en: "Baseline Information Security Government (BIO) 2023",
    date: "2023-01-01",
    type: "framework",
    series: "BIO",
    summary: "De Baseline Informatiebeveiliging Overheid (BIO) 2023 is het verplichte normenkader voor informatiebeveiliging voor alle Nederlandse overheidsorganisaties. Gebaseerd op ISO 27001:2022 en ISO 27002:2022 met specifieke eisen voor de overheidscontext.",
    full_text: "De Baseline Informatiebeveiliging Overheid (BIO) is het gezamenlijke normenkader voor alle overheidslagen in Nederland: Rijk, provincies, gemeenten en waterschappen. De BIO is gebaseerd op de internationale normen ISO 27001 en ISO 27002 en bevat aanvullende overheidsspecifieke eisen. Structuur van de BIO: De BIO is opgebouwd uit maatregelen op basis van ISO 27002. Per maatregel is aangegeven of het gaat om een verplichte maatregel (Basis) of een richtlijn (Aanbeveling). Implementatieniveaus: (1) Verplicht — maatregelen die alle overheidsorganisaties moeten implementeren; (2) Aanbevolen — maatregelen die aanbevolen worden maar waarbij afwijken mogelijk is met onderbouwde risicoafweging. Risicobeheer: De BIO schrijft voor dat overheidsorganisaties een risicoanalyse uitvoeren en op basis daarvan aanvullende maatregelen nemen. Toezicht: Overheidsorganisaties zijn verplicht een ISAE 3402-verklaring of gelijkwaardige assuranceverklaring te leveren over de naleving van de BIO. Het NCSC-NL biedt ondersteuning bij de implementatie en publiceert factsheets en handleidingen.",
    topics: JSON.stringify(["BIO", "ISO-27001", "overheid", "gemeente", "informatiebeveiliging"]),
    status: "current",
  },
  {
    reference: "NCSC-NL-ICT-2023",
    title: "ICT-beveiligingsrichtlijnen voor webapplicaties",
    title_en: "ICT Security Guidelines for Web Applications",
    date: "2023-04-01",
    type: "technical",
    series: "ICT-beveiligingsrichtlijnen",
    summary: "Technische richtlijnen van het NCSC-NL voor het beveiligen van webapplicaties. Bevat concrete maatregelen voor authenticatie, autorisatie, sessiemanagement, invoervalidatie, cryptografie en veilige configuratie.",
    full_text: "De ICT-beveiligingsrichtlijnen voor webapplicaties van het NCSC-NL bieden concrete technische maatregelen voor ontwikkelaars en beheerders van webapplicaties. De richtlijnen zijn gebaseerd op de OWASP Top 10 en andere geaccepteerde standaarden. Hoofdthemas: (1) Authenticatie — gebruik sterke authenticatiemechanismen, implementeer multi-factorauthenticatie voor gevoelige functies, beperk inlogpogingen, gebruik veilige wachtwoordopslag (bcrypt, Argon2); (2) Autorisatie — implementeer toegangscontrole op basis van het principe van minimale rechten, valideer autorisatie bij elke request, gebruik veilige direct object references; (3) Sessiemanagement — genereer sessietokens met voldoende entropie, vernieuw sessietokens na authenticatie, implementeer sessietime-outs; (4) Invoervalidatie — valideer alle invoer aan de serverzijde, gebruik parameterized queries ter preventie van SQL-injectie, encode uitvoer om XSS te voorkomen; (5) Cryptografie — gebruik TLS 1.2 of hoger, vermijd zwakke algoritmen (MD5, SHA-1, RC4), sla gevoelige gegevens versleuteld op; (6) Configuratie — verwijder standaardwachtwoorden, beperk foutmeldingen, implementeer beveiligingsheaders (CSP, HSTS, X-Frame-Options).",
    topics: JSON.stringify(["webapplicaties", "OWASP", "authenticatie", "TLS", "beveiliging"]),
    status: "current",
  },
  {
    reference: "NCSC-NL-AP-2024",
    title: "Aanpak Digitale Weerbaarheid voor MKB",
    title_en: "Digital Resilience Approach for SMEs",
    date: "2024-01-15",
    type: "guidance",
    series: "NCSC-NL",
    summary: "Praktische gids van het NCSC-NL voor het midden- en kleinbedrijf (MKB) om de digitale weerbaarheid te verbeteren. Bevat vijf basismaatregelen die elk MKB minimaal moet treffen: updates, back-ups, sterke wachtwoorden, tweestapsverificatie en antivirussoftware.",
    full_text: "Het NCSC-NL heeft een praktische aanpak ontwikkeld voor het MKB om de digitale weerbaarheid te vergroten. Vijf basismaatregelen: (1) Installeer updates — zorg dat alle apparaten, besturingssystemen en software up-to-date zijn. Stel automatische updates in waar mogelijk. Verwijder software die niet meer ondersteund wordt; (2) Maak regelmatig back-ups — maak dagelijks back-ups van kritieke data. Bewaar back-ups op een locatie die niet direct verbonden is met het netwerk. Test regelmatig of herstellen van back-ups werkt; (3) Gebruik sterke wachtwoorden — gebruik lange, unieke wachtwoorden. Gebruik een wachtwoordmanager. Verander standaardwachtwoorden van apparaten en diensten; (4) Gebruik tweestapsverificatie — activeer tweestapsverificatie op alle accounts waar mogelijk, in het bijzonder voor e-mail, cloudopslag en financiele diensten; (5) Installeer antivirussoftware — gebruik antivirussoftware op alle apparaten en houd deze up-to-date. Schakel ook de ingebouwde firewall in. Boven op deze vijf basismaatregelen geeft het NCSC-NL aanvullende adviezen voor bewustwording van personeel, veilige configuratie van thuiswerkoplossingen en het omgaan met phishing.",
    topics: JSON.stringify(["MKB", "digitale-weerbaarheid", "basis-maatregelen", "back-up"]),
    status: "current",
  },
  {
    reference: "NCSC-NL-NIS2-2024",
    title: "NIS2 in Nederland — Verplichtingen en implementatie",
    title_en: "NIS2 in the Netherlands — Obligations and Implementation",
    date: "2024-04-01",
    type: "guidance",
    series: "NIS2",
    summary: "Overzicht van de verplichtingen onder de Nederlandse implementatie van de NIS2-richtlijn. Beschrijft welke organisaties als essentieel of belangrijk worden aangemerkt, welke beveiligingsmaatregelen verplicht zijn en hoe incidenten gemeld moeten worden aan het NCSC-NL.",
    full_text: "De NIS2-richtlijn (Network and Information Security 2) is in Nederland geimplementeerd via de Wet beveiliging netwerk- en informatiesystemen (Wbni) en nadere regelgeving. Het NCSC-NL is het Computer Security Incident Response Team (CSIRT) voor de Nederlandse overheid en vitale aanbieders. Toepassingsgebied: Essentieel aangemerkte entiteiten (grote organisaties in sectoren energie, transport, bankwezen, financiele marktinfrastructuur, gezondheidszorg, drinkwater, afvalwater, digitale infrastructuur, beheer van ICT-diensten, overheid, ruimtevaart). Belangrijk aangemerkte entiteiten (middelgrote organisaties in dezelfde sectoren, plus post- en koeriersdiensten, afvalbeheer, chemie, levensmiddelen, maakindustrie, digitale aanbieders). Beveiligingsmaatregelen: risicoanalyse, beveiligingsbeleid, bedrijfscontinuiteit, beveiliging van de toeleveringsketen, gebruik van cryptografie, toegangscontrole, vulnerability management. Meldplicht: significante incidenten moeten binnen 24 uur worden gemeld bij het NCSC-NL (vroege waarschuwing) en binnen 72 uur (incidentmelding). Sancties: boetes tot EUR 10 miljoen of 2% van de wereldwijde jaaromzet voor essentieel aangemerkte entiteiten.",
    topics: JSON.stringify(["NIS2", "Wbni", "meldplicht", "essentieel", "incidenten"]),
    status: "current",
  },
  {
    reference: "NCSC-NL-CLOUD-2023",
    title: "Handreiking Cloudbeveiliging voor organisaties",
    title_en: "Cloud Security Guidance for Organizations",
    date: "2023-09-01",
    type: "guidance",
    series: "NCSC-NL",
    summary: "Handreiking van het NCSC-NL voor het veilig gebruik van clouddiensten. Behandelt de verantwoordelijkheidsverdeling tussen cloudgebruiker en cloudaanbieder (shared responsibility model), de selectie van cloudaanbieders en beveiligingseisen voor cloudmigratie.",
    full_text: "De handreiking cloudbeveiliging van het NCSC-NL helpt organisaties bij het veilig gebruikmaken van clouddiensten. Gedeelde verantwoordelijkheid (shared responsibility model): Bij gebruik van clouddiensten is de verantwoordelijkheid voor beveiliging gedeeld tussen de cloudaanbieder en de organisatie. IaaS: de aanbieder beveiligt de fysieke infrastructuur; de organisatie beveiligt het besturingssysteem, de middleware en de applicaties. PaaS: de aanbieder beveiligt de infrastructuur en het platform; de organisatie beveiligt de applicaties en data. SaaS: de aanbieder beveiligt nagenoeg alles; de organisatie beheert gebruikersaccounts en configuratie. Selectie van cloudaanbieders: beoordeel de beveiligingscertificeringen (ISO 27001, SOC 2, C5 van het BSI), de datalocatie en jurisdictie, de contractuele bepalingen over data-eigendom en vertrouwelijkheid, de exitstrategie. Beveiligingsmaatregelen voor cloudgebruik: gebruik sterke identiteits- en toegangsbeheer (IAM), versleutel data in rust en in transit, configureer monitoring en logging, voer regelmatig beveiligingsaudits uit.",
    topics: JSON.stringify(["cloud", "shared-responsibility", "IaaS", "SaaS", "beveiliging"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`
  INSERT OR IGNORE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertGuidanceAll = db.transaction(() => {
  for (const g of guidance) {
    insertGuidance.run(
      g.reference, g.title, g.title_en, g.date, g.type,
      g.series, g.summary, g.full_text, g.topics, g.status,
    );
  }
});

insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

// --- Advisories --------------------------------------------------------------

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string;
}

const advisories: AdvisoryRow[] = [
  {
    reference: "NCSC-NL-ADV-2024-001",
    title: "Actieve uitbuiting van kwetsbaarheden in Ivanti Connect Secure",
    date: "2024-01-12",
    severity: "critical",
    affected_products: JSON.stringify(["Ivanti Connect Secure", "Ivanti Policy Secure"]),
    summary: "Het NCSC-NL waarschuwt voor actieve uitbuiting van kritieke kwetsbaarheden in Ivanti Connect Secure en Policy Secure. CVE-2023-46805 en CVE-2024-21887 worden gecombineerd gebruikt voor niet-geauthenticeerde code-uitvoering op afstand.",
    full_text: "Het NCSC-NL heeft kennis genomen van de actieve uitbuiting van twee kritieke kwetsbaarheden in Ivanti Connect Secure (voorheen Pulse Secure) en Ivanti Policy Secure. CVE-2023-46805 (CVSS 8.2) is een authenticatie-omzeiling en CVE-2024-21887 (CVSS 9.1) is een command-injectie kwetsbaarheid. Samen stellen ze aanvallers in staat om zonder authenticatie code uit te voeren op de getroffen systemen. Aanvallers, waaronder door overheden gesponsorde actoren, hebben de kwetsbaarheden actief uitgebuit om toegang te verkrijgen tot doelnetwerken. Het NCSC-NL heeft van Nederlandse organisaties vernomen dat zij zijn getroffen. Getroffen versies: Ivanti Connect Secure 9.x en 22.x, Ivanti Policy Secure 22.x. Aanbevolen maatregelen: pas de beveiligingsupdates van Ivanti onmiddellijk toe, voer een fabrieksreset uit als compromittering wordt vermoed, roteer alle mogelijk gecompromitteerde credentials. Meld compromittering aan het NCSC-NL.",
    cve_references: JSON.stringify(["CVE-2023-46805", "CVE-2024-21887"]),
  },
  {
    reference: "NCSC-NL-ADV-2023-020",
    title: "Ransomware-aanvallen op Nederlandse organisaties — NCSC-NL advies",
    date: "2023-10-05",
    severity: "high",
    affected_products: JSON.stringify(["Windows Server", "VMware ESXi", "Citrix ADC"]),
    summary: "Het NCSC-NL signaleert een toename van ransomware-aanvallen gericht op Nederlandse organisaties in diverse sectoren. Aanvallers richten zich op kwetsbare VPN- en remote access-oplossingen als initieel toegangspunt.",
    full_text: "Het NCSC-NL constateert een verhoogde dreiging van ransomware voor Nederlandse organisaties. Meerdere ransomwaregroepen — waaronder LockBit, ALPHV/BlackCat en Cl0p — zijn actief met aanvallen op Nederlandse doelen in sectoren als gezondheidszorg, logistiek, maakindustrie en professionele diensten. Veelgebruikte initiole toegangsvectoren: uitbuiting van kwetsbaarheden in VPN-oplossingen (Ivanti, Cisco, Fortinet), uitbuiting van kwetsbaarheden in Citrix ADC/Gateway, gebruik van gecompromitteerde RDP-credentials, phishing-campagnes gericht op medewerkers met toegang tot kritieke systemen. Aanbevolen maatregelen: (1) Patch management — pas beveiligingsupdates onmiddellijk toe, met prioriteit voor internet-facing systemen; (2) Multi-factorauthenticatie — implementeer MFA voor alle externe toegang en privileged accounts; (3) Netwerksegmentatie — segmenteer het netwerk om laterale beweging te beperken; (4) Back-up — zorg voor offline back-ups en test herstelprocessen regelmatig; (5) Monitoring — implementeer centraal logging en detecteer afwijkend gedrag. Meld ransomware-incidenten aan het NCSC-NL en de politie (Team High Tech Crime).",
    cve_references: JSON.stringify(["CVE-2023-46805", "CVE-2023-4966", "CVE-2023-20269"]),
  },
  {
    reference: "NCSC-NL-ADV-2024-005",
    title: "Kritieke kwetsbaarheid in Fortinet FortiOS SSL-VPN",
    date: "2024-02-14",
    severity: "critical",
    affected_products: JSON.stringify(["Fortinet FortiOS", "Fortinet FortiProxy"]),
    summary: "Het NCSC-NL waarschuwt voor actieve uitbuiting van CVE-2024-21762 in Fortinet FortiOS en FortiProxy. De kwetsbaarheid maakt niet-geauthenticeerde code-uitvoering op afstand mogelijk via de SSL-VPN functionaliteit.",
    full_text: "CVE-2024-21762 (CVSS 9.6) is een out-of-bounds write kwetsbaarheid in de FortiOS SSL-VPN daemon die een niet-geauthenticeerde aanvaller in staat stelt om code op afstand uit te voeren via speciaal geconstrueerde HTTP-verzoeken. Fortinet heeft bevestigd dat de kwetsbaarheid actief wordt uitgebuit. Het NCSC-NL heeft indicaties dat Nederlandse organisaties zijn getroffen. Getroffen versies: FortiOS 7.4.0-7.4.2 (gepatcht in 7.4.3), FortiOS 7.2.0-7.2.6 (gepatcht in 7.2.7), FortiOS 7.0.0-7.0.13 (gepatcht in 7.0.14), FortiOS 6.4.0-6.4.14 (gepatcht in 6.4.15), FortiProxy 7.4.0-7.4.2 (gepatcht in 7.4.3). Aanbevolen maatregelen: pas updates onmiddellijk toe, schakel SSL-VPN uit als patching niet direct mogelijk is, controleer logs op aanwijzingen van compromittering, meld compromittering aan het NCSC-NL.",
    cve_references: JSON.stringify(["CVE-2024-21762", "CVE-2024-23108", "CVE-2024-23109"]),
  },
];

const insertAdvisory = db.prepare(`
  INSERT OR IGNORE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAdvisoriesAll = db.transaction(() => {
  for (const a of advisories) {
    insertAdvisory.run(
      a.reference, a.title, a.date, a.severity,
      a.affected_products, a.summary, a.full_text, a.cve_references,
    );
  }
});

insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

console.log(`\nDatabase summary:`);
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`\nDone. Database ready at ${DB_PATH}`);

db.close();
