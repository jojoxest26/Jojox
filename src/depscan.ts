import type { Finding, Severity, SourceFile } from "./types.js";
import { SKIP_PATH } from "./analyze.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
/** Il limite ufficiale di OSV.dev per /v1/querybatch è 1000 query — restiamo ben sotto per gentilezza verso il servizio pubblico. */
const OSV_BATCH_CHUNK_SIZE = 100;
const LOCKFILE_NAME = "package-lock.json";

export interface NpmDependency {
  name: string;
  version: string;
}

interface OsvBatchQueryResult {
  vulns?: { id: string }[];
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  database_specific?: { severity?: string };
  affected?: OsvAffected[];
}

/**
 * Estrae la lista di dipendenze (nome + versione esatta installata) da un
 * package-lock.json, in qualunque lockfileVersion (1, 2 o 3) sia stato
 * generato — i formati sono molto diversi tra loro:
 * - v2/v3: una mappa piatta "packages", con chiavi tipo "node_modules/lodash"
 *   (o "node_modules/a/node_modules/b" per le dipendenze annidate).
 * - v1: un albero ricorsivo "dependencies", con lo stesso nome che può
 *   comparire più volte a livelli diversi se installato in versioni diverse.
 * Ritorna un elenco deduplicato per coppia nome+versione.
 */
export function parseNpmLockfile(content: string): NpmDependency[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  if (!data || typeof data !== "object") return [];

  const seen = new Set<string>();
  const deps: NpmDependency[] = [];
  const add = (name: string, version: string): void => {
    if (!name || !version) return;
    const key = `${name}@${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push({ name, version });
  };

  const packages = (data as Record<string, unknown>).packages;
  const dependencies = (data as Record<string, unknown>).dependencies;

  if (packages && typeof packages === "object") {
    for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
      if (key === "") continue; // il pacchetto radice del progetto stesso, non una dipendenza
      const idx = key.lastIndexOf("node_modules/");
      if (idx === -1) continue;
      const name = key.slice(idx + "node_modules/".length);
      const version = (value as Record<string, unknown> | undefined)?.version;
      if (typeof version === "string") add(name, version);
    }
  } else if (dependencies && typeof dependencies === "object") {
    const walk = (tree: Record<string, unknown>): void => {
      for (const [name, value] of Object.entries(tree)) {
        const entry = value as Record<string, unknown> | undefined;
        const version = entry?.version;
        if (typeof version === "string") add(name, version);
        const nested = entry?.dependencies;
        if (nested && typeof nested === "object") walk(nested as Record<string, unknown>);
      }
    };
    walk(dependencies as Record<string, unknown>);
  }

  return deps;
}

function depKey(dep: NpmDependency): string {
  return `${dep.name}@${dep.version}`;
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Interroga OSV.dev in batch per sapere quali, tra le dipendenze passate,
 * hanno vulnerabilità note — ritorna solo gli ID, non i dettagli (l'endpoint
 * batch è pensato per essere veloce su tanti pacchetti insieme, i dettagli
 * si recuperano dopo solo per gli ID trovati). Se OSV.dev non è
 * raggiungibile, la scansione dipendenze torna vuota invece di far fallire
 * il resto dell'analisi — è un controllo aggiuntivo "best effort", non il
 * motore principale basato su pattern.
 */
async function queryOsvBatch(deps: NpmDependency[], ecosystem: string): Promise<Map<string, string[]>> {
  const result = new Map<string, string[]>();

  for (const batch of chunk(deps, OSV_BATCH_CHUNK_SIZE)) {
    let json: { results?: OsvBatchQueryResult[] };
    try {
      const res = await fetch(OSV_BATCH_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: batch.map((d) => ({ package: { name: d.name, ecosystem }, version: d.version })),
        }),
      });
      if (!res.ok) continue;
      json = (await res.json()) as { results?: OsvBatchQueryResult[] };
    } catch {
      continue;
    }

    const results = json.results ?? [];
    batch.forEach((dep, i) => {
      const ids = (results[i]?.vulns ?? []).map((v) => v.id);
      if (ids.length > 0) result.set(depKey(dep), ids);
    });
  }

  return result;
}

/** Recupera i dettagli (riassunto, gravità, versione corretta) solo per gli ID di vulnerabilità trovati. */
async function fetchVulnDetails(ids: string[]): Promise<Map<string, OsvVulnerability>> {
  const out = new Map<string, OsvVulnerability>();

  await Promise.all(
    [...new Set(ids)].map(async (id) => {
      try {
        const res = await fetch(OSV_VULN_URL + id);
        if (!res.ok) return;
        out.set(id, (await res.json()) as OsvVulnerability);
      } catch {
        // un singolo ID irraggiungibile non deve bloccare gli altri
      }
    })
  );

  return out;
}

/**
 * OSV.dev non sempre espone una gravità già calcolata — alcune voci hanno
 * `database_specific.severity` (tipico delle advisory GitHub/GHSA), altre
 * solo un vettore CVSS grezzo che richiederebbe di implementare l'intera
 * formula CVSS per ricavare un punteggio, fuori scopo qui. In assenza di un
 * segnale chiaro, una vulnerabilità pubblica confermata viene trattata come
 * "high" di default — mai silenziata a "low" solo perché non classificata.
 */
function mapSeverity(vuln: OsvVulnerability): Severity {
  const dbSeverity = vuln.database_specific?.severity?.toUpperCase();
  if (dbSeverity === "CRITICAL") return "critical";
  if (dbSeverity === "HIGH") return "high";
  if (dbSeverity === "MODERATE" || dbSeverity === "MEDIUM") return "medium";
  if (dbSeverity === "LOW") return "low";
  return "high";
}

/** Cerca, tra i blocchi "affected" della vulnerabilità, la prima versione corretta nota per questo pacchetto. */
function findFixedVersion(vuln: OsvVulnerability, name: string, ecosystem: string): string | null {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.ecosystem !== ecosystem || affected.package?.name !== name) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Trova la riga del package-lock.json dove compare la versione di questa dipendenza, per dare un riferimento preciso invece che genericamente "riga 1". */
function locateDependency(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const keyPattern = new RegExp(`"(?:[^"]*/)?${escapeRegExp(name)}"\\s*:`);
  const versionPattern = new RegExp(`"version"\\s*:\\s*"${escapeRegExp(version)}"`);

  for (let i = 0; i < lines.length; i++) {
    if (!keyPattern.test(lines[i])) continue;
    for (let j = i; j < Math.min(i + 5, lines.length); j++) {
      if (versionPattern.test(lines[j])) return { line: j + 1, snippet: lines[j].trim() };
    }
  }

  return { line: 1, snippet: `"${name}": "${version}"` };
}

/**
 * Fase 2, primo controllo: cerca dipendenze npm con vulnerabilità note nel
 * database pubblico OSV.dev. A differenza dei controlli a pattern (sincroni,
 * zero rete), questo fa vere chiamate di rete — per questo è una funzione
 * async separata, da richiamare esplicitamente insieme a analyzeFiles() e
 * non dentro di essa. Supporta solo npm/package-lock.json per ora; Python
 * (requirements.txt) e gli altri ecosistemi arrivano in un secondo momento.
 */
export async function scanDependencies(files: readonly SourceFile[]): Promise<Finding[]> {
  const lockFile = files.find(
    (f) => !SKIP_PATH.test(f.path) && (f.path === LOCKFILE_NAME || f.path.endsWith(`/${LOCKFILE_NAME}`))
  );
  if (!lockFile) return [];

  const deps = parseNpmLockfile(lockFile.content);
  if (deps.length === 0) return [];

  const vulnIdsByDep = await queryOsvBatch(deps, "npm");
  if (vulnIdsByDep.size === 0) return [];

  const vulnDetails = await fetchVulnDetails([...vulnIdsByDep.values()].flat());

  const findings: Finding[] = [];
  for (const dep of deps) {
    for (const id of vulnIdsByDep.get(depKey(dep)) ?? []) {
      const vuln = vulnDetails.get(id);
      if (!vuln) continue;

      const { line, snippet } = locateDependency(lockFile.content, dep.name, dep.version);
      const fixedVersion = findFixedVersion(vuln, dep.name, "npm");

      findings.push({
        checkId: "vulnerable-dependency",
        severity: mapSeverity(vuln),
        confidence: "confirmed",
        title: `Dipendenza vulnerabile: ${dep.name}@${dep.version} (${id})`,
        description:
          vuln.summary ||
          (vuln.details ? vuln.details.slice(0, 220) : `Vulnerabilità nota (${id}) su OSV.dev per questa versione di ${dep.name}.`),
        file: lockFile.path,
        line,
        snippet,
        fix: {
          before: `"${dep.name}": "${dep.version}"`,
          after: fixedVersion
            ? `"${dep.name}": "${fixedVersion}"`
            : "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        },
      });
    }
  }

  return findings;
}