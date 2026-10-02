import type { Finding, Severity, SourceFile } from "./types.js";
import { SKIP_PATH } from "./util/skipPath.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
/** Il limite ufficiale di OSV.dev per /v1/querybatch è 1000 query — restiamo ben sotto per gentilezza verso il servizio pubblico. */
const OSV_BATCH_CHUNK_SIZE = 100;

export interface DependencyRef {
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
export function parseNpmLockfile(content: string): DependencyRef[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  if (!data || typeof data !== "object") return [];

  const deps = new DependencyCollector();

  const packages = (data as Record<string, unknown>).packages;
  const dependencies = (data as Record<string, unknown>).dependencies;

  if (packages && typeof packages === "object") {
    for (const [key, value] of Object.entries(packages as Record<string, unknown>)) {
      if (key === "") continue; // il pacchetto radice del progetto stesso, non una dipendenza
      const idx = key.lastIndexOf("node_modules/");
      if (idx === -1) continue;
      const name = key.slice(idx + "node_modules/".length);
      const version = (value as Record<string, unknown> | undefined)?.version;
      if (typeof version === "string") deps.add(name, version);
    }
  } else if (dependencies && typeof dependencies === "object") {
    const walk = (tree: Record<string, unknown>): void => {
      for (const [name, value] of Object.entries(tree)) {
        const entry = value as Record<string, unknown> | undefined;
        const version = entry?.version;
        if (typeof version === "string") deps.add(name, version);
        const nested = entry?.dependencies;
        if (nested && typeof nested === "object") walk(nested as Record<string, unknown>);
      }
    };
    walk(dependencies as Record<string, unknown>);
  }

  return deps.values();
}

/**
 * Estrae nome + versione da un composer.lock — stesso principio di
 * package-lock.json: contiene già le versioni esatte risolte di ogni
 * dipendenza, dirette ("packages") e di sviluppo ("packages-dev").
 */
export function parseComposerLock(content: string): DependencyRef[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  if (!data || typeof data !== "object") return [];

  const deps = new DependencyCollector();
  for (const key of ["packages", "packages-dev"]) {
    const list = (data as Record<string, unknown>)[key];
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      const name = (entry as Record<string, unknown> | undefined)?.name;
      const version = (entry as Record<string, unknown> | undefined)?.version;
      if (typeof name === "string" && typeof version === "string") deps.add(name, version);
    }
  }

  return deps.values();
}

/**
 * Estrae nome + versione da un requirements.txt — solo le righe "pinnate"
 * con "==" (es. "flask==2.0.1"): sono le uniche per cui conosciamo la
 * versione davvero installata. Una riga con un intervallo (">=2.0", "~=2.0")
 * o senza versione non lo dice con certezza, quindi viene ignorata invece di
 * rischiare di controllare la versione sbagliata — stessa scelta fatta per
 * npm (package-lock.json invece di package.json, per lo stesso motivo).
 * Gestisce anche extra ("requests[security]==2.25.1"), marker d'ambiente
 * (";  python_version >= \"3.8\"") e commenti, e ignora le righe direttiva
 * (-r altro.txt, -e ., --hash=...).
 */
export function parseRequirementsTxt(content: string): DependencyRef[] {
  const deps = new DependencyCollector();
  const pinPattern = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.*+!_-]*)/;

  for (const rawLine of content.split("\n")) {
    const withoutComment = rawLine.split("#")[0];
    const withoutMarkers = withoutComment.split(";")[0].trim();
    if (!withoutMarkers || withoutMarkers.startsWith("-")) continue;

    const match = pinPattern.exec(withoutMarkers);
    if (!match) continue;
    deps.add(match[1], match[2]);
  }

  return deps.values();
}

/**
 * Nomi di pacchetto in un requirements.txt che NON sono stati controllati
 * perché non pinnati con "==" (un intervallo come ">=2.0", o nessuna
 * versione affatto) — usata per avvisare l'utente di quali dipendenze sono
 * state saltate, invece di farlo in silenzio come faceva parseRequirementsTxt
 * da sola. Esclude le stesse righe già escluse lì (commenti, righe vuote,
 * direttive -r/-e/--hash) più le righe VCS/URL (es. "git+https://...") che
 * non hanno comunque un nome di pacchetto PyPI riconoscibile.
 */
export function findUnanalyzedRequirements(content: string): string[] {
  const names: string[] = [];
  const seen = new Set<string>();
  const namePattern = /^([A-Za-z0-9][A-Za-z0-9._-]*)/;

  for (const rawLine of content.split("\n")) {
    const withoutComment = rawLine.split("#")[0];
    const withoutMarkers = withoutComment.split(";")[0].trim();
    if (!withoutMarkers || withoutMarkers.startsWith("-")) continue;
    if (withoutMarkers.includes("==")) continue; // già pinnata, analizzata regolarmente
    if (/^\w+\+|:\/\//.test(withoutMarkers)) continue; // riferimento VCS/URL, non un nome di pacchetto

    const match = namePattern.exec(withoutMarkers);
    if (!match) continue;
    const name = match[1];
    if (seen.has(name)) continue;
    seen.add(name);
    names.push(name);
  }

  return names;
}

/**
 * Estrae nome + versione da un yarn.lock, sia nel formato classico (Yarn 1,
 * "version \"x.y.z\"") sia in quello di Yarn Berry (2+, "version: x.y.z").
 * Una riga di intestazione blocco (non indentata, finisce con ":") può
 * elencare più spec separate da virgola per lo stesso pacchetto installato
 * (es. due range diversi risolti alla stessa versione) — tutte vengono
 * associate alla "version" che segue, nella prima riga indentata che la
 * dichiara. Il nome del pacchetto si ricava togliendo l'ultimo "@" e tutto
 * quello che segue (il range) — per i pacchetti scoped (es. "@babel/core")
 * il primo "@" fa parte del nome, quindi si cerca l'ULTIMO "@" nella stringa.
 */
export function parseYarnLock(content: string): DependencyRef[] {
  const deps = new DependencyCollector();
  let pendingNames: string[] = [];

  const nameFromSpec = (spec: string): string => {
    const trimmed = spec.trim().replace(/^["']|["']$/g, "");
    const at = trimmed.lastIndexOf("@");
    return at > 0 ? trimmed.slice(0, at) : trimmed;
  };

  for (const rawLine of content.split("\n")) {
    if (!rawLine.trim() || rawLine.trim().startsWith("#")) continue;

    if (/^\S/.test(rawLine) && rawLine.trim().endsWith(":")) {
      const header = rawLine.trim().slice(0, -1);
      pendingNames = header.split(",").map(nameFromSpec);
      continue;
    }

    if (pendingNames.length === 0) continue;
    const classic = rawLine.match(/^\s+version\s+"([^"]+)"/);
    const berry = rawLine.match(/^\s+version:\s*"?([^"\s]+)"?/);
    const version = classic?.[1] ?? berry?.[1];
    if (!version) continue;

    for (const name of pendingNames) deps.add(name, version);
    pendingNames = [];
  }

  return deps.values();
}

/**
 * Estrae nome + versione da un pnpm-lock.yaml — la chiave di ogni voce nella
 * sezione "packages" combina nome e versione con "@" (es. "/lodash@4.17.21:"
 * nelle versioni più vecchie di pnpm, "lodash@4.17.21:" nelle più recenti,
 * che non usano più lo slash iniziale). Eventuali suffissi tra parentesi
 * (dipendenze peer risolte, es. "(react@18.0.0)") vengono ignorati. Stessa
 * scelta delle altre funzioni qui: nessun parser YAML, la chiave è abbastanza
 * specifica da riconoscere con una regex per riga.
 */
export function parsePnpmLock(content: string): DependencyRef[] {
  const deps = new DependencyCollector();
  const pattern = /^\s*["']?\/?(@[^/\s'"]+\/[^@\s'"]+|[^@\s'"/]+)@([^\s'":()]+)/;

  for (const rawLine of content.split("\n")) {
    const match = pattern.exec(rawLine);
    if (!match) continue;
    deps.add(match[1], match[2]);
  }

  return deps.values();
}

/**
 * Estrae nome + versione da un poetry.lock (Poetry) o un uv.lock (uv) — lo
 * stesso formato TOML "array di tabelle" ([[package]] seguito da "name" e
 * "version"), usato identico da entrambi gli strumenti.
 */
export function parsePythonTomlLock(content: string): DependencyRef[] {
  const deps = new DependencyCollector();
  let currentName: string | null = null;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (line === "[[package]]") {
      currentName = null;
      continue;
    }
    const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/);
    if (nameMatch) {
      currentName = nameMatch[1];
      continue;
    }
    const versionMatch = line.match(/^version\s*=\s*"([^"]+)"/);
    if (versionMatch && currentName) {
      deps.add(currentName, versionMatch[1]);
      currentName = null;
    }
  }

  return deps.values();
}

/**
 * Estrae nome + versione da un Pipfile.lock — JSON con due sezioni separate,
 * "default" (dipendenze dirette) e "develop" (dipendenze di sviluppo). La
 * versione include il prefisso "==" tipico degli specificatori pip, tolto
 * prima di restituirla.
 */
export function parsePipfileLock(content: string): DependencyRef[] {
  let data: unknown;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  if (!data || typeof data !== "object") return [];

  const deps = new DependencyCollector();
  for (const section of ["default", "develop"]) {
    const group = (data as Record<string, unknown>)[section];
    if (!group || typeof group !== "object") continue;
    for (const [name, info] of Object.entries(group as Record<string, unknown>)) {
      const version = (info as Record<string, unknown> | undefined)?.version;
      if (typeof version === "string") deps.add(name, version.replace(/^==/, ""));
    }
  }

  return deps.values();
}

/**
 * Estrae nome + versione da un go.mod. A differenza di npm/Python, Go
 * risolve già tutte le dipendenze (dirette e indirette) a una versione
 * esatta dentro lo stesso go.mod grazie al suo sistema di moduli (minimal
 * version selection) — non serve un file di lock separato come go.sum, che
 * contiene solo gli hash di verifica, non informazioni aggiuntive sulla
 * versione scelta. Riconosce sia il blocco "require (...)" sia le righe
 * "require module version" singole, e ignora "module", "go", "toolchain",
 * "replace" ed "exclude" (non sono dipendenze da controllare).
 */
export function parseGoMod(content: string): DependencyRef[] {
  const deps = new DependencyCollector();
  const versionPattern = /^(\S+)\s+(v\d[^\s/]*)/;

  for (const rawLine of content.split("\n")) {
    let line = rawLine.split("//")[0].trim();
    if (!line) continue;

    if (/^(module|go|toolchain|replace|exclude)\b/.test(line)) continue;
    if (line === "require" || line === "require (" || line === ")") continue;
    line = line.replace(/^require\s+/, "");

    const match = versionPattern.exec(line);
    if (!match) continue;
    deps.add(match[1], match[2]);
  }

  return deps.values();
}

/**
 * Java/Maven non ha un file di lock standard committato nel progetto come
 * gli altri ecosistemi (pom.xml da solo spesso non basta: eredita versioni
 * da un parent POM o da un import di BOM — vedi il commento su
 * MANIFEST_SOURCES più sotto). Stesso schema già usato per Supabase: il
 * cliente lancia lui, in locale, un comando di sola lettura che non
 * modifica nulla, e carica il risultato insieme al resto del codice. Il
 * comando scrive già il file con questo nome esatto, zero passi in più.
 */
export const MAVEN_DEPENDENCY_LIST_FILENAME = "jojox-maven-dependencies.txt";
export const MAVEN_DEPENDENCY_LIST_COMMAND = `mvn dependency:list -DoutputFile=${MAVEN_DEPENDENCY_LIST_FILENAME}`;

/**
 * Estrae nome ("groupId:artifactId") + versione dall'output di
 * `mvn dependency:list`, un elenco piatto tipo
 * "com.google.guava:guava:jar:31.1-jre:compile" (5 campi) o, per i pacchetti
 * con classifier, "io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.86.Final:compile"
 * (6 campi). Ignora l'intestazione del comando e ogni riga che non
 * corrisponde esattamente a questo schema.
 */
export function parseMavenDependencyList(content: string): DependencyRef[] {
  const deps = new DependencyCollector();
  const fieldPattern = /^[\w.-]+$/;

  for (const rawLine of content.split("\n")) {
    const parts = rawLine.trim().split(":");
    if (parts.length !== 5 && parts.length !== 6) continue;

    const [groupId, artifactId] = parts;
    const version = parts.length === 6 ? parts[4] : parts[3];
    if (![groupId, artifactId, version].every((field) => fieldPattern.test(field))) continue;

    deps.add(`${groupId}:${artifactId}`, version);
  }

  return deps.values();
}

/** Dedup per coppia nome+versione, usata da ogni parser di manifest. */
class DependencyCollector {
  private seen = new Set<string>();
  private deps: DependencyRef[] = [];

  add(name: string, version: string): void {
    if (!name || !version) return;
    const key = `${name}@${version}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.deps.push({ name, version });
  }

  values(): DependencyRef[] {
    return this.deps;
  }
}

function depKey(dep: DependencyRef): string {
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
 *
 * `queryName` permette di normalizzare il nome solo per l'interrogazione
 * (es. PyPI vuole il nome canonico minuscolo), lasciando `dep.name`
 * originale per tutto il resto (titolo, snippet, versione corretta).
 */
async function queryOsvBatch(
  deps: DependencyRef[],
  ecosystem: string,
  queryName: (name: string) => string
): Promise<Map<string, string[]>> {
  const result = new Map<string, string[]>();

  for (const batch of chunk(deps, OSV_BATCH_CHUNK_SIZE)) {
    let json: { results?: OsvBatchQueryResult[] };
    try {
      const res = await fetch(OSV_BATCH_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: batch.map((d) => ({ package: { name: queryName(d.name), ecosystem }, version: d.version })),
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
function locateInNpmLockfile(content: string, name: string, version: string): { line: number; snippet: string } {
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

/** Trova la riga del requirements.txt dove compare questa dipendenza pinnata. */
function locateInRequirementsTxt(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const pattern = new RegExp(`^\\s*${escapeRegExp(name)}\\s*(?:\\[[^\\]]*\\])?\\s*==\\s*${escapeRegExp(version)}\\b`);

  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return { line: i + 1, snippet: lines[i].trim() };
  }

  return { line: 1, snippet: `${name}==${version}` };
}

/** Trova la riga del composer.lock dove compare la versione di questo pacchetto. */
function locateInComposerLock(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const namePattern = new RegExp(`"name"\\s*:\\s*"${escapeRegExp(name)}"`);
  const versionPattern = new RegExp(`"version"\\s*:\\s*"${escapeRegExp(version)}"`);

  for (let i = 0; i < lines.length; i++) {
    if (!namePattern.test(lines[i])) continue;
    for (let j = i; j < Math.min(i + 5, lines.length); j++) {
      if (versionPattern.test(lines[j])) return { line: j + 1, snippet: lines[j].trim() };
    }
  }

  return { line: 1, snippet: `"${name}": "${version}"` };
}

/** Trova la riga dello yarn.lock dove compare la versione (sia formato classico sia Berry). */
function locateInYarnLock(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const headerPattern = new RegExp(`(^|,\\s*)["']?${escapeRegExp(name)}@`);
  const versionPattern = new RegExp(`^\\s+version:?\\s+?"?${escapeRegExp(version)}"?\\s*$`);

  for (let i = 0; i < lines.length; i++) {
    if (!headerPattern.test(lines[i]) || !lines[i].trim().endsWith(":")) continue;
    for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
      if (versionPattern.test(lines[j])) return { line: j + 1, snippet: lines[j].trim() };
    }
  }

  return { line: 1, snippet: `${name}@${version}` };
}

/** Trova la riga del pnpm-lock.yaml dove compare questa dipendenza (chiave "nome@versione" nella sezione packages). */
function locateInPnpmLock(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const pattern = new RegExp(`^\\s*["']?\\/?${escapeRegExp(name)}@${escapeRegExp(version)}\\b`);

  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return { line: i + 1, snippet: lines[i].trim() };
  }

  return { line: 1, snippet: `${name}@${version}` };
}

/** Trova la riga del poetry.lock/uv.lock dove compare la versione, dentro il blocco [[package]] di questo nome. */
function locateInPythonTomlLock(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const namePattern = new RegExp(`^name\\s*=\\s*"${escapeRegExp(name)}"`);
  const versionPattern = new RegExp(`^version\\s*=\\s*"${escapeRegExp(version)}"`);

  for (let i = 0; i < lines.length; i++) {
    if (!namePattern.test(lines[i].trim())) continue;
    for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
      if (versionPattern.test(lines[j].trim())) return { line: j + 1, snippet: lines[j].trim() };
    }
  }

  return { line: 1, snippet: `name = "${name}"\nversion = "${version}"` };
}

/** Trova la riga del Pipfile.lock dove compare la versione di questo pacchetto (con il prefisso "==" tipico di pip). */
function locateInPipfileLock(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const namePattern = new RegExp(`"${escapeRegExp(name)}"\\s*:\\s*\\{`);
  const versionPattern = new RegExp(`"version"\\s*:\\s*"==${escapeRegExp(version)}"`);

  for (let i = 0; i < lines.length; i++) {
    if (!namePattern.test(lines[i])) continue;
    for (let j = i; j < Math.min(i + 5, lines.length); j++) {
      if (versionPattern.test(lines[j])) return { line: j + 1, snippet: lines[j].trim() };
    }
  }

  return { line: 1, snippet: `"${name}": { "version": "==${version}" }` };
}

/** Trova la riga del go.mod dove compare questa dipendenza. */
function locateInGoMod(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const pattern = new RegExp(`^\\s*(?:require\\s+)?${escapeRegExp(name)}\\s+${escapeRegExp(version)}\\b`);

  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return { line: i + 1, snippet: lines[i].trim() };
  }

  return { line: 1, snippet: `${name} ${version}` };
}

/** Trova la riga dell'output di `mvn dependency:list` dove compare questa dipendenza ("groupId:artifactId"). */
function locateInMavenDependencyList(content: string, name: string, version: string): { line: number; snippet: string } {
  const lines = content.split("\n");
  const pattern = new RegExp(`^\\s*${escapeRegExp(name)}:[\\w.-]+(?::[\\w.-]+)?:${escapeRegExp(version)}:`);

  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return { line: i + 1, snippet: lines[i].trim() };
  }

  return { line: 1, snippet: `${name}:${version}` };
}

/** PEP 503: normalizzazione canonica di un nome pacchetto PyPI (minuscolo, separatori unificati a "-"). */
function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[._-]+/g, "-");
}

interface ManifestSource {
  ecosystem: string;
  filename: string;
  parse: (content: string) => DependencyRef[];
  locate: (content: string, name: string, version: string) => { line: number; snippet: string };
  formatPin: (name: string, version: string) => string;
  /** Nome usato per interrogare OSV.dev, se diverso da quello mostrato nel finding (es. PyPI vuole la forma canonica). */
  queryName: (name: string) => string;
  /** Solo per requirements.txt: nomi dei pacchetti non pinnati, quindi non controllati — usata per avvisare invece di saltarli in silenzio. */
  findUnanalyzed?: (content: string) => string[];
}

/**
 * Java (Maven) non ha un pom.xml leggibile con precisione da solo: nello
 * stack Spring Boot pubblicizzato da JoJoX, le versioni sono quasi sempre
 * ereditate da un parent POM o da un import di BOM, non scritte nel
 * progetto. Per questo non c'è un parser di pom.xml qui sotto — l'unica
 * fonte affidabile è l'output di `mvn dependency:list` (vedi
 * MAVEN_DEPENDENCY_LIST_FILENAME sopra), che il cliente genera lui in
 * locale e carica insieme al resto, stesso schema già usato per Supabase.
 */
const MANIFEST_SOURCES: ManifestSource[] = [
  {
    ecosystem: "npm",
    filename: "package-lock.json",
    parse: parseNpmLockfile,
    locate: locateInNpmLockfile,
    formatPin: (name, version) => `"${name}": "${version}"`,
    queryName: (name) => name,
  },
  {
    ecosystem: "npm",
    filename: "yarn.lock",
    parse: parseYarnLock,
    locate: locateInYarnLock,
    formatPin: (name, version) => `${name}@${version}`,
    queryName: (name) => name,
  },
  {
    ecosystem: "npm",
    filename: "pnpm-lock.yaml",
    parse: parsePnpmLock,
    locate: locateInPnpmLock,
    formatPin: (name, version) => `${name}@${version}`,
    queryName: (name) => name,
  },
  {
    ecosystem: "PyPI",
    filename: "requirements.txt",
    parse: parseRequirementsTxt,
    locate: locateInRequirementsTxt,
    formatPin: (name, version) => `${name}==${version}`,
    queryName: normalizePypiName,
    findUnanalyzed: findUnanalyzedRequirements,
  },
  {
    ecosystem: "PyPI",
    filename: "poetry.lock",
    parse: parsePythonTomlLock,
    locate: locateInPythonTomlLock,
    formatPin: (name, version) => `${name}==${version}`,
    queryName: normalizePypiName,
  },
  {
    ecosystem: "PyPI",
    filename: "uv.lock",
    parse: parsePythonTomlLock,
    locate: locateInPythonTomlLock,
    formatPin: (name, version) => `${name}==${version}`,
    queryName: normalizePypiName,
  },
  {
    ecosystem: "PyPI",
    filename: "Pipfile.lock",
    parse: parsePipfileLock,
    locate: locateInPipfileLock,
    formatPin: (name, version) => `${name}==${version}`,
    queryName: normalizePypiName,
  },
  {
    ecosystem: "Go",
    filename: "go.mod",
    parse: parseGoMod,
    locate: locateInGoMod,
    formatPin: (name, version) => `${name} ${version}`,
    queryName: (name) => name,
  },
  {
    ecosystem: "Packagist",
    filename: "composer.lock",
    parse: parseComposerLock,
    locate: locateInComposerLock,
    formatPin: (name, version) => `"${name}": "${version}"`,
    queryName: (name) => name,
  },
  {
    ecosystem: "Maven",
    filename: MAVEN_DEPENDENCY_LIST_FILENAME,
    parse: parseMavenDependencyList,
    locate: locateInMavenDependencyList,
    formatPin: (name, version) => `${name}:${version}`,
    queryName: (name) => name,
  },
];

function findManifest(files: readonly SourceFile[], filename: string): SourceFile | undefined {
  return files.find((f) => !SKIP_PATH.test(f.path) && (f.path === filename || f.path.endsWith(`/${filename}`)));
}

const NO_FIXED_VERSION_MESSAGE =
  "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.";

/**
 * Un avviso, non una vulnerabilità: elenca le dipendenze di un
 * requirements.txt che non sono state controllate perché non pinnate con
 * "==" — invece di saltarle in silenzio come prima. Un solo finding
 * aggregato per file, non uno per dipendenza, per non riempire l'elenco dei
 * risultati quando un progetto ha molte versioni non pinnate.
 */
function unanalyzedDependenciesFinding(filePath: string, names: string[]): Finding {
  const shown = names.slice(0, 15);
  const list = shown.join(", ") + (names.length > shown.length ? `, +${names.length - shown.length} altre` : "");

  return {
    checkId: "dependency-scan-unpinned-skipped",
    severity: "low",
    confidence: "heuristic",
    title:
      names.length === 1
        ? `1 dipendenza in requirements.txt non è stata controllata perché non è pinnata con "=="`
        : `${names.length} dipendenze in requirements.txt non sono state controllate perché non sono pinnate con "=="`,
    description: `La scansione delle dipendenze vulnerabili legge solo le versioni "pinnate" con "==" (es. "flask==2.0.1"), perché solo lì si conosce con certezza quale versione è davvero installata. Queste dipendenze usano un intervallo di versioni (es. ">=2.0") o non specificano nessuna versione, quindi non sono state controllate: ${list}. Per includerle nella scansione, pinna una versione esatta nel file.`,
    file: filePath,
    line: 1,
    snippet: list,
    fix: { before: "requests>=2.0", after: "requests==2.31.0" },
  };
}

/**
 * Fase 2: cerca dipendenze con vulnerabilità note nel database pubblico
 * OSV.dev, per ogni manifest supportato trovato tra i file caricati — npm
 * (package-lock.json, yarn.lock, pnpm-lock.yaml), Python (requirements.txt
 * pinnato, poetry.lock, uv.lock, Pipfile.lock), Go e PHP/Composer letti
 * direttamente dal progetto; Java/Maven invece solo se il cliente carica
 * anche il file generato da MAVEN_DEPENDENCY_LIST_COMMAND (vedi il commento
 * su MANIFEST_SOURCES più sotto per il perché). Un requirements.txt con
 * dipendenze non pinnate produce in più un avviso (non una vulnerabilità)
 * che le elenca, invece di saltarle in silenzio. A differenza dei controlli
 * a pattern (sincroni, zero rete), questo fa vere chiamate di rete — per
 * questo è una funzione async separata, da richiamare esplicitamente
 * insieme a analyzeFiles() e non dentro di essa.
 */
export async function scanDependencies(files: readonly SourceFile[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const source of MANIFEST_SOURCES) {
    const manifestFile = findManifest(files, source.filename);
    if (!manifestFile) continue;

    if (source.findUnanalyzed) {
      const unanalyzed = source.findUnanalyzed(manifestFile.content);
      if (unanalyzed.length > 0) findings.push(unanalyzedDependenciesFinding(manifestFile.path, unanalyzed));
    }

    const deps = source.parse(manifestFile.content);
    if (deps.length === 0) continue;

    const vulnIdsByDep = await queryOsvBatch(deps, source.ecosystem, source.queryName);
    if (vulnIdsByDep.size === 0) continue;

    const vulnDetails = await fetchVulnDetails([...vulnIdsByDep.values()].flat());

    for (const dep of deps) {
      for (const id of vulnIdsByDep.get(depKey(dep)) ?? []) {
        const vuln = vulnDetails.get(id);
        if (!vuln) continue;

        const { line, snippet } = source.locate(manifestFile.content, dep.name, dep.version);
        const fixedVersion = findFixedVersion(vuln, dep.name, source.ecosystem);

        findings.push({
          checkId: "vulnerable-dependency",
          severity: mapSeverity(vuln),
          confidence: "confirmed",
          title: `Dipendenza vulnerabile: ${dep.name}@${dep.version} (${id})`,
          description:
            vuln.summary ||
            (vuln.details ? vuln.details.slice(0, 220) : `Vulnerabilità nota (${id}) su OSV.dev per questa versione di ${dep.name}.`),
          file: manifestFile.path,
          line,
          snippet,
          fix: {
            before: source.formatPin(dep.name, dep.version),
            after: fixedVersion ? source.formatPin(dep.name, fixedVersion) : NO_FIXED_VERSION_MESSAGE,
          },
        });
      }
    }
  }

  return findings;
}