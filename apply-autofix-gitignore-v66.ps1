# JoJoX - Punto 11 della lista: prima estensione delle correzioni automatiche.
# Aggiunta la capacita' (architetturale) di correggere un file diverso da quello
# dove e' stato trovato il problema, e usata per il primo caso reale: un file
# .env con valori veri viene ora aggiunto automaticamente al .gitignore
# (solo quando si analizza l'intero progetto, mai sulle sole modifiche di una
# pull request, per non rischiare di sovrascrivere un .gitignore vero che non
# abbiamo visto per intero).
# Esegui questo script da PowerShell nella cartella principale del tuo repository Jojox in locale
# (quella che contiene le cartelle "web", "src", ecc.)

$ErrorActionPreference = "Stop"

if (-not (Test-Path "web/src/index.css")) {
    Write-Host "ERRORE: non sembra la cartella del repository Jojox. Esegui questo script dalla cartella principale del progetto (quella con dentro 'web')." -ForegroundColor Red
    exit 1
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8NoBom($path, $content) {
    $dir = Split-Path $path -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($path, $content, $utf8NoBom)
    Write-Host "Scritto: $path"
}

$content_src_types_ts = @'
export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "confirmed" | "heuristic";

export interface SourceFile {
  /** Repo-relative path, forward slashes. */
  path: string;
  content: string;
}

export interface FixExample {
  before: string;
  after: string;
}

export interface Finding {
  checkId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  file: string;
  line: number;
  /** Minimal redacted context around the match — never the full line. */
  snippet: string;
  fix: FixExample;
}

export interface CheckMatch {
  line: number;
  snippet: string;
}

export interface Check {
  id: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  fix: FixExample;
  detect: (file: SourceFile, allFiles: readonly SourceFile[]) => CheckMatch[];
  /**
   * Corregge davvero il contenuto del file, quando è possibile farlo in modo
   * meccanico e sicuro (senza dover indovinare logica specifica del
   * progetto). Ritorna il contenuto corretto, oppure null se in questo file
   * non c'è nulla da correggere automaticamente — in quel caso il problema
   * resta segnalato solo con l'esempio "prima/dopo".
   */
  autofix?: (file: SourceFile) => string | null;
  /**
   * Per correzioni che non toccano il file dove è stato trovato il problema,
   * ma un file diverso del progetto (es. aggiungere una riga al
   * `.gitignore` invece di modificare il `.env` segnalato). Riceve il file
   * che ha fatto scattare il controllo e tutti i file del progetto, e
   * ritorna il file da creare o aggiornare altrove — o null se non c'è
   * nulla da fare (es. è già a posto).
   */
  autofixOtherFile?: (file: SourceFile, allFiles: readonly SourceFile[]) => SourceFile | null;
}

export interface AnalysisResult {
  score: number;
  findings: Finding[];
  summary: Record<Severity, number>;
}
'@
Write-Utf8NoBom "src/types.ts" $content_src_types_ts

$content_src_autofix_ts = @'
import type { SourceFile } from "./types.js";
import { ALL_CHECKS } from "./checks/index.js";

export interface AutofixResult {
  /** I file con le correzioni applicate — stessa forma dei file in ingresso. */
  files: SourceFile[];
  /** Solo i file il cui contenuto è stato davvero modificato (sottoinsieme di `files`). */
  changedFiles: SourceFile[];
  /** id dei controlli per cui è stata applicata almeno una correzione. */
  fixedCheckIds: Set<string>;
  /** id dei controlli con problemi trovati ma senza correzione automatica disponibile. */
  manualCheckIds: Set<string>;
  /** numero di file effettivamente modificati. */
  filesChanged: number;
}

/**
 * Applica in sequenza le correzioni automatiche di ogni controllo che ne ha
 * una. Ogni controllo lavora sul risultato del precedente, così più
 * correzioni sullo stesso file si sommano invece di sovrascriversi.
 */
export interface AutofixOptions {
  /**
   * true quando `files` rappresenta l'intero progetto (scansione CLI, Full
   * Site Audit), false quando sono solo i file cambiati in una pull request
   * (monitoraggio continuo via GitHub App). Le correzioni che toccano un
   * file diverso da quello segnalato (`autofixOtherFile`, es. .gitignore)
   * girano solo quando è true: altrimenti, non avendo il vero contenuto
   * attuale di quel file dal resto del repository, rischieremmo di
   * sovrascriverlo per intero invece di aggiungerci solo una riga.
   */
  fullProject?: boolean;
}

export function applyAutofixes(files: readonly SourceFile[], options: AutofixOptions = {}): AutofixResult {
  const { fullProject = false } = options;
  const fixedCheckIds = new Set<string>();
  const manualCheckIds = new Set<string>();
  const changedFiles: SourceFile[] = [];
  let filesChanged = 0;

  // Correzioni che toccano un file diverso da quello in cui è stato trovato
  // il problema (es. aggiungere una riga al .gitignore) — raccolte a parte
  // e unite una sola volta a fine ciclo, non ad ogni file che le fa scattare.
  const otherFileUpdates = new Map<string, SourceFile>();

  const result = files.map((file) => {
    let current = file;
    let fileWasChanged = false;

    for (const check of ALL_CHECKS) {
      const matches = check.detect(current, files);
      if (matches.length === 0) continue;

      let fixedSomething = false;

      if (check.autofix) {
        const fixedContent = check.autofix(current);
        if (fixedContent !== null && fixedContent !== current.content) {
          current = { ...current, content: fixedContent };
          fileWasChanged = true;
          fixedSomething = true;
        }
      }

      if (check.autofixOtherFile && fullProject) {
        const updated = check.autofixOtherFile(current, files);
        if (updated) {
          otherFileUpdates.set(updated.path, updated);
          fixedSomething = true;
        }
      }

      if (fixedSomething) {
        fixedCheckIds.add(check.id);
      } else {
        manualCheckIds.add(check.id);
      }
    }

    if (fileWasChanged) {
      filesChanged++;
      changedFiles.push(current);
    }
    return current;
  });

  // Applica gli aggiornamenti ad altri file: sostituisce il file se esisteva
  // già nel progetto, altrimenti lo aggiunge (es. un .gitignore che prima non c'era).
  for (const updated of otherFileUpdates.values()) {
    const index = result.findIndex((f) => f.path === updated.path);
    if (index >= 0) {
      result[index] = updated;
    } else {
      result.push(updated);
    }
    changedFiles.push(updated);
    filesChanged++;
  }

  return { files: result, changedFiles, fixedCheckIds, manualCheckIds, filesChanged };
}
'@
Write-Utf8NoBom "src/autofix.ts" $content_src_autofix_ts

$content_src_checks_critical_ts = @'
import type { Check } from "../types.js";
import { scanLines, fileMatch, replaceLines } from "../util/scan.js";
import { toEnvName } from "../util/envName.js";

const PUBLIC_ENV_PREFIX = /(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|PUBLIC_)/;
const SERVER_ONLY_PATH = /(^|\/)(api|server|edge-functions?|functions)(\/|\.)/i;

const PLACEHOLDER_VALUE = /^(process\.env|import\.meta\.env|xxx+|your[-_]?\w*|changeme|example|placeholder|<.*>|\$\{)/i;

// Nomi di variabile che, assegnati a un valore letterale, indicano quasi sempre un segreto.
// Condiviso tra detect() e autofix() così restano sempre allineati.
const SECRET_LIKE_NAMES =
  "apiKey|api_key|secret|secretKey|apiSecret|clientSecret|accessToken|refreshToken|privateKey|dbPassword|password|token|authToken";

// Valori che, oltre a essere hardcoded, hanno un formato riconoscibile di chiave reale
// (AKIA…, sk_live_/sk_test_…): vanno anche revocati presso il fornitore, non solo tolti
// dal codice — l'autofix li lascia quindi segnalati soltanto, mai riscritti in automatico.
const HIGH_CONFIDENCE_SECRET_VALUE = /AKIA[0-9A-Z]{16}|sk_(live|test)_[0-9a-zA-Z]{16,}/;

export const criticalChecks: Check[] = [
  {
    id: "supabase-service-role-in-client",
    severity: "critical",
    confidence: "confirmed",
    title: "La chiave segreta di Supabase finisce in una parte pensata per il browser",
    description:
      "Una variabile con prefisso pubblico (es. NEXT_PUBLIC_, VITE_) o un file lato client fa riferimento alla service role key di Supabase. Questa chiave bypassa la Row Level Security: se finisce nel bundle del browser, chiunque può leggerla e agire come amministratore sul database.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (solo server)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
    detect(file) {
      if (SERVER_ONLY_PATH.test(file.path)) return [];
      const basename = file.path.split("/").pop() ?? "";
      if (/\.(example|sample|template)$/.test(basename)) return [];
      const pattern = new RegExp(
        `${PUBLIC_ENV_PREFIX.source}\\w*(SERVICE_ROLE|SUPABASE_SECRET)\\w*|SUPABASE_SERVICE_ROLE_KEY`,
        "gi"
      );
      return scanLines(file, pattern);
    },
    // Nessun autofix: la correzione vera è spostare questo codice in un file
    // solo-server, una decisione architetturale che non possiamo prendere
    // al posto tuo senza rischiare di rompere il progetto.
  },

  {
    id: "hardcoded-secret",
    severity: "critical",
    confidence: "confirmed",
    title: "Ci sono password o chiavi segrete scritte direttamente nel codice",
    description:
      "Una chiave API, un token o una password sembrano scritti come valore letterale invece che letti da una variabile d'ambiente. Chiunque legga il codice sorgente (o il repository, se pubblico) ottiene quel segreto.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
    detect(file) {
      const highConfidenceMatches = [
        ...scanLines(file, /AKIA[0-9A-Z]{16}/g),
        ...scanLines(file, /sk_(live|test)_[0-9a-zA-Z]{16,}/g),
        ...scanLines(file, /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g),
      ];

      const alreadyFlaggedLines = new Set(highConfidenceMatches.map((m) => m.line));
      const assignmentPattern = new RegExp(`\\b(${SECRET_LIKE_NAMES})\\s*[:=]\\s*["'\`]([^"'\`]{12,})["'\`]`, "gi");
      const lines = file.content.split("\n");
      const assignmentMatches = scanLines(file, assignmentPattern).filter((m) => {
        if (alreadyFlaggedLines.has(m.line)) return false;
        const raw = lines[m.line - 1] ?? "";
        if (/process\.env|import\.meta\.env/.test(raw)) return false;
        const valueMatch = raw.match(/["'`]([^"'`]{6,})["'`]/);
        return !(valueMatch && PLACEHOLDER_VALUE.test(valueMatch[1]));
      });

      return [...highConfidenceMatches, ...assignmentMatches];
    },
    autofix(file) {
      // Correggiamo solo la forma "nomeVariabile = 'valore letterale'": è
      // l'unica per cui possiamo dedurre in modo affidabile il nome della
      // variabile d'ambiente da usare. Le chiavi riconosciute per formato
      // (AKIA…, sk_live_…, blocchi PRIVATE KEY) restano segnalate soltanto:
      // vanno anche revocate, non solo tolte dal codice — se sono finite in
      // un commit, potrebbero già essere compromesse.
      const pattern = new RegExp(`\\b(${SECRET_LIKE_NAMES})(\\s*[:=]\\s*)["'\`][^"'\`]{12,}["'\`]`, "gi");
      const { content, changed } = replaceLines(file.content, pattern, (line, m) => {
        if (/process\.env|import\.meta\.env/.test(line)) return null;
        if (HIGH_CONFIDENCE_SECRET_VALUE.test(line)) return null;
        const [, varName, operator] = m;
        const replacement = `${varName}${operator}process.env.${toEnvName(varName)}`;
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      return changed ? content : null;
    },
  },

  {
    id: "env-file-with-real-values",
    severity: "critical",
    confidence: "heuristic",
    title: "Un file con le password vere del progetto è tra quelli analizzati",
    description:
      "Un file .env con valori reali (non un .env.example) è incluso nell'analisi. Se questo file finisce in un repository o in un deploy pubblico, tutte le credenziali che contiene sono esposte.",
    fix: {
      before: `# .env (committato per errore)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (committato)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env resta fuori dal repo (.gitignore)`,
    },
    detect(file) {
      const basename = file.path.split("/").pop() ?? "";
      if (!/^\.env(\..+)?$/.test(basename)) return [];
      if (/\.(example|sample|template)$/.test(basename)) return [];

      const pattern = /^[A-Z][A-Z0-9_]*=\S+/gm;
      const hasRealValue = pattern.test(file.content);
      if (!hasRealValue) return [];

      return [{ line: 1, snippet: `…${basename} contiene variabili con valori assegnati…` }];
    },
    // Niente autofix sul contenuto del .env stesso: riscrivere o cancellare
    // credenziali vere senza sapere se servono ancora in locale sarebbe
    // distruttivo, e ruotarle resta comunque un'azione che deve fare una
    // persona. L'unica parte meccanica e sempre sicura — impedire che
    // finisca di nuovo in un commit — la facciamo aggiungendolo al
    // .gitignore, un file diverso da quello segnalato.
    autofixOtherFile(file, allFiles) {
      const gitignore = allFiles.find((f) => f.path === ".gitignore");
      const entry = file.path;
      const existingLines = (gitignore?.content ?? "").split("\n");
      const alreadyIgnored = existingLines.some((line) => line.trim() === entry || line.trim() === `/${entry}`);
      if (alreadyIgnored) return null;

      const base = gitignore?.content ?? "";
      const needsNewline = base.length > 0 && !base.endsWith("\n");
      return { path: ".gitignore", content: `${base}${needsNewline ? "\n" : ""}${entry}\n` };
    },
  },

  {
    id: "missing-row-level-security",
    severity: "critical",
    confidence: "confirmed",
    title: "Chiunque può leggere o modificare i dati di tutti gli utenti",
    description:
      "La Row Level Security è disattivata, oppure una policy permette l'accesso a chiunque (USING (true)) senza controllare chi sta facendo la richiesta. Ogni utente autenticato — o anche anonimo — può leggere o modificare i dati di tutti gli altri.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
    detect(file) {
      return [
        ...scanLines(file, /DISABLE ROW LEVEL SECURITY/gi),
        ...scanLines(file, /USING\s*\(\s*true\s*\)/gi),
      ];
    },
    autofix(file) {
      // Riattiviamo la RLS quando è esplicitamente disattivata: è un
      // ripristino sicuro. Una policy "USING (true)" invece richiede di
      // sapere qual è la vera regola di proprietà dei dati — non la
      // inventiamo, resta segnalata per una correzione manuale.
      const { content, changed } = replaceLines(file.content, /DISABLE ROW LEVEL SECURITY/gi, (line, m) => {
        return line.slice(0, m.index) + "ENABLE ROW LEVEL SECURITY" + line.slice(m.index + m[0].length);
      });
      return changed ? content : null;
    },
  },

  {
    id: "sql-injection",
    severity: "critical",
    confidence: "confirmed",
    title: "Un valore inserito dall'utente viene incollato direttamente dentro una query al database",
    description:
      "Una query SQL è costruita concatenando o interpolando direttamente una stringa invece di usare parametri. Se quel testo arriva (anche indirettamente) da un utente, può alterare la query stessa — SQL injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
    detect(file) {
      return [
        ...scanLines(file, /\.(query|raw|execute)\s*\(\s*`[^`]*\$\{/g),
        ...scanLines(file, /\.(query|raw|execute)\s*\(\s*["'][^"']*["']\s*\+\s*\w/g),
      ];
    },
    // Nessun autofix: parametrizzare correttamente la query dipende dal
    // driver/ORM usato — un tentativo automatico rischierebbe di generare
    // SQL sintatticamente sbagliato o, peggio, ancora vulnerabile.
  },

  {
    id: "plaintext-password-storage",
    severity: "critical",
    confidence: "heuristic",
    title: "Le password sembrano non essere protette",
    description:
      "Un campo password viene salvato così com'è arrivato dalla richiesta, e nel file non compare nessuna funzione di hashing (bcrypt, argon2, scrypt). Se il database viene compromesso, tutte le password sono immediatamente utilizzabili.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
    detect(file) {
      if (/bcrypt|argon2|scrypt|hashSync|hashPassword|crypto\.hash|pbkdf2/i.test(file.content)) return [];
      return scanLines(
        file,
        /password\s*[:=]\s*(req\.body\.password|req\.body\[["']password["']\]|password)\b/gi
      );
    },
    autofix(file) {
      if (/bcrypt|argon2|scrypt|hashSync|hashPassword|crypto\.hash|pbkdf2/i.test(file.content)) return null;
      const pattern = /password\s*[:=]\s*(req\.body\.password|req\.body\[["']password["']\]|password)\b/gi;
      const note = " /* JoJoX: serve il pacchetto bcrypt — npm install bcrypt */";
      const { content, changed } = replaceLines(file.content, pattern, (line, m) => {
        const value = m[1];
        const prefix = m[0].slice(0, m[0].length - value.length);
        const replacement = `${prefix}await bcrypt.hash(${value}, 12)${note}`;
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      return changed ? content : null;
    },
  },

  {
    id: "hardcoded-jwt-secret",
    severity: "critical",
    confidence: "confirmed",
    title: "Il secret usato per firmare gli accessi è scritto in chiaro nel codice",
    description:
      "Il secret passato a jwt.sign / jwt.verify (o la variabile JWT_SECRET) è un valore letterale nel codice invece di venire da una variabile d'ambiente. Chiunque lo legga può creare token di accesso validi per qualsiasi utente.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
    detect(file) {
      return [
        ...scanLines(file, /jwt\.(sign|verify)\s*\([^)]*,\s*["'][^"']{6,}["']/g),
        ...scanLines(file, /JWT_SECRET\s*=\s*["'][^"']+["']/g),
      ];
    },
    autofix(file) {
      const r1 = replaceLines(
        file.content,
        /jwt\.(sign|verify)\s*\(([^)]*),\s*["'][^"']{6,}["']/g,
        (line, m) => {
          const [, method, args] = m;
          const replacement = `jwt.${method}(${args}, process.env.JWT_SECRET`;
          return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
        }
      );
      const r2 = replaceLines(r1.content, /JWT_SECRET\s*=\s*["'][^"']+["']/g, (line, m) => {
        return line.slice(0, m.index) + "JWT_SECRET = process.env.JWT_SECRET" + line.slice(m.index + m[0].length);
      });
      return r1.changed || r2.changed ? r2.content : null;
    },
  },

  {
    id: "command-injection",
    severity: "critical",
    confidence: "confirmed",
    title: "Il server può essere costretto a eseguire comandi esterni",
    description:
      "Una funzione che esegue comandi di sistema (exec, execSync, spawn) riceve una stringa costruita per interpolazione o concatenazione. Se una parte di quella stringa arriva da input utente, chi lo controlla può far eseguire comandi arbitrari sul server.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
    detect(file) {
      if (!fileMatch(file, /\b(exec|execSync|spawn)\s*\(/)) return [];
      return [
        ...scanLines(file, /\b(exec|execSync|spawn)\s*\(\s*`[^`]*\$\{/g),
        ...scanLines(file, /\b(exec|execSync|spawn)\s*\(\s*["'][^"']*["']\s*\+\s*\w/g),
      ];
    },
    // Nessun autofix: separare comando e argomenti in modo sicuro richiede
    // di capire quale sia davvero il programma e quali i suoi parametri —
    // provarci alla cieca rischia di generare codice che non funziona più.
  },
];
'@
Write-Utf8NoBom "src/checks/critical.ts" $content_src_checks_critical_ts

$content_src_cli_ts = @'
#!/usr/bin/env node
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import fg from "fast-glob";
import { analyzeFiles, applyAutofixes } from "./analyze.js";
import { ALL_CHECKS } from "./checks/index.js";
import type { Severity } from "./types.js";

const AUTOFIXABLE_CHECK_IDS = new Set(ALL_CHECKS.filter((c) => c.autofix).map((c) => c.id));

const HOOK_MARKER = "# jojox-precommit-hook";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICO",
  high: "ALTO",
  medium: "MEDIO",
  low: "BASSO",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

/**
 * Installa un git hook pre-commit nel repository indicato: da quel momento,
 * ogni commit viene analizzato prima di essere accettato, e viene bloccato
 * se trova un problema critico. Riusa `tsx` già installato dentro JoJoX
 * stesso (percorso assoluto), così funziona indipendentemente da cosa c'è
 * installato nel repository di destinazione.
 */
function installHook(target: string): void {
  const root = resolve(target);
  const gitDir = resolve(root, ".git");
  if (!existsSync(gitDir)) {
    console.error(`Non trovo una cartella .git in ${root} — lancia questo comando dentro un repository Git.`);
    process.exitCode = 1;
    return;
  }

  const hooksDir = resolve(gitDir, "hooks");
  mkdirSync(hooksDir, { recursive: true });
  const hookPath = resolve(hooksDir, "pre-commit");

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, "utf8");
    if (!existing.includes(HOOK_MARKER)) {
      console.error(
        `C'è già un pre-commit hook in ${hookPath} non installato da JoJoX — rimuovilo o rinominalo a mano prima di riprovare, per non perdere quello che fa già.`
      );
      process.exitCode = 1;
      return;
    }
  }

  const jojoxSrcDir = dirname(fileURLToPath(import.meta.url));
  const precommitScript = resolve(jojoxSrcDir, "precommit.ts");
  const tsxBin = resolve(jojoxSrcDir, "..", "node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");

  const hookContent = `#!/bin/sh
${HOOK_MARKER} — non modificare a mano, per aggiornarlo rilancia "npm run cli -- install-hook"
"${tsxBin}" "${precommitScript}"
exit $?
`;

  writeFileSync(hookPath, hookContent, "utf8");
  chmodSync(hookPath, 0o755);

  console.log(
    `\n✓ Hook installato in ${hookPath}\nDa ora, ogni commit in questo repository viene controllato da JoJoX — se trova un problema critico, blocca il commit.\n`
  );
}

async function main() {
  if (process.argv[2] === "install-hook") {
    installHook(process.argv[3] ?? ".");
    return;
  }

  const target = process.argv[2] ?? ".";
  const asJson = process.argv.includes("--json");
  const shouldFix = process.argv.includes("--fix");
  const root = resolve(target);

  const relativePaths = await fg("**/*", {
    cwd: root,
    dot: true,
    onlyFiles: true,
    ignore: ["node_modules/**", ".git/**", "dist/**", "build/**", ".next/**", "coverage/**"],
  });

  const files = (
    await Promise.all(
      relativePaths.map(async (path) => ({
        path,
        content: await readFile(resolve(root, path), "utf8").catch(() => ""),
      }))
    )
  ).filter((f) => f.content !== "");

  if (shouldFix) {
    await runFix(root, files, asJson);
    return;
  }

  const result = analyzeFiles(files);

  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(`\nJoJoX — Security Score: ${result.score}/100\n`);
  for (const severity of SEVERITY_ORDER) {
    const inSeverity = result.findings.filter((f) => f.severity === severity);
    if (inSeverity.length === 0) continue;
    console.log(`${SEVERITY_LABEL[severity]} (${inSeverity.length})`);
    for (const finding of inSeverity) {
      const confidenceTag = finding.confidence === "confirmed" ? "confermato" : "da verificare";
      console.log(`  ${finding.file}:${finding.line}  [${confidenceTag}]  ${finding.title}`);
      console.log(`    ${finding.snippet}`);
    }
    console.log("");
  }

  if (result.findings.length === 0) {
    console.log("Nessun problema trovato nei 21 controlli. 🎉\n");
  } else if (result.findings.some((f) => AUTOFIXABLE_CHECK_IDS.has(f.checkId))) {
    console.log("Suggerimento: rilancia con --fix per correggere in automatico quello che si può.\n");
  }
}

/**
 * Corregge i file in place sul disco (come `eslint --fix`): scrive solo i
 * file che il motore di correzione ha effettivamente cambiato.
 */
async function runFix(root: string, files: { path: string; content: string }[], asJson: boolean): Promise<void> {
  const before = analyzeFiles(files);
  // Scansione dell'intera cartella del progetto, non solo alcuni file: le
  // correzioni che toccano un file diverso da quello segnalato (es. .gitignore) sono sicure qui.
  const autofix = applyAutofixes(files, { fullProject: true });
  const changed = autofix.changedFiles;

  await Promise.all(changed.map((fixed) => writeFile(resolve(root, fixed.path), fixed.content, "utf8")));

  const after = analyzeFiles(autofix.files);

  if (asJson) {
    console.log(
      JSON.stringify(
        {
          scoreBefore: before.score,
          scoreAfter: after.score,
          filesChanged: changed.map((fixed) => fixed.path),
          fixedCheckIds: [...autofix.fixedCheckIds],
          manualCheckIds: [...autofix.manualCheckIds],
        },
        null,
        2
      )
    );
    return;
  }

  if (changed.length === 0) {
    console.log("\nNessuna correzione automatica applicabile su questo codice.\n");
  } else {
    console.log(`\nJoJoX — corretti ${changed.length} file (punteggio: ${before.score} → ${after.score}/100)\n`);
    for (const fixed of changed) {
      console.log(`  ✓ ${fixed.path}`);
    }
    console.log("");
  }

  if (autofix.manualCheckIds.size > 0) {
    console.log(
      `${autofix.manualCheckIds.size} ${autofix.manualCheckIds.size === 1 ? "tipo di problema resta" : "tipi di problema restano"} da sistemare a mano — rilancia senza --fix per vederli in dettaglio.\n`
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
'@
Write-Utf8NoBom "src/cli.ts" $content_src_cli_ts

$content_src_server_routes_analyzeAudit_ts = @'
import { Router } from "express";
import { z } from "zod";
import { analyzeFiles, applyAutofixes } from "../../analyze.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getGithubApp } from "../github/app.js";
import { openAuditFixPr, getRepoFilePaths } from "../github/auditFixPr.js";
import { getTeamUserIds } from "../team.js";

// Sotto questa quota di file caricati già presenti nel repository scelto,
// consideriamo probabile uno scambio di repository (es. selezionato quello
// sbagliato dal menu) e non apriamo la Pull Request in automatico.
const MIN_REPO_OVERLAP_RATIO = 0.3;

// Un Full Site Audit copre un intero progetto, non poche modifiche: limite
// più alto dell'analisi normale (300), ma comunque un tetto per evitare
// richieste ingestibili. Il limite di byte per file resta lo stesso.
const MAX_FILES = 2000;
const MAX_FILE_BYTES = 200_000;

const requestSchema = z.object({
  files: z
    .array(
      z.object({
        path: z.string().min(1).max(500),
        content: z.string().max(MAX_FILE_BYTES),
      })
    )
    .min(1)
    .max(MAX_FILES),
  // Facoltativo: se il cliente sceglie un repository GitHub collegato, invece
  // (o oltre) di scaricare lo zip apriamo una Pull Request con le correzioni
  // automatiche direttamente su quel repository.
  githubTarget: z
    .object({
      installationId: z.number(),
      owner: z.string().min(1),
      repo: z.string().min(1),
    })
    .optional(),
});

export const analyzeAuditRouter = Router();

analyzeAuditRouter.post("/api/analyze-audit", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
  }

  const { githubTarget } = parsed.data;
  if (githubTarget) {
    const { data: installation } = await supabaseAdmin
      .from("github_installations")
      .select("installed_by")
      .eq("installation_id", githubTarget.installationId)
      .single();

    const teamUserIds = await getTeamUserIds(req.userId!);
    if (!installation || !installation.installed_by || !teamUserIds.includes(installation.installed_by)) {
      res.status(403).json({ error: "Installazione GitHub non trovata o non collegata al tuo account" });
      return;
    }
  }

  const { data: credit, error: creditError } = await supabaseAdmin
    .from("audit_credits")
    .select("id")
    .eq("user_id", req.userId)
    .eq("status", "unused")
    .order("created_at", { ascending: true })
    .limit(1)
    .maybeSingle();

  if (creditError) {
    res.status(500).json({ error: "Errore nel controllo dei Full Site Audit disponibili" });
    return;
  }

  if (!credit) {
    res.status(402).json({ error: "Nessun Full Site Audit disponibile — acquistane uno per continuare." });
    return;
  }

  // Reclama il credito con una update condizionata sullo stesso stato letto
  // sopra: se due richieste arrivano in parallelo (due schede aperte, doppio
  // click) possono leggere entrambe lo stesso credito "unused" prima che
  // l'altra lo segni come usato — qui la condizione WHERE status = 'unused'
  // fa sì che solo una delle due update tocchi davvero la riga; l'altra non
  // trova più corrispondenza e lo scopriamo da `claimed` vuoto.
  const { data: claimed, error: claimErr } = await supabaseAdmin
    .from("audit_credits")
    .update({ status: "used", used_at: new Date().toISOString() })
    .eq("id", credit.id)
    .eq("status", "unused")
    .select("id");

  if (claimErr) {
    res.status(500).json({ error: "Errore nel controllo dei Full Site Audit disponibili" });
    return;
  }

  if (!claimed || claimed.length === 0) {
    res.status(402).json({ error: "Nessun Full Site Audit disponibile — acquistane uno per continuare." });
    return;
  }

  const result = analyzeFiles(parsed.data.files);

  await supabaseAdmin.from("analyses").insert({
    user_id: req.userId,
    // "audit", non "manual": distingue nello storico un Full Site Audit
    // pagato da una normale analisi manuale gratuita — prima finivano
    // mescolati sotto la stessa etichetta generica.
    source: "audit",
    score: result.score,
    summary: result.summary,
    findings: result.findings,
  });

  let prUrl: string | null = null;
  let prSkipped: "mismatch" | null = null;
  if (githubTarget) {
    // La correzione qui gira sempre lato server (a differenza dell'analisi
    // manuale nel browser): serve il contenuto corretto per poterlo davvero
    // pushare su GitHub tramite l'installazione della GitHub App.
    // Il Full Site Audit carica l'intero progetto, non solo alcuni file: le
    // correzioni che toccano un file diverso da quello segnalato (es. .gitignore) sono sicure qui.
    const autofix = applyAutofixes(parsed.data.files, { fullProject: true });
    const changedFiles = autofix.changedFiles;

    if (changedFiles.length > 0) {
      try {
        const octokit = await getGithubApp().getInstallationOctokit(githubTarget.installationId);

        // I file caricati dovrebbero essere il codice di quello stesso
        // repository: controlliamo la sovrapposizione prima di aprire una PR,
        // per non proporre correzioni a caso se è stato scelto il repository
        // sbagliato dal menu.
        const repoPaths = await getRepoFilePaths(octokit, { owner: githubTarget.owner, repo: githubTarget.repo });
        const overlap = parsed.data.files.filter((f) => repoPaths.has(f.path)).length / parsed.data.files.length;

        if (overlap < MIN_REPO_OVERLAP_RATIO) {
          prSkipped = "mismatch";
        } else {
          prUrl = await openAuditFixPr(octokit, {
            owner: githubTarget.owner,
            repo: githubTarget.repo,
            changedFiles,
            fixedCheckIds: autofix.fixedCheckIds,
            filesChanged: autofix.filesChanged,
          });
        }
      } catch (err) {
        console.error(
          `impossibile aprire la pull request di correzione su ${githubTarget.owner}/${githubTarget.repo}`,
          err
        );
        // Non facciamo fallire l'intera risposta per questo: l'analisi e il
        // credito sono comunque validi, l'utente ha comunque lo zip da scaricare.
      }
    }
  }

  res.json({ ...result, prUrl, prSkipped });
});
'@
Write-Utf8NoBom "src/server/routes/analyzeAudit.ts" $content_src_server_routes_analyzeAudit_ts

$content_test_autofix_test_ts = @'
import { describe, expect, it } from "vitest";
import { applyAutofixes } from "../src/autofix.js";

describe("applyAutofixes", () => {
  it("returns changedFiles as the subset of files whose content was actually modified", () => {
    const result = applyAutofixes([
      { path: "src/payments.ts", content: 'const apiSecret = "supersecretvaluethatislong"' },
      { path: "README.md", content: "# demo, nothing to fix here" },
    ]);

    expect(result.changedFiles.map((f) => f.path)).toEqual(["src/payments.ts"]);
    expect(result.changedFiles[0]!.content).not.toContain("supersecretvaluethatislong");
    expect(result.filesChanged).toBe(1);
  });

  it("returns an empty changedFiles array when nothing can be fixed automatically", () => {
    const result = applyAutofixes([{ path: "src/server.ts", content: "app.use(cors())" }]);

    expect(result.changedFiles).toEqual([]);
    expect(result.filesChanged).toBe(0);
    expect(result.manualCheckIds.has("permissive-cors")).toBe(true);
  });

  describe("autofixOtherFile (es. .gitignore per env-file-with-real-values)", () => {
    const envFile = { path: ".env", content: "DATABASE_URL=postgres://user:realpassword@db.host/prod" };

    it("creates a new .gitignore when the project has none, only in full-project mode", () => {
      const result = applyAutofixes([envFile], { fullProject: true });

      const gitignore = result.files.find((f) => f.path === ".gitignore");
      expect(gitignore?.content).toBe(".env\n");
      expect(result.changedFiles.map((f) => f.path)).toContain(".gitignore");
      expect(result.fixedCheckIds.has("env-file-with-real-values")).toBe(true);
    });

    it("appends to an existing .gitignore without losing its other entries", () => {
      const result = applyAutofixes(
        [envFile, { path: ".gitignore", content: "node_modules\ndist\n" }],
        { fullProject: true }
      );

      const gitignore = result.files.find((f) => f.path === ".gitignore");
      expect(gitignore?.content).toBe("node_modules\ndist\n.env\n");
    });

    it("does nothing if the file is already listed in .gitignore", () => {
      const result = applyAutofixes([envFile, { path: ".gitignore", content: ".env\n" }], { fullProject: true });

      const gitignoreChanged = result.changedFiles.some((f) => f.path === ".gitignore");
      expect(gitignoreChanged).toBe(false);
      expect(result.manualCheckIds.has("env-file-with-real-values")).toBe(true);
    });

    it("never touches other files outside full-project mode (e.g. a PR-diff scan)", () => {
      const result = applyAutofixes([envFile]);

      expect(result.files.some((f) => f.path === ".gitignore")).toBe(false);
      expect(result.manualCheckIds.has("env-file-with-real-values")).toBe(true);
    });
  });
});
'@
Write-Utf8NoBom "test/autofix.test.ts" $content_test_autofix_test_ts


Write-Host ""
Write-Host "Fatto. Tutti i file sono stati aggiornati." -ForegroundColor Green
Write-Host "Nessuna migrazione SQL questa volta. Apri il terminale, fai commit + push." -ForegroundColor Green
