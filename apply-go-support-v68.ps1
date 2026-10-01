# JoJoX - Punto 12: secondo linguaggio in piu' oltre JS/TS/SQL/Python - Go.
# Tutti i 21 controlli ora riconoscono anche Go (Gin, net/http): chiavi
# segrete, SQL injection (database/sql), password in chiaro, JWT secret
# (golang-jwt), CORS permissivo (gin-contrib/cors), funzioni admin senza
# controllo, SSRF, hashing debole (md5/sha1 -> bcrypt), XSS (template.HTML),
# bucket pubblici (AWS SDK per Go), redirect aperti, IDOR (GORM), rate limit
# sul login (solo segnalato, vedi sotto) e dati sensibili nei log.
# Testato sia con test automatici mirati sia con un vero file Gin realistico
# (10 problemi trovati correttamente, correzioni applicate verificate come
# sintassi Go valida con go/parser). Aggiornati anche i testi del sito.
#
# Unica eccezione voluta: il rate limiting sul login in Go viene solo
# segnalato, senza correzione automatica. Un middleware autonomo come quello
# fatto per JS/Python richiederebbe una mappa condivisa tra richieste
# concorrenti (sync.Mutex), e non possiamo aggiungere in sicurezza l'import
# "sync" senza rischiare un doppio import nello stesso file: in Go, a
# differenza di JS e Python, un import duplicato non fa compilare il codice.
#
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

$content_src_util_scan_ts = @'
import type { CheckMatch, SourceFile } from "../types.js";

/** True per un file Python — usato dai controlli che riconoscono anche questo linguaggio, non solo JS/TS. */
export function isPythonFile(file: SourceFile): boolean {
  return /\.py$/.test(file.path);
}

/** True per un file Go — usato dai controlli che riconoscono anche questo linguaggio, non solo JS/TS/Python. */
export function isGoFile(file: SourceFile): boolean {
  return /\.go$/.test(file.path);
}

const CONTEXT_CHARS = 12;
const MASK_CHAR = "•";

/** Redacts the matched substring and trims the line to a short window around it — never the full line. */
export function redactLine(lineText: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - CONTEXT_CHARS);
  const end = Math.min(lineText.length, matchIndex + matchLength + CONTEXT_CHARS);
  const secret = lineText.slice(matchIndex, matchIndex + matchLength);

  let windowed = lineText.slice(start, end);
  if (secret.length > 8) {
    const masked = secret.slice(0, 3) + MASK_CHAR.repeat(Math.min(secret.length - 6, 24)) + secret.slice(-3);
    windowed = windowed.split(secret).join(masked);
  }

  return (start > 0 ? "…" : "") + windowed.trim() + (end < lineText.length ? "…" : "");
}

/** Scans a file line by line for a regex, returning one CheckMatch per match with a redacted snippet. */
export function scanLines(file: SourceFile, pattern: RegExp): CheckMatch[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  const lines = file.content.split("\n");
  const matches: CheckMatch[] = [];

  lines.forEach((lineText, idx) => {
    const re = new RegExp(pattern.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(lineText)) !== null) {
      matches.push({ line: idx + 1, snippet: redactLine(lineText, m.index, m[0].length) });
      if (m[0].length === 0) re.lastIndex++;
    }
  });

  return matches;
}

/** True if `pattern` matches anywhere in a window of `span` lines around `centerLine` (1-indexed). */
export function nearbyMatches(file: SourceFile, centerLine: number, span: number, pattern: RegExp): boolean {
  const lines = file.content.split("\n");
  const from = Math.max(0, centerLine - 1 - span);
  const to = Math.min(lines.length, centerLine - 1 + span + 1);
  const windowText = lines.slice(from, to).join("\n");
  return pattern.test(windowText);
}

export function fileMatch(file: SourceFile, pattern: RegExp): boolean {
  return pattern.test(file.content);
}

export function lineFromIndex(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

/**
 * Riscrive ogni riga che combacia con `pattern` usando `replacer`. Se
 * `replacer` ritorna `null` per una riga, quella riga resta invariata.
 * Ritorna il nuovo contenuto e `true` se è stata cambiata almeno una riga.
 */
export function replaceLines(
  content: string,
  pattern: RegExp,
  replacer: (lineText: string, match: RegExpExecArray) => string | null
): { content: string; changed: boolean } {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  let changed = false;
  const lines = content.split("\n").map((lineText) => {
    const re = new RegExp(pattern.source, flags);
    const m = re.exec(lineText);
    if (!m) return lineText;
    const replaced = replacer(lineText, m);
    if (replaced === null) return lineText;
    changed = true;
    return replaced;
  });
  return { content: lines.join("\n"), changed };
}
'@
Write-Utf8NoBom "src/util/scan.ts" $content_src_util_scan_ts

$content_src_checks_critical_ts = @'
import type { Check, CheckMatch } from "../types.js";
import { scanLines, fileMatch, replaceLines, isPythonFile, isGoFile } from "../util/scan.js";
import { toEnvName } from "../util/envName.js";

const PUBLIC_ENV_PREFIX = /(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|PUBLIC_)/;
const SERVER_ONLY_PATH = /(^|\/)(api|server|edge-functions?|functions)(\/|\.)/i;

// Come si legge una variabile d'ambiente nel linguaggio del file — usato per
// non segnalare un valore già letto correttamente, e per scrivere l'autofix.
const ENV_READ_PATTERN = /process\.env|import\.meta\.env|os\.environ|os\.getenv|os\.Getenv/;

const PLACEHOLDER_VALUE =
  /^(process\.env|import\.meta\.env|os\.environ|os\.getenv|os\.Getenv|xxx+|your[-_]?\w*|changeme|example|placeholder|<.*>|\$\{)/i;

// L'operatore di assegnazione: "=" o ":" in JS/Python, ma anche ":=" in Go
// (dichiarazione breve di variabile) — va provato per primo, altrimenti il
// solo ":" verrebbe consumato lasciando "=" sul posto e l'intero match fallirebbe.
const ASSIGN_OP = ":=|[:=]";

// Nomi di variabile che, assegnati a un valore letterale, indicano quasi sempre un segreto.
// Sia in stile camelCase (JS/TS) sia snake_case (Python, lo stile idiomatico
// lì) — condiviso tra detect() e autofix() così restano sempre allineati.
const SECRET_LIKE_NAMES =
  "apiKey|api_key|secret|secretKey|secret_key|apiSecret|api_secret|clientSecret|client_secret|accessToken|access_token|refreshToken|refresh_token|privateKey|private_key|dbPassword|db_password|password|token|authToken|auth_token";

// Valori che, oltre a essere hardcoded, hanno un formato riconoscibile di chiave reale
// (AKIA…, sk_live_/sk_test_…): vanno anche revocati presso il fornitore, non solo tolti
// dal codice — l'autofix li lascia quindi segnalati soltanto, mai riscritti in automatico.
const HIGH_CONFIDENCE_SECRET_VALUE = /AKIA[0-9A-Z]{16}|sk_(live|test)_[0-9a-zA-Z]{16,}/;

// Librerie/funzioni di hashing riconosciute, JS e Python insieme — se il file le usa già
// da qualche parte, diamo per buono che la password sia protetta e non segnaliamo nulla.
const ALREADY_HASHES_PASSWORD =
  /bcrypt|argon2|scrypt|hashSync|hashPassword|crypto\.hash|pbkdf2|werkzeug\.security|check_password_hash|generate_password_hash|make_password|passlib/i;

// Il valore grezzo della password così come arriva dalla richiesta — Express (req.body),
// Flask (request.form/request.json), Django (request.POST), Gin (c.PostForm) e net/http
// (r.FormValue) hanno ognuno il suo nome. Il confine di parola (\b) sta solo sulle forme
// che finiscono con un identificatore semplice: le altre finiscono già con un carattere
// non alfanumerico (']', ')'), dove un \b dopo non potrebbe mai combaciare.
const RAW_PASSWORD_VALUE =
  'req\\.body\\.password\\b|req\\.body\\[["\']password["\']\\]|request\\.form\\[["\']password["\']\\]|request\\.form\\.get\\(["\']password["\']\\)|request\\.json\\[["\']password["\']\\]|request\\.POST\\[["\']password["\']\\]|c\\.PostForm\\(["\']password["\']\\)|r\\.FormValue\\(["\']password["\']\\)|password\\b';

const PLAINTEXT_PASSWORD_ASSIGNMENT = new RegExp(`password\\s*[:=]\\s*(${RAW_PASSWORD_VALUE})`, "gi");

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
    //
    // Non esteso a Python o Go: il problema che segnala è specifico dei
    // bundler JS (Next.js, Vite...) che impacchettano variabili con prefisso
    // pubblico dentro il codice spedito al browser. Un backend Python o un
    // binario Go compilato non hanno un passaggio di bundling equivalente —
    // non c'è un rischio paragonabile da riconoscere con lo stesso pattern.
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
      const assignmentPattern = new RegExp(`\\b(${SECRET_LIKE_NAMES})\\s*(?:${ASSIGN_OP})\\s*["'\`]([^"'\`]{12,})["'\`]`, "gi");
      const lines = file.content.split("\n");
      const assignmentMatches = scanLines(file, assignmentPattern).filter((m) => {
        if (alreadyFlaggedLines.has(m.line)) return false;
        const raw = lines[m.line - 1] ?? "";
        if (ENV_READ_PATTERN.test(raw)) return false;
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
      const pattern = new RegExp(`\\b(${SECRET_LIKE_NAMES})(\\s*(?:${ASSIGN_OP})\\s*)["'\`][^"'\`]{12,}["'\`]`, "gi");
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const { content, changed } = replaceLines(file.content, pattern, (line, m) => {
        if (ENV_READ_PATTERN.test(line)) return null;
        if (HIGH_CONFIDENCE_SECRET_VALUE.test(line)) return null;
        const [, varName, operator] = m;
        const envName = toEnvName(varName);
        // Go: "name := value" diventa "name = os.Getenv(...)" — una volta
        // letta da env non è più una nuova dichiarazione, serve "=" non ":=".
        const goOperator = operator.replace(":=", "=");
        const envRead = python ? `os.environ["${envName}"]` : go ? `os.Getenv("${envName}")` : `process.env.${envName}`;
        const replacement = `${varName}${go ? goOperator : operator}${envRead}`;
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
        // JS/TS: template literal con interpolazione `${...}`.
        ...scanLines(file, /\.(query|raw|execute)\s*\(\s*`[^`]*\$\{/g),
        // Python: f-string con interpolazione f"...{...}" (gestisce anche un
        // apice dell'altro tipo dentro la stringa, es. f"...WHERE x = '{v}'").
        ...scanLines(file, /\.(query|raw|execute)\s*\(\s*(f"[^"]*\{|f'[^']*\{)/g),
        // Concatenazione con "+": stessa sintassi in JS/Python/Go.
        ...scanLines(file, /\.(query|raw|execute)\s*\(\s*["'][^"']*["']\s*\+\s*\w/g),
        // Go: database/sql, costruzione con fmt.Sprintf invece che parametri $1/?.
        ...scanLines(file, /\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf\s*\(/g),
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
      if (ALREADY_HASHES_PASSWORD.test(file.content)) return [];
      return scanLines(file, PLAINTEXT_PASSWORD_ASSIGNMENT);
    },
    autofix(file) {
      if (ALREADY_HASHES_PASSWORD.test(file.content)) return null;
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const note = python
        ? " # JoJoX: serve il pacchetto bcrypt — pip install bcrypt"
        : go
          ? " // JoJoX: serve il pacchetto golang.org/x/crypto/bcrypt"
          : " /* JoJoX: serve il pacchetto bcrypt — npm install bcrypt */";
      const { content, changed } = replaceLines(file.content, PLAINTEXT_PASSWORD_ASSIGNMENT, (line, m) => {
        const value = m[1];
        const prefix = m[0].slice(0, m[0].length - value.length);
        // Go: GenerateFromPassword ritorna ([]byte, error) — qui mettiamo solo
        // la chiamata, va comunque gestito l'errore secondo lo stile del file.
        const hashCall = python
          ? `bcrypt.hashpw(${value}.encode(), bcrypt.gensalt())`
          : go
            ? `bcrypt.GenerateFromPassword([]byte(${value}), bcrypt.DefaultCost)`
            : `await bcrypt.hash(${value}, 12)`;
        const replacement = `${prefix}${hashCall}${note}`;
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
        // JS (jsonwebtoken): jwt.sign(...)/jwt.verify(...).
        ...scanLines(file, /jwt\.(sign|verify)\s*\([^)]*,\s*["'][^"']{6,}["']/g),
        // Python (PyJWT): jwt.encode(...)/jwt.decode(...).
        ...scanLines(file, /jwt\.(encode|decode)\s*\([^)]*,\s*["'][^"']{6,}["']/g),
        // Go (golang-jwt): token.SignedString([]byte("secret-letterale")).
        ...scanLines(file, /\.SignedString\s*\(\s*\[\]byte\s*\(\s*["'`][^"'`]{6,}["'`]\s*\)\s*\)/g),
        ...scanLines(file, /JWT_SECRET\s*(?:=|:=)\s*["'][^"']+["']/g),
      ];
    },
    autofix(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const envRead = python ? 'os.environ["JWT_SECRET"]' : go ? 'os.Getenv("JWT_SECRET")' : "process.env.JWT_SECRET";
      const jsMethods = replaceLines(file.content, /jwt\.(sign|verify)\s*\(([^)]*),\s*["'][^"']{6,}["']/g, (line, m) => {
        const [, method, args] = m;
        const replacement = `jwt.${method}(${args}, ${envRead}`;
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const pyMethods = replaceLines(jsMethods.content, /jwt\.(encode|decode)\s*\(([^)]*),\s*["'][^"']{6,}["']/g, (line, m) => {
        const [, method, args] = m;
        const replacement = `jwt.${method}(${args}, ${envRead}`;
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const goMethods = replaceLines(
        pyMethods.content,
        /\.SignedString\s*\(\s*\[\]byte\s*\(\s*["'`][^"'`]{6,}["'`]\s*\)\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `.SignedString([]byte(${envRead}))` + line.slice(m.index + m[0].length);
        }
      );
      const literal = replaceLines(goMethods.content, /JWT_SECRET\s*(=|:=)\s*["'][^"']+["']/g, (line, m) => {
        const op = go ? m[1].replace(":=", "=") : m[1];
        return line.slice(0, m.index) + `JWT_SECRET ${op} ${envRead}` + line.slice(m.index + m[0].length);
      });
      return jsMethods.changed || pyMethods.changed || goMethods.changed || literal.changed ? literal.content : null;
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
      const matches: CheckMatch[] = [];

      if (fileMatch(file, /\b(exec|execSync|spawn)\s*\(/)) {
        matches.push(
          ...scanLines(file, /\b(exec|execSync|spawn)\s*\(\s*`[^`]*\$\{/g),
          ...scanLines(file, /\b(exec|execSync|spawn)\s*\(\s*["'][^"']*["']\s*\+\s*\w/g)
        );
      }

      // Python: os.system/os.popen sono pericolosi non appena il comando è
      // costruito da input (nessuna via sicura, a differenza di subprocess),
      // mentre subprocess.call/run/Popen/check_output lo sono solo quando
      // shell=True è esplicito — con shell=False (il default) una lista di
      // argomenti interpolati resta sicura, non la segnaliamo.
      if (fileMatch(file, /\bos\.(system|popen)\s*\(|\bsubprocess\.(call|run|Popen|check_output)\s*\(/)) {
        matches.push(
          ...scanLines(file, /\bos\.(system|popen)\s*\(\s*(f"[^"]*\{|f'[^']*\{)/g),
          ...scanLines(file, /\bos\.(system|popen)\s*\(\s*["'][^"']*["']\s*\+\s*\w/g),
          ...scanLines(
            file,
            /\bsubprocess\.(call|run|Popen|check_output)\s*\(\s*(f"[^"]*\{[^)]*|f'[^']*\{[^)]*)shell\s*=\s*True/g
          ),
          ...scanLines(file, /\bsubprocess\.(call|run|Popen|check_output)\s*\([^)]*\+\s*\w[^)]*shell\s*=\s*True/g)
        );
      }

      // Go: exec.Command con una lista di argomenti separati è sicuro di
      // default — il rischio è specifico di invocare una shell (sh -c /
      // bash -c / cmd /c) con un comando costruito per interpolazione o
      // concatenazione, esattamente come per subprocess+shell=True in Python.
      if (fileMatch(file, /exec\.Command\s*\(\s*["'`](sh|bash|cmd)["'`]\s*,\s*["'`](-c|\/c)["'`]/)) {
        matches.push(
          ...scanLines(
            file,
            /exec\.Command\s*\(\s*["'`](?:sh|bash|cmd)["'`]\s*,\s*["'`](?:-c|\/c)["'`]\s*,\s*fmt\.Sprintf\s*\(/g
          ),
          ...scanLines(
            file,
            /exec\.Command\s*\(\s*["'`](?:sh|bash|cmd)["'`]\s*,\s*["'`](?:-c|\/c)["'`]\s*,\s*["'`][^"'`]*["'`]\s*\+\s*\w/g
          )
        );
      }

      return matches;
    },
    // Nessun autofix: separare comando e argomenti in modo sicuro richiede
    // di capire quale sia davvero il programma e quali i suoi parametri —
    // provarci alla cieca rischia di generare codice che non funziona più.
  },
];
'@
Write-Utf8NoBom "src/checks/critical.ts" $content_src_checks_critical_ts

$content_src_checks_high_ts = @'
import type { Check, CheckMatch } from "../types.js";
import { scanLines, lineFromIndex, redactLine, replaceLines, isPythonFile, isGoFile } from "../util/scan.js";

// JS/Express (requireAuth, req.user...), Python/Flask/Django (login_required,
// request.user.is_staff...) e Go/Gin (MustGet, AuthRequired...) insieme — un
// controllo di autenticazione o ruolo riconoscibile in tutti e tre i mondi.
// Case-insensitive: così la stessa lista copre sia lo stile camelCase di
// JS/Python sia il PascalCase idiomatico di Go, senza doverle scrivere due volte.
const ADMIN_AUTH_KEYWORDS =
  /requireAuth|isAdmin|checkRole|verifyToken|session\.user|req\.user|assertRole|login_required|permission_required|staff_member_required|is_staff|is_superuser|request\.user\.is_authenticated|current_user|MustGet|AuthRequired|Authorization/i;

function findUnprotectedTables(content: string): string[] {
  const createRe = /CREATE TABLE\s+(?:IF NOT EXISTS\s+)?"?(?:\w+\.)?(\w+)"?/gi;
  const tables: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = createRe.exec(content)) !== null) {
    const table = m[1];
    const protectedPattern = new RegExp(
      `${table}"?\\s+ENABLE ROW LEVEL SECURITY|ENABLE ROW LEVEL SECURITY[\\s\\S]{0,3}${table}`,
      "i"
    );
    if (!protectedPattern.test(content)) tables.push(table);
  }
  return tables;
}

export const highChecks: Check[] = [
  {
    id: "unprotected-new-table",
    severity: "high",
    confidence: "heuristic",
    title: "Una nuova tabella sembra creata senza protezione",
    description:
      "Una migrazione SQL crea una tabella ma non attiva la Row Level Security per quella stessa tabella nello stesso file. Finché resta così, la tabella nasce senza nessuna restrizione su chi può leggerla o scriverla.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
    detect(file) {
      if (!/\.sql$/i.test(file.path)) return [];
      const createRe = /CREATE TABLE\s+(?:IF NOT EXISTS\s+)?"?(?:\w+\.)?(\w+)"?/gi;
      const matches: CheckMatch[] = [];
      let m: RegExpExecArray | null;
      while ((m = createRe.exec(file.content)) !== null) {
        const table = m[1];
        const protectedPattern = new RegExp(
          `${table}"?\\s+ENABLE ROW LEVEL SECURITY|ENABLE ROW LEVEL SECURITY[\\s\\S]{0,3}${table}`,
          "i"
        );
        if (protectedPattern.test(file.content)) continue;
        const line = lineFromIndex(file.content, m.index);
        const lineText = file.content.split("\n")[line - 1] ?? "";
        matches.push({ line, snippet: redactLine(lineText, m.index - (file.content.lastIndexOf("\n", m.index) + 1), m[0].length) });
      }
      return matches;
    },
    autofix(file) {
      if (!/\.sql$/i.test(file.path)) return null;
      const tables = findUnprotectedTables(file.content);
      if (tables.length === 0) return null;
      const additions = tables.map((t) => `ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY;`).join("\n");
      return `${file.content.trimEnd()}\n\n${additions}\n`;
    },
  },

  {
    id: "permissive-cors",
    severity: "high",
    confidence: "confirmed",
    title: "Il sito accetta richieste da qualsiasi altro sito web",
    description:
      "L'intestazione CORS è impostata per accettare richieste da qualunque origine (*), oppure il middleware cors() è usato senza restrizioni. Qualsiasi sito web di terzi può chiamare le tue API dal browser di un utente già autenticato.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://tuosito.com"] }))`,
    },
    detect(file) {
      return [
        // Intestazione grezza — identica in qualsiasi linguaggio.
        ...scanLines(file, /Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["']/gi),
        ...scanLines(file, /origin\s*[:=]\s*["']\*["']/gi),
        // JS: middleware cors() di Express usato senza restrizioni.
        ...scanLines(file, /\bcors\(\s*\)/g),
        // Python: Flask-CORS senza restrizioni, o django-cors-headers che
        // permette esplicitamente qualsiasi origine.
        ...scanLines(file, /\bCORS\(\s*\w+\s*\)/g),
        ...scanLines(file, /CORS_ORIGIN_ALLOW_ALL\s*=\s*True/g),
        ...scanLines(file, /CORS_ALLOWED_ORIGINS\s*=\s*\[\s*["']\*["']/g),
        // Go: gin-contrib/cors — cors.Default() non applica nessuna
        // restrizione, o AllowOrigins impostato esplicitamente a "*".
        ...scanLines(file, /\bcors\.Default\(\s*\)/g),
        ...scanLines(file, /AllowOrigins\s*[:=]\s*\[\]string\{\s*["']\*["']/g),
      ];
    },
    // Nessun autofix: non sappiamo qual è il tuo vero dominio. Un elenco di
    // origini indovinato sarebbe inutile o, peggio, dato per buono senza
    // controllo — meglio dirtelo chiaramente e farlo scrivere a te.
  },

  {
    id: "admin-function-missing-auth",
    severity: "high",
    confidence: "heuristic",
    title: "Una funzione con permessi da amministratore non controlla chi la usa",
    description:
      "Una rotta o funzione il cui nome suggerisce operazioni da amministratore non contiene, nelle righe vicine, nessun controllo di autenticazione o di ruolo. Chiunque conosca l'URL potrebbe eseguirla.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
    detect(file) {
      const routePatterns = [
        // JS/Express: router.get("/admin/...", ...).
        /\.(get|post|put|patch|delete)\s*\(\s*["'][^"']*\/admin[^"']*["']/gi,
        // Python/Flask: @app.route("/admin/...") — la riga del decoratore.
        // (Django non è incluso: lì la rotta sta in urls.py e il controllo di
        // permesso nella view in un altro file — "righe vicine" non significa
        // nulla in quell'architettura, darebbe solo falsi allarmi.)
        /@\w+\.route\s*\(\s*["'][^"']*\/admin[^"']*["']/gi,
      ];
      const matches: CheckMatch[] = [];
      const lines = file.content.split("\n");
      lines.forEach((lineText, idx) => {
        const hit = routePatterns.some((p) => {
          const found = p.test(lineText);
          p.lastIndex = 0;
          return found;
        });
        if (!hit) return;
        const windowText = lines.slice(idx, Math.min(lines.length, idx + 15)).join("\n");
        if (ADMIN_AUTH_KEYWORDS.test(windowText)) return;
        matches.push({ line: idx + 1, snippet: redactLine(lineText, 0, lineText.length) });
      });
      return matches;
    },
    // Nessun autofix: non conosciamo il nome della tua funzione/middleware
    // di autenticazione — inventarne uno finto darebbe un falso senso di
    // sicurezza, peggio di lasciare il problema segnalato.
  },

  {
    id: "ssrf",
    severity: "high",
    confidence: "confirmed",
    title: "Il sito può essere costretto a eseguire codice esterno",
    description:
      "Una richiesta HTTP in uscita (fetch, axios) usa direttamente un valore che arriva dalla richiesta di un utente come URL di destinazione. Un utente malintenzionato può far chiamare al tuo server indirizzi interni o arbitrari — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.tuoservizio.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL non consentito")\nconst data = await fetch(req.query.url)`,
    },
    detect(file) {
      return [
        // JS: fetch/axios con un valore preso direttamente dalla richiesta.
        ...scanLines(file, /\b(fetch|axios\.get|axios\.post|axios\.request|request)\s*\(\s*req\.(query|body|params)/g),
        // Python: requests/urllib con un valore preso da Flask (request.args/
        // form/json) o Django (request.GET/POST).
        ...scanLines(
          file,
          /\b(requests\.(get|post|put|request)|urllib\.request\.urlopen)\s*\(\s*request\.(args|form|json|GET|POST)/g
        ),
        // Go: http.Get/http.Post con un valore preso da Gin (c.Query/c.PostForm)
        // o da net/http puro (r.FormValue/r.URL.Query).
        ...scanLines(
          file,
          /\bhttp\.(Get|Post)\s*\(\s*(c\.(Query|PostForm)|r\.(FormValue|URL\.Query\(\)\.Get))\s*\(/g
        ),
      ];
    },
    // Nessun autofix: quali destinazioni siano legittime lo sai solo tu —
    // un elenco consentito inventato non protegge davvero.
  },

  {
    id: "weak-password-hashing",
    severity: "high",
    confidence: "confirmed",
    title: "Le password sono protette con un metodo ormai facile da violare",
    description:
      "Nella stessa riga, md5() o sha1() vengono applicati a un valore legato a una password. Questi algoritmi sono troppo veloci da calcolare: un attaccante con il database può provare miliardi di password al secondo.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
    detect(file) {
      const pattern =
        /createHash\(\s*["'](md5|sha1)["']\s*\)|hashlib\.(md5|sha1)\s*\(|\b(md5|sha1)\.Sum\s*\(|\b(md5|sha1)\s*\(\s*password/gi;
      const lines = file.content.split("\n");
      return scanLines(file, pattern).filter((m) => /password/i.test(lines[m.line - 1] ?? ""));
    },
    autofix(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const note = python
        ? " # JoJoX: serve il pacchetto bcrypt — pip install bcrypt"
        : go
          ? " // JoJoX: serve il pacchetto golang.org/x/crypto/bcrypt"
          : " /* JoJoX: serve il pacchetto bcrypt — npm install bcrypt */";
      const hashCall = (value: string) =>
        python
          ? `bcrypt.hashpw(${value}.encode(), bcrypt.gensalt())`
          : go
            ? `bcrypt.GenerateFromPassword([]byte(${value}), bcrypt.DefaultCost)`
            : `await bcrypt.hash(${value}, 12)`;

      // Il valore passato può a sua volta contenere una chiamata con le sue
      // parentesi (es. Python password.encode()) — un semplice [^)]* si
      // fermerebbe alla prima ")" interna, troncando l'argomento e
      // producendo codice sintatticamente rotto. Questo pattern tollera un
      // livello di parentesi annidate.
      const BALANCED_ARG = "(?:[^()]|\\([^()]*\\))*";

      const chainPattern = new RegExp(
        `crypto\\.createHash\\(\\s*["'](?:md5|sha1)["']\\s*\\)\\.update\\((${BALANCED_ARG})\\)\\.digest\\([^)]*\\)`,
        "gi"
      );
      let result = replaceLines(file.content, chainPattern, (line, m) => {
        if (!/password/i.test(line)) return null;
        return line.slice(0, m.index) + `${hashCall(m[1]!)}${note}` + line.slice(m.index + m[0].length);
      });
      if (!result.changed) {
        // Python: hashlib.md5(password.encode()).hexdigest() — la "chiamata
        // intera" sostituita è solo hashlib.md5(...), il resto (.hexdigest())
        // resta sulla riga: bcrypt non ne ha bisogno, ma toglierlo da solo
        // rischierebbe di rompere la sintassi se il valore è usato altrove.
        const hashlibPattern = new RegExp(`hashlib\\.(?:md5|sha1)\\((${BALANCED_ARG})\\)`, "gi");
        result = replaceLines(file.content, hashlibPattern, (line, m) => {
          if (!/password/i.test(line)) return null;
          return line.slice(0, m.index) + `${hashCall(m[1]!)}${note}` + line.slice(m.index + m[0].length);
        });
      }
      if (!result.changed) {
        // Go: md5.Sum([]byte(password)) — stessa logica dell'hashlib Python,
        // sostituiamo solo la chiamata, quello che viene dopo (es. un
        // ulteriore uso del risultato) resta intatto sulla riga.
        const goSumPattern = new RegExp(`(?:md5|sha1)\\.Sum\\(\\s*(${BALANCED_ARG})\\s*\\)`, "gi");
        result = replaceLines(file.content, goSumPattern, (line, m) => {
          if (!/password/i.test(line)) return null;
          return line.slice(0, m.index) + `${hashCall(m[1]!)}${note}` + line.slice(m.index + m[0].length);
        });
      }
      if (!result.changed) {
        const barePattern = new RegExp(`\\b(?:md5|sha1)\\s*\\((${BALANCED_ARG})\\)`, "gi");
        result = replaceLines(file.content, barePattern, (line, m) => {
          if (!/password/i.test(line)) return null;
          return line.slice(0, m.index) + `${hashCall(m[1]!)}${note}` + line.slice(m.index + m[0].length);
        });
      }
      return result.changed ? result.content : null;
    },
  },
];
'@
Write-Utf8NoBom "src/checks/high.ts" $content_src_checks_high_ts

$content_src_checks_medium_ts = @'
import type { Check, CheckMatch } from "../types.js";
import { scanLines, redactLine, replaceLines } from "../util/scan.js";

// JS (userId, req.user...), Python/Django/Flask (request.user, user_id...) e
// Go (UserID, c.MustGet...) insieme — case-insensitive per coprire anche il
// PascalCase idiomatico di Go senza doverlo scrivere due volte.
const OWNERSHIP_KEYWORDS = /userId|user_id|user\.id|owner|req\.user|request\.user|auth\.uid|current_user|MustGet/i;
const REDIRECT_REMOVED_NOTE =
  " /* JoJoX: reindirizzamento verso un URL esterno non validato rimosso — se ti serve, valida il valore contro un elenco di percorsi permessi prima di riattivarlo */";

export const mediumChecks: Check[] = [
  {
    id: "xss-dangerous-html",
    severity: "medium",
    confidence: "heuristic",
    title: "Un testo scritto dagli utenti potrebbe eseguire codice nel browser",
    description:
      "Del contenuto viene inserito nella pagina come HTML grezzo (dangerouslySetInnerHTML, v-html, .innerHTML) invece che come testo semplice. Se quel contenuto include input di un utente, può contenere script che vengono eseguiti nel browser di chi legge la pagina.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// oppure, se serve HTML: DOMPurify.sanitize(comment.text)`,
    },
    detect(file) {
      return [
        ...scanLines(file, /dangerouslySetInnerHTML/g),
        ...scanLines(file, /v-html\s*=/g),
        ...scanLines(file, /\.innerHTML\s*=\s*[^"'`\s][^;]*/g),
        // Python/Jinja2 (Flask) e Django template: il filtro |safe o
        // mark_safe() disattivano l'escape automatico dell'HTML.
        ...scanLines(file, /\{\{[^}]*\|\s*safe\s*\}\}/g),
        ...scanLines(file, /\bmark_safe\s*\(/g),
        // Go: html/template — template.HTML(...) marca una stringa come HTML
        // già sicuro, disattivando l'escape automatico del pacchetto.
        ...scanLines(file, /\btemplate\.HTML\s*\(/g),
      ];
    },
    // Nessun autofix: non sappiamo se quell'HTML deve restare tale (e va
    // solo sanificato, aggiungendo una dipendenza) o può diventare testo
    // semplice — dipende da cosa deve davvero mostrare quella pagina.
  },

  {
    id: "public-storage-bucket",
    severity: "medium",
    confidence: "confirmed",
    title: "Lo spazio dei file caricati è visibile a chiunque",
    description:
      "Un bucket di storage (Supabase Storage, S3) è configurato come pubblico. Se contiene documenti, foto o file caricati dagli utenti, chiunque conosca — o indovini — il percorso può accedervi senza autenticazione.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// servire i file con URL firmati a tempo: createSignedUrl(path, 60)`,
    },
    detect(file) {
      return [
        // JS: supabase-js, dict-style con "true" minuscolo.
        ...scanLines(file, /createBucket\([^)]*public\s*:\s*true/g),
        // Python: supabase-py, stesso dict ma "True" maiuscolo (sintassi Python).
        ...scanLines(file, /create_bucket\([^)]*public["']?\s*:\s*True/g),
        // JS e Python insieme: boto3 (Python) e SDK JS di S3 usano entrambi
        // la stessa chiave "ACL" con lo stesso valore letterale.
        ...scanLines(file, /acl\s*[:=]\s*["']public-read["']/gi),
        // Go: SDK AWS per Go, il valore è avvolto in aws.String(...).
        ...scanLines(file, /ACL:\s*aws\.String\(\s*["']public-read["']\s*\)/g),
      ];
    },
    autofix(file) {
      const r1 = replaceLines(file.content, /createBucket\([^)]*public\s*:\s*true/g, (line, m) => {
        const replacement = m[0].replace(/public\s*:\s*true/, "public: false");
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const r2 = replaceLines(r1.content, /create_bucket\([^)]*public["']?\s*:\s*True/g, (line, m) => {
        const replacement = m[0].replace(/public(["']?)\s*:\s*True/, "public$1: False");
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const r3 = replaceLines(r2.content, /acl\s*([:=])\s*["']public-read["']/gi, (line, m) => {
        const replacement = m[1] === "=" ? `ACL="private"` : `acl: "private"`;
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const r4 = replaceLines(r3.content, /ACL:\s*aws\.String\(\s*["']public-read["']\s*\)/g, (line, m) => {
        return line.slice(0, m.index) + `ACL: aws.String("private")` + line.slice(m.index + m[0].length);
      });
      return r1.changed || r2.changed || r3.changed || r4.changed ? r4.content : null;
    },
  },

  {
    id: "csrf-state-changing-get",
    severity: "medium",
    confidence: "heuristic",
    title: "Basta un link per cancellare o modificare dei dati",
    description:
      "Una rotta GET esegue un'operazione che cambia dati (il percorso contiene delete/remove/update/edit). Le richieste GET vengono eseguite anche solo visitando un link o caricando un'immagine da un sito esterno — è il punto d'appoggio classico per un attacco CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
    detect(file) {
      const matches: CheckMatch[] = [...scanLines(file, /\.get\s*\(\s*["'][^"']*\/(delete|remove|update|edit)[^"']*["']/gi)];

      // Python/Flask: @app.route("/posts/<id>/delete") è una GET per
      // default finché non specifichi methods= con POST/PUT/DELETE nella
      // stessa riga — un form che chiama una rotta così è comunque un rischio.
      const flaskRoutePattern = /@\w+\.route\s*\(\s*["'][^"']*\/(delete|remove|update|edit)[^"']*["']/gi;
      const lines = file.content.split("\n");
      lines.forEach((lineText, idx) => {
        if (!flaskRoutePattern.test(lineText)) return;
        flaskRoutePattern.lastIndex = 0;
        if (/methods\s*=\s*\[[^\]]*(POST|PUT|DELETE)/i.test(lineText)) return;
        matches.push({ line: idx + 1, snippet: redactLine(lineText, 0, lineText.length) });
      });

      return matches;
    },
    // Nessun autofix: cambiare il metodo da GET a POST rompe chiunque
    // chiami questa rotta altrove (form, link, fetch) — quei punti di
    // chiamata non li vediamo, quindi non possiamo aggiornarli insieme.
  },

  {
    id: "insecure-token-storage",
    severity: "medium",
    confidence: "confirmed",
    title: "I dati di accesso salvati nel browser non sono ben protetti",
    description:
      "Un token di accesso viene salvato in localStorage. A differenza di un cookie httpOnly, qualunque script eseguito nella pagina (incluso uno script malevolo iniettato via XSS) può leggerlo e rubarlo.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// impostare il token come cookie httpOnly dal server:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
    detect(file) {
      return scanLines(file, /localStorage\.setItem\(\s*["'][^"']*(token|jwt|auth)[^"']*["']/gi);
    },
    // Nessun autofix: la correzione vera sposta la scrittura del cookie sul
    // server, cioè in un file diverso da quello dove vive questa riga —
    // non possiamo farlo senza sapere dov'è quel server.
    //
    // Non esteso a Python o Go: localStorage è un'API del browser, non ha un
    // corrispondente lato server in nessuno dei due. Un backend che genera
    // HTML/JS con la stessa riga (es. in un template) verrebbe comunque
    // riconosciuto dal pattern così com'è, scansionando quel file come se fosse JS.
  },

  {
    id: "open-redirect",
    severity: "medium",
    confidence: "confirmed",
    title: "Il sito può essere usato per reindirizzare verso un sito truffa",
    description:
      "Il sito reindirizza l'utente verso un indirizzo preso direttamente dalla richiesta (query, body, params) senza controllare che sia un dominio conosciuto. Un link che sembra puntare al tuo sito può in realtà portare a una pagina di phishing.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
    detect(file) {
      return [
        ...scanLines(file, /res\.redirect\(\s*req\.(query|body|params)/g),
        ...scanLines(file, /window\.location(\.href)?\s*=\s*(req\.(query|body|params)|new URLSearchParams)/g),
        // Python/Flask: redirect(request.args[...]). Django: redirect(request.GET[...])
        // o HttpResponseRedirect(request.GET[...]).
        ...scanLines(file, /\b(redirect|HttpResponseRedirect)\s*\(\s*request\.(args|form|GET|POST)/g),
        // Go/Gin: c.Redirect(status, c.Query(...)). net/http: http.Redirect(w, r, r.FormValue(...), status).
        ...scanLines(file, /c\.Redirect\s*\(\s*[^,]+,\s*c\.(Query|PostForm)\s*\(/g),
        ...scanLines(file, /http\.Redirect\s*\([^,]+,[^,]+,\s*r\.FormValue\s*\(/g),
      ];
    },
    autofix(file) {
      // Non conosciamo l'elenco di percorsi che dovrebbero essere permessi,
      // quindi non lo inventiamo: chiudiamo il buco reindirizzando sempre
      // alla home. Se il redirect dinamico serve davvero, va riattivato a
      // mano con un vero elenco di destinazioni consentite.
      const r1 = replaceLines(
        file.content,
        /res\.redirect\(\s*req\.(query|body|params)(?:\.\w+|\[[^\]]+\])*\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `res.redirect("/")${REDIRECT_REMOVED_NOTE}` + line.slice(m.index + m[0].length);
        }
      );
      const r2 = replaceLines(
        r1.content,
        /window\.location(\.href)?\s*=\s*(req\.(query|body|params)(?:\.\w+|\[[^\]]+\])*|new URLSearchParams\([^)]*\)[^;\n]*)/g,
        (line, m) => {
          const prop = m[1] ?? "";
          return line.slice(0, m.index) + `window.location${prop} = "/"${REDIRECT_REMOVED_NOTE}` + line.slice(m.index + m[0].length);
        }
      );
      const pythonNote = REDIRECT_REMOVED_NOTE.replace("/*", "#").replace("*/", "");
      const r3 = replaceLines(
        r2.content,
        /\b(redirect|HttpResponseRedirect)\s*\(\s*request\.(args|form|GET|POST)(?:\.\w+|\[[^\]]+\]|\.get\([^)]*\))*\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `${m[1]}("/")${pythonNote}` + line.slice(m.index + m[0].length);
        }
      );
      const goNote = REDIRECT_REMOVED_NOTE.replace("/*", "//").replace("*/", "");
      const r4 = replaceLines(
        r3.content,
        /c\.Redirect\s*\(\s*([^,]+),\s*c\.(?:Query|PostForm)\s*\([^)]*\)\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `c.Redirect(${m[1]}, "/")${goNote}` + line.slice(m.index + m[0].length);
        }
      );
      const r5 = replaceLines(
        r4.content,
        /http\.Redirect\s*\(\s*([^,]+),\s*([^,]+),\s*r\.FormValue\s*\([^)]*\)\s*,\s*([^)]+)\)/g,
        (line, m) => {
          return (
            line.slice(0, m.index) + `http.Redirect(${m[1]}, ${m[2]}, "/", ${m[3]})${goNote}` + line.slice(m.index + m[0].length)
          );
        }
      );
      return r1.changed || r2.changed || r3.changed || r4.changed || r5.changed ? r5.content : null;
    },
  },

  {
    id: "idor",
    severity: "medium",
    confidence: "heuristic",
    title: "Cambiando un numero nell'indirizzo si potrebbero vedere dati altrui",
    description:
      "Una query al database usa direttamente un identificativo preso dall'URL (req.params.id) senza verificare, nelle righe vicine, che appartenga all'utente che sta facendo la richiesta. Cambiando l'id nell'indirizzo si potrebbe accedere ai dati di un altro utente — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
    detect(file) {
      const pattern =
        /\.findById\(\s*req\.params\.id\s*\)|findOne\(\s*\{\s*_id:\s*req\.params\.id\s*\}\s*\)|\.objects\.get\(\s*(pk|id)\s*=\s*request\.(GET|POST|args)\[[^\]]+\]\s*\)|get_object_or_404\([^,]+,\s*(pk|id)\s*=\s*request\.(GET|POST|args)\[[^\]]+\]\s*\)|\.(First|Find)\(\s*&\w+\s*,\s*c\.Param\(\s*["'][^"']+["']\s*\)\s*\)/g;
      const matches: CheckMatch[] = [];
      const lines = file.content.split("\n");
      lines.forEach((lineText, idx) => {
        const re = new RegExp(pattern.source, "g");
        if (!re.test(lineText)) return;
        const from = Math.max(0, idx - 5);
        const to = Math.min(lines.length, idx + 6);
        const windowText = lines.slice(from, to).join("\n");
        if (OWNERSHIP_KEYWORDS.test(windowText)) return;
        matches.push({ line: idx + 1, snippet: redactLine(lineText, 0, lineText.length) });
      });
      return matches;
    },
    // Nessun autofix: non sappiamo qual è il campo che collega il record
    // all'utente proprietario nel tuo schema dati — aggiungerne uno a
    // caso creerebbe una query che sembra corretta ma non lo è.
  },
];
'@
Write-Utf8NoBom "src/checks/medium.ts" $content_src_checks_medium_ts

$content_src_checks_low_ts = @'
import type { Check } from "../types.js";
import { scanLines, fileMatch, replaceLines, isPythonFile, isGoFile } from "../util/scan.js";

const RATE_LIMIT_HELPER = `// JoJoX: limite tentativi di accesso (5 ogni 15 minuti), senza dipendenze esterne
const __jojoxLoginAttempts = new Map();
function __jojoxRateLimit(req, res, next) {
  const key = req.ip;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const max = 5;
  const rec = __jojoxLoginAttempts.get(key) ?? { count: 0, start: now };
  if (now - rec.start > windowMs) {
    rec.count = 0;
    rec.start = now;
  }
  rec.count++;
  __jojoxLoginAttempts.set(key, rec);
  if (rec.count > max) {
    res.status(429).json({ error: "Troppi tentativi, riprova più tardi." });
    return;
  }
  next();
}

`;

const RATE_LIMIT_HELPER_PYTHON = `# JoJoX: limite tentativi di accesso (5 ogni 15 minuti), senza dipendenze esterne
import time
from functools import wraps
from flask import request, jsonify

__jojox_login_attempts = {}

def __jojox_rate_limit(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        key = request.remote_addr
        now = time.time()
        window = 15 * 60
        max_attempts = 5
        rec = __jojox_login_attempts.get(key, {"count": 0, "start": now})
        if now - rec["start"] > window:
            rec = {"count": 0, "start": now}
        rec["count"] += 1
        __jojox_login_attempts[key] = rec
        if rec["count"] > max_attempts:
            return jsonify({"error": "Troppi tentativi, riprova più tardi."}), 429
        return view(*args, **kwargs)
    return wrapped

`;

export const lowChecks: Check[] = [
  {
    id: "no-login-rate-limit",
    severity: "low",
    confidence: "heuristic",
    title: "Il modulo di accesso non blocca troppi tentativi di fila",
    description:
      "Una rotta di login è definita nel file, ma non c'è traccia di un middleware di rate limiting nello stesso file. Senza un limite ai tentativi, un attaccante può provare password in sequenza (brute force) senza essere rallentato.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
    detect(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const routePattern = python
        ? /@\w+\.route\s*\(\s*["'][^"']*\/login[^"']*["']/i
        : go
          ? /\.(POST|post)\s*\(\s*["'][^"']*\/login[^"']*["']/
          : /\.post\s*\(\s*["'][^"']*\/login[^"']*["']/i;
      const limiterPattern = python
        ? /rateLimit|rate-limit|rate_limit|flask_limiter|Limiter\(/i
        : go
          ? /rate\.NewLimiter|tollbooth|ulule\/limiter|gin-contrib\/limiter|RateLimit|rate_limit/i
          : /rateLimit|rate-limit|rate_limit/i;

      if (!fileMatch(file, routePattern)) return [];
      if (fileMatch(file, limiterPattern)) return [];
      return scanLines(file, new RegExp(routePattern.source, "gi"));
    },
    autofix(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);

      // Per il Go non generiamo un rate limiter autonomo come per JS/Python:
      // servirebbe un map condiviso tra goroutine, che senza sync.Mutex può
      // andare in crash ("concurrent map writes"), e non possiamo aggiungere
      // in sicurezza l'import "sync" senza rischiare un doppio import (in Go,
      // a differenza di JS e Python, un import duplicato non compila). Per
      // ora segnaliamo soltanto il problema senza un fix automatico.
      if (go) return null;

      if (python) {
        if (!fileMatch(file, /@\w+\.route\s*\(\s*["'][^"']*\/login[^"']*["']/i)) return null;
        if (fileMatch(file, /rateLimit|rate-limit|rate_limit|flask_limiter|Limiter\(|__jojox_rate_limit/i)) return null;
        // Stesso ragionamento del caso JS: non installiamo Flask-Limiter al
        // posto tuo, un decoratore autonomo incluso nel file funziona subito.
        // @app.route deve restare il decoratore più esterno perché Flask
        // registri la rotta correttamente: il nostro va subito sotto, non sopra.
        const { content, changed } = replaceLines(
          file.content,
          /(@\w+\.route\s*\(\s*["'][^"']*\/login[^"']*["'][^)]*\))/,
          (line, m) => {
            const indent = line.match(/^(\s*)/)?.[1] ?? "";
            return line.slice(0, m.index) + m[1] + "\n" + indent + "@__jojox_rate_limit" + line.slice(m.index + m[0].length);
          }
        );
        return changed ? RATE_LIMIT_HELPER_PYTHON + content : null;
      }

      if (!fileMatch(file, /\.post\s*\(\s*["'][^"']*\/login[^"']*["']/i)) return null;
      if (fileMatch(file, /rateLimit|rate-limit|rate_limit|__jojoxRateLimit/i)) return null;
      // Non aggiungiamo una dipendenza npm nuova (non possiamo installarla
      // per te): un piccolo limitatore autonomo, incluso direttamente nel
      // file, è meno raffinato di express-rate-limit ma funziona subito.
      const { content, changed } = replaceLines(
        file.content,
        /\.post\s*\(\s*(["'][^"']*\/login[^"']*["'])\s*,\s*/,
        (line, m) => {
          return line.slice(0, m.index) + `.post(${m[1]}, __jojoxRateLimit, ` + line.slice(m.index + m[0].length);
        }
      );
      return changed ? RATE_LIMIT_HELPER + content : null;
    },
  },

  {
    id: "sensitive-data-in-logs",
    severity: "low",
    confidence: "heuristic",
    title: "Password o dati sensibili finiscono nei log",
    description:
      "Una chiamata a console.log (o simili) include una variabile chiamata password, token, secret o apiKey. Se questi log finiscono in un servizio esterno o in un file, i dati sensibili restano in chiaro molto più a lungo del necessario.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
    detect(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const pattern = python
        ? /\b(print|logging\.(debug|info|warning|error|critical)|logger\.(debug|info|warning|error|critical))\([^)]*\b(password|token|secret|api_key|apiKey)\b/gi
        : go
          ? /\b(log\.(Println|Printf|Print|Fatal|Fatalln|Fatalf)|fmt\.(Println|Printf|Print))\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi
          : /console\.(log|error|warn|info)\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi;
      const commentPattern = python ? /^\s*#/ : /^\s*\/\//;
      const lines = file.content.split("\n");
      return scanLines(file, pattern).filter((m) => !commentPattern.test(lines[m.line - 1] ?? ""));
    },
    autofix(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const pattern = python
        ? /\b(print|logging\.(debug|info|warning|error|critical)|logger\.(debug|info|warning|error|critical))\([^)]*\b(password|token|secret|api_key|apiKey)\b/gi
        : go
          ? /\b(log\.(Println|Printf|Print|Fatal|Fatalln|Fatalf)|fmt\.(Println|Printf|Print))\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi
          : /console\.(log|error|warn|info)\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi;
      const commentPrefix = python ? "#" : "//";
      const { content, changed } = replaceLines(file.content, pattern, (line) => {
        const indent = line.match(/^(\s*)/)?.[1] ?? "";
        return `${indent}${commentPrefix} ${line.trim()}  ${commentPrefix} rimossa da JoJoX: registrava dati sensibili nei log`;
      });
      return changed ? content : null;
    },
  },
];
'@
Write-Utf8NoBom "src/checks/low.ts" $content_src_checks_low_ts

$content_test_checks_critical_test_ts = @'
import { describe, expect, it } from "vitest";
import { criticalChecks } from "../src/checks/critical.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = criticalChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("critical checks", () => {
  it("supabase-service-role-in-client: flags a public env var referencing the service role key in client code", () => {
    const check = checkById("supabase-service-role-in-client");
    const vulnerable = file(
      "src/components/Dashboard.tsx",
      "const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)"
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("supabase-service-role-in-client: does not flag the server-only usage", () => {
    const check = checkById("supabase-service-role-in-client");
    const clean = file(
      "src/api/admin/route.ts",
      "const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)"
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("supabase-service-role-in-client: does not flag an empty placeholder in .env.example", () => {
    const check = checkById("supabase-service-role-in-client");
    const clean = file(".env.example", "SUPABASE_SERVICE_ROLE_KEY=");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("hardcoded-secret: flags a literal Stripe secret key", () => {
    const check = checkById("hardcoded-secret");
    const vulnerable = file("src/payments.ts", 'const apiKey = "sk_live_51H8x9K2eZvKYlo2Cxxxxxxxxxxxxxxxx"');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("hardcoded-secret: does not flag a value read from process.env", () => {
    const check = checkById("hardcoded-secret");
    const clean = file("src/payments.ts", "const apiKey = process.env.STRIPE_SECRET_KEY");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("hardcoded-secret: flags other common secret-like variable names", () => {
    const check = checkById("hardcoded-secret");
    const names = ["clientSecret", "accessToken", "refreshToken", "privateKey", "dbPassword", "apiSecret"];
    for (const name of names) {
      const vulnerable = file("src/config.ts", `const ${name} = "abcdefghijklmnop123456"`);
      expect(detect(check, vulnerable), `expected ${name} to be flagged`).toHaveLength(1);
    }
  });

  it("hardcoded-secret autofix: replaces a hardcoded clientSecret with process.env, converted to SCREAMING_SNAKE_CASE", () => {
    const check = checkById("hardcoded-secret");
    const vulnerable = file("src/config.ts", 'const clientSecret = "abcdefghijklmnop123456"');
    const fixed = check.autofix?.(vulnerable);
    expect(fixed).toBe("const clientSecret = process.env.CLIENT_SECRET");
  });

  it("hardcoded-secret autofix: does not touch a value already read from process.env", () => {
    const check = checkById("hardcoded-secret");
    const clean = file("src/payments.ts", "const apiKey = process.env.STRIPE_SECRET_KEY");
    expect(check.autofix?.(clean)).toBeNull();
  });

  it("hardcoded-secret autofix: leaves format-detected keys (sk_live_…) alone — those must be revoked, not just removed", () => {
    const check = checkById("hardcoded-secret");
    const vulnerable = file("src/payments.ts", 'const apiKey = "sk_live_51H8x9K2eZvKYlo2Cxxxxxxxxxxxxxxxx"');
    expect(check.autofix?.(vulnerable)).toBeNull();
  });

  it("env-file-with-real-values: flags a committed .env with real values", () => {
    const check = checkById("env-file-with-real-values");
    const vulnerable = file(".env", "DATABASE_URL=postgres://user:realpassword@db.host/prod\nJWT_SECRET=abcdef123456");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("env-file-with-real-values: does not flag .env.example", () => {
    const check = checkById("env-file-with-real-values");
    const clean = file(".env.example", "DATABASE_URL=postgres://user:password@localhost/dev");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("missing-row-level-security: flags RLS explicitly disabled", () => {
    const check = checkById("missing-row-level-security");
    const vulnerable = file("supabase/migrations/001.sql", "ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("missing-row-level-security: does not flag a scoped policy", () => {
    const check = checkById("missing-row-level-security");
    const clean = file(
      "supabase/migrations/001.sql",
      'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders USING (auth.uid() = user_id);'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("sql-injection: flags a template-literal query", () => {
    const check = checkById("sql-injection");
    const vulnerable = file("src/db.ts", "db.query(`SELECT * FROM users WHERE email = '${email}'`)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("sql-injection: does not flag a parameterized query", () => {
    const check = checkById("sql-injection");
    const clean = file("src/db.ts", 'db.query("SELECT * FROM users WHERE email = $1", [email])');
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("plaintext-password-storage: flags a raw password saved without hashing anywhere in the file", () => {
    const check = checkById("plaintext-password-storage");
    const vulnerable = file("src/signup.ts", "await db.users.insert({ email, password: req.body.password })");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("plaintext-password-storage: does not flag when the file hashes the password first", () => {
    const check = checkById("plaintext-password-storage");
    const clean = file(
      "src/signup.ts",
      "const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })"
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("hardcoded-jwt-secret: flags a literal signing secret", () => {
    const check = checkById("hardcoded-jwt-secret");
    const vulnerable = file("src/auth.ts", 'jwt.sign(payload, "super-secret-key-123")');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("hardcoded-jwt-secret: does not flag a secret read from the environment", () => {
    const check = checkById("hardcoded-jwt-secret");
    const clean = file("src/auth.ts", "jwt.sign(payload, process.env.JWT_SECRET)");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("command-injection: flags an interpolated shell command", () => {
    const check = checkById("command-injection");
    const vulnerable = file("src/convert.ts", "execSync(`convert ${filename} output.png`)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("command-injection: does not flag execFile with an argument array", () => {
    const check = checkById("command-injection");
    const clean = file("src/convert.ts", 'execFile("convert", [filename, "output.png"])');
    expect(detect(check, clean)).toHaveLength(0);
  });

  describe("Python", () => {
    it("hardcoded-secret: flags a snake_case secret, same as camelCase", () => {
      const check = checkById("hardcoded-secret");
      const vulnerable = file("app/config.py", 'api_secret = "abcdefghijklmnop123456"');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("hardcoded-secret: does not flag a value read with os.environ or os.getenv", () => {
      const check = checkById("hardcoded-secret");
      const clean1 = file("app/config.py", 'api_key = os.environ["STRIPE_SECRET_KEY"]');
      const clean2 = file("app/config.py", 'api_key = os.getenv("STRIPE_SECRET_KEY")');
      expect(detect(check, clean1)).toHaveLength(0);
      expect(detect(check, clean2)).toHaveLength(0);
    });

    it("hardcoded-secret autofix: replaces a hardcoded secret with os.environ, not process.env", () => {
      const check = checkById("hardcoded-secret");
      const vulnerable = file("app/config.py", 'client_secret = "abcdefghijklmnop123456"');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('client_secret = os.environ["CLIENT_SECRET"]');
    });

    it("sql-injection: flags an f-string query", () => {
      const check = checkById("sql-injection");
      const vulnerable = file("app/db.py", 'cursor.execute(f"SELECT * FROM users WHERE email = \'{email}\'")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sql-injection: flags string concatenation (same syntax as JS)", () => {
      const check = checkById("sql-injection");
      const vulnerable = file("app/db.py", 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sql-injection: does not flag a parameterized query", () => {
      const check = checkById("sql-injection");
      const clean = file("app/db.py", 'cursor.execute("SELECT * FROM users WHERE email = %s", (email,))');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("plaintext-password-storage: flags a Flask request.form password stored without hashing", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("app/signup.py", "user.password = request.form['password']");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("plaintext-password-storage: flags a Django request.POST password stored without hashing", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("app/views.py", "user.password = request.POST['password']");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("plaintext-password-storage: does not flag when the file already hashes with werkzeug/passlib/bcrypt", () => {
      const check = checkById("plaintext-password-storage");
      const clean = file(
        "app/signup.py",
        "from werkzeug.security import generate_password_hash\nuser.password = generate_password_hash(request.form['password'])"
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("plaintext-password-storage autofix: wraps the raw value in bcrypt.hashpw", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("app/signup.py", "user.password = request.form['password']");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())");
    });

    it("hardcoded-jwt-secret: flags a literal secret passed to PyJWT's encode/decode", () => {
      const check = checkById("hardcoded-jwt-secret");
      const vulnerable = file("app/auth.py", 'jwt.encode(payload, "super-secret-key-123", algorithm="HS256")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("hardcoded-jwt-secret: does not flag a secret read from os.environ", () => {
      const check = checkById("hardcoded-jwt-secret");
      const clean = file("app/auth.py", 'jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("hardcoded-jwt-secret autofix: replaces the literal with os.environ, not process.env", () => {
      const check = checkById("hardcoded-jwt-secret");
      const vulnerable = file("app/auth.py", 'jwt.encode(payload, "super-secret-key-123")');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('jwt.encode(payload, os.environ["JWT_SECRET"])');
    });

    it("command-injection: flags os.system with an interpolated f-string", () => {
      const check = checkById("command-injection");
      const vulnerable = file("app/convert.py", 'os.system(f"convert {filename} output.png")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("command-injection: flags subprocess.run with shell=True and string concatenation", () => {
      const check = checkById("command-injection");
      const vulnerable = file("app/convert.py", 'subprocess.run("convert " + filename, shell=True)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("command-injection: does not flag subprocess.run with an argument list (shell=False, the default)", () => {
      const check = checkById("command-injection");
      const clean = file("app/convert.py", 'subprocess.run(["convert", filename, "output.png"])');
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Go", () => {
    it("hardcoded-secret: flags a PascalCase secret (case-insensitive, same pattern as camelCase)", () => {
      const check = checkById("hardcoded-secret");
      const vulnerable = file("main.go", 'ApiSecret := "abcdefghijklmnop123456"');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("hardcoded-secret: does not flag a value read with os.Getenv", () => {
      const check = checkById("hardcoded-secret");
      const clean = file("main.go", 'apiKey := os.Getenv("STRIPE_SECRET_KEY")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("hardcoded-secret autofix: replaces a hardcoded secret with os.Getenv, turning := into = (no longer a new declaration)", () => {
      const check = checkById("hardcoded-secret");
      const vulnerable = file("main.go", 'clientSecret := "abcdefghijklmnop123456"');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('clientSecret = os.Getenv("CLIENT_SECRET")');
    });

    it("sql-injection: flags a query built with fmt.Sprintf", () => {
      const check = checkById("sql-injection");
      const vulnerable = file("main.go", 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE email = \'%s\'", email))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sql-injection: does not flag a parameterized query", () => {
      const check = checkById("sql-injection");
      const clean = file("main.go", 'db.Query("SELECT * FROM users WHERE email = $1", email)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("plaintext-password-storage: flags a Gin c.PostForm password stored without hashing", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("main.go", 'user.Password = c.PostForm("password")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("plaintext-password-storage: flags a net/http r.FormValue password stored without hashing", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("main.go", 'user.Password = r.FormValue("password")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("plaintext-password-storage: does not flag when the file already uses bcrypt", () => {
      const check = checkById("plaintext-password-storage");
      const clean = file(
        "main.go",
        'hashed, _ := bcrypt.GenerateFromPassword([]byte(c.PostForm("password")), bcrypt.DefaultCost)\nuser.Password = string(hashed)'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("plaintext-password-storage autofix: wraps the raw value in bcrypt.GenerateFromPassword, not JS/Python bcrypt", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("main.go", 'user.Password = c.PostForm("password")');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('bcrypt.GenerateFromPassword([]byte(c.PostForm("password")), bcrypt.DefaultCost)');
    });

    it("hardcoded-jwt-secret: flags a literal secret passed to golang-jwt's SignedString", () => {
      const check = checkById("hardcoded-jwt-secret");
      const vulnerable = file("main.go", 'tokenString, _ := token.SignedString([]byte("super-secret-key-123"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("hardcoded-jwt-secret: does not flag a secret read from os.Getenv", () => {
      const check = checkById("hardcoded-jwt-secret");
      const clean = file("main.go", 'tokenString, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("hardcoded-jwt-secret autofix: replaces the literal with os.Getenv, not process.env or os.environ", () => {
      const check = checkById("hardcoded-jwt-secret");
      const vulnerable = file("main.go", 'tokenString, _ := token.SignedString([]byte("super-secret-key-123"))');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('tokenString, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))');
    });

    it("command-injection: flags exec.Command invoking a shell with fmt.Sprintf", () => {
      const check = checkById("command-injection");
      const vulnerable = file("main.go", 'exec.Command("sh", "-c", fmt.Sprintf("convert %s output.png", filename))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("command-injection: flags exec.Command invoking a shell with string concatenation", () => {
      const check = checkById("command-injection");
      const vulnerable = file("main.go", 'exec.Command("bash", "-c", "rm -rf " + path)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("command-injection: does not flag exec.Command with separate arguments (no shell involved)", () => {
      const check = checkById("command-injection");
      const clean = file("main.go", 'exec.Command("convert", filename, "output.png")');
      expect(detect(check, clean)).toHaveLength(0);
    });
  });
});
'@
Write-Utf8NoBom "test/checks.critical.test.ts" $content_test_checks_critical_test_ts

$content_test_checks_high_test_ts = @'
import { describe, expect, it } from "vitest";
import { highChecks } from "../src/checks/high.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = highChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("high checks", () => {
  it("unprotected-new-table: flags a table with no RLS enabled in the same file", () => {
    const check = checkById("unprotected-new-table");
    const vulnerable = file(
      "migrations/001_create_invoices.sql",
      "CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);"
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("unprotected-new-table: does not flag a table that enables RLS in the same file", () => {
    const check = checkById("unprotected-new-table");
    const clean = file(
      "migrations/001_create_invoices.sql",
      "CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;"
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("unprotected-new-table: ignores non-SQL files", () => {
    const check = checkById("unprotected-new-table");
    const notSql = file("migrations/001.ts", "CREATE TABLE public.invoices (id uuid PRIMARY KEY);");
    expect(detect(check, notSql)).toHaveLength(0);
  });

  it("permissive-cors: flags cors() with no origin restriction", () => {
    const check = checkById("permissive-cors");
    const vulnerable = file("src/server.ts", "app.use(cors())");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("permissive-cors: does not flag a restricted origin list", () => {
    const check = checkById("permissive-cors");
    const clean = file("src/server.ts", 'app.use(cors({ origin: ["https://tuosito.com"] }))');
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("admin-function-missing-auth: flags an admin route with no nearby auth check", () => {
    const check = checkById("admin-function-missing-auth");
    const vulnerable = file(
      "src/routes/admin.ts",
      'router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})'
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("admin-function-missing-auth: does not flag when requireAuth guards the route", () => {
    const check = checkById("admin-function-missing-auth");
    const clean = file(
      "src/routes/admin.ts",
      'router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("ssrf: flags an outgoing request built from user input", () => {
    const check = checkById("ssrf");
    const vulnerable = file("src/proxy.ts", "const data = await fetch(req.query.url)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("ssrf: does not flag a request to an allowlisted target", () => {
    const check = checkById("ssrf");
    const clean = file(
      "src/proxy.ts",
      'const ALLOWED = new Set(["https://api.tuoservizio.com"])\nconst target = ALLOWED.has(userUrl) ? userUrl : DEFAULT_URL\nconst data = await fetch(target)'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("weak-password-hashing: flags md5 used near password handling", () => {
    const check = checkById("weak-password-hashing");
    const vulnerable = file(
      "src/auth.ts",
      'const hashed = crypto.createHash("md5").update(password).digest("hex")'
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("weak-password-hashing: does not flag bcrypt", () => {
    const check = checkById("weak-password-hashing");
    const clean = file("src/auth.ts", "const hashed = await bcrypt.hash(password, 12)");
    expect(detect(check, clean)).toHaveLength(0);
  });

  describe("Python", () => {
    it("permissive-cors: flags Flask-CORS used with no restriction", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("app/server.py", "CORS(app)");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: flags django-cors-headers allowing all origins", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("app/settings.py", "CORS_ORIGIN_ALLOW_ALL = True");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: does not flag a restricted django-cors-headers list", () => {
      const check = checkById("permissive-cors");
      const clean = file("app/settings.py", 'CORS_ALLOWED_ORIGINS = ["https://tuosito.com"]');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("admin-function-missing-auth: flags a Flask admin route with no nearby auth decorator", () => {
      const check = checkById("admin-function-missing-auth");
      const vulnerable = file(
        "app/admin.py",
        '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    db.users.delete(request.form["id"])'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("admin-function-missing-auth: does not flag when login_required guards the route", () => {
      const check = checkById("admin-function-missing-auth");
      const clean = file(
        "app/admin.py",
        '@app.route("/admin/delete-user", methods=["POST"])\n@login_required\ndef delete_user():\n    db.users.delete(request.form["id"])'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("ssrf: flags an outgoing request built from Flask request.args", () => {
      const check = checkById("ssrf");
      const vulnerable = file("app/proxy.py", "data = requests.get(request.args['url'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: flags an outgoing request built from Django request.GET", () => {
      const check = checkById("ssrf");
      const vulnerable = file("app/views.py", "data = requests.get(request.GET['url'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: does not flag a request to a fixed URL", () => {
      const check = checkById("ssrf");
      const clean = file("app/proxy.py", 'data = requests.get("https://api.example.com")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing: flags hashlib.md5 used near password handling", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("app/auth.py", "hashed = hashlib.md5(password.encode()).hexdigest()");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-password-hashing: does not flag bcrypt", () => {
      const check = checkById("weak-password-hashing");
      const clean = file("app/auth.py", "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing autofix: replaces hashlib.md5 with bcrypt.hashpw, not JS bcrypt.hash", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("app/auth.py", "hashed = hashlib.md5(password).hexdigest()");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("bcrypt.hashpw(password.encode(), bcrypt.gensalt())");
      expect(fixed).not.toContain("await bcrypt.hash");
    });

    it("weak-password-hashing autofix: handles a nested call inside the argument, e.g. password.encode(), without breaking the syntax", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("app/auth.py", "hashed = hashlib.md5(password.encode()).hexdigest()");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe(
        "hashed = bcrypt.hashpw(password.encode().encode(), bcrypt.gensalt()) # JoJoX: serve il pacchetto bcrypt — pip install bcrypt.hexdigest()"
      );
      // Soprattutto: le parentesi devono restare bilanciate.
      const opens = (fixed!.match(/\(/g) ?? []).length;
      const closes = (fixed!.match(/\)/g) ?? []).length;
      expect(opens).toBe(closes);
    });
  });

  describe("Go", () => {
    it("permissive-cors: flags gin-contrib/cors used with no restriction", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("main.go", "r.Use(cors.Default())");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: flags AllowOrigins set to *", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("main.go", 'config.AllowOrigins = []string{"*"}');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: does not flag a restricted AllowOrigins list", () => {
      const check = checkById("permissive-cors");
      const clean = file("main.go", 'config.AllowOrigins = []string{"https://tuosito.com"}');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("admin-function-missing-auth: flags a Gin admin route (uppercase POST) with no nearby auth check", () => {
      const check = checkById("admin-function-missing-auth");
      const vulnerable = file(
        "main.go",
        'router.POST("/admin/delete-user", func(c *gin.Context) {\n  db.Delete(&user, c.PostForm("id"))\n})'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("admin-function-missing-auth: does not flag when MustGet (reading the authenticated user) guards the route", () => {
      const check = checkById("admin-function-missing-auth");
      const clean = file(
        "main.go",
        'router.POST("/admin/delete-user", func(c *gin.Context) {\n  user := c.MustGet("user")\n  db.Delete(&user, c.PostForm("id"))\n})'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("ssrf: flags http.Get built from a Gin query parameter", () => {
      const check = checkById("ssrf");
      const vulnerable = file("main.go", 'resp, _ := http.Get(c.Query("url"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: flags http.Get built from a net/http form value", () => {
      const check = checkById("ssrf");
      const vulnerable = file("main.go", 'resp, _ := http.Get(r.FormValue("url"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: does not flag a request to a fixed URL", () => {
      const check = checkById("ssrf");
      const clean = file("main.go", 'resp, _ := http.Get("https://api.example.com")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing: flags crypto/md5's Sum used near password handling", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("main.go", "hashed := md5.Sum([]byte(password))");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-password-hashing: does not flag bcrypt", () => {
      const check = checkById("weak-password-hashing");
      const clean = file("main.go", "hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing autofix: replaces md5.Sum with bcrypt.GenerateFromPassword, not JS/Python bcrypt", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("main.go", "hashed := md5.Sum([]byte(password))");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("bcrypt.GenerateFromPassword([]byte([]byte(password)), bcrypt.DefaultCost)");
      expect(fixed).not.toContain("await bcrypt.hash");
      expect(fixed).not.toContain("hashpw");
    });
  });
});
'@
Write-Utf8NoBom "test/checks.high.test.ts" $content_test_checks_high_test_ts

$content_test_checks_medium_test_ts = @'
import { describe, expect, it } from "vitest";
import { mediumChecks } from "../src/checks/medium.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = mediumChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("medium checks", () => {
  it("xss-dangerous-html: flags dangerouslySetInnerHTML", () => {
    const check = checkById("xss-dangerous-html");
    const vulnerable = file(
      "src/Comment.tsx",
      "<div dangerouslySetInnerHTML={{ __html: comment.text }} />"
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("xss-dangerous-html: does not flag plain JSX text content", () => {
    const check = checkById("xss-dangerous-html");
    const clean = file("src/Comment.tsx", "<div>{comment.text}</div>");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("public-storage-bucket: flags a bucket created as public", () => {
    const check = checkById("public-storage-bucket");
    const vulnerable = file("src/storage.ts", 'supabase.storage.createBucket("uploads", { public: true })');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("public-storage-bucket: does not flag a private bucket", () => {
    const check = checkById("public-storage-bucket");
    const clean = file("src/storage.ts", 'supabase.storage.createBucket("uploads", { public: false })');
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("csrf-state-changing-get: flags a GET route that deletes data", () => {
    const check = checkById("csrf-state-changing-get");
    const vulnerable = file("src/routes/posts.ts", 'router.get("/posts/:id/delete", deletePost)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("csrf-state-changing-get: does not flag a POST route", () => {
    const check = checkById("csrf-state-changing-get");
    const clean = file(
      "src/routes/posts.ts",
      'router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("insecure-token-storage: flags a token saved to localStorage", () => {
    const check = checkById("insecure-token-storage");
    const vulnerable = file("src/auth.ts", 'localStorage.setItem("authToken", token)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("insecure-token-storage: does not flag an httpOnly cookie", () => {
    const check = checkById("insecure-token-storage");
    const clean = file(
      "src/auth.ts",
      'res.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("open-redirect: flags a redirect built from unsanitized query input", () => {
    const check = checkById("open-redirect");
    const vulnerable = file("src/routes/auth.ts", "res.redirect(req.query.next)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("open-redirect: does not flag a redirect validated against an allowlist", () => {
    const check = checkById("open-redirect");
    const clean = file(
      "src/routes/auth.ts",
      'const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("idor: flags a lookup by params.id with no ownership check nearby", () => {
    const check = checkById("idor");
    const vulnerable = file("src/routes/orders.ts", "const order = await Order.findById(req.params.id)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("idor: does not flag when an ownership check follows the lookup", () => {
    const check = checkById("idor");
    const clean = file(
      "src/routes/orders.ts",
      'const order = await Order.findById(req.params.id)\nif (order.userId !== req.user.id) throw new Error("Forbidden")'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  describe("Python", () => {
    it("xss-dangerous-html: flags Jinja2's |safe filter", () => {
      const check = checkById("xss-dangerous-html");
      const vulnerable = file("templates/comment.html", "{{ comment.text|safe }}");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("xss-dangerous-html: flags Django's mark_safe()", () => {
      const check = checkById("xss-dangerous-html");
      const vulnerable = file("app/views.py", "return mark_safe(comment.text)");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("xss-dangerous-html: does not flag plain Jinja2 output (auto-escaped by default)", () => {
      const check = checkById("xss-dangerous-html");
      const clean = file("templates/comment.html", "{{ comment.text }}");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("public-storage-bucket: flags a supabase-py bucket created as public (capital True)", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("app/storage.py", 'supabase.storage.create_bucket("uploads", {"public": True})');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: flags a boto3 S3 object made public", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("app/storage.py", 's3.put_object(Bucket="uploads", Key=key, ACL="public-read")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: does not flag a private supabase-py bucket", () => {
      const check = checkById("public-storage-bucket");
      const clean = file("app/storage.py", 'supabase.storage.create_bucket("uploads", {"public": False})');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("csrf-state-changing-get: flags a Flask route that deletes data with no explicit POST method", () => {
      const check = checkById("csrf-state-changing-get");
      const vulnerable = file("app/routes.py", '@app.route("/posts/<id>/delete")\ndef delete_post(id):\n    ...');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("csrf-state-changing-get: does not flag a Flask route restricted to POST", () => {
      const check = checkById("csrf-state-changing-get");
      const clean = file(
        "app/routes.py",
        '@app.route("/posts/<id>/delete", methods=["POST"])\ndef delete_post(id):\n    ...'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect: flags a Flask redirect built from request.args", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("app/auth.py", "return redirect(request.args['next'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: flags a Django HttpResponseRedirect built from request.GET", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("app/views.py", "return HttpResponseRedirect(request.GET['next'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: does not flag a redirect to a fixed path", () => {
      const check = checkById("open-redirect");
      const clean = file("app/auth.py", 'return redirect("/dashboard")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect autofix: replaces the Flask redirect with a fixed one, commented in Python style", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("app/auth.py", "return redirect(request.args['next'])");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('redirect("/")');
      expect(fixed).toContain("# JoJoX:");
      expect(fixed).not.toContain("/*");
    });

    it("idor: flags a Django ORM lookup by request.GET id with no ownership check nearby", () => {
      const check = checkById("idor");
      const vulnerable = file("app/views.py", "order = Order.objects.get(pk=request.GET['id'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: flags get_object_or_404 with no ownership check nearby", () => {
      const check = checkById("idor");
      const vulnerable = file("app/views.py", "order = get_object_or_404(Order, pk=request.GET['id'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: does not flag when an ownership check follows the lookup", () => {
      const check = checkById("idor");
      const clean = file(
        "app/views.py",
        "order = Order.objects.get(pk=request.GET['id'])\nif order.user_id != request.user.id:\n    raise PermissionDenied"
      );
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Go", () => {
    it("xss-dangerous-html: flags html/template's template.HTML()", () => {
      const check = checkById("xss-dangerous-html");
      const vulnerable = file("main.go", "data.Comment = template.HTML(comment.Text)");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: flags an AWS SDK for Go object made public", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file(
        "main.go",
        '_, err := svc.PutObject(&s3.PutObjectInput{Bucket: aws.String("uploads"), ACL: aws.String("public-read")})'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("public-storage-bucket: does not flag a private AWS SDK for Go object", () => {
      const check = checkById("public-storage-bucket");
      const clean = file(
        "main.go",
        '_, err := svc.PutObject(&s3.PutObjectInput{Bucket: aws.String("uploads"), ACL: aws.String("private")})'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("public-storage-bucket autofix: replaces aws.String(\"public-read\") with aws.String(\"private\")", () => {
      const check = checkById("public-storage-bucket");
      const vulnerable = file("main.go", 'ACL: aws.String("public-read")');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('ACL: aws.String("private")');
    });

    it("csrf-state-changing-get: flags a Gin route (uppercase GET) that deletes data", () => {
      const check = checkById("csrf-state-changing-get");
      const vulnerable = file("main.go", 'router.GET("/posts/:id/delete", deletePost)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: flags a Gin redirect built from c.Query", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("main.go", 'c.Redirect(http.StatusFound, c.Query("next"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: flags a net/http redirect built from r.FormValue", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("main.go", 'http.Redirect(w, r, r.FormValue("next"), http.StatusFound)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("open-redirect: does not flag a redirect to a fixed path", () => {
      const check = checkById("open-redirect");
      const clean = file("main.go", 'c.Redirect(http.StatusFound, "/dashboard")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("open-redirect autofix: replaces the Gin redirect with a fixed one, commented in Go style", () => {
      const check = checkById("open-redirect");
      const vulnerable = file("main.go", 'c.Redirect(http.StatusFound, c.Query("next"))');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('c.Redirect(http.StatusFound, "/")');
      expect(fixed).toContain("// JoJoX:");
    });

    it("idor: flags a GORM lookup by Gin's c.Param id with no ownership check nearby", () => {
      const check = checkById("idor");
      const vulnerable = file("main.go", 'db.First(&order, c.Param("id"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("idor: does not flag when an ownership check (UserID) follows the lookup", () => {
      const check = checkById("idor");
      const clean = file(
        "main.go",
        'db.First(&order, c.Param("id"))\nif order.UserID != currentUser.ID {\n  panic("forbidden")\n}'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });
  });
});
'@
Write-Utf8NoBom "test/checks.medium.test.ts" $content_test_checks_medium_test_ts

$content_test_checks_low_test_ts = @'
import { describe, expect, it } from "vitest";
import { lowChecks } from "../src/checks/low.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = lowChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("low checks", () => {
  it("no-login-rate-limit: flags a login route with no rate limiter in the file", () => {
    const check = checkById("no-login-rate-limit");
    const vulnerable = file("src/routes/auth.ts", 'router.post("/login", loginHandler)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("no-login-rate-limit: does not flag a login route guarded by rate limiting", () => {
    const check = checkById("no-login-rate-limit");
    const clean = file(
      "src/routes/auth.ts",
      'import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 900000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("sensitive-data-in-logs: flags a password logged to the console", () => {
    const check = checkById("sensitive-data-in-logs");
    const vulnerable = file("src/routes/auth.ts", 'console.log("login attempt", { email, password })');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("sensitive-data-in-logs: does not flag a log without sensitive fields", () => {
    const check = checkById("sensitive-data-in-logs");
    const clean = file("src/routes/auth.ts", 'console.log("login attempt", { email })');
    expect(detect(check, clean)).toHaveLength(0);
  });

  describe("Python", () => {
    it("no-login-rate-limit: flags a Flask login route with no rate limiter in the file", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file(
        "app/routes.py",
        '@app.route("/login", methods=["POST"])\ndef login():\n    ...'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("no-login-rate-limit: does not flag a login route guarded by Flask-Limiter", () => {
      const check = checkById("no-login-rate-limit");
      const clean = file(
        "app/routes.py",
        'from flask_limiter import Limiter\nlimiter = Limiter(app)\n\n@app.route("/login", methods=["POST"])\n@limiter.limit("5/15minutes")\ndef login():\n    ...'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("no-login-rate-limit autofix: inserts a self-contained decorator right below @app.route", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file(
        "app/routes.py",
        '@app.route("/login", methods=["POST"])\ndef login():\n    ...'
      );
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("def __jojox_rate_limit(view):");
      expect(fixed).toContain('@app.route("/login", methods=["POST"])\n@__jojox_rate_limit\ndef login():');
    });

    it("sensitive-data-in-logs: flags a password logged with print()", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("app/auth.py", 'print("login attempt", email, password)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: flags a password logged with logging.info()", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("app/auth.py", 'logging.info("login attempt email=%s password=%s", email, password)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: does not flag a log without sensitive fields", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("app/auth.py", 'print("login attempt", email)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs: does not flag a line already commented out with #", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("app/auth.py", '# print("login attempt", password)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs autofix: comments the line out with #, not //", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("app/auth.py", 'print("login attempt", password)');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('# print("login attempt", password)  # rimossa da JoJoX');
    });
  });

  describe("Go", () => {
    it("no-login-rate-limit: flags a Gin login route (uppercase POST) with no rate limiter in the file", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file("main.go", 'router.POST("/login", loginHandler)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("no-login-rate-limit: does not flag a login route guarded by a rate limiter", () => {
      const check = checkById("no-login-rate-limit");
      const clean = file(
        "main.go",
        'limiter := tollbooth.NewLimiter(1, nil)\nrouter.POST("/login", tollbooth_gin.LimitHandler(limiter), loginHandler)'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("no-login-rate-limit autofix: does not attempt a fix (needs sync.Mutex / import merging we can't do safely)", () => {
      const check = checkById("no-login-rate-limit");
      const vulnerable = file("main.go", 'router.POST("/login", loginHandler)');
      expect(check.autofix?.(vulnerable)).toBeNull();
    });

    it("sensitive-data-in-logs: flags a password logged with log.Printf", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("main.go", 'log.Printf("login attempt email=%s password=%s", email, password)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: flags a token logged with fmt.Println", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("main.go", 'fmt.Println("issued token", token)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sensitive-data-in-logs: does not flag a log without sensitive fields", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("main.go", 'log.Println("login attempt", email)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs: does not flag a line already commented out with //", () => {
      const check = checkById("sensitive-data-in-logs");
      const clean = file("main.go", '// log.Println("login attempt", password)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("sensitive-data-in-logs autofix: comments the line out with //", () => {
      const check = checkById("sensitive-data-in-logs");
      const vulnerable = file("main.go", 'log.Println("login attempt", password)');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('// log.Println("login attempt", password)  // rimossa da JoJoX');
    });
  });
});
'@
Write-Utf8NoBom "test/checks.low.test.ts" $content_test_checks_low_test_ts

$content_web_src_i18n_translations_ts = @'
export type Lang = "it" | "en";

interface FeatureItem {
  icon: string;
  accent: string;
  title: string;
  text: string;
}

interface RoadmapItem {
  icon: string;
  title: string;
  text: string;
}

interface AudienceItem {
  icon: string;
  title: string;
  text: string;
}

export interface TranslationTree {
  meta: {
    dateLocale: string;
    title: string;
  };
  common: {
    severity: { critical: string; high: string; medium: string; low: string };
    confirmed: string;
    heuristic: string;
    before: string;
    after: string;
    correctionsManifest: {
      title: string;
      filesIntro: string;
      filesHeader: string;
      manualHeader: string;
      manualNone: string;
      occurrences: string;
    };
  };
  header: {
    connect: string;
    connectAnother: string;
    connected: string;
    logout: string;
    login: string;
  };
  hero: {
    titleLine1: string;
    titleLine2Suffix: string;
    body: string;
    bodyMonitoring: string;
    bodyScore: string;
    sub: string;
    pill1: string;
    pill2: string;
    pill3: string;
    badge: string;
    cta: string;
    guestNote: string;
    scanTag: string;
    statChecksLabel: string;
    statScoreLabel: string;
    statFreeLabel: string;
  };
  howItWorks: {
    eyebrow: string;
    title: string;
    step1Title: string;
    step1Text: string;
    step2Title: string;
    step2Text: string;
    step3Title: string;
    step3Text: string;
  };
  features: {
    eyebrow: string;
    title: string;
    subtitle: string;
    items: FeatureItem[];
  };
  whyNotAi: {
    eyebrow: string;
    question: string;
    readMore: string;
    point1: string;
    point2: string;
    point3: string;
    closingLead: string;
    closingPunch: string;
  };
  dividers: {
    howItWorks: string;
    features: string;
    audience: string;
    pricing: string;
    integrations: string;
    team: string;
    roadmap: string;
    checks: string;
  };
  audience: {
    eyebrow: string;
    title: string;
    items: AudienceItem[];
  };
  pricing: {
    title: string;
    subtitle: string;
    noticeSuccess: string;
    noticeCancel: string;
    guestTitle: string;
    guestList: string[];
    guestCta: string;
    billingMonthly: string;
    billingAnnual: string;
    billingAnnualBadge: string;
    freeTitle: string;
    freeList: string[];
    freeCta: string;
    freeNote: string;
    proBadge: string;
    proTitle: string;
    proPer: string;
    proPerAnnual: string;
    proPriceAnnual: string;
    proList: string[];
    proCta: string;
    proActivating: string;
    proNote: string;
    teamBadge: string;
    teamTitle: string;
    teamPer: string;
    teamPerAnnual: string;
    teamPriceAnnual: string;
    teamList: string[];
    teamCta: string;
    teamActivating: string;
    teamNote: string;
    enterpriseContactQuestion: string;
    enterpriseContactLink: string;
    activePlan: string;
    manageSubscription: string;
    opening: string;
    errorActivation: string;
    errorPortal: string;
    disclaimer: string;
  };
  footer: {
    intro: string;
    items: string[];
    privacyLink: string;
    termsLink: string;
    securityLink: string;
  };
  checksList: {
    title: string;
    body: string;
    subLabel: string;
  };
  team: {
    title: string;
    body: string;
    seatsCount: string;
    seatsFull: string;
    roleOwner: string;
    roleMember: string;
    roleInvited: string;
    invitePlaceholder: string;
    inviteCta: string;
    inviting: string;
    remove: string;
    errorInvite: string;
    errorRemove: string;
  };
  login: {
    sent: string;
    prompt: string;
    sending: string;
    send: string;
    error: string;
    close: string;
  };
  analyzer: {
    gateTitle: string;
    gateBody: string;
    gateCta: string;
    dropzoneCta: string;
    dropzoneHintLoggedIn: string;
    dropzoneHintGuest: string;
    dropzoneHintAny: string;
    dropzoneHintLanguages: string;
    sectionEyebrow: string;
    sectionTitle: string;
    moreFiles: string;
    analyzeButton: string;
    analyzeButtonCount: string;
    analyzing: string;
    errorGuestUsed: string;
    errorGeneric: string;
    autofixFixedOne: string;
    autofixFixedMany: string;
    autofixManualSuffix: string;
    autofixManualOnly: string;
    downloadZip: string;
    downloadPdf: string;
    newAnalysis: string;
  };
  history: {
    title: string;
    toggleShow: string;
    toggleHide: string;
    manualSource: string;
    auditSource: string;
    error: string;
  };
  scoreChart: {
    title: string;
    ariaLabel: string;
  };
  findingsList: {
    scoreLabel: string;
    emptyState: string;
    autoFixed: string;
  };
  github: {
    title: string;
    badge: string;
    flowTitle: string;
    flowBody: string;
    flowStep1: string;
    flowStep2: string;
    flowStep3: string;
    flowStep4: string;
    flowStep5: string;
    body1: string;
    body2: string;
    note: string;
    teamShareNotice: string;
    connectedLabel: string;
    toggleShow: string;
    toggleHide: string;
    badgeTitle: string;
    badgeBody: string;
    publicScoreTitle: string;
    publicScoreBody: string;
    terminalTitle: string;
    terminalBody: string;
    terminalLink: string;
    hookTitle: string;
    hookBody: string;
    slackTitle: string;
    slackConnectFirst: string;
    slackBody: string;
    slackLink: string;
    slackSaving: string;
    slackSave: string;
    slackSaved: string;
    slackErrorGeneric: string;
  };
  waitlist: {
    title: string;
    subtitle: string;
    toggleShow: string;
    toggleHide: string;
    roadmap: RoadmapItem[];
    emailPlaceholder: string;
    submit: string;
    done: string;
    error: string;
  };
  supabase: {
    title: string;
    badge: string;
    body1: string;
    body2: string;
    sqlEditor: string;
    toggleShow: string;
    toggleHide: string;
  };
  report: {
    brandSub: string;
    reportLabel: string;
    generatedOn: string;
    controlsNoLLM: string;
    filesScannedOne: string;
    filesScannedMany: string;
    projectFallback: string;
    noProblems: string;
    oneProblem: string;
    manyProblems: string;
    autofixNoteOne: string;
    autofixNoteMany: string;
    autofixNoteSuffix: string;
    resultsLabel: string;
    emptyState: string;
    printBtn: string;
    printHint: string;
    popupBlocked: string;
  };
  publicScore: {
    loading: string;
    notFoundTitle: string;
    notFoundBody: string;
    scoreLabel: string;
    issuesLabel: string;
    noIssues: string;
    updatedLabel: string;
    ctaText: string;
    copyLink: string;
    linkCopied: string;
    poweredBy: string;
  };
  fullSiteAudit: {
    eyebrow: string;
    title: string;
    subtitle: string;
    priceLabel: string;
    priceNote: string;
    features: string[];
    ctaBuy: string;
    buying: string;
    errorPurchase: string;
    creditsAvailable: string;
    dropzoneCta: string;
    dropzoneHint: string;
    analyzeButton: string;
    analyzeButtonCount: string;
    analyzing: string;
    errorNoCredit: string;
    errorGeneric: string;
    downloadPdf: string;
    downloadZip: string;
    newAudit: string;
    changeFiles: string;
    scoreBefore: string;
    scoreAfter: string;
    scoreAfterNote: string;
    scoreStuckNote: string;
    zipHelp: string;
    zipHelpWithPr: string;
    connectGithubSuggestion: string;
    githubTargetLabel: string;
    githubTargetChooseAccount: string;
    githubTargetNone: string;
    viewPr: string;
    prFailedNote: string;
    prMismatchNote: string;
    trialOfferTitle: string;
    trialOfferBody: string;
    trialCta: string;
    trialActivating: string;
    trialActivated: string;
    trialError: string;
  };
}

const it: TranslationTree = {
  meta: {
    dateLocale: "it-IT",
    title: "JoJoX — Sicurezza per il tuo codice",
  },
  common: {
    severity: {
      critical: "Critico",
      high: "Alto",
      medium: "Medio",
      low: "Basso",
    },
    confirmed: "confermato",
    heuristic: "da verificare",
    before: "Prima",
    after: "Dopo",
    correctionsManifest: {
      title: "Correzioni automatiche di JoJoX",
      filesIntro:
        "Questo zip contiene SOLO i file che sono stati modificati, non l'intero progetto. Copia questi file dentro il tuo progetto reale, sovrascrivendo quelli con lo stesso percorso — non sostituire l'intera cartella.",
      filesHeader: "File corretti ({{count}}):",
      manualHeader:
        "Problemi che restano da correggere a mano nel tuo codice sorgente ({{count}} tipi — vedi il report PDF per l'elenco completo con file e riga):",
      manualNone: "Nessun problema residuo: JoJoX ha corretto automaticamente tutto quello che aveva trovato.",
      occurrences: "{{count}} casi",
    },
  },
  header: {
    connect: "Collega GitHub",
    connectAnother: "Collega un altro account GitHub",
    connected: "✓ GitHub collegato",
    logout: "Esci",
    login: "Accedi",
  },
  hero: {
    titleLine1: "Il tuo agente AI scrive codice ogni giorno, o lo scrivi tu?",
    titleLine2Suffix: "lo sorveglia.",
    body: "Non un controllo una tantum. {{monitoring}}. 21 controlli pubblici sugli errori più comuni nel codice, un {{score}} chiaro, e correzioni pronte da copiare.",
    bodyMonitoring: "Monitoraggio continuo",
    bodyScore: "punteggio di sicurezza",
    sub: "Le verifiche che normalmente richiedono ore, automatizzate e sempre attive.",
    pill1: "Correzioni sempre nel tuo browser",
    pill2: "Nessuna registrazione per iniziare",
    pill3: "Gratis",
    badge: "AI Code Security",
    cta: "Analizza il tuo codice — gratis",
    guestNote: "1 analisi gratuita senza email. Poi basta la mail — 5 analisi/mese gratis.",
    scanTag: "CRITICO",
    statChecksLabel: "controlli pubblici",
    statScoreLabel: "punteggio",
    statFreeLabel: "analisi gratis / mese",
  },
  howItWorks: {
    eyebrow: "In 3 passaggi",
    title: "Come funziona, dall'inizio alla fine.",
    step1Title: "Analizza",
    step1Text: "Carica il codice, o collega il tuo repository GitHub.",
    step2Title: "Rileva",
    step2Text: "JoJoX esegue i 21 controlli e trova i problemi di sicurezza.",
    step3Title: "Correggi",
    step3Text: "Ricevi spiegazione, gravità e una correzione pronta da copiare.",
  },
  features: {
    eyebrow: "Nessuna sorpresa",
    title: "Vedi esattamente cosa succede al tuo codice.",
    subtitle: "Tre cose vere, non promesse generiche: dove resta il codice, come vedi le correzioni, come si calcola il punteggio.",
    items: [
      {
        icon: "🛡️",
        accent: "blue",
        title: "Il tuo codice resta tuo",
        text: "L'analisi che carichi a mano passa dai nostri server (per salvare punteggio e storico), ma il testo dei file non viene mai conservato — solo i risultati. Le correzioni automatiche, invece, restano sempre e solo nel tuo browser.",
      },
      {
        icon: "🔧",
        accent: "amber",
        title: "Non solo l'errore, anche come risolverlo",
        text: "Ogni problema è accompagnato da un esempio di correzione, mostrato come un prima/dopo: capisci subito cosa cambiare.",
      },
      {
        icon: "📊",
        accent: "mint",
        title: "Punteggio di sicurezza + badge",
        text: "Un punteggio da 0 a 100, calcolato con una formula che vedi per intero, più un badge da mettere nel README del progetto.",
      },
    ],
  },
  whyNotAi: {
    eyebrow: "La domanda che ci fanno sempre",
    question: "Il mio agente AI già scrive il codice. Non può controllarlo anche lui?",
    readMore: "Leggi la risposta completa",
    point1: "Puoi chiederlo. Ma nella pratica quasi nessuno lo fa ogni volta, su ogni file, dopo ogni modifica — e basta dimenticarsene una volta per lasciare un buco aperto. JoJoX non aspetta che te ne ricordi: controlla da solo, a ogni push.",
    point2: "Chiedere \"è sicuro?\" a un modello è come chiedere un parere: cambia ogni volta e non lascia una prova. JoJoX esegue sempre gli stessi 21 controlli pubblici, identici per tutti, verificabili riga per riga nel codice — un responso, non un'opinione.",
    point3: "Nessun LLM, nessuna allucinazione, nessun costo che cresce con l'uso: pattern matching puro, istantaneo, pensato per girare su ogni pull request quante volte serve.",
    closingLead: "JoJoX non scrive il tuo codice.",
    closingPunch: "Lo sorveglia.",
  },
  dividers: {
    howItWorks: "Come funziona",
    features: "Cosa vedi dopo l'analisi",
    audience: "Per chi è",
    pricing: "Prezzi",
    integrations: "Integrazioni",
    team: "Il tuo team",
    roadmap: "In arrivo",
    checks: "I 21 controlli",
  },
  audience: {
    eyebrow: "Per chi è",
    title: "Che tu scriva codice da solo o in team.",
    items: [
      {
        icon: "👨‍💻",
        title: "Developer",
        text: "Controlla il codice prima che diventi un problema — da terminale, VS Code, o dal sito.",
      },
      {
        icon: "🚀",
        title: "Startup",
        text: "Proteggi il prodotto mentre il team sviluppa veloce, senza fermarsi per una revisione manuale.",
      },
      {
        icon: "👥",
        title: "Team",
        text: "Monitora ogni push e pull request su più repository, con blocco automatico dei problemi critici.",
      },
      {
        icon: "🤖",
        title: "Sviluppo con AI",
        text: "Controlla il codice scritto o modificato da agenti AI come Claude Code, prima che finisca in produzione.",
      },
    ],
  },
  pricing: {
    title: "Paghi il monitoraggio continuo, non le singole analisi",
    subtitle: "Prova 1 analisi senza dare nulla. Poi basta l'email, nessuna password: fino a 5 analisi al mese gratis.",
    noticeSuccess: "✓ Pagamento ricevuto, stiamo attivando il piano — qualche secondo e questa pagina si aggiorna da sola.",
    noticeCancel: "Attivazione annullata, nessun addebito. Riprova quando vuoi.",
    guestTitle: "Modalità ospite",
    guestList: [
      "1 analisi gratuita, senza email",
      "Tutti i 21 controlli con esempi di correzione",
      "Punteggio di sicurezza",
      "Un solo tentativo per visitatore, imposto dal nostro server",
    ],
    guestCta: "Prova senza registrarti",
    billingMonthly: "Mensile",
    billingAnnual: "Annuale",
    billingAnnualBadge: "risparmi ~17%",
    freeTitle: "Gratis",
    freeList: [
      "5 analisi al mese",
      "Tutti i 21 controlli, con esempi di correzione",
      "Punteggio di sicurezza + badge da scaricare (.svg)",
      "Cronologia delle ultime 20 analisi",
    ],
    freeCta: "Inizia gratis",
    freeNote: "Per chi analizza progetti una tantum",
    proBadge: "MONITORING",
    proTitle: "Pro",
    proPer: "/mese",
    proPerAnnual: "/anno",
    proPriceAnnual: "99€",
    proList: [
      "Analisi e cronologia illimitate",
      "Integrazione con GitHub: controlla ogni push e blocca le modifiche più rischiose",
      "Un account/organizzazione GitHub collegato",
      "Commenti automatici sulle pull request",
      "Correzioni automatiche proposte come pull request",
      "Badge che si aggiorna da solo a ogni push",
    ],
    proCta: "Attiva Pro",
    proActivating: "Attivazione...",
    proNote: "Per monitoraggio continuo su ogni push",
    teamBadge: "TEAM",
    teamTitle: "Team",
    teamPer: "/mese",
    teamPerAnnual: "/anno",
    teamPriceAnnual: "249€",
    teamList: [
      "Analisi e cronologia illimitate",
      "Integrazione con GitHub: controlla ogni push e blocca le modifiche più rischiose",
      "Account/organizzazioni GitHub collegati: quanti vuoi",
      "Fino a 5 persone incluse, con repository e storico condivisi",
      "Commenti automatici sulle pull request",
      "Correzioni automatiche proposte come pull request",
      "Badge che si aggiorna da solo a ogni push",
    ],
    teamCta: "Attiva Team",
    teamActivating: "Attivazione...",
    teamNote: "Per team con più repo — oggi un account per abbonamento",
    enterpriseContactQuestion: "Esigenze diverse o un team più grande?",
    enterpriseContactLink: "Scrivici",
    activePlan: "Piano attivo",
    manageSubscription: "Gestisci abbonamento",
    opening: "Apertura...",
    errorActivation: "Errore nell'attivazione del piano",
    errorPortal: "Errore nell'apertura del portale abbonamento",
    disclaimer: "Disdici quando vuoi, senza vincoli — l'abbonamento si gestisce da solo, direttamente dal tuo account.",
  },
  footer: {
    intro: "*Per l'analisi manuale:",
    items: [
      "Se salvi lo storico, inviamo solo un frammento minimo della riga interessata da ogni problema — mai la riga intera, mai il file.",
      "In modalità ospite, il codice passa comunque dai nostri server per l'analisi (serve per far rispettare il limite di un tentativo gratuito), ma non viene mai salvato: resta solo il risultato che vedi tu, e un'impronta anonima del tuo indirizzo IP per riconoscere il tentativo già usato.",
      "L'integrazione GitHub, invece, elabora il codice sui nostri server.",
    ],
    privacyLink: "Informativa sulla Privacy",
    termsLink: "Termini di Servizio",
    securityLink: "Sicurezza e segnalazione vulnerabilità",
  },
  checksList: {
    title: "Tutti i controlli, senza segreti",
    body: "JoJoX non nasconde come funziona: qui sotto trovi tutti i 21 controlli, quanto sono gravi, e quanto siamo sicuri di ognuno — «confermato» quando il problema è certo, «da verificare» quando manca un segnale nel codice ma potrebbe essere gestito altrove (il controllo viene comunque sempre eseguito).",
    subLabel: "{{count}} controlli, in 4 livelli di gravità",
  },
  team: {
    title: "Il tuo team",
    body: "Repository collegati e storico analisi condivisi tra tutti i membri — fino a 5 persone incluse nel piano Team.",
    seatsCount: "{{used}} di {{max}} persone incluse nel piano",
    seatsFull: "Hai raggiunto il numero massimo di persone incluse nel piano Team.",
    roleOwner: "Proprietario",
    roleMember: "Membro",
    roleInvited: "Invito in sospeso",
    invitePlaceholder: "email@esempio.com",
    inviteCta: "Invita",
    inviting: "Invio invito...",
    remove: "Rimuovi",
    errorInvite: "Errore nell'invio dell'invito",
    errorRemove: "Errore nella rimozione",
  },
  login: {
    sent: "Controlla la tua email: ti abbiamo mandato un link per accedere. Puoi chiudere questo popup.",
    prompt: "Accedi con la tua email — nessuna password, ti mandiamo un link.",
    sending: "Invio…",
    send: "Invia link di accesso",
    error: "Qualcosa è andato storto. Riprova.",
    close: "Chiudi",
  },
  analyzer: {
    gateTitle: "Hai già usato la tua analisi gratuita senza email",
    gateBody: "Accedi con la tua email per continuare: nessuna password, 5 analisi gratuite al mese.",
    gateCta: "Accedi con la tua email",
    dropzoneCta: "Trascina qui i tuoi file, o clicca per sceglierli",
    dropzoneHintLoggedIn: "Sei loggato: l'analisi viene salvata nel tuo storico.",
    dropzoneHintGuest: "Modalità ospite: 1 analisi gratuita, senza email. Dopo, basta la mail per continuare (5 al mese, gratis).",
    dropzoneHintAny: "Funziona su qualsiasi codice — anche scritto interamente a mano, non solo generato dall'AI.",
    dropzoneHintLanguages: "I 21 controlli coprono JavaScript/TypeScript, SQL/Supabase, Python (Flask, Django) e Go (Gin, net/http). Su altri linguaggi (Java, Rust, PHP...) alcuni controlli generici possono comunque essere utili, ma la copertura non è ancora completa.",
    sectionEyebrow: "L'analyzer",
    sectionTitle: "Carica il codice, guarda cosa trova.",
    moreFiles: "+{{count}} altri",
    analyzeButton: "Analizza",
    analyzeButtonCount: "Analizza {{count}} file",
    analyzing: "Analisi in corso…",
    errorGuestUsed: "Risulta già usata l'analisi gratuita senza email (magari da un altro dispositivo sulla stessa rete). Accedi con la tua email per continuare — 5 analisi gratuite al mese.",
    errorGeneric: "Analisi fallita, riprova.",
    autofixFixedOne: "🔧 Ho corretto da solo {{files}} file per {{types}} tipo di problema.",
    autofixFixedMany: "🔧 Ho corretto da solo {{files}} file per {{types}} tipi di problema.",
    autofixManualSuffix: " Altri {{count}} restano da sistemare a mano — richiedono decisioni sul tuo progetto che non possiamo prendere al posto tuo.",
    autofixManualOnly: "I problemi trovati richiedono decisioni sul tuo progetto che non possiamo correggere in automatico — guarda gli esempi \"prima/dopo\" qui sotto.",
    downloadZip: "Scarica file corretti (.zip)",
    downloadPdf: "Scarica report PDF",
    newAnalysis: "🔁 Nuova analisi",
  },
  history: {
    title: "Il tuo storico",
    toggleShow: "▼ Vedi lo storico",
    toggleHide: "▲ Nascondi lo storico",
    manualSource: "Analisi manuale",
    auditSource: "Controllo Completo del Sito",
    error: "Errore nel caricamento dello storico",
  },
  scoreChart: {
    title: "Andamento del punteggio",
    ariaLabel: "Andamento del punteggio di sicurezza nelle ultime {{count}} analisi: da {{from}} a {{to}} su 100",
  },
  findingsList: {
    scoreLabel: "Punteggio di sicurezza",
    emptyState: "Nessun problema trovato nei 21 controlli. 🎉",
    autoFixed: "🔧 già corretto nel file scaricabile",
  },
  github: {
    title: "GitHub App + CI",
    badge: "DISPONIBILE",
    flowTitle: "Non solo scansione. Monitoraggio.",
    flowBody: "Collega GitHub e lascia che JoJoX analizzi ogni modifica rilevante al tuo codice.",
    flowStep1: "GitHub",
    flowStep2: "JoJoX",
    flowStep3: "Analisi di sicurezza",
    flowStep4: "Rischio rilevato",
    flowStep5: "Correzione / Pull request",
    body1: "Collega GitHub. A ogni push e a ogni pull request JoJoX controlla il codice. Se trova un problema critico, blocca la pull request e lascia un commento chiaro con il riepilogo.",
    body2: "Basta impostarlo come controllo obbligatorio nelle impostazioni del branch: le modifiche rischiose non potranno più essere unite.",
    note: "Stesso motore dell'analisi manuale, nessun LLM. Gira sui nostri server per poter intervenire in automatico a ogni push.",
    teamShareNotice: "Sei nel piano Team: il repository che colleghi sarà visibile a tutto il team, e resterà al team anche se in futuro lasci il gruppo.",
    connectedLabel: "✓ COLLEGATO",
    toggleShow: "▼ Vedi anche: notifiche Slack, badge, CLI, VS Code e agenti AI",
    toggleHide: "▲ Nascondi dettagli avanzati",
    badgeTitle: "🏷️ Badge sempre aggiornato nel README",
    badgeBody: "Dopo aver collegato il repository, incolla questa riga nel tuo {{readme}} (sostituisci {{repo}} con i tuoi) — il punteggio si aggiorna da solo a ogni analisi, senza bisogno di rigenerarlo a mano:",
    publicScoreTitle: "🔗 Una pagina pubblica da condividere",
    publicScoreBody: "Oltre al badge, ogni repository collegato ha anche una pagina di punteggio pubblica e condivisibile — utile per un post, un tweet, o semplicemente per mostrare quanto è sicuro il tuo codice:",
    terminalTitle: "🖥️ Anche da terminale, in VS Code e per agenti AI",
    terminalBody: "JoJoX si può usare anche senza sito: da riga di comando (con {{fix}} per correggere in automatico), come estensione VS Code che sottolinea i problemi mentre scrivi, o come strumento MCP per Claude Code e altri agenti AI, che così possono controllarsi da soli mentre scrivono codice. Istruzioni complete nel {{link}}.",
    terminalLink: "README del repository",
    hookTitle: "🪝 Blocco commit in locale",
    hookBody: "Un comando da terminale ({{cmd}}) installa un controllo che ferma il commit sul tuo computer, prima ancora che il codice arrivi su GitHub, se trova un problema critico — così il problema non entra mai nella cronologia del repository.",
    slackTitle: "🔔 Notifiche su Slack",
    slackConnectFirst: "Collega prima GitHub (bottone qui sopra) per poter impostare le notifiche Slack.",
    slackBody: "Incolla qui l'URL di un {{link}} per ricevere un avviso sul canale del team quando una pull request viene bloccata o corretta in automatico:",
    slackLink: "Incoming Webhook Slack",
    slackSaving: "Salvataggio...",
    slackSave: "Salva",
    slackSaved: "✓ Salvato",
    slackErrorGeneric: "Errore nel salvataggio",
  },
  waitlist: {
    title: "In arrivo",
    subtitle: "Ancora in lavorazione — te lo diciamo chiaramente, invece di fingere che esista già:",
    toggleShow: "▼ Vedi la roadmap",
    toggleHide: "▲ Nascondi la roadmap",
    roadmap: [
      {
        icon: "🏢",
        title: "Piani Business / Enterprise",
        text: "Sappiamo che alcune aziende più grandi hanno esigenze diverse da Pro e Team — fatturazione dedicata, contratti, supporto prioritario. Non abbiamo ancora deciso cosa includere di preciso: preferiamo dirlo chiaramente ora, piuttosto che promettere dettagli che non esistono ancora.",
      },
      {
        icon: "🌍",
        title: "Sito in più lingue",
        text: "Già disponibile in italiano e inglese, sito e i 21 controlli inclusi. Altre lingue in arrivo più avanti.",
      },
      {
        icon: "➕",
        title: "Sempre più correzioni automatiche",
        text: "Oggi l'autofix corregge in automatico solo quando la risposta giusta è certa e non dipende dal tuo progetto — mai indovinando le tue regole di accesso. In arrivo: correzioni più sofisticate, anche su blocchi di codice interi e non solo righe singole, estese a sempre più problemi man mano che crescono i controlli — sempre con logica deterministica, mai un modello che indovina.",
      },
      {
        icon: "🧩",
        title: "Controlli per altri linguaggi",
        text: "Oltre a JavaScript/TypeScript e SQL/Supabase, i 21 controlli ora riconoscono anche Python (Flask, Django) e Go (Gin, net/http), testati su codice reale. Un linguaggio nuovo fatto bene — controlli e test per non generare falsi positivi — richiede giorni di lavoro dedicato per ognuno. Restano da coprire Java, Rust e PHP: uno alla volta, nello stesso modo.",
      },
      {
        icon: "📦",
        title: "Controllo delle librerie che usi",
        text: "Oggi JoJoX controlla il codice che scrivi tu. In arrivo: un controllo in più che guarda le librerie esterne del tuo progetto (es. il tuo package.json) e verifica, contro database pubblici come OSV.dev e GitHub Advisory, se una versione che usi ha una vulnerabilità già nota — l'unico controllo che, per funzionare, deve contattare un servizio esterno (mai il tuo codice, solo nome e versione della libreria).",
      },
      {
        icon: "🧱",
        title: "Controllo dell'infrastruttura (Terraform, Kubernetes)",
        text: "Stessa logica di pattern matching di oggi, applicata a un tipo di file diverso: configurazioni Terraform o Kubernetes, per trovare errori come un database lasciato accessibile a tutti per sbaglio.",
      },
      {
        icon: "🧠",
        title: "Livello AI per i bug difficilissimi",
        text: "I 21 controlli restano il cuore di JoJoX: sempre uguali, sempre verificabili — il punteggio su cui contare. In arrivo: un livello AI in più, pensato per scovare anche i bug di logica difficilissimi da trovare, quelli che nessun pattern può catturare — ma sempre con una persona che controlla prima che il codice venga davvero cambiato, mai in automatico e da solo.",
      },
    ],
    emailPlaceholder: "tua@email.com",
    submit: "Unisciti alla lista d'attesa",
    done: "✓ Sei in lista!",
    error: "Qualcosa è andato storto, riprova.",
  },
  supabase: {
    title: "Controllo Supabase",
    badge: "DISPONIBILE",
    body1: "Gli altri controlli leggono il codice e deducono cosa dovrebbe succedere a runtime. Questo invece si collega al tuo vero progetto Supabase e verifica cosa succede davvero: Row Level Security attiva o no, almeno una policy presente, bucket di storage pubblici o privati.",
    body2: "Non ti chiediamo mai le tue credenziali Supabase. Esegui tu stesso questa query di sola lettura (nessuna scrittura possibile) nell'{{sqlEditor}} del tuo progetto, copia il risultato in un file chiamato esattamente {{filename}}, e caricalo insieme al resto del codice nell'analyzer qui sopra — i risultati si aggiungono automaticamente a quelli degli altri 21 controlli.",
    sqlEditor: "SQL Editor",
    toggleShow: "▼ Mostra la query",
    toggleHide: "▲ Nascondi la query",
  },
  report: {
    brandSub: "Report di sicurezza del codice",
    reportLabel: "Report",
    generatedOn: "Generato il {{date}}",
    controlsNoLLM: "21 controlli · nessun LLM",
    filesScannedOne: "1 file analizzato",
    filesScannedMany: "{{count}} file analizzati",
    projectFallback: "Analisi codice",
    noProblems: "Nessun problema trovato",
    oneProblem: "1 problema trovato",
    manyProblems: "{{count}} problemi trovati, di gravità diversa",
    autofixNoteOne: "1 problema su {{total}} può essere corretto in automatico da JoJoX.",
    autofixNoteMany: "{{count}} problemi su {{total}} possono essere corretti in automatico da JoJoX.",
    autofixNoteSuffix: " Il file corretto è scaricabile dal sito come archivio .zip, separatamente da questo report.",
    resultsLabel: "Risultati",
    emptyState: "Nessun problema trovato nei 21 controlli.",
    printBtn: "Stampa / Salva come PDF",
    printHint: "Se la finestra di stampa non si apre da sola, usa Ctrl+P (Cmd+P su Mac).",
    popupBlocked: "Il browser ha bloccato l'apertura della finestra. Consenti i popup per questo sito e riprova.",
  },
  publicScore: {
    loading: "Caricamento del punteggio...",
    notFoundTitle: "Nessun punteggio pubblico per questo repository",
    notFoundBody: "Non risulta ancora nessuna analisi collegata a questo repository tramite la GitHub App di JoJoX.",
    scoreLabel: "Punteggio di sicurezza",
    issuesLabel: "Problemi trovati nell'ultima analisi",
    noIssues: "Nessun problema trovato. 🎉",
    updatedLabel: "Ultima analisi: {{date}}",
    ctaText: "Analizza il tuo codice — gratis",
    copyLink: "Copia link",
    linkCopied: "✓ Link copiato",
    poweredBy: "Generato da JoJoX — 21 controlli pubblici, nessun LLM",
  },
  fullSiteAudit: {
    eyebrow: "Novità",
    title: "Controllo Completo del Sito",
    subtitle: "Hai un sito già online da un po'? Un controllo completo su tutto il progetto, una volta sola — non un abbonamento.",
    priceLabel: "49€",
    priceNote: "pagamento singolo, non un abbonamento",
    features: [
      "Analizza l'intero progetto — frontend e backend insieme, non solo poche modifiche",
      "Gli stessi 21 controlli pubblici, sullo stesso motore usato per il monitoraggio continuo",
      "Correzioni automatiche dove possibile, istruzioni chiare per il resto",
      "Report scaricabile in PDF, valido subito dopo il pagamento",
    ],
    ctaBuy: "Acquista il tuo Controllo Completo del Sito",
    buying: "Apertura del pagamento...",
    errorPurchase: "Errore nell'apertura del pagamento",
    creditsAvailable: "Hai {{count}} Controlli Completi del Sito disponibili — carica il tuo progetto quando vuoi.",
    dropzoneCta: "Trascina qui l'intero progetto, o clicca per selezionarlo",
    dropzoneHint: "Fino a 2000 file — funziona anche su progetti grandi, frontend e backend insieme.",
    analyzeButton: "Avvia il Controllo Completo del Sito",
    analyzeButtonCount: "Avvia l'audit su {{count}} file",
    analyzing: "Analisi in corso — può richiedere qualche istante su progetti grandi…",
    errorNoCredit: "Nessun Controllo Completo del Sito disponibile. Acquistane uno per continuare.",
    errorGeneric: "Audit fallito, riprova.",
    downloadPdf: "Scarica report PDF",
    downloadZip: "Scarica file corretti (.zip)",
    newAudit: "🔁 Nuovo Controllo Completo del Sito",
    changeFiles: "Cambia file",
    scoreBefore: "Prima",
    scoreAfter: "Dopo la correzione automatica",
    scoreAfterNote: "Solo i problemi corretti automaticamente sono già risolti nei file scaricabili — quelli senza correzione automatica restano da sistemare a mano.",
    scoreStuckNote: "Il punteggio non si è ancora spostato, ma abbiamo corretto comunque {{fixed}} problemi su {{total}}: restano problemi critici che il correttore automatico non può risolvere da solo (es. SQL injection) e servono modifiche manuali. I problemi già corretti restano corretti nei file scaricabili qui sotto.",
    zipHelp: "Lo zip contiene solo i file corretti (non l'intero progetto), più un file CORREZIONI.txt che elenca cosa copiare nel tuo progetto e cosa resta da sistemare a mano. Per un progetto reale su GitHub conviene comunque collegare il repository qui sopra prima di avviare l'audit: la Pull Request mostra le stesse modifiche come diff, pronte da unire con un click.",
    zipHelpWithPr: "Lo zip contiene solo i file corretti (non l'intero progetto), più un file CORREZIONI.txt con i dettagli. Le stesse modifiche sono già pronte come diff nella Pull Request qui sopra.",
    connectGithubSuggestion: "Hai un repository GitHub? Collegalo prima di iniziare per ricevere le correzioni come Pull Request pronta da un merge, invece che come zip da copiare a mano nel tuo progetto.",
    githubTargetLabel: "Vuoi anche una Pull Request su GitHub con le correzioni? (opzionale)",
    githubTargetChooseAccount: "Scegli un account collegato",
    githubTargetNone: "Nessuno — solo file da scaricare",
    viewPr: "Vedi la Pull Request su GitHub",
    prFailedNote: "Non siamo riusciti ad aprire la Pull Request su GitHub — puoi comunque scaricare i file corretti qui sopra.",
    prMismatchNote: "I file caricati non sembrano corrispondere al repository scelto — controlla di aver selezionato quello giusto. Non abbiamo aperto nessuna Pull Request, ma puoi comunque scaricare i file corretti qui sopra.",
    trialOfferTitle: "Vuoi vedere JoJoX controllare ogni tuo push in automatico?",
    trialOfferBody: "Attiva 30 giorni gratuiti di monitoraggio continuo (piano Pro) — nessuna carta di credito richiesta. Alla fine dei 30 giorni torni al piano Free senza addebiti automatici.",
    trialCta: "Attiva 30 giorni gratis",
    trialActivating: "Attivazione...",
    trialActivated: "✓ Prova attivata — hai il piano Pro per i prossimi 30 giorni.",
    trialError: "Non siamo riusciti ad attivare la prova gratuita, riprova.",
  },
};

const en: TranslationTree = {
  meta: {
    dateLocale: "en-GB",
    title: "JoJoX — Security for your code",
  },
  common: {
    severity: {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
    },
    confirmed: "confirmed",
    heuristic: "to verify",
    before: "Before",
    after: "After",
    correctionsManifest: {
      title: "JoJoX automatic corrections",
      filesIntro:
        "This zip contains ONLY the files that were changed, not the whole project. Copy these files into your real project, overwriting the ones with the same path — don't replace the whole folder.",
      filesHeader: "Fixed files ({{count}}):",
      manualHeader:
        "Issues that still need a manual fix in your source code ({{count}} types — see the PDF report for the full list with file and line):",
      manualNone: "Nothing left to fix: JoJoX automatically fixed everything it found.",
      occurrences: "{{count}} occurrences",
    },
  },
  header: {
    connect: "Connect GitHub",
    connectAnother: "Connect another GitHub account",
    connected: "✓ GitHub connected",
    logout: "Log out",
    login: "Log in",
  },
  hero: {
    titleLine1: "Your AI agent writes code every day, or do you write it yourself?",
    titleLine2Suffix: "keeps watch.",
    body: "Not a one-off check. {{monitoring}}. 21 public checks for the most common mistakes in your code, a clear {{score}}, and fixes ready to copy.",
    bodyMonitoring: "Continuous monitoring",
    bodyScore: "security score",
    sub: "The checks that normally take hours, automated and always on.",
    pill1: "Fixes always stay in your browser",
    pill2: "No sign-up to start",
    pill3: "Free",
    badge: "AI Code Security",
    cta: "Analyze your code — free",
    guestNote: "1 free analysis with no email. Then just an email — 5 free analyses/month.",
    scanTag: "CRITICAL",
    statChecksLabel: "public checks",
    statScoreLabel: "score",
    statFreeLabel: "free analyses / month",
  },
  howItWorks: {
    eyebrow: "In 3 steps",
    title: "How it works, start to finish.",
    step1Title: "Analyze",
    step1Text: "Upload the code, or connect your GitHub repository.",
    step2Title: "Detect",
    step2Text: "JoJoX runs the 21 checks and finds the security issues.",
    step3Title: "Fix",
    step3Text: "Get an explanation, severity, and a fix ready to copy.",
  },
  features: {
    eyebrow: "No surprises",
    title: "See exactly what happens to your code.",
    subtitle: "Three true things, not generic promises: where the code stays, how you see the fixes, how the score is calculated.",
    items: [
      {
        icon: "🛡️",
        accent: "blue",
        title: "Your code stays yours",
        text: "The analysis you upload passes through our servers (to save the score and history), but the file contents are never kept — only the results. Automatic fixes, on the other hand, always stay in your browser.",
      },
      {
        icon: "🔧",
        accent: "amber",
        title: "Not just the problem, also how to fix it",
        text: "Every issue comes with a fix example, shown as a before/after: you immediately see what to change.",
      },
      {
        icon: "📊",
        accent: "mint",
        title: "Security score + badge",
        text: "A score from 0 to 100, calculated with a formula you can see in full, plus a badge to put in your project's README.",
      },
    ],
  },
  whyNotAi: {
    eyebrow: "The question we always get",
    question: "My AI agent already writes the code. Can't it check it too?",
    readMore: "Read the full answer",
    point1: "You can. But almost no one does it every time, on every file, after every change — and it only takes one missed check to leave a hole open. JoJoX doesn't wait for you to remember: it checks on its own, on every push.",
    point2: "Asking a model \"is this secure?\" is like asking for an opinion: it changes every time and leaves no proof. JoJoX runs the same 21 public checks every time, identical for everyone, verifiable line by line in the code — a verdict, not an opinion.",
    point3: "No LLM, no hallucinations, no cost that grows with usage: pure pattern matching, instant, built to run on every pull request as often as you need.",
    closingLead: "JoJoX doesn't write your code.",
    closingPunch: "It keeps watch.",
  },
  dividers: {
    howItWorks: "How it works",
    features: "What you see after the analysis",
    audience: "Who it's for",
    pricing: "Pricing",
    integrations: "Integrations",
    team: "Your team",
    roadmap: "Coming soon",
    checks: "The 21 checks",
  },
  audience: {
    eyebrow: "Who it's for",
    title: "Whether you code solo or with a team.",
    items: [
      {
        icon: "👨‍💻",
        title: "Developers",
        text: "Check your code before it becomes a problem — from the terminal, VS Code, or the site.",
      },
      {
        icon: "🚀",
        title: "Startups",
        text: "Protect the product while the team ships fast, without stopping for a manual review.",
      },
      {
        icon: "👥",
        title: "Teams",
        text: "Monitor every push and pull request across multiple repositories, with automatic blocking of critical issues.",
      },
      {
        icon: "🤖",
        title: "AI-powered development",
        text: "Check code written or modified by AI agents like Claude Code, before it reaches production.",
      },
    ],
  },
  pricing: {
    title: "You pay for continuous monitoring, not for individual analyses",
    subtitle: "Try 1 analysis with nothing to give. Then just an email, no password: up to 5 free analyses a month.",
    noticeSuccess: "✓ Payment received, we're activating your plan — this page will refresh itself in a few seconds.",
    noticeCancel: "Activation cancelled, no charge. Try again whenever you like.",
    guestTitle: "Guest mode",
    guestList: [
      "1 free analysis, no email",
      "All 21 checks with fix examples",
      "Security score",
      "One attempt per visitor, enforced by our server",
    ],
    guestCta: "Try it without signing up",
    billingMonthly: "Monthly",
    billingAnnual: "Annual",
    billingAnnualBadge: "save ~17%",
    freeTitle: "Free",
    freeList: [
      "5 analyses a month",
      "All 21 checks, with fix examples",
      "Security score + downloadable badge (.svg)",
      "History of the last 20 analyses",
    ],
    freeCta: "Start for free",
    freeNote: "For one-off project analyses",
    proBadge: "MONITORING",
    proTitle: "Pro",
    proPer: "/month",
    proPerAnnual: "/year",
    proPriceAnnual: "€99",
    proList: [
      "Unlimited analyses and history",
      "GitHub integration: checks every push and blocks the riskiest changes",
      "One connected GitHub account/organization",
      "Automatic comments on pull requests",
      "Automatic fixes proposed as pull requests",
      "Badge that updates itself on every push",
    ],
    proCta: "Activate Pro",
    proActivating: "Activating...",
    proNote: "For continuous monitoring on every push",
    teamBadge: "TEAM",
    teamTitle: "Team",
    teamPer: "/month",
    teamPerAnnual: "/year",
    teamPriceAnnual: "€249",
    teamList: [
      "Unlimited analyses and history",
      "GitHub integration: checks every push and blocks the riskiest changes",
      "As many connected GitHub accounts/organizations as you need",
      "Up to 5 people included, with shared repositories and history",
      "Automatic comments on pull requests",
      "Automatic fixes proposed as pull requests",
      "Badge that updates itself on every push",
    ],
    teamCta: "Activate Team",
    teamActivating: "Activating...",
    teamNote: "For teams with multiple repos — one account per subscription today",
    enterpriseContactQuestion: "Need something custom for a larger team?",
    enterpriseContactLink: "Get in touch",
    activePlan: "Active plan",
    manageSubscription: "Manage subscription",
    opening: "Opening...",
    errorActivation: "Error activating the plan",
    errorPortal: "Error opening the subscription portal",
    disclaimer: "Cancel anytime, no strings attached — the subscription manages itself, straight from your account.",
  },
  footer: {
    intro: "*For manual analysis:",
    items: [
      "If you save your history, we only send a minimal fragment of the line affected by each issue — never the whole line, never the file.",
      "In guest mode, the code still goes through our servers for analysis (needed to enforce the one-free-try limit), but it's never saved: only the result you see is kept, plus an anonymous fingerprint of your IP address to recognize a try you've already used.",
      "The GitHub integration, instead, processes the code on our servers.",
    ],
    privacyLink: "Privacy Policy",
    termsLink: "Terms of Service",
    securityLink: "Security & vulnerability disclosure",
  },
  checksList: {
    title: "Every check, no secrets",
    body: "JoJoX doesn't hide how it works: below is the full list of all 21 checks, how severe each is, and how confident we are in each — \"confirmed\" when the problem is certain, \"to verify\" when a signal is missing from the code but it might be handled elsewhere (the check still always runs).",
    subLabel: "{{count}} checks, across 4 severity levels",
  },
  team: {
    title: "Your team",
    body: "Connected repositories and analysis history shared across every member — up to 5 people included in the Team plan.",
    seatsCount: "{{used}} of {{max}} people included in the plan",
    seatsFull: "You've reached the maximum number of people included in the Team plan.",
    roleOwner: "Owner",
    roleMember: "Member",
    roleInvited: "Invite pending",
    invitePlaceholder: "email@example.com",
    inviteCta: "Invite",
    inviting: "Sending invite...",
    remove: "Remove",
    errorInvite: "Error sending the invite",
    errorRemove: "Error removing member",
  },
  login: {
    sent: "Check your email: we've sent you a link to sign in. You can close this popup.",
    prompt: "Sign in with your email — no password, we'll send you a link.",
    sending: "Sending…",
    send: "Send sign-in link",
    error: "Something went wrong. Try again.",
    close: "Close",
  },
  analyzer: {
    gateTitle: "You've already used your free analysis without an email",
    gateBody: "Sign in with your email to continue: no password, 5 free analyses a month.",
    gateCta: "Sign in with your email",
    dropzoneCta: "Drag your files here, or click to choose them",
    dropzoneHintLoggedIn: "You're signed in: the analysis is saved to your history.",
    dropzoneHintGuest: "Guest mode: 1 free analysis, no email. After that, just an email to continue (5 a month, free).",
    dropzoneHintAny: "Works on any code — even written entirely by hand, not just AI-generated.",
    dropzoneHintLanguages: "The 21 checks cover JavaScript/TypeScript, SQL/Supabase, Python (Flask, Django) and Go (Gin, net/http). On other languages (Java, Rust, PHP...) some generic checks may still help, but coverage isn't complete yet.",
    sectionEyebrow: "The analyzer",
    sectionTitle: "Upload the code, see what it finds.",
    moreFiles: "+{{count}} more",
    analyzeButton: "Analyze",
    analyzeButtonCount: "Analyze {{count}} files",
    analyzing: "Analyzing…",
    errorGuestUsed: "The free analysis without email has already been used (maybe from another device on the same network). Sign in with your email to continue — 5 free analyses a month.",
    errorGeneric: "Analysis failed, try again.",
    autofixFixedOne: "🔧 I fixed {{files}} file myself for {{types}} type of issue.",
    autofixFixedMany: "🔧 I fixed {{files}} files myself for {{types}} types of issue.",
    autofixManualSuffix: " Another {{count}} still need fixing by hand — they need decisions about your project we can't make for you.",
    autofixManualOnly: "The issues found need decisions about your project we can't fix automatically — see the \"before/after\" examples below.",
    downloadZip: "Download fixed files (.zip)",
    downloadPdf: "Download PDF report",
    newAnalysis: "🔁 New analysis",
  },
  history: {
    title: "Your history",
    toggleShow: "▼ See history",
    toggleHide: "▲ Hide history",
    manualSource: "Manual analysis",
    auditSource: "Full Site Audit",
    error: "Error loading history",
  },
  scoreChart: {
    title: "Score over time",
    ariaLabel: "Security score trend over the last {{count}} analyses: from {{from}} to {{to}} out of 100",
  },
  findingsList: {
    scoreLabel: "Security score",
    emptyState: "No problems found across the 21 checks. 🎉",
    autoFixed: "🔧 already fixed in the downloadable file",
  },
  github: {
    title: "GitHub App + CI",
    badge: "AVAILABLE",
    flowTitle: "Don't just scan. Monitor.",
    flowBody: "Connect GitHub and let JoJoX analyze every relevant change to your code.",
    flowStep1: "GitHub",
    flowStep2: "JoJoX",
    flowStep3: "Security analysis",
    flowStep4: "Risk detected",
    flowStep5: "Fix / Pull request",
    body1: "Connect GitHub. On every push and every pull request, JoJoX checks the code. If it finds a critical issue, it blocks the pull request and leaves a clear comment with the summary.",
    body2: "Just set it as a required check in your branch settings: risky changes won't be mergeable anymore.",
    note: "Same engine as the manual analysis, no LLM. It runs on our servers so it can act automatically on every push.",
    teamShareNotice: "You're on the Team plan: the repository you connect will be visible to your whole team, and will stay with the team even if you leave it later.",
    connectedLabel: "✓ CONNECTED",
    toggleShow: "▼ Also see: Slack notifications, badge, CLI, VS Code and AI agents",
    toggleHide: "▲ Hide advanced details",
    badgeTitle: "🏷️ Always up-to-date badge in the README",
    badgeBody: "After connecting the repository, paste this line into your {{readme}} (replace {{repo}} with yours) — the score updates itself on every analysis, no need to regenerate it by hand:",
    publicScoreTitle: "🔗 A public page to share",
    publicScoreBody: "Besides the badge, every connected repository also gets a public, shareable score page — handy for a post, a tweet, or just showing off how secure your code is:",
    terminalTitle: "🖥️ Also from the terminal, in VS Code, and for AI agents",
    terminalBody: "JoJoX can also be used without the website: from the command line (with {{fix}} to fix automatically), as a VS Code extension that underlines issues as you type, or as an MCP tool for Claude Code and other AI agents, so they can check themselves while writing code. Full instructions in the {{link}}.",
    terminalLink: "repository README",
    hookTitle: "🪝 Local commit blocking",
    hookBody: "A terminal command ({{cmd}}) installs a check that stops the commit on your computer, before the code even reaches GitHub, if it finds a critical issue — so the problem never enters the repository's history.",
    slackTitle: "🔔 Slack notifications",
    slackConnectFirst: "Connect GitHub first (button above) to set up Slack notifications.",
    slackBody: "Paste the URL of an {{link}} here to get an alert on the team channel when a pull request is blocked or automatically fixed:",
    slackLink: "Incoming Webhook Slack",
    slackSaving: "Saving...",
    slackSave: "Save",
    slackSaved: "✓ Saved",
    slackErrorGeneric: "Error saving",
  },
  waitlist: {
    title: "Coming soon",
    subtitle: "Still in progress — we tell you clearly, instead of pretending it already exists:",
    toggleShow: "▼ See the roadmap",
    toggleHide: "▲ Hide the roadmap",
    roadmap: [
      {
        icon: "🏢",
        title: "Business / Enterprise plans",
        text: "We know some larger companies need something different from Pro and Team — dedicated billing, contracts, priority support. We haven't decided exactly what's included yet: we'd rather say that clearly now than promise details that don't exist.",
      },
      {
        icon: "🌍",
        title: "Site in more languages",
        text: "Already available in Italian and English, site and all 21 checks included. More languages coming later.",
      },
      {
        icon: "➕",
        title: "More and more automatic fixes",
        text: "Today autofix only corrects automatically when the right answer is certain and doesn't depend on your project — never guessing your access rules. Coming soon: more sophisticated fixes, including whole blocks of code and not just single lines, extended to more and more issues as the checks grow — always with deterministic logic, never a model guessing.",
      },
      {
        icon: "🧩",
        title: "Checks for more languages",
        text: "Besides JavaScript/TypeScript and SQL/Supabase, the 21 checks now also recognize Python (Flask, Django) and Go (Gin, net/http), tested on real code. A new language done properly — checks and tests to avoid false positives — takes days of dedicated work each. Java, Rust and PHP are still to cover, one at a time, the same way.",
      },
      {
        icon: "📦",
        title: "Checking the libraries you use",
        text: "Today JoJoX checks the code you write. Coming soon: an extra check that looks at your project's external libraries (e.g. your package.json) and verifies, against public databases like OSV.dev and GitHub Advisory, whether a version you use has a known vulnerability — the only check that, to work, needs to contact an external service (never your code, only the library's name and version).",
      },
      {
        icon: "🧱",
        title: "Infrastructure checks (Terraform, Kubernetes)",
        text: "Same pattern-matching logic as today, applied to a different kind of file: Terraform or Kubernetes configuration, to catch mistakes like a database accidentally left open to everyone.",
      },
      {
        icon: "🧠",
        title: "AI layer for the hardest bugs",
        text: "The 21 checks stay the heart of JoJoX: always the same, always verifiable — the score you can count on. Coming soon: an extra AI layer, built to catch the logic bugs that are hardest to find, the ones no pattern can catch — but always with a person reviewing before code is actually changed, never on its own.",
      },
    ],
    emailPlaceholder: "you@email.com",
    submit: "Join the waitlist",
    done: "✓ You're on the list!",
    error: "Something went wrong, try again.",
  },
  supabase: {
    title: "Supabase check",
    badge: "AVAILABLE",
    body1: "The other checks read the code and infer what should happen at runtime. This one instead connects to your real Supabase project and verifies what actually happens: Row Level Security on or off, at least one policy present, storage buckets public or private.",
    body2: "We never ask for your Supabase credentials. Run this read-only query yourself (no writes possible) in your project's {{sqlEditor}}, copy the result into a file named exactly {{filename}}, and upload it together with the rest of the code in the analyzer above — the results are automatically added to the other 21 checks.",
    sqlEditor: "SQL Editor",
    toggleShow: "▼ Show the query",
    toggleHide: "▲ Hide the query",
  },
  report: {
    brandSub: "Code security report",
    reportLabel: "Report",
    generatedOn: "Generated on {{date}}",
    controlsNoLLM: "21 checks · no LLM",
    filesScannedOne: "1 file scanned",
    filesScannedMany: "{{count}} files scanned",
    projectFallback: "Code analysis",
    noProblems: "No problems found",
    oneProblem: "1 problem found",
    manyProblems: "{{count}} problems found, of varying severity",
    autofixNoteOne: "1 problem out of {{total}} can be fixed automatically by JoJoX.",
    autofixNoteMany: "{{count}} problems out of {{total}} can be fixed automatically by JoJoX.",
    autofixNoteSuffix: " The fixed file can be downloaded from the site as a .zip archive, separately from this report.",
    resultsLabel: "Results",
    emptyState: "No problems found across the 21 checks.",
    printBtn: "Print / Save as PDF",
    printHint: "If the print window doesn't open by itself, use Ctrl+P (Cmd+P on Mac).",
    popupBlocked: "Your browser blocked the popup window. Allow popups for this site and try again.",
  },
  publicScore: {
    loading: "Loading score...",
    notFoundTitle: "No public score for this repository",
    notFoundBody: "No analysis linked to this repository through the JoJoX GitHub App yet.",
    scoreLabel: "Security score",
    issuesLabel: "Issues found in the latest analysis",
    noIssues: "No problems found. 🎉",
    updatedLabel: "Last analysis: {{date}}",
    ctaText: "Analyze your code — free",
    copyLink: "Copy link",
    linkCopied: "✓ Link copied",
    poweredBy: "Generated by JoJoX — 21 public checks, no LLM",
  },
  fullSiteAudit: {
    eyebrow: "New",
    title: "Full Site Audit",
    subtitle: "Already have a site live for a while? A complete check on the whole project, once — not a subscription.",
    priceLabel: "€49",
    priceNote: "one-time payment, not a subscription",
    features: [
      "Scans the whole project — frontend and backend together, not just a few changes",
      "The same 21 public checks, on the same engine used for continuous monitoring",
      "Automatic fixes where possible, clear instructions for the rest",
      "Downloadable PDF report, ready right after payment",
    ],
    ctaBuy: "Buy your Full Site Audit",
    buying: "Opening payment...",
    errorPurchase: "Error opening payment",
    creditsAvailable: "You have {{count}} Full Site Audits available — upload your project whenever you're ready.",
    dropzoneCta: "Drag your whole project here, or click to select it",
    dropzoneHint: "Up to 2000 files — works on large projects too, frontend and backend together.",
    analyzeButton: "Start the Full Site Audit",
    analyzeButtonCount: "Start the audit on {{count}} files",
    analyzing: "Analyzing — this can take a moment on large projects…",
    errorNoCredit: "No Full Site Audit available. Buy one to continue.",
    errorGeneric: "Audit failed, try again.",
    downloadPdf: "Download PDF report",
    downloadZip: "Download fixed files (.zip)",
    newAudit: "🔁 New Full Site Audit",
    changeFiles: "Change files",
    scoreBefore: "Before",
    scoreAfter: "After the automatic fixes",
    scoreAfterNote: "Only the automatically fixed issues are already resolved in the downloadable files — anything without an automatic fix still needs a manual fix.",
    scoreStuckNote: "The score hasn't moved yet, but we still fixed {{fixed}} of {{total}} issues: there are critical issues left that the automatic fixer can't resolve on its own (e.g. SQL injection) and need manual changes. The issues already fixed stay fixed in the downloadable files below.",
    zipHelp: "The zip only contains the fixed files (not the whole project), plus a CORREZIONI.txt file listing what to copy into your project and what's still left to fix by hand. For a real GitHub project, connecting the repository above before starting the audit is still the smoother path: the Pull Request shows the same changes as a diff, ready to merge with one click.",
    zipHelpWithPr: "The zip only contains the fixed files (not the whole project), plus a CORREZIONI.txt file with the details. The same changes are already there as a diff in the Pull Request above.",
    connectGithubSuggestion: "Have a GitHub repository? Connect it before you start to get the fixes as a Pull Request ready to merge, instead of a zip to copy by hand into your project.",
    githubTargetLabel: "Also want a GitHub Pull Request with the fixes? (optional)",
    githubTargetChooseAccount: "Choose a connected account",
    githubTargetNone: "None — just the downloadable files",
    viewPr: "View the Pull Request on GitHub",
    prFailedNote: "We couldn't open the Pull Request on GitHub — you can still download the fixed files above.",
    prMismatchNote: "The uploaded files don't seem to match the chosen repository — check you picked the right one. We didn't open a Pull Request, but you can still download the fixed files above.",
    trialOfferTitle: "Want to see JoJoX check every one of your pushes automatically?",
    trialOfferBody: "Activate 30 free days of continuous monitoring (Pro plan) — no credit card required. After 30 days you're back on the Free plan, no automatic charges.",
    trialCta: "Activate 30 days free",
    trialActivating: "Activating...",
    trialActivated: "✓ Trial activated — you have the Pro plan for the next 30 days.",
    trialError: "We couldn't activate the free trial, try again.",
  },
};

export const translations: Record<Lang, TranslationTree> = { it, en };
'@
Write-Utf8NoBom "web/src/i18n/translations.ts" $content_web_src_i18n_translations_ts


Write-Host ""
Write-Host "Fatto. Tutti i file sono stati aggiornati." -ForegroundColor Green
Write-Host "Nessuna migrazione SQL questa volta. Apri il terminale, fai commit + push." -ForegroundColor Green
