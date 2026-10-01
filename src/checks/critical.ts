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