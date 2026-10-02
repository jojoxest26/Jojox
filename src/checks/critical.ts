import type { Check, CheckMatch } from "../types.js";
import { scanLines, fileMatch, replaceLines, isPythonFile, isGoFile, isJavaFile, isPhpFile } from "../util/scan.js";
import { toEnvName } from "../util/envName.js";

const PUBLIC_ENV_PREFIX = /(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|PUBLIC_)/;
const SERVER_ONLY_PATH = /(^|\/)(api|server|edge-functions?|functions)(\/|\.)/i;

// Come si legge una variabile d'ambiente nel linguaggio del file — usato per
// non segnalare un valore già letto correttamente, e per scrivere l'autofix.
const ENV_READ_PATTERN = /process\.env|import\.meta\.env|os\.environ|os\.getenv|os\.Getenv|System\.getenv|\bgetenv\s*\(/;

const PLACEHOLDER_VALUE =
  /^(process\.env|import\.meta\.env|os\.environ|os\.getenv|os\.Getenv|System\.getenv|getenv\(|xxx+|your[-_]?\w*|changeme|example|placeholder|<.*>|\$\{)/i;

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
// (AKIA…, sk_live_/sk_test_…, chiavi AI, token OAuth con prefisso di provider): vanno
// anche revocati presso il fornitore, non solo tolti dal codice — l'autofix li lascia
// quindi segnalati soltanto, mai riscritti in automatico.
//
// Punto 13, fase 1: secret detection più ampia. Prima chiavi AI (OpenAI, Anthropic) e
// token OAuth con prefisso riconoscibile (GitHub, Slack, Google, Discord) — pubblico di
// JoJoX fa "vibe coding" con questi strumenti ogni giorno, è il pattern più probabile.
// Niente "token OAuth generico": senza un prefisso fisso di provider non è distinguibile
// da un qualunque ID/hash lungo, darebbe troppi falsi positivi — stesso principio già
// seguito per Stripe/AWS, solo formati con un'impronta riconoscibile.
const OPENAI_KEY = /sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}/;
const ANTHROPIC_KEY = /sk-ant-[A-Za-z0-9_-]{20,}/;
const GITHUB_TOKEN = /gh[pousr]_[A-Za-z0-9]{20,}/;
const SLACK_TOKEN = /xox[baprs]-[A-Za-z0-9-]{10,}/;
const GOOGLE_OAUTH_TOKEN = /ya29\.[A-Za-z0-9_-]{20,}/;
const DISCORD_BOT_TOKEN = /[MN][A-Za-z\d]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}/;
// Seguito del punto 13, fase 1: Twilio e SendGrid hanno anche loro un
// prefisso fisso riconoscibile, stesso principio delle chiavi sopra.
const TWILIO_SID = /AC[a-fA-F0-9]{32}/;
const SENDGRID_KEY = /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/;
// Certificati privati: oltre a RSA/EC/OPENSSH già coperti, anche DSA,
// PKCS8 cifrato, e il formato a blocco separato di PGP.
const PRIVATE_KEY_BLOCK = /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----/;

const HIGH_CONFIDENCE_SECRET_VALUE = new RegExp(
  [
    "AKIA[0-9A-Z]{16}",
    "sk_(live|test)_[0-9a-zA-Z]{16,}",
    ANTHROPIC_KEY.source,
    OPENAI_KEY.source,
    GITHUB_TOKEN.source,
    SLACK_TOKEN.source,
    GOOGLE_OAUTH_TOKEN.source,
    DISCORD_BOT_TOKEN.source,
    TWILIO_SID.source,
    SENDGRID_KEY.source,
  ].join("|")
);

// Stringa di connessione a un database con la password incrustata
// (postgres://utente:password@host/db e simili) — il segreto è il segmento
// tra ":" e "@". Un valore segnaposto ovvio (es. "password", "changeme") non
// va segnalato: è lo stesso principio di PLACEHOLDER_VALUE, applicato qui al
// segmento password invece che al valore di un'assegnazione intera.
const DB_CONNECTION_STRING = /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\/\s"'@]+:([^@\/\s"']+)@/gi;
const DB_CONNECTION_PLACEHOLDER_PASSWORD = /^(password|pass|changeme|xxx+|example|your[-_]?\w*|<.*>|\$\{)/i;

// Librerie/funzioni di hashing riconosciute, JS e Python insieme — se il file le usa già
// da qualche parte, diamo per buono che la password sia protetta e non segnaliamo nulla.
// password_hash/password_verify sono le funzioni native di PHP per questo scopo.
const ALREADY_HASHES_PASSWORD =
  /bcrypt|argon2|scrypt|hashSync|hashPassword|crypto\.hash|pbkdf2|werkzeug\.security|check_password_hash|generate_password_hash|make_password|passlib|password_hash|password_verify/i;

// Il valore grezzo della password così come arriva dalla richiesta — Express (req.body),
// Flask (request.form/request.json), Django (request.POST), Gin (c.PostForm), net/http
// (r.FormValue), Servlet/Spring (request.getParameter) e PHP ($_POST/$_REQUEST) hanno
// ognuno il suo nome. Il confine di parola (\b) sta solo sulle forme che finiscono con un
// identificatore semplice: le altre finiscono già con un carattere non alfanumerico
// (']', ')'), dove un \b dopo non potrebbe mai combaciare.
const RAW_PASSWORD_VALUE =
  'req\\.body\\.password\\b|req\\.body\\[["\']password["\']\\]|request\\.form\\[["\']password["\']\\]|request\\.form\\.get\\(["\']password["\']\\)|request\\.json\\[["\']password["\']\\]|request\\.POST\\[["\']password["\']\\]|c\\.PostForm\\(["\']password["\']\\)|r\\.FormValue\\(["\']password["\']\\)|request\\.getParameter\\(["\']password["\']\\)|\\$_POST\\[["\']password["\']\\]|\\$_REQUEST\\[["\']password["\']\\]|password\\b';

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
    // Non esteso a Python, Go, Java o PHP: il problema che segnala è
    // specifico dei bundler JS (Next.js, Vite...) che impacchettano variabili
    // con prefisso pubblico dentro il codice spedito al browser. Un backend
    // Python, un binario Go compilato, un .jar Java o uno script PHP eseguito
    // lato server non hanno un passaggio di bundling equivalente — non c'è un
    // rischio paragonabile da riconoscere con lo stesso pattern.
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
        ...scanLines(file, new RegExp(PRIVATE_KEY_BLOCK.source, "g")),
        // Punto 13, fase 1: chiavi AI e token OAuth con prefisso riconoscibile.
        // ANTHROPIC_KEY prima di OPENAI_KEY: non per evitare ambiguità nel
        // match (sono scanLines separate, non in competizione tra loro), ma
        // perché "sk-ant-..." non ha comunque una corsa di 32+ caratteri
        // alfanumerici subito dopo "sk-" (si interrompe su "ant-"), quindi
        // OPENAI_KEY (versione legacy) non potrebbe comunque confonderla.
        ...scanLines(file, new RegExp(ANTHROPIC_KEY.source, "g")),
        ...scanLines(file, new RegExp(OPENAI_KEY.source, "g")),
        ...scanLines(file, new RegExp(GITHUB_TOKEN.source, "g")),
        ...scanLines(file, new RegExp(SLACK_TOKEN.source, "g")),
        ...scanLines(file, new RegExp(GOOGLE_OAUTH_TOKEN.source, "g")),
        ...scanLines(file, new RegExp(DISCORD_BOT_TOKEN.source, "g")),
        ...scanLines(file, new RegExp(TWILIO_SID.source, "g")),
        ...scanLines(file, new RegExp(SENDGRID_KEY.source, "g")),
      ];

      const alreadyFlaggedLines = new Set(highConfidenceMatches.map((m) => m.line));
      const lines = file.content.split("\n");

      // Stringa di connessione DB con password incrustata: il segreto è nel
      // segmento catturato tra ":" e "@", non nell'intera stringa di
      // connessione — va escluso solo quando quel segmento è un segnaposto
      // ovvio, non l'intera riga.
      const dbConnectionMatches = scanLines(file, new RegExp(DB_CONNECTION_STRING.source, "gi")).filter((m) => {
        if (alreadyFlaggedLines.has(m.line)) return false;
        const raw = lines[m.line - 1] ?? "";
        const passwordMatch = raw.match(new RegExp(DB_CONNECTION_STRING.source, "i"));
        const password = passwordMatch?.[1];
        return !(password && DB_CONNECTION_PLACEHOLDER_PASSWORD.test(password));
      });
      for (const m of dbConnectionMatches) alreadyFlaggedLines.add(m.line);

      const assignmentPattern = new RegExp(`\\b(${SECRET_LIKE_NAMES})\\s*(?:${ASSIGN_OP})\\s*["'\`]([^"'\`]{12,})["'\`]`, "gi");
      const assignmentMatches = scanLines(file, assignmentPattern).filter((m) => {
        if (alreadyFlaggedLines.has(m.line)) return false;
        const raw = lines[m.line - 1] ?? "";
        if (ENV_READ_PATTERN.test(raw)) return false;
        const valueMatch = raw.match(/["'`]([^"'`]{6,})["'`]/);
        return !(valueMatch && PLACEHOLDER_VALUE.test(valueMatch[1]));
      });

      return [...highConfidenceMatches, ...dbConnectionMatches, ...assignmentMatches];
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
      const java = isJavaFile(file);
      const php = isPhpFile(file);
      const { content, changed } = replaceLines(file.content, pattern, (line, m) => {
        if (ENV_READ_PATTERN.test(line)) return null;
        if (HIGH_CONFIDENCE_SECRET_VALUE.test(line)) return null;
        const [, varName, operator] = m;
        const envName = toEnvName(varName);
        // Go: "name := value" diventa "name = os.Getenv(...)" — una volta
        // letta da env non è più una nuova dichiarazione, serve "=" non ":=".
        const goOperator = operator.replace(":=", "=");
        const envRead = python
          ? `os.environ["${envName}"]`
          : go
            ? `os.Getenv("${envName}")`
            : java
              ? `System.getenv("${envName}")`
              : php
                ? `getenv("${envName}")`
                : `process.env.${envName}`;
        // PHP: il nome catturato non include il "$" iniziale (sta fuori dal
        // match, prima di m.index) — resta al suo posto automaticamente.
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
        // Java: JDBC Statement.executeQuery/executeUpdate con concatenazione,
        // invece di PreparedStatement con segnaposto "?" (".execute(" semplice
        // è già coperto dal pattern generico qui sopra).
        ...scanLines(file, /\.(executeQuery|executeUpdate)\s*\(\s*["'][^"']*["']\s*\+\s*\w/g),
        // PHP: mysqli/PDO — la chiamata al metodo usa "->" (non "."), e la
        // concatenazione usa "." (non "+") invece di query parametrizzate;
        // oppure una variabile interpolata direttamente dentro una stringa fra
        // doppi apici (es. "SELECT ... WHERE id = $id").
        ...scanLines(file, /->\s*(query|exec)\s*\(\s*["'][^"']*["']\s*\.\s*\$/g),
        ...scanLines(file, /->\s*(query|exec)\s*\(\s*"[^"]*\$\w/g),
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
      const java = isJavaFile(file);
      const php = isPhpFile(file);
      // Nota a blocco /* */ per Java e PHP: a differenza di Go e JS, nessuno
      // dei due ha l'inserimento automatico di ";" — un commento // a fine
      // riga inghiottirebbe il punto e virgola che resta dopo, rompendo la
      // sintassi. Per PHP non serve comunque menzionare un pacchetto esterno:
      // password_hash() è nativa del linguaggio da PHP 5.5.
      const note = python
        ? " # JoJoX: serve il pacchetto bcrypt — pip install bcrypt"
        : go
          ? " // JoJoX: serve il pacchetto golang.org/x/crypto/bcrypt"
          : java
            ? " /* JoJoX: serve la libreria jBCrypt — org.mindrot:jbcrypt */"
            : php
              ? ""
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
            : java
              ? `BCrypt.hashpw(${value}, BCrypt.gensalt())`
              : php
                ? `password_hash(${value}, PASSWORD_BCRYPT)`
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
        // Java (jjwt): .signWith(SignatureAlgorithm.HS256, "secret") (API vecchia)
        // o .signWith(Keys.hmacShaKeyFor("secret".getBytes())) (API 0.11+).
        ...scanLines(file, /\.signWith\s*\(\s*SignatureAlgorithm\.\w+\s*,\s*["'][^"']{6,}["']\s*\)/g),
        ...scanLines(file, /\.signWith\s*\(\s*Keys\.hmacShaKeyFor\s*\(\s*["'][^"']{6,}["']\s*\.getBytes\s*\(\s*\)\s*\)\s*\)/g),
        // PHP (firebase/php-jwt): JWT::encode($payload, "secret", 'HS256') e
        // new Key("secret", 'HS256') lato decode.
        ...scanLines(file, /JWT::encode\s*\(\s*\$\w+\s*,\s*["'][^"']{6,}["']/g),
        ...scanLines(file, /new\s+Key\s*\(\s*["'][^"']{6,}["']/g),
        ...scanLines(file, /JWT_SECRET\s*(?:=|:=)\s*["'][^"']+["']/g),
      ];
    },
    autofix(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const java = isJavaFile(file);
      const php = isPhpFile(file);
      const envRead = python
        ? 'os.environ["JWT_SECRET"]'
        : go
          ? 'os.Getenv("JWT_SECRET")'
          : java
            ? 'System.getenv("JWT_SECRET")'
            : php
              ? 'getenv("JWT_SECRET")'
              : "process.env.JWT_SECRET";
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
      const javaOldApi = replaceLines(
        goMethods.content,
        /\.signWith\s*\(\s*(SignatureAlgorithm\.\w+)\s*,\s*["'][^"']{6,}["']\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `.signWith(${m[1]}, ${envRead})` + line.slice(m.index + m[0].length);
        }
      );
      const javaNewApi = replaceLines(
        javaOldApi.content,
        /\.signWith\s*\(\s*Keys\.hmacShaKeyFor\s*\(\s*["'][^"']{6,}["']\s*\.getBytes\s*\(\s*\)\s*\)\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `.signWith(Keys.hmacShaKeyFor(${envRead}.getBytes()))` + line.slice(m.index + m[0].length);
        }
      );
      const phpEncode = replaceLines(
        javaNewApi.content,
        /JWT::encode\s*\(\s*(\$\w+)\s*,\s*["'][^"']{6,}["']/g,
        (line, m) => {
          return line.slice(0, m.index) + `JWT::encode(${m[1]}, ${envRead}` + line.slice(m.index + m[0].length);
        }
      );
      const phpKey = replaceLines(phpEncode.content, /new\s+Key\s*\(\s*["'][^"']{6,}["']/g, (line, m) => {
        return line.slice(0, m.index) + `new Key(${envRead}` + line.slice(m.index + m[0].length);
      });
      const literal = replaceLines(phpKey.content, /JWT_SECRET\s*(=|:=)\s*["'][^"']+["']/g, (line, m) => {
        const op = go ? m[1].replace(":=", "=") : m[1];
        return line.slice(0, m.index) + `JWT_SECRET ${op} ${envRead}` + line.slice(m.index + m[0].length);
      });
      return jsMethods.changed ||
        pyMethods.changed ||
        goMethods.changed ||
        javaOldApi.changed ||
        javaNewApi.changed ||
        phpEncode.changed ||
        phpKey.changed ||
        literal.changed
        ? literal.content
        : null;
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

      // Java: Runtime.getRuntime().exec("..." + x) è già coperto dal pattern
      // generico qui sopra (".exec(" con stringa concatenata combacia
      // comunque). new ProcessBuilder("sh","-c", comando) invece ha lo
      // stesso problema di exec.Command("sh","-c", ...) in Go; con argomenti
      // separati (senza shell -c) resta sicuro, non lo segnaliamo.
      if (fileMatch(file, /new\s+ProcessBuilder\s*\(\s*["'`](sh|bash|cmd)["'`]\s*,\s*["'`](-c|\/c)["'`]/)) {
        matches.push(
          ...scanLines(
            file,
            /new\s+ProcessBuilder\s*\(\s*["'`](?:sh|bash|cmd)["'`]\s*,\s*["'`](?:-c|\/c)["'`]\s*,\s*["'][^"']*["']\s*\+\s*\w/g
          )
        );
      }

      // PHP: exec/shell_exec/system/passthru/popen/proc_open con una stringa
      // costruita per concatenazione (".", non "+") o con una variabile
      // interpolata direttamente dentro una stringa fra doppi apici. L'operatore
      // backtick `comando` di PHP esegue comunque una shell — stesso rischio
      // se contiene una variabile interpolata.
      if (
        fileMatch(
          file,
          /\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\(|`[^`]*\$\w/
        )
      ) {
        matches.push(
          ...scanLines(file, /\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*["'][^"']*["']\s*\.\s*\$/g),
          ...scanLines(file, /\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*"[^"]*\$\w/g),
          ...scanLines(file, /`[^`]*\$\w[^`]*`/g)
        );
      }

      return matches;
    },
    // Nessun autofix: separare comando e argomenti in modo sicuro richiede
    // di capire quale sia davvero il programma e quali i suoi parametri —
    // provarci alla cieca rischia di generare codice che non funziona più.
  },

  // Punto 13, fase 1 — injection oltre SQL/command: iniziamo da path
  // traversal e NoSQL injection, i due pattern a rischio di falso positivo
  // più basso (stessa logica "input utente dentro un sink pericoloso" già
  // usata per SSRF/SQL injection). LDAP injection, XXE e SSTI restano per un
  // giro dedicato: richiedono una validazione più attenta coi payload OWASP,
  // come deciso insieme prima di partire con questo punto.
  {
    id: "path-traversal",
    severity: "critical",
    confidence: "confirmed",
    title: "Un file sul server può essere letto o scritto scegliendo il percorso dall'esterno",
    description:
      "Una funzione che legge, scrive o invia un file riceve il percorso direttamente da un valore della richiesta (query, body, params) senza controllare che resti dentro una cartella consentita. Un attaccante può inserire \"../\" per uscire dalla cartella prevista e leggere o sovrascrivere file arbitrari sul server (es. file di configurazione con credenziali).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Percorso non consentito")\n  res.sendFile(target)\n})`,
    },
    detect(file) {
      return [
        // JS/Node: fs.*/res.sendFile con un valore preso direttamente dalla richiesta.
        ...scanLines(
          file,
          /\b(fs\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync)|res\.(sendFile|download))\s*\(\s*req\.(query|body|params)/g
        ),
        // Python: open()/Flask send_file con un valore da Flask (request.args/form) o Django (request.GET/POST).
        ...scanLines(
          file,
          /\b(open|send_file)\s*\(\s*request\.(args|form|GET|POST)/g
        ),
        // Go: os.Open/http.ServeFile con un valore da Gin (c.Query/c.PostForm) o net/http puro (r.FormValue/r.URL.Query).
        ...scanLines(
          file,
          /\b(os\.Open|os\.ReadFile|http\.ServeFile)\s*\([^)]*\b(c\.(Query|PostForm)|r\.(FormValue|URL\.Query\(\)\.Get))\s*\(/g
        ),
        // Java: new File(...)/FileInputStream/FileReader con request.getParameter.
        ...scanLines(file, /new\s+(File|FileInputStream|FileReader)\s*\(\s*request\.getParameter/g),
        // PHP: file_get_contents/fopen/readfile/include/require con $_GET/$_POST/$_REQUEST —
        // include/require con input utente è anche Local File Inclusion, ancora più grave (può portare a RCE).
        ...scanLines(
          file,
          /\b(file_get_contents|fopen|readfile|include|include_once|require|require_once)\s*\(\s*\$_(GET|POST|REQUEST)\[/g
        ),
      ];
    },
    // Nessun autofix: la cartella consentita e il modo corretto di validare il
    // percorso dipendono dal progetto — inventarli rischierebbe di bloccare
    // casi d'uso legittimi o, peggio, lasciare comunque un modo per uscirne.
  },

  {
    id: "nosql-injection",
    severity: "critical",
    confidence: "confirmed",
    title: "Un valore inserito dall'utente viene eseguito come codice dentro una query MongoDB",
    description:
      "L'operatore $where di MongoDB esegue del JavaScript lato server per ogni documento — se quella stringa è costruita concatenando un valore che arriva dall'utente, chi lo controlla può far eseguire codice arbitrario nel contesto del database, non solo alterare il filtro come con una normale SQL injection.",
    fix: {
      before: "db.collection.find({ $where: \"this.username == '\" + username + \"'\" })",
      after: `db.collection.find({ username: username })`,
    },
    detect(file) {
      // Python (pymongo) scrive la chiave come stringa tra apici ("$where":
      // ...), non come proprietà nuda (JS: $where: ...) — l'apice di
      // chiusura opzionale copre entrambe le forme con lo stesso pattern.
      //
      // Per la concatenazione: due alternative con lo STESSO tipo di apice
      // (non un generico ["'`]) — una stringa come "...== '" contiene un
      // apice singolo prima di chiudere con uno doppio, e un carattere
      // escluso genericamente da entrambi i tipi la spezzerebbe troppo presto.
      return [
        ...scanLines(file, /\$where["']?\s*[:=]\s*("[^"]*"|'[^']*')\s*\+\s*\w/g),
        ...scanLines(file, /\$where["']?\s*[:=]\s*`[^`]*\$\{/g),
        ...scanLines(file, /\$where["']?\s*[:=]\s*(f"[^"]*\{|f'[^']*\{)/g),
      ];
    },
    // Nessun autofix: $where va quasi sempre eliminato e sostituito con un
    // filtro sui campi veri, una riscrittura che dipende troppo dalla logica
    // originale per essere generata alla cieca.
  },
];