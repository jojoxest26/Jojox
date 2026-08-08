import type { Check } from "../types.js";
import { scanLines, fileMatch, replaceLines } from "../util/scan.js";
import { toEnvName } from "../util/envName.js";

const PUBLIC_ENV_PREFIX = /(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|PUBLIC_)/;
const SERVER_ONLY_PATH = /(^|\/)(api|server|edge-functions?|functions)(\/|\.)/i;

const PLACEHOLDER_VALUE = /^(process\.env|import\.meta\.env|xxx+|your[-_]?\w*|changeme|example|placeholder|<.*>|\$\{)/i;

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
      const assignmentPattern =
        /\b(apiKey|api_key|secret|secretKey|password|token|authToken)\s*[:=]\s*["'`]([^"'`]{12,})["'`]/gi;
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
      const pattern =
        /\b(apiKey|api_key|secret|secretKey|password|token|authToken)(\s*[:=]\s*)["'`][^"'`]{12,}["'`]/gi;
      const { content, changed } = replaceLines(file.content, pattern, (line, m) => {
        if (/process\.env|import\.meta\.env/.test(line)) return null;
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
    // Nessun autofix: spostare le credenziali fuori dal repo (.gitignore) e
    // ruotarle è un'azione che deve fare una persona, non uno script.
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