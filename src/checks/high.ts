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