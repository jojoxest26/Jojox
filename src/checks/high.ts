import type { Check, CheckMatch } from "../types.js";
import { scanLines, lineFromIndex, redactLine, replaceLines } from "../util/scan.js";

const ADMIN_AUTH_KEYWORDS = /requireAuth|isAdmin|checkRole|verifyToken|session\.user|req\.user|assertRole/;

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
        ...scanLines(file, /Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["']/gi),
        ...scanLines(file, /origin\s*:\s*["']\*["']/gi),
        ...scanLines(file, /\bcors\(\s*\)/g),
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
      const routePattern = /\.(get|post|put|patch|delete)\s*\(\s*["'][^"']*\/admin[^"']*["']/gi;
      const matches: CheckMatch[] = [];
      const lines = file.content.split("\n");
      lines.forEach((lineText, idx) => {
        if (!routePattern.test(lineText)) return;
        routePattern.lastIndex = 0;
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
      return scanLines(file, /\b(fetch|axios\.get|axios\.post|axios\.request|request)\s*\(\s*req\.(query|body|params)/g);
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
      const pattern = /createHash\(\s*["'](md5|sha1)["']\s*\)|\b(md5|sha1)\s*\(\s*password/gi;
      const lines = file.content.split("\n");
      return scanLines(file, pattern).filter((m) => /password/i.test(lines[m.line - 1] ?? ""));
    },
    autofix(file) {
      const note = " /* JoJoX: serve il pacchetto bcrypt — npm install bcrypt */";
      const chainPattern = /crypto\.createHash\(\s*["'](?:md5|sha1)["']\s*\)\.update\(([^)]*)\)\.digest\([^)]*\)/gi;
      let result = replaceLines(file.content, chainPattern, (line, m) => {
        if (!/password/i.test(line)) return null;
        return line.slice(0, m.index) + `await bcrypt.hash(${m[1]}, 12)${note}` + line.slice(m.index + m[0].length);
      });
      if (!result.changed) {
        result = replaceLines(file.content, /\b(?:md5|sha1)\s*\(\s*([^)]*)\)/gi, (line, m) => {
          if (!/password/i.test(line)) return null;
          return line.slice(0, m.index) + `await bcrypt.hash(${m[1]}, 12)${note}` + line.slice(m.index + m[0].length);
        });
      }
      return result.changed ? result.content : null;
    },
  },
];