import type { Check, CheckMatch } from "../types.js";
import { scanLines, lineFromIndex, redactLine } from "../util/scan.js";

const ADMIN_AUTH_KEYWORDS = /requireAuth|isAdmin|checkRole|verifyToken|session\.user|req\.user|assertRole/;

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
  },
];