import type { Check } from "../types.js";
import { scanLines, fileMatch, replaceLines } from "../util/scan.js";

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
      if (!fileMatch(file, /\.post\s*\(\s*["'][^"']*\/login[^"']*["']/i)) return [];
      if (fileMatch(file, /rateLimit|rate-limit|rate_limit/i)) return [];
      return scanLines(file, /\.post\s*\(\s*["'][^"']*\/login[^"']*["']/gi);
    },
    autofix(file) {
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
      const pattern = /console\.(log|error|warn|info)\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi;
      const lines = file.content.split("\n");
      return scanLines(file, pattern).filter((m) => !/^\s*\/\//.test(lines[m.line - 1] ?? ""));
    },
    autofix(file) {
      const pattern = /console\.(log|error|warn|info)\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi;
      const { content, changed } = replaceLines(file.content, pattern, (line) => {
        const indent = line.match(/^(\s*)/)?.[1] ?? "";
        return `${indent}// ${line.trim()}  // rimossa da JoJoX: registrava dati sensibili nei log`;
      });
      return changed ? content : null;
    },
  },
];