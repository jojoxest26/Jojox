import type { Check } from "../types.js";
import { scanLines, fileMatch } from "../util/scan.js";

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
      return scanLines(
        file,
        /console\.(log|error|warn|info)\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi
      );
    },
  },
];
