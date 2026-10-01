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