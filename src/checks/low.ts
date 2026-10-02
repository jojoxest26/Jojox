import type { Check } from "../types.js";
import { scanLines, fileMatch, replaceLines, isPythonFile, isGoFile, isJavaFile, isPhpFile, isDockerfile } from "../util/scan.js";

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
      const java = isJavaFile(file);
      const php = isPhpFile(file);
      const routePattern = python
        ? /@\w+\.route\s*\(\s*["'][^"']*\/login[^"']*["']/i
        : go
          ? /\.(POST|post)\s*\(\s*["'][^"']*\/login[^"']*["']/
          : java
            ? /@PostMapping\s*\(\s*(?:value\s*=\s*)?["'][^"']*\/login[^"']*["']/
            : php
              ? /Route::post\s*\(\s*["'][^"']*\/login[^"']*["']/i
              : /\.post\s*\(\s*["'][^"']*\/login[^"']*["']/i;
      const limiterPattern = python
        ? /rateLimit|rate-limit|rate_limit|flask_limiter|Limiter\(/i
        : go
          ? /rate\.NewLimiter|tollbooth|ulule\/limiter|gin-contrib\/limiter|RateLimit|rate_limit/i
          : java
            ? /RateLimiter|Bucket4j|resilience4j|rate_limit/i
            : php
              ? /throttle:|RateLimiter::|rate_limit/i
              : /rateLimit|rate-limit|rate_limit/i;

      if (!fileMatch(file, routePattern)) return [];
      if (fileMatch(file, limiterPattern)) return [];
      return scanLines(file, new RegExp(routePattern.source, "gi"));
    },
    autofix(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const java = isJavaFile(file);
      const php = isPhpFile(file);

      // Per il Go e per Java non generiamo un rate limiter autonomo come per
      // JS/Python: servirebbe uno stato condiviso tra richieste concorrenti
      // (thread diversi in un server Java, goroutine diverse in Go) con una
      // sincronizzazione corretta che un autofix basato su pattern non può
      // garantire alla cieca. Per PHP il motivo è ancora più diretto: nel
      // deployment classico (PHP-FPM/Apache), ogni richiesta parte da un
      // interprete nuovo — una variabile in memoria come quella usata per
      // JS/Python non sopravvivrebbe da una richiesta all'altra e non
      // proteggerebbe davvero nulla. Per tutti e tre segnaliamo soltanto il
      // problema senza un fix automatico.
      if (go || java || php) return null;

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
      const java = isJavaFile(file);
      const php = isPhpFile(file);
      // \$? nell'alternativa PHP copre il sigillo "$" davanti al nome della
      // variabile (es. $password), diverso dalle forme bare delle altre lingue.
      const pattern = python
        ? /\b(print|logging\.(debug|info|warning|error|critical)|logger\.(debug|info|warning|error|critical))\([^)]*\b(password|token|secret|api_key|apiKey)\b/gi
        : go
          ? /\b(log\.(Println|Printf|Print|Fatal|Fatalln|Fatalf)|fmt\.(Println|Printf|Print))\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi
          : java
            ? /\b(System\.out\.(println|print|printf)|log\.(debug|info|warn|error)|logger\.(debug|info|warn|error))\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi
            : php
              ? /\b(error_log|var_dump|print_r)\s*\([^)]*\$(password|token|secret|api_key|apiKey)\b/gi
              : /console\.(log|error|warn|info)\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi;
      const commentPattern = python ? /^\s*#/ : /^\s*\/\//;
      const lines = file.content.split("\n");
      return scanLines(file, pattern).filter((m) => !commentPattern.test(lines[m.line - 1] ?? ""));
    },
    autofix(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const java = isJavaFile(file);
      const php = isPhpFile(file);
      const pattern = python
        ? /\b(print|logging\.(debug|info|warning|error|critical)|logger\.(debug|info|warning|error|critical))\([^)]*\b(password|token|secret|api_key|apiKey)\b/gi
        : go
          ? /\b(log\.(Println|Printf|Print|Fatal|Fatalln|Fatalf)|fmt\.(Println|Printf|Print))\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi
          : java
            ? /\b(System\.out\.(println|print|printf)|log\.(debug|info|warn|error)|logger\.(debug|info|warn|error))\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi
            : php
              ? /\b(error_log|var_dump|print_r)\s*\([^)]*\$(password|token|secret|api_key|apiKey)\b/gi
              : /console\.(log|error|warn|info)\([^)]*\b(password|token|secret|apiKey|api_key)\b/gi;
      const commentPrefix = python ? "#" : "//";
      const { content, changed } = replaceLines(file.content, pattern, (line) => {
        const indent = line.match(/^(\s*)/)?.[1] ?? "";
        return `${indent}${commentPrefix} ${line.trim()}  ${commentPrefix} rimossa da JoJoX: registrava dati sensibili nei log`;
      });
      return changed ? content : null;
    },
  },

  {
    id: "docker-unpinned-base-image",
    severity: "low",
    confidence: "heuristic",
    title: "L'immagine di base del Dockerfile usa il tag \":latest\"",
    description:
      "Un'istruzione FROM usa esplicitamente il tag \":latest\" invece di una versione precisa. \"latest\" cambia nel tempo: la stessa build, rifatta in un altro momento, può ottenere una versione diversa dell'immagine di base — build non riproducibile, e un aggiornamento indesiderato può arrivare senza che nessuno l'abbia deciso.",
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
    detect(file) {
      if (!isDockerfile(file)) return [];
      return scanLines(file, /^\s*FROM\s+\S+:latest(?=\s|$)/gim);
    },
    // Nessun autofix: non possiamo indovinare quale versione precisa
    // dell'immagine il progetto si aspetta — richiede una scelta umana.
  },

  {
    id: "docker-add-remote-url",
    severity: "low",
    confidence: "heuristic",
    title: "Il Dockerfile scarica un file remoto con ADD invece di COPY",
    description:
      "L'istruzione ADD con un URL http/https scarica un file da internet durante la build, senza verifica dell'integrità e senza che il contenuto sia visibile nel repository. Se quell'URL viene compromesso in futuro, la build incorpora contenuto arbitrario senza che nessuno se ne accorga leggendo il Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<hash atteso>  /tmp/install.sh" | sha256sum -c -`,
    },
    detect(file) {
      if (!isDockerfile(file)) return [];
      return scanLines(file, /^\s*ADD\s+https?:\/\//gim);
    },
    // Nessun autofix: servirebbe conoscere l'hash atteso del file scaricato,
    // che non possiamo calcolare senza scaricarlo noi stessi.
  },
];