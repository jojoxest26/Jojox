import type { Check, CheckMatch } from "../types.js";
import { scanLines, redactLine } from "../util/scan.js";

const OWNERSHIP_KEYWORDS = /userId|user\.id|owner|req\.user|auth\.uid/;

export const mediumChecks: Check[] = [
  {
    id: "xss-dangerous-html",
    severity: "medium",
    confidence: "heuristic",
    title: "Un testo scritto dagli utenti potrebbe eseguire codice nel browser",
    description:
      "Del contenuto viene inserito nella pagina come HTML grezzo (dangerouslySetInnerHTML, v-html, .innerHTML) invece che come testo semplice. Se quel contenuto include input di un utente, può contenere script che vengono eseguiti nel browser di chi legge la pagina.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// oppure, se serve HTML: DOMPurify.sanitize(comment.text)`,
    },
    detect(file) {
      return [
        ...scanLines(file, /dangerouslySetInnerHTML/g),
        ...scanLines(file, /v-html\s*=/g),
        ...scanLines(file, /\.innerHTML\s*=\s*[^"'`\s][^;]*/g),
      ];
    },
  },

  {
    id: "public-storage-bucket",
    severity: "medium",
    confidence: "heuristic",
    title: "Lo spazio dei file caricati è visibile a chiunque",
    description:
      "Un bucket di storage (Supabase Storage, S3) è configurato come pubblico. Se contiene documenti, foto o file caricati dagli utenti, chiunque conosca — o indovini — il percorso può accedervi senza autenticazione.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// servire i file con URL firmati a tempo: createSignedUrl(path, 60)`,
    },
    detect(file) {
      return [
        ...scanLines(file, /createBucket\([^)]*public\s*:\s*true/g),
        ...scanLines(file, /acl\s*:\s*["']public-read["']/g),
      ];
    },
  },

  {
    id: "csrf-state-changing-get",
    severity: "medium",
    confidence: "heuristic",
    title: "Basta un link per cancellare o modificare dei dati",
    description:
      "Una rotta GET esegue un'operazione che cambia dati (il percorso contiene delete/remove/update/edit). Le richieste GET vengono eseguite anche solo visitando un link o caricando un'immagine da un sito esterno — è il punto d'appoggio classico per un attacco CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
    detect(file) {
      return scanLines(file, /\.get\s*\(\s*["'][^"']*\/(delete|remove|update|edit)[^"']*["']/gi);
    },
  },

  {
    id: "insecure-token-storage",
    severity: "medium",
    confidence: "confirmed",
    title: "I dati di accesso salvati nel browser non sono ben protetti",
    description:
      "Un token di accesso viene salvato in localStorage. A differenza di un cookie httpOnly, qualunque script eseguito nella pagina (incluso uno script malevolo iniettato via XSS) può leggerlo e rubarlo.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// impostare il token come cookie httpOnly dal server:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
    detect(file) {
      return scanLines(file, /localStorage\.setItem\(\s*["'][^"']*(token|jwt|auth)[^"']*["']/gi);
    },
  },

  {
    id: "open-redirect",
    severity: "medium",
    confidence: "heuristic",
    title: "Il sito può essere usato per reindirizzare verso un sito truffa",
    description:
      "Il sito reindirizza l'utente verso un indirizzo preso direttamente dalla richiesta (query, body, params) senza controllare che sia un dominio conosciuto. Un link che sembra puntare al tuo sito può in realtà portare a una pagina di phishing.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
    detect(file) {
      return [
        ...scanLines(file, /res\.redirect\(\s*req\.(query|body|params)/g),
        ...scanLines(file, /window\.location(\.href)?\s*=\s*(req\.(query|body|params)|new URLSearchParams)/g),
      ];
    },
  },

  {
    id: "idor",
    severity: "medium",
    confidence: "heuristic",
    title: "Cambiando un numero nell'indirizzo si potrebbero vedere dati altrui",
    description:
      "Una query al database usa direttamente un identificativo preso dall'URL (req.params.id) senza verificare, nelle righe vicine, che appartenga all'utente che sta facendo la richiesta. Cambiando l'id nell'indirizzo si potrebbe accedere ai dati di un altro utente — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
    detect(file) {
      const pattern = /\.findById\(\s*req\.params\.id\s*\)|findOne\(\s*\{\s*_id:\s*req\.params\.id\s*\}\s*\)/g;
      const matches: CheckMatch[] = [];
      const lines = file.content.split("\n");
      lines.forEach((lineText, idx) => {
        const re = new RegExp(pattern.source, "g");
        if (!re.test(lineText)) return;
        const from = Math.max(0, idx - 5);
        const to = Math.min(lines.length, idx + 6);
        const windowText = lines.slice(from, to).join("\n");
        if (OWNERSHIP_KEYWORDS.test(windowText)) return;
        matches.push({ line: idx + 1, snippet: redactLine(lineText, 0, lineText.length) });
      });
      return matches;
    },
  },
];
