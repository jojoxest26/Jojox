import type { Check, CheckMatch } from "../types.js";
import { scanLines, redactLine, replaceLines } from "../util/scan.js";

const OWNERSHIP_KEYWORDS = /userId|user\.id|owner|req\.user|auth\.uid/;
const REDIRECT_REMOVED_NOTE =
  " /* JoJoX: reindirizzamento verso un URL esterno non validato rimosso — se ti serve, valida il valore contro un elenco di percorsi permessi prima di riattivarlo */";

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
    // Nessun autofix: non sappiamo se quell'HTML deve restare tale (e va
    // solo sanificato, aggiungendo una dipendenza) o può diventare testo
    // semplice — dipende da cosa deve davvero mostrare quella pagina.
  },

  {
    id: "public-storage-bucket",
    severity: "medium",
    confidence: "confirmed",
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
    autofix(file) {
      const r1 = replaceLines(file.content, /createBucket\([^)]*public\s*:\s*true/g, (line, m) => {
        const replacement = m[0].replace(/public\s*:\s*true/, "public: false");
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const r2 = replaceLines(r1.content, /acl\s*:\s*["']public-read["']/g, (line, m) => {
        return line.slice(0, m.index) + `acl: "private"` + line.slice(m.index + m[0].length);
      });
      return r1.changed || r2.changed ? r2.content : null;
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
    // Nessun autofix: cambiare il metodo da GET a POST rompe chiunque
    // chiami questa rotta altrove (form, link, fetch) — quei punti di
    // chiamata non li vediamo, quindi non possiamo aggiornarli insieme.
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
    // Nessun autofix: la correzione vera sposta la scrittura del cookie sul
    // server, cioè in un file diverso da quello dove vive questa riga —
    // non possiamo farlo senza sapere dov'è quel server.
  },

  {
    id: "open-redirect",
    severity: "medium",
    confidence: "confirmed",
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
    autofix(file) {
      // Non conosciamo l'elenco di percorsi che dovrebbero essere permessi,
      // quindi non lo inventiamo: chiudiamo il buco reindirizzando sempre
      // alla home. Se il redirect dinamico serve davvero, va riattivato a
      // mano con un vero elenco di destinazioni consentite.
      const r1 = replaceLines(
        file.content,
        /res\.redirect\(\s*req\.(query|body|params)(?:\.\w+|\[[^\]]+\])*\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `res.redirect("/")${REDIRECT_REMOVED_NOTE}` + line.slice(m.index + m[0].length);
        }
      );
      const r2 = replaceLines(
        r1.content,
        /window\.location(\.href)?\s*=\s*(req\.(query|body|params)(?:\.\w+|\[[^\]]+\])*|new URLSearchParams\([^)]*\)[^;\n]*)/g,
        (line, m) => {
          const prop = m[1] ?? "";
          return line.slice(0, m.index) + `window.location${prop} = "/"${REDIRECT_REMOVED_NOTE}` + line.slice(m.index + m[0].length);
        }
      );
      return r1.changed || r2.changed ? r2.content : null;
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
    // Nessun autofix: non sappiamo qual è il campo che collega il record
    // all'utente proprietario nel tuo schema dati — aggiungerne uno a
    // caso creerebbe una query che sembra corretta ma non lo è.
  },
];