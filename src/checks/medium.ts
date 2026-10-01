import type { Check, CheckMatch } from "../types.js";
import { scanLines, redactLine, replaceLines } from "../util/scan.js";

// JS (userId, req.user...), Python/Django/Flask (request.user, user_id...),
// Go (UserID, c.MustGet...), Java/Spring Security (getPrincipal,
// authentication.getName...) e PHP/Laravel (Auth::id, auth()->id...) insieme —
// case-insensitive per coprire anche il PascalCase idiomatico di Go e Java
// senza doverlo scrivere due volte.
const OWNERSHIP_KEYWORDS =
  /userId|user_id|user\.id|owner|req\.user|request\.user|auth\.uid|current_user|MustGet|getPrincipal|AuthenticationPrincipal|authentication\.getName|Auth::id|auth\(\)->id/i;
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
        // Python/Jinja2 (Flask) e Django template: il filtro |safe o
        // mark_safe() disattivano l'escape automatico dell'HTML.
        ...scanLines(file, /\{\{[^}]*\|\s*safe\s*\}\}/g),
        ...scanLines(file, /\bmark_safe\s*\(/g),
        // Go: html/template — template.HTML(...) marca una stringa come HTML
        // già sicuro, disattivando l'escape automatico del pacchetto.
        ...scanLines(file, /\btemplate\.HTML\s*\(/g),
        // Java/Thymeleaf: th:utext stampa HTML senza escape (th:text, la
        // forma sicura, non viene toccato).
        ...scanLines(file, /\bth:utext\s*=/g),
        // PHP/Laravel Blade: {!! $var !!} stampa senza escape ({{ $var }}, la
        // forma sicura, non viene toccato).
        ...scanLines(file, /\{!!.*?!!\}/g),
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
        // JS: supabase-js, dict-style con "true" minuscolo.
        ...scanLines(file, /createBucket\([^)]*public\s*:\s*true/g),
        // Python: supabase-py, stesso dict ma "True" maiuscolo (sintassi Python).
        ...scanLines(file, /create_bucket\([^)]*public["']?\s*:\s*True/g),
        // JS e Python insieme: boto3 (Python) e SDK JS di S3 usano entrambi
        // la stessa chiave "ACL" con lo stesso valore letterale.
        ...scanLines(file, /acl\s*[:=]\s*["']public-read["']/gi),
        // Go: SDK AWS per Go, il valore è avvolto in aws.String(...).
        ...scanLines(file, /ACL:\s*aws\.String\(\s*["']public-read["']\s*\)/g),
        // Java: SDK AWS per Java — v1 usa la costante CannedAccessControlList
        // .PublicRead, v2 l'enum ObjectCannedACL.PUBLIC_READ.
        ...scanLines(file, /CannedAccessControlList\.PublicRead/g),
        ...scanLines(file, /ObjectCannedACL\.PUBLIC_READ/g),
        // PHP: SDK AWS per PHP usa la sintassi ad array con "=>", non ":"/"=",
        // quindi il pattern generico "acl[:=]" qui sopra non la riconosce.
        ...scanLines(file, /['"]ACL['"]\s*=>\s*['"]public-read['"]/gi),
      ];
    },
    autofix(file) {
      const r1 = replaceLines(file.content, /createBucket\([^)]*public\s*:\s*true/g, (line, m) => {
        const replacement = m[0].replace(/public\s*:\s*true/, "public: false");
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const r2 = replaceLines(r1.content, /create_bucket\([^)]*public["']?\s*:\s*True/g, (line, m) => {
        const replacement = m[0].replace(/public(["']?)\s*:\s*True/, "public$1: False");
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const r3 = replaceLines(r2.content, /acl\s*([:=])\s*["']public-read["']/gi, (line, m) => {
        const replacement = m[1] === "=" ? `ACL="private"` : `acl: "private"`;
        return line.slice(0, m.index) + replacement + line.slice(m.index + m[0].length);
      });
      const r4 = replaceLines(r3.content, /ACL:\s*aws\.String\(\s*["']public-read["']\s*\)/g, (line, m) => {
        return line.slice(0, m.index) + `ACL: aws.String("private")` + line.slice(m.index + m[0].length);
      });
      const r5 = replaceLines(r4.content, /CannedAccessControlList\.PublicRead/g, (line, m) => {
        return line.slice(0, m.index) + `CannedAccessControlList.Private` + line.slice(m.index + m[0].length);
      });
      const r6 = replaceLines(r5.content, /ObjectCannedACL\.PUBLIC_READ/g, (line, m) => {
        return line.slice(0, m.index) + `ObjectCannedACL.PRIVATE` + line.slice(m.index + m[0].length);
      });
      const r7 = replaceLines(r6.content, /(['"])ACL\1\s*=>\s*['"]public-read['"]/gi, (line, m) => {
        return line.slice(0, m.index) + `${m[1]}ACL${m[1]} => 'private'` + line.slice(m.index + m[0].length);
      });
      return r1.changed || r2.changed || r3.changed || r4.changed || r5.changed || r6.changed || r7.changed
        ? r7.content
        : null;
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
      const matches: CheckMatch[] = [...scanLines(file, /\.get\s*\(\s*["'][^"']*\/(delete|remove|update|edit)[^"']*["']/gi)];

      // Python/Flask: @app.route("/posts/<id>/delete") è una GET per
      // default finché non specifichi methods= con POST/PUT/DELETE nella
      // stessa riga — un form che chiama una rotta così è comunque un rischio.
      const flaskRoutePattern = /@\w+\.route\s*\(\s*["'][^"']*\/(delete|remove|update|edit)[^"']*["']/gi;
      const lines = file.content.split("\n");
      lines.forEach((lineText, idx) => {
        if (!flaskRoutePattern.test(lineText)) return;
        flaskRoutePattern.lastIndex = 0;
        if (/methods\s*=\s*\[[^\]]*(POST|PUT|DELETE)/i.test(lineText)) return;
        matches.push({ line: idx + 1, snippet: redactLine(lineText, 0, lineText.length) });
      });

      // Java/Spring: @GetMapping("/posts/{id}/delete") esegue
      // un'operazione di scrittura su una rotta GET.
      matches.push(
        ...scanLines(file, /@GetMapping\s*\(\s*(?:value\s*=\s*)?["'][^"']*\/(delete|remove|update|edit)[^"']*["']/gi)
      );

      // PHP/Laravel: Route::get('/posts/{id}/delete', ...) esegue
      // un'operazione di scrittura su una rotta GET.
      matches.push(
        ...scanLines(file, /Route::get\s*\(\s*["'][^"']*\/(delete|remove|update|edit)[^"']*["']/gi)
      );

      return matches;
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
    //
    // Non esteso a Python, Go, Java o PHP: localStorage è un'API del browser,
    // non ha un corrispondente lato server in nessuno dei quattro. Un backend
    // che genera HTML/JS con la stessa riga (es. in un template) verrebbe
    // comunque riconosciuto dal pattern così com'è, scansionando quel file
    // come se fosse JS.
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
        // Python/Flask: redirect(request.args[...]). Django: redirect(request.GET[...])
        // o HttpResponseRedirect(request.GET[...]).
        ...scanLines(file, /\b(redirect|HttpResponseRedirect)\s*\(\s*request\.(args|form|GET|POST)/g),
        // Go/Gin: c.Redirect(status, c.Query(...)). net/http: http.Redirect(w, r, r.FormValue(...), status).
        ...scanLines(file, /c\.Redirect\s*\(\s*[^,]+,\s*c\.(Query|PostForm)\s*\(/g),
        ...scanLines(file, /http\.Redirect\s*\([^,]+,[^,]+,\s*r\.FormValue\s*\(/g),
        // Java/Servlet: response.sendRedirect(request.getParameter(...)).
        ...scanLines(file, /response\.sendRedirect\s*\(\s*request\.getParameter\s*\(/g),
        // PHP: header("Location: " . $_GET[...]) con concatenazione, oppure
        // una variabile interpolata direttamente dentro una stringa fra
        // doppi apici (es. header("Location: $next")).
        ...scanLines(file, /header\s*\(\s*["']Location:\s*["']?\s*\.\s*\$_(GET|POST|REQUEST)/gi),
        ...scanLines(file, /header\s*\(\s*"Location:[^"]*\$_(GET|POST|REQUEST)/gi),
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
      const pythonNote = REDIRECT_REMOVED_NOTE.replace("/*", "#").replace("*/", "");
      const r3 = replaceLines(
        r2.content,
        /\b(redirect|HttpResponseRedirect)\s*\(\s*request\.(args|form|GET|POST)(?:\.\w+|\[[^\]]+\]|\.get\([^)]*\))*\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `${m[1]}("/")${pythonNote}` + line.slice(m.index + m[0].length);
        }
      );
      const goNote = REDIRECT_REMOVED_NOTE.replace("/*", "//").replace("*/", "");
      const r4 = replaceLines(
        r3.content,
        /c\.Redirect\s*\(\s*([^,]+),\s*c\.(?:Query|PostForm)\s*\([^)]*\)\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `c.Redirect(${m[1]}, "/")${goNote}` + line.slice(m.index + m[0].length);
        }
      );
      const r5 = replaceLines(
        r4.content,
        /http\.Redirect\s*\(\s*([^,]+),\s*([^,]+),\s*r\.FormValue\s*\([^)]*\)\s*,\s*([^)]+)\)/g,
        (line, m) => {
          return (
            line.slice(0, m.index) + `http.Redirect(${m[1]}, ${m[2]}, "/", ${m[3]})${goNote}` + line.slice(m.index + m[0].length)
          );
        }
      );
      // Qui, a differenza di Go, teniamo la nota come commento a blocco /* */
      // (REDIRECT_REMOVED_NOTE è già in questa forma): Java non ha
      // l'inserimento automatico di ";" come Go, quindi un commento // a fine
      // riga inghiottirebbe il punto e virgola che resta dopo la chiamata.
      const r6 = replaceLines(
        r5.content,
        /response\.sendRedirect\s*\(\s*request\.getParameter\s*\([^)]*\)\s*\)/g,
        (line, m) => {
          return line.slice(0, m.index) + `response.sendRedirect("/")${REDIRECT_REMOVED_NOTE}` + line.slice(m.index + m[0].length);
        }
      );
      // Stesso ragionamento di Java: PHP non ha l'inserimento automatico di
      // ";", quindi teniamo la nota come commento a blocco /* */.
      const r7 = replaceLines(
        r6.content,
        /header\s*\(\s*["']Location:\s*["']?\s*\.\s*\$_(?:GET|POST|REQUEST)\[[^\]]+\]\s*\)/gi,
        (line, m) => {
          return line.slice(0, m.index) + `header("Location: /")${REDIRECT_REMOVED_NOTE}` + line.slice(m.index + m[0].length);
        }
      );
      const r8 = replaceLines(
        r7.content,
        /header\s*\(\s*"Location:[^"]*\$_(?:GET|POST|REQUEST)\[[^\]]+\][^"]*"\s*\)/gi,
        (line, m) => {
          return line.slice(0, m.index) + `header("Location: /")${REDIRECT_REMOVED_NOTE}` + line.slice(m.index + m[0].length);
        }
      );
      return r1.changed ||
        r2.changed ||
        r3.changed ||
        r4.changed ||
        r5.changed ||
        r6.changed ||
        r7.changed ||
        r8.changed
        ? r8.content
        : null;
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
      const pattern =
        /\.findById\(\s*req\.params\.id\s*\)|findOne\(\s*\{\s*_id:\s*req\.params\.id\s*\}\s*\)|\.objects\.get\(\s*(pk|id)\s*=\s*request\.(GET|POST|args)\[[^\]]+\]\s*\)|get_object_or_404\([^,]+,\s*(pk|id)\s*=\s*request\.(GET|POST|args)\[[^\]]+\]\s*\)|\.(First|Find)\(\s*&\w+\s*,\s*c\.Param\(\s*["'][^"']+["']\s*\)\s*\)|\.findById\(\s*(?:\w+\.parse\w+\(\s*)?request\.getParameter\([^)]*\)\s*\)?\s*\)|\w+::find(?:OrFail)?\(\s*\$_(GET|POST|REQUEST)\[[^\]]+\]\s*\)|\w+::find(?:OrFail)?\(\s*\$request->(?:input|get)\([^)]*\)\s*\)/g;
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