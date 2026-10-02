import type { Check, CheckMatch } from "../types.js";
import {
  scanLines,
  lineFromIndex,
  redactLine,
  replaceLines,
  isPythonFile,
  isGoFile,
  isJavaFile,
  isPhpFile,
  isKubernetesManifest,
  isTerraformFile,
  nearbyMatches,
} from "../util/scan.js";

// Fase 2, IaC: manifest Kubernetes — stessa scelta di non usare un parser
// YAML già spiegata in critical.ts, qui per i campi "meno gravi del
// privileged" ma comunque seri.
const K8S_RUN_AS_ROOT = /^\s*runAsUser:\s*0\b|^\s*runAsNonRoot:\s*false\b/gim;
const K8S_PRIVILEGE_ESCALATION = /^\s*allowPrivilegeEscalation:\s*true\b/gim;
const K8S_HOST_NAMESPACE = /^\s*(hostNetwork|hostPID|hostIPC):\s*true\b/gim;

// Fase 2, IaC: Terraform. "actions"/"resources" (array, stile HCL nativo
// aws_iam_policy_document) e "Action"/"Resource" (stile JSON/jsonencode) —
// coperti entrambi perché sono i due modi più comuni di scrivere una policy
// IAM dentro un file .tf.
const TF_ACTION_WILDCARD = /\bactions?\s*[:=]\s*(\["\*"\]|"\*")/i;
const TF_RESOURCE_WILDCARD = /\bresources?\s*[:=]\s*(\["\*"\]|"\*")/i;
const TF_PUBLIC_ACCESS_BLOCK_DISABLED =
  /\b(block_public_acls|ignore_public_acls|block_public_policy|restrict_public_buckets)\s*=\s*false\b/gi;

// JS/Express (requireAuth, req.user...), Python/Flask/Django (login_required,
// request.user.is_staff...), Go/Gin (MustGet, AuthRequired...),
// Java/Spring Security (@PreAuthorize, @Secured...) e PHP/Laravel
// (middleware('auth'), Auth::check()...) insieme — un controllo di
// autenticazione o ruolo riconoscibile in tutti e cinque i mondi.
// Case-insensitive: così la stessa lista copre sia lo stile camelCase di
// JS/Python sia il PascalCase idiomatico di Go e Java, senza doverle scrivere due volte.
const ADMIN_AUTH_KEYWORDS =
  /requireAuth|isAdmin|checkRole|verifyToken|session\.user|req\.user|assertRole|login_required|permission_required|staff_member_required|is_staff|is_superuser|request\.user\.is_authenticated|current_user|MustGet|AuthRequired|Authorization|PreAuthorize|@Secured|RolesAllowed|SecurityContextHolder|Auth::check|Auth::user|middleware\(["']auth/i;

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
        // Java/Spring: @CrossOrigin senza argomenti (o con parentesi vuote)
        // permette di default qualsiasi origine; origins="*" o
        // addAllowedOrigin("*") lo fanno esplicitamente.
        ...scanLines(file, /@CrossOrigin(?:\s*\(\s*\))?(?!\s*\()/g),
        ...scanLines(file, /origins\s*=\s*["']\*["']/g),
        ...scanLines(file, /addAllowedOrigin\s*\(\s*["']\*["']\s*\)/g),
        // PHP: l'header grezzo è scritto come stringa intera dentro header(),
        // non come coppia chiave/valore — il pattern generico sopra non la
        // riconosce perché richiede una virgoletta subito prima di "*".
        ...scanLines(file, /header\s*\(\s*["']Access-Control-Allow-Origin:\s*\*["']/gi),
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
        // Java/Spring: @GetMapping/@PostMapping/... ("/admin/...") o
        // @RequestMapping con lo stesso percorso.
        /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["'][^"']*\/admin[^"']*["']/gi,
        // PHP/Laravel: Route::get/post/put/patch/delete('/admin/...', ...).
        /Route::(?:get|post|put|patch|delete)\s*\(\s*["'][^"']*\/admin[^"']*["']/gi,
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
        // Java: RestTemplate o new URL(...) con un valore preso direttamente
        // da request.getParameter.
        ...scanLines(
          file,
          /\brestTemplate\.(getForObject|getForEntity|postForObject|exchange)\s*\(\s*request\.getParameter/gi
        ),
        ...scanLines(file, /\bnew\s+URL\s*\(\s*request\.getParameter/g),
        // PHP: file_get_contents o cURL con un valore preso direttamente da
        // $_GET/$_POST/$_REQUEST.
        ...scanLines(file, /\bfile_get_contents\s*\(\s*\$_(GET|POST|REQUEST)\[/g),
        ...scanLines(file, /CURLOPT_URL\s*,\s*\$_(GET|POST|REQUEST)\[/g),
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
      // \$?password nell'ultima alternativa copre sia la chiamata nuda di
      // JS/Python ("password") sia quella PHP, dove l'argomento ha il sigillo
      // del linguaggio ("$password").
      const pattern =
        /createHash\(\s*["'](md5|sha1)["']\s*\)|hashlib\.(md5|sha1)\s*\(|\b(md5|sha1)\.Sum\s*\(|\b(md5|sha1)\s*\(\s*\$?password|MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']\s*\)/gi;
      const lines = file.content.split("\n");
      return scanLines(file, pattern).filter((m) => /password/i.test(lines[m.line - 1] ?? ""));
    },
    autofix(file) {
      const python = isPythonFile(file);
      const go = isGoFile(file);
      const java = isJavaFile(file);
      const php = isPhpFile(file);
      // Nota a blocco /* */ per Java e PHP: a differenza di Go e JS, nessuno
      // dei due ha l'inserimento automatico di ";" — un commento // a fine
      // riga inghiottirebbe il punto e virgola che resta dopo, rompendo la
      // sintassi. Per PHP non serve menzionare un pacchetto: password_hash()
      // è nativa del linguaggio da PHP 5.5.
      const note = python
        ? " # JoJoX: serve il pacchetto bcrypt — pip install bcrypt"
        : go
          ? " // JoJoX: serve il pacchetto golang.org/x/crypto/bcrypt"
          : java
            ? " /* JoJoX: serve la libreria jBCrypt — org.mindrot:jbcrypt */"
            : php
              ? ""
              : " /* JoJoX: serve il pacchetto bcrypt — npm install bcrypt */";
      const hashCall = (value: string) =>
        python
          ? `bcrypt.hashpw(${value}.encode(), bcrypt.gensalt())`
          : go
            ? `bcrypt.GenerateFromPassword([]byte(${value}), bcrypt.DefaultCost)`
            : java
              ? `BCrypt.hashpw(${value}, BCrypt.gensalt())`
              : php
                ? `password_hash(${value}, PASSWORD_BCRYPT)`
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
      if (!result.changed) {
        // Java: MessageDigest.getInstance("MD5").digest(password.getBytes())
        // — stessa logica di md5.Sum in Go, sostituiamo solo la chiamata di
        // hashing. Nota: se l'argomento catturato include già .getBytes(),
        // jBCrypt (che vuole una String) andrà aggiustato a mano — lo stesso
        // compromesso già accettato per il doppio .encode() in Python.
        const javaDigestPattern = new RegExp(
          `MessageDigest\\.getInstance\\(\\s*["'](?:MD5|SHA-1|SHA1)["']\\s*\\)\\.digest\\((${BALANCED_ARG})\\)`,
          "gi"
        );
        result = replaceLines(file.content, javaDigestPattern, (line, m) => {
          if (!/password/i.test(line)) return null;
          return line.slice(0, m.index) + `${hashCall(m[1]!)}${note}` + line.slice(m.index + m[0].length);
        });
      }
      return result.changed ? result.content : null;
    },
  },

  {
    id: "k8s-run-as-root",
    severity: "high",
    confidence: "confirmed",
    title: "Un container del manifest Kubernetes è impostato per girare come root",
    description:
      "\"runAsUser: 0\" o \"runAsNonRoot: false\" nel securityContext impongono esplicitamente l'esecuzione come root dentro il container. Se un attaccante riesce a eseguire codice nel container (es. sfruttando una libreria vulnerabile), root dentro il container rende più facile un'eventuale fuga verso l'host o un impatto più ampio.",
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
    detect(file) {
      if (!isKubernetesManifest(file)) return [];
      return scanLines(file, K8S_RUN_AS_ROOT);
    },
    // Nessun autofix: l'UID giusto da usare dipende dall'immagine (alcune
    // hanno già un utente non-root pronto, altre no) — non possiamo
    // indovinarlo senza rischiare un pod che non si avvia più.
  },

  {
    id: "k8s-privilege-escalation",
    severity: "high",
    confidence: "confirmed",
    title: "Un container del manifest Kubernetes può ottenere più privilegi di quelli iniziali",
    description:
      "\"allowPrivilegeEscalation: true\" nel securityContext permette a un processo dentro il container di ottenere più privilegi del processo che lo ha avviato (es. tramite un binario con lo sticky bit setuid). Combinato con una vulnerabilità nell'applicazione, è un passo in più verso l'esecuzione di codice con privilegi maggiori di quelli previsti.",
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
    detect(file) {
      if (!isKubernetesManifest(file)) return [];
      return scanLines(file, K8S_PRIVILEGE_ESCALATION);
    },
    autofix(file) {
      if (!isKubernetesManifest(file)) return null;
      const { content, changed } = replaceLines(file.content, K8S_PRIVILEGE_ESCALATION, (line) =>
        line.replace(/true\b/i, "false")
      );
      return changed ? content : null;
    },
  },

  {
    id: "k8s-host-namespace-access",
    severity: "high",
    confidence: "confirmed",
    title: "Un pod del manifest Kubernetes condivide la rete, i processi o la memoria condivisa dell'host",
    description:
      "\"hostNetwork\", \"hostPID\" o \"hostIPC\" impostati a true fanno uscire il pod dal suo normale isolamento: hostNetwork espone il pod sulla rete dell'host (bypassando le policy di rete del cluster), hostPID gli dà visibilità su tutti i processi della macchina host, hostIPC gli dà accesso alla memoria condivisa dell'host. Quasi mai necessario per un'app normale — tipico solo di strumenti di sistema/monitoraggio a basso livello.",
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
    detect(file) {
      if (!isKubernetesManifest(file)) return [];
      return scanLines(file, K8S_HOST_NAMESPACE);
    },
    // Nessun autofix: a differenza di allowPrivilegeEscalation (dove "false"
    // è sempre la scelta più sicura), qui alcuni workload di sistema
    // dipendono davvero da questo accesso — disattivarlo alla cieca
    // potrebbe romperli.
  },

  {
    id: "terraform-s3-block-public-access-disabled",
    severity: "high",
    confidence: "confirmed",
    title: "Block Public Access è disattivato su un bucket S3 definito in Terraform",
    description:
      "Una o più delle quattro protezioni di \"aws_s3_bucket_public_access_block\" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) sono impostate su false. Non significa che il bucket sia già pubblico, ma toglie una rete di sicurezza che impedirebbe di renderlo pubblico per errore in futuro.",
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
    detect(file) {
      if (!isTerraformFile(file)) return [];
      return scanLines(file, TF_PUBLIC_ACCESS_BLOCK_DISABLED);
    },
    autofix(file) {
      if (!isTerraformFile(file)) return null;
      const { content, changed } = replaceLines(file.content, TF_PUBLIC_ACCESS_BLOCK_DISABLED, (line) => line.replace(/false\b/i, "true"));
      return changed ? content : null;
    },
  },

  {
    id: "terraform-iam-wildcard-policy",
    severity: "high",
    confidence: "confirmed",
    title: "Una policy IAM definita in Terraform concede accesso completo",
    description:
      "Uno statement con azione \"*\" e risorsa \"*\" concede accesso completo a ogni servizio e risorsa AWS — stesso controllo già fatto sullo stato IAM live, qui letto direttamente dal codice prima ancora di essere applicato. Può essere voluto per un ruolo di emergenza, ma va confermato: per l'uso quotidiano concedi solo i permessi davvero necessari.",
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::il-tuo-bucket/*"]\n}`,
    },
    detect(file) {
      if (!isTerraformFile(file)) return [];
      const matches: CheckMatch[] = [];
      const lines = file.content.split("\n");

      lines.forEach((lineText, idx) => {
        if (!TF_ACTION_WILDCARD.test(lineText)) return;
        if (!nearbyMatches(file, idx + 1, 5, TF_RESOURCE_WILDCARD)) return;
        matches.push({ line: idx + 1, snippet: redactLine(lineText, 0, lineText.length) });
      });

      return matches;
    },
    // Nessun autofix: non conosciamo quali permessi servano davvero al
    // progetto — restringerli alla cieca romperebbe quasi certamente
    // qualcosa che dipende da quell'accesso.
  },
];