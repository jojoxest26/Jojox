// Traduzioni in inglese dei 40 controlli. Il motore (src/checks/) resta
// l'unica fonte di verità per id, gravità e logica di rilevamento — qui
// traduciamo solo il testo pensato per chi legge, tenuto in un file separato
// così il motore condiviso (CLI, MCP, server) resta invariato e in italiano.
export interface CheckTranslation {
  title: string;
  description: string;
  fix: { before: string; after: string };
}

/**
 * I controlli a pattern (src/checks/) hanno un titolo e una descrizione
 * fissi per ogni checkId, qui traducibili con una semplice voce statica. I
 * controlli di Fase 2 (dipendenze, e in arrivo IaC/cloud config) generano
 * invece testo diverso ad ogni finding (nome pacchetto, versione, ID della
 * vulnerabilità...) — per questi la voce è una funzione che riceve il testo
 * italiano originale e ne deriva la versione inglese, invece di un oggetto fisso.
 */
type CheckTranslationEntry = CheckTranslation | ((original: CheckTranslation) => CheckTranslation);

/**
 * L'italiano è la lingua "nativa" del motore (src/checks/), quindi in
 * italiano restituiamo sempre il testo originale del Check/Finding così
 * com'è. In inglese, applichiamo la traduzione se esiste per quel checkId
 * — altrimenti (caso limite: id sconosciuto) restituiamo l'italiano invece
 * di mostrare un testo mancante.
 */
export function translateCheckText<T extends { title: string; description: string; fix: { before: string; after: string } }>(
  checkId: string,
  original: T,
  lang: "it" | "en"
): { title: string; description: string; fix: { before: string; after: string } } {
  if (lang === "it") return original;
  const translated = checkTranslationsEn[checkId];
  if (!translated) return original;
  return typeof translated === "function" ? translated(original) : translated;
}

export const checkTranslationsEn: Record<string, CheckTranslationEntry> = {
  "supabase-service-role-in-client": {
    title: "Supabase's secret key ends up in a browser-facing file",
    description:
      "A variable with a public prefix (e.g. NEXT_PUBLIC_, VITE_) or a client-side file references Supabase's service role key. This key bypasses Row Level Security: if it ends up in the browser bundle, anyone can read it and act as a database administrator.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (server only)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Passwords or secret keys are written directly in the code",
    description:
      "An API key, token, or password appears to be written as a literal value instead of read from an environment variable. Anyone who reads the source code (or the repository, if public) gets that secret.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "A file with the project's real passwords is among those analyzed",
    description:
      "A .env file with real values (not a .env.example) is included in the analysis. If this file ends up in a repository or a public deploy, every credential it contains is exposed.",
    fix: {
      before: `# .env (committed by mistake)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (committed)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env stays out of the repo (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Anyone can read or modify every user's data",
    description:
      "Row Level Security is disabled, or a policy allows access to anyone (USING (true)) without checking who's making the request. Every authenticated user — or even an anonymous one — can read or modify everyone else's data.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "A value entered by the user is pasted directly into a database query",
    description:
      "A SQL query is built by concatenating or interpolating a string directly instead of using parameters. If that text comes (even indirectly) from a user, it can alter the query itself — SQL injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Passwords don't seem to be protected",
    description:
      "A password field is saved exactly as it arrived in the request, and no hashing function (bcrypt, argon2, scrypt) appears in the file. If the database is compromised, every password is immediately usable.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "The secret used to sign logins is written in plain text in the code",
    description:
      "The secret passed to jwt.sign / jwt.verify (or the JWT_SECRET variable) is a literal value in the code instead of coming from an environment variable. Anyone who reads it can create valid access tokens for any user.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "The server can be forced to run external commands",
    description:
      "A function that runs system commands (exec, execSync, spawn) receives a string built by interpolation or concatenation. If part of that string comes from user input, whoever controls it can run arbitrary commands on the server.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "A new table appears to be created without protection",
    description:
      "A SQL migration creates a table but doesn't enable Row Level Security for that same table in the same file. As long as it stays this way, the table starts out with no restriction on who can read or write it.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "The site accepts requests from any other website",
    description:
      "The CORS header is set to accept requests from any origin (*), or the cors() middleware is used without restrictions. Any third-party website can call your APIs from the browser of an already-authenticated user.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "A function with admin permissions doesn't check who's using it",
    description:
      "A route or function whose name suggests admin operations doesn't contain, in the nearby lines, any authentication or role check. Anyone who knows the URL could run it.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "The site can be forced to run external code",
    description:
      "An outgoing HTTP request (fetch, axios) directly uses a value coming from a user's request as the destination URL. A malicious user can make your server call internal or arbitrary addresses — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL not allowed")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Passwords are protected with a method that's now easy to break",
    description:
      "On the same line, md5() or sha1() are applied to a value tied to a password. These algorithms are too fast to compute: an attacker with the database can try billions of passwords per second.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Text written by users could run code in the browser",
    description:
      "Content is inserted into the page as raw HTML (dangerouslySetInnerHTML, v-html, .innerHTML) instead of as plain text. If that content includes user input, it can contain scripts that run in the browser of whoever reads the page.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// or, if HTML is needed: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "The space for uploaded files is visible to anyone",
    description:
      "A storage bucket (Supabase Storage, S3) is configured as public. If it contains documents, photos, or files uploaded by users, anyone who knows — or guesses — the path can access them without authentication.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// serve files with time-limited signed URLs: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "A single link is enough to delete or change data",
    description:
      "A GET route performs an operation that changes data (the path contains delete/remove/update/edit). GET requests run just by visiting a link or loading an image from an external site — the classic stepping stone for a CSRF attack.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Login data saved in the browser isn't well protected",
    description:
      "An access token is saved in localStorage. Unlike an httpOnly cookie, any script running on the page (including a malicious one injected via XSS) can read and steal it.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// set the token as an httpOnly cookie from the server:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "The site can be used to redirect to a scam website",
    description:
      "The site redirects the user to an address taken directly from the request (query, body, params) without checking that it's a known domain. A link that looks like it points to your site can actually lead to a phishing page.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Changing a number in the address could show someone else's data",
    description:
      "A database query directly uses an identifier taken from the URL (req.params.id) without checking, in the nearby lines, that it belongs to the user making the request. Changing the id in the address could give access to another user's data — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "The login form doesn't block too many attempts in a row",
    description:
      "A login route is defined in the file, but there's no trace of rate-limiting middleware in the same file. Without a limit on attempts, an attacker can try passwords in sequence (brute force) without being slowed down.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Passwords or sensitive data end up in logs",
    description:
      "A call to console.log (or similar) includes a variable called password, token, secret, or apiKey. If these logs end up in an external service or a file, sensitive data stays exposed for much longer than necessary.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },

  // Fase 2 — dependency scanning. Nome pacchetto, versione e ID della
  // vulnerabilità (es. GHSA-...) sono lasciati invariati: sono identificatori
  // tecnici, non testo da tradurre. Lo stesso vale per il riassunto preso da
  // OSV.dev nella description: i database di vulnerabilità pubblici (CVE,
  // GHSA) sono nativamente in inglese anche quando il sito è in italiano —
  // tradurlo rischierebbe di perdere precisione tecnica, per questo resta
  // identico in entrambe le lingue.
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Vulnerable dependency:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "No fixed version known yet — consider an alternative package or follow the project's updates."
      ),
    },
  }),

  // Fase 2 — IaC (Dockerfile e Kubernetes).
  "docker-hardcoded-secret": {
    title: "A secret is written directly in an ENV or ARG instruction in the Dockerfile",
    description:
      "A variable with a name like password/secret/token/key has a literal value in an ENV or ARG instruction. Unlike a .env file (which normally doesn't end up in the image), this value gets baked into the Docker image itself — anyone who can pull it or inspect the layer history can recover it, even if the line is removed in a later version of the Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# passed with: docker build --build-arg DB_PASSWORD=*** (or, better yet,\n# a BuildKit secret mount, which never ends up in the layer history)`,
    },
  },
  "docker-missing-user": {
    title: "The Dockerfile doesn't set a non-root user",
    description:
      "No USER instruction in the Dockerfile: without one, the container runs as root. If an attacker manages to run code inside the container (e.g. by exploiting a vulnerable library), being root inside the container makes an escape to the host — or a wider impact on the surrounding system — easier.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'The Dockerfile\'s base image uses the ":latest" tag',
    description:
      'A FROM instruction explicitly uses the ":latest" tag instead of a precise version. "latest" changes over time: the same build, redone at a different moment, can get a different version of the base image — a non-reproducible build, and an unwanted update can arrive without anyone having decided it should.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "The Dockerfile downloads a remote file with ADD instead of COPY",
    description:
      "An ADD instruction with an http/https URL downloads a file from the internet during the build, with no integrity check and with the content invisible in the repository. If that URL is ever compromised, the build pulls in arbitrary content without anyone noticing just by reading the Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<expected hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "A container in the Kubernetes manifest runs as privileged",
    description:
      '"privileged: true" in a container\'s securityContext disables almost all the usual isolation between container and host: the container can access the host\'s devices, change its network configuration, and in many cases effectively gain root access to the machine running it. Almost never needed for a normal app.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # only the capabilities actually needed`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "A secret is written in plain text in a Kubernetes manifest's env variable",
    description:
      'An environment variable with a name like password/secret/token/key has a literal value ("value:") instead of being read from a Secret ("valueFrom.secretKeyRef"). The manifest itself — often committed to a repository — therefore contains the secret in plain text, visible even to someone who can only read the configuration, not necessarily run commands in the cluster.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "A container in the Kubernetes manifest is set to run as root",
    description:
      '"runAsUser: 0" or "runAsNonRoot: false" in the securityContext explicitly force the container to run as root. If an attacker manages to run code inside the container (e.g. by exploiting a vulnerable library), being root inside the container makes an escape to the host — or a wider impact — easier.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "A container in the Kubernetes manifest can gain more privileges than it started with",
    description:
      '"allowPrivilegeEscalation: true" in the securityContext lets a process inside the container gain more privileges than the process that started it (e.g. through a setuid binary). Combined with a vulnerability in the application, it\'s one more step toward running code with more privileges than intended.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "A pod in the Kubernetes manifest shares the host's network, processes, or shared memory",
    description:
      '"hostNetwork", "hostPID" or "hostIPC" set to true take the pod out of its normal isolation: hostNetwork exposes the pod on the host\'s network (bypassing the cluster\'s network policies), hostPID gives it visibility into every process on the host machine, hostIPC gives it access to the host\'s shared memory. Almost never needed for a normal app — typically only for low-level system/monitoring tools.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "The Kubernetes manifest doesn't explicitly enforce running as a non-root user",
    description:
      'No "runAsNonRoot" anywhere in the manifest (neither at pod nor at container level): without setting it, a container runs as whatever user its image defines — often root by default, if the image itself hasn\'t changed that. Setting it explicitly to true makes the pod fail to start if the image still tries to run as root, instead of only finding out after an incident.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
};