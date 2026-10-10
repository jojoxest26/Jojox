import { describe, expect, it } from "vitest";
import { highChecks } from "../src/checks/high.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = highChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("high checks", () => {
  it("unprotected-new-table: flags a table with no RLS enabled in the same file", () => {
    const check = checkById("unprotected-new-table");
    const vulnerable = file(
      "migrations/001_create_invoices.sql",
      "CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);"
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("unprotected-new-table: does not flag a table that enables RLS in the same file", () => {
    const check = checkById("unprotected-new-table");
    const clean = file(
      "migrations/001_create_invoices.sql",
      "CREATE TABLE public.invoices (\n  id uuid PRIMARY KEY,\n  user_id uuid REFERENCES auth.users\n);\nALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;"
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("unprotected-new-table: ignores non-SQL files", () => {
    const check = checkById("unprotected-new-table");
    const notSql = file("migrations/001.ts", "CREATE TABLE public.invoices (id uuid PRIMARY KEY);");
    expect(detect(check, notSql)).toHaveLength(0);
  });

  it("permissive-cors: flags cors() with no origin restriction", () => {
    const check = checkById("permissive-cors");
    const vulnerable = file("src/server.ts", "app.use(cors())");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("permissive-cors: does not flag a restricted origin list", () => {
    const check = checkById("permissive-cors");
    const clean = file("src/server.ts", 'app.use(cors({ origin: ["https://tuosito.com"] }))');
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("admin-function-missing-auth: flags an admin route with no nearby auth check", () => {
    const check = checkById("admin-function-missing-auth");
    const vulnerable = file(
      "src/routes/admin.ts",
      'router.post("/admin/delete-user", async (req, res) => {\n  await db.users.delete(req.body.id)\n})'
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("admin-function-missing-auth: does not flag when requireAuth guards the route", () => {
    const check = checkById("admin-function-missing-auth");
    const clean = file(
      "src/routes/admin.ts",
      'router.post("/admin/delete-user", requireAuth, requireRole("admin"), async (req, res) => {\n  await db.users.delete(req.body.id)\n})'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("ssrf: flags an outgoing request built from user input", () => {
    const check = checkById("ssrf");
    const vulnerable = file("src/proxy.ts", "const data = await fetch(req.query.url)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("ssrf: does not flag a request to an allowlisted target", () => {
    const check = checkById("ssrf");
    const clean = file(
      "src/proxy.ts",
      'const ALLOWED = new Set(["https://api.tuoservizio.com"])\nconst target = ALLOWED.has(userUrl) ? userUrl : DEFAULT_URL\nconst data = await fetch(target)'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("weak-password-hashing: flags md5 used near password handling", () => {
    const check = checkById("weak-password-hashing");
    const vulnerable = file(
      "src/auth.ts",
      'const hashed = crypto.createHash("md5").update(password).digest("hex")'
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("weak-password-hashing: does not flag bcrypt", () => {
    const check = checkById("weak-password-hashing");
    const clean = file("src/auth.ts", "const hashed = await bcrypt.hash(password, 12)");
    expect(detect(check, clean)).toHaveLength(0);
  });

  describe("Python", () => {
    it("permissive-cors: flags Flask-CORS used with no restriction", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("app/server.py", "CORS(app)");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: flags django-cors-headers allowing all origins", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("app/settings.py", "CORS_ORIGIN_ALLOW_ALL = True");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: does not flag a restricted django-cors-headers list", () => {
      const check = checkById("permissive-cors");
      const clean = file("app/settings.py", 'CORS_ALLOWED_ORIGINS = ["https://tuosito.com"]');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("admin-function-missing-auth: flags a Flask admin route with no nearby auth decorator", () => {
      const check = checkById("admin-function-missing-auth");
      const vulnerable = file(
        "app/admin.py",
        '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    db.users.delete(request.form["id"])'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("admin-function-missing-auth: does not flag when login_required guards the route", () => {
      const check = checkById("admin-function-missing-auth");
      const clean = file(
        "app/admin.py",
        '@app.route("/admin/delete-user", methods=["POST"])\n@login_required\ndef delete_user():\n    db.users.delete(request.form["id"])'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("ssrf: flags an outgoing request built from Flask request.args", () => {
      const check = checkById("ssrf");
      const vulnerable = file("app/proxy.py", "data = requests.get(request.args['url'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: flags an outgoing request built from Django request.GET", () => {
      const check = checkById("ssrf");
      const vulnerable = file("app/views.py", "data = requests.get(request.GET['url'])");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: does not flag a request to a fixed URL", () => {
      const check = checkById("ssrf");
      const clean = file("app/proxy.py", 'data = requests.get("https://api.example.com")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing: flags hashlib.md5 used near password handling", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("app/auth.py", "hashed = hashlib.md5(password.encode()).hexdigest()");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-password-hashing: does not flag bcrypt", () => {
      const check = checkById("weak-password-hashing");
      const clean = file("app/auth.py", "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing autofix: replaces hashlib.md5 with bcrypt.hashpw, not JS bcrypt.hash", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("app/auth.py", "hashed = hashlib.md5(password).hexdigest()");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("bcrypt.hashpw(password.encode(), bcrypt.gensalt())");
      expect(fixed).not.toContain("await bcrypt.hash");
    });

    it("weak-password-hashing autofix: handles a nested call inside the argument, e.g. password.encode(), without breaking the syntax", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("app/auth.py", "hashed = hashlib.md5(password.encode()).hexdigest()");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe(
        "hashed = bcrypt.hashpw(password.encode().encode(), bcrypt.gensalt()) # JoJoX: serve il pacchetto bcrypt — pip install bcrypt.hexdigest()"
      );
      // Soprattutto: le parentesi devono restare bilanciate.
      const opens = (fixed!.match(/\(/g) ?? []).length;
      const closes = (fixed!.match(/\)/g) ?? []).length;
      expect(opens).toBe(closes);
    });
  });

  describe("Go", () => {
    it("permissive-cors: flags gin-contrib/cors used with no restriction", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("main.go", "r.Use(cors.Default())");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: flags AllowOrigins set to *", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("main.go", 'config.AllowOrigins = []string{"*"}');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: does not flag a restricted AllowOrigins list", () => {
      const check = checkById("permissive-cors");
      const clean = file("main.go", 'config.AllowOrigins = []string{"https://tuosito.com"}');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("admin-function-missing-auth: flags a Gin admin route (uppercase POST) with no nearby auth check", () => {
      const check = checkById("admin-function-missing-auth");
      const vulnerable = file(
        "main.go",
        'router.POST("/admin/delete-user", func(c *gin.Context) {\n  db.Delete(&user, c.PostForm("id"))\n})'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("admin-function-missing-auth: does not flag when MustGet (reading the authenticated user) guards the route", () => {
      const check = checkById("admin-function-missing-auth");
      const clean = file(
        "main.go",
        'router.POST("/admin/delete-user", func(c *gin.Context) {\n  user := c.MustGet("user")\n  db.Delete(&user, c.PostForm("id"))\n})'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("ssrf: flags http.Get built from a Gin query parameter", () => {
      const check = checkById("ssrf");
      const vulnerable = file("main.go", 'resp, _ := http.Get(c.Query("url"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: flags http.Get built from a net/http form value", () => {
      const check = checkById("ssrf");
      const vulnerable = file("main.go", 'resp, _ := http.Get(r.FormValue("url"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: does not flag a request to a fixed URL", () => {
      const check = checkById("ssrf");
      const clean = file("main.go", 'resp, _ := http.Get("https://api.example.com")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing: flags crypto/md5's Sum used near password handling", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("main.go", "hashed := md5.Sum([]byte(password))");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-password-hashing: does not flag bcrypt", () => {
      const check = checkById("weak-password-hashing");
      const clean = file("main.go", "hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing autofix: replaces md5.Sum with bcrypt.GenerateFromPassword, not JS/Python bcrypt", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("main.go", "hashed := md5.Sum([]byte(password))");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("bcrypt.GenerateFromPassword([]byte([]byte(password)), bcrypt.DefaultCost)");
      expect(fixed).not.toContain("await bcrypt.hash");
      expect(fixed).not.toContain("hashpw");
    });
  });

  describe("Java", () => {
    it("permissive-cors: flags a bare @CrossOrigin with no restriction", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("AdminController.java", "@CrossOrigin\npublic class AdminController {}");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: flags origins set to *", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("AdminController.java", '@CrossOrigin(origins = "*")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: does not flag a restricted origins list", () => {
      const check = checkById("permissive-cors");
      const clean = file("AdminController.java", '@CrossOrigin(origins = "https://tuosito.com")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("admin-function-missing-auth: flags a Spring @PostMapping admin route with no nearby auth check", () => {
      const check = checkById("admin-function-missing-auth");
      const vulnerable = file(
        "AdminController.java",
        '@PostMapping("/admin/delete-user")\npublic void deleteUser(@RequestParam String id) {\n  userRepository.deleteById(id);\n}'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("admin-function-missing-auth: does not flag when @PreAuthorize guards the route", () => {
      const check = checkById("admin-function-missing-auth");
      const clean = file(
        "AdminController.java",
        '@PostMapping("/admin/delete-user")\n@PreAuthorize("hasRole(\'ADMIN\')")\npublic void deleteUser(@RequestParam String id) {\n  userRepository.deleteById(id);\n}'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("ssrf: flags RestTemplate built from request.getParameter", () => {
      const check = checkById("ssrf");
      const vulnerable = file("ProxyController.java", 'String data = restTemplate.getForObject(request.getParameter("url"), String.class);');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: flags a new URL(...) built from request.getParameter", () => {
      const check = checkById("ssrf");
      const vulnerable = file("ProxyController.java", 'URL target = new URL(request.getParameter("url"));');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: does not flag a request to a fixed URL", () => {
      const check = checkById("ssrf");
      const clean = file("ProxyController.java", 'String data = restTemplate.getForObject("https://api.example.com", String.class);');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing: flags MessageDigest MD5 used near password handling", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("AuthService.java", "byte[] hashed = MessageDigest.getInstance(\"MD5\").digest(password.getBytes());");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-password-hashing: does not flag BCrypt", () => {
      const check = checkById("weak-password-hashing");
      const clean = file("AuthService.java", "String hashed = BCrypt.hashpw(password, BCrypt.gensalt());");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing autofix: replaces MessageDigest.getInstance(\"MD5\") with BCrypt.hashpw, not JS/Python/Go bcrypt", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("AuthService.java", "byte[] hashed = MessageDigest.getInstance(\"MD5\").digest(password.getBytes());");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("BCrypt.hashpw(password.getBytes(), BCrypt.gensalt())");
      expect(fixed).not.toContain("await bcrypt.hash");
      expect(fixed).not.toContain("GenerateFromPassword");
      const opens = (fixed!.match(/\(/g) ?? []).length;
      const closes = (fixed!.match(/\)/g) ?? []).length;
      expect(opens).toBe(closes);
    });
  });

  describe("PHP", () => {
    it("permissive-cors: flags a raw Access-Control-Allow-Origin header set to *", () => {
      const check = checkById("permissive-cors");
      const vulnerable = file("api.php", 'header("Access-Control-Allow-Origin: *");');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("permissive-cors: does not flag a restricted origin header", () => {
      const check = checkById("permissive-cors");
      const clean = file("api.php", 'header("Access-Control-Allow-Origin: https://tuosito.com");');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("admin-function-missing-auth: flags a Laravel Route::post admin route with no nearby auth check", () => {
      const check = checkById("admin-function-missing-auth");
      const vulnerable = file(
        "routes/web.php",
        "Route::post('/admin/delete-user', function (Request $request) {\n  User::destroy($request->input('id'));\n});"
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("admin-function-missing-auth: does not flag when the auth middleware guards the route", () => {
      const check = checkById("admin-function-missing-auth");
      const clean = file(
        "routes/web.php",
        "Route::post('/admin/delete-user', function (Request $request) {\n  User::destroy($request->input('id'));\n})->middleware('auth');"
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("ssrf: flags file_get_contents built from $_GET", () => {
      const check = checkById("ssrf");
      const vulnerable = file("proxy.php", "$data = file_get_contents($_GET['url']);");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: flags a cURL request with CURLOPT_URL built from $_GET", () => {
      const check = checkById("ssrf");
      const vulnerable = file("proxy.php", "curl_setopt($ch, CURLOPT_URL, $_GET['url']);");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ssrf: does not flag a request to a fixed URL", () => {
      const check = checkById("ssrf");
      const clean = file("proxy.php", '$data = file_get_contents("https://api.example.com");');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing: flags a bare md5($password) call", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("auth.php", "$hashed = md5($password);");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-password-hashing: does not flag password_hash", () => {
      const check = checkById("weak-password-hashing");
      const clean = file("auth.php", "$hashed = password_hash($password, PASSWORD_BCRYPT);");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-password-hashing autofix: replaces md5($password) with password_hash, not bcrypt/BCrypt, with no install note", () => {
      const check = checkById("weak-password-hashing");
      const vulnerable = file("auth.php", "$hashed = md5($password);");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe("$hashed = password_hash($password, PASSWORD_BCRYPT);");
    });
  });

  describe("Fase 2 — IaC (Kubernetes)", () => {
    const k8s = (body: string) => file("deployment.yaml", `apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n${body}`);

    it("k8s-run-as-root: flags runAsUser: 0", () => {
      const check = checkById("k8s-run-as-root");
      const vulnerable = k8s("      containers:\n        - name: app\n          securityContext:\n            runAsUser: 0\n");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("k8s-run-as-root: flags runAsNonRoot: false", () => {
      const check = checkById("k8s-run-as-root");
      const vulnerable = k8s("      containers:\n        - name: app\n          securityContext:\n            runAsNonRoot: false\n");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("k8s-run-as-root: does not flag runAsUser: 1000", () => {
      const check = checkById("k8s-run-as-root");
      const clean = k8s("      containers:\n        - name: app\n          securityContext:\n            runAsUser: 1000\n");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("k8s-privilege-escalation: flags allowPrivilegeEscalation: true", () => {
      const check = checkById("k8s-privilege-escalation");
      const vulnerable = k8s("      containers:\n        - name: app\n          securityContext:\n            allowPrivilegeEscalation: true\n");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("k8s-privilege-escalation: does not flag allowPrivilegeEscalation: false", () => {
      const check = checkById("k8s-privilege-escalation");
      const clean = k8s("      containers:\n        - name: app\n          securityContext:\n            allowPrivilegeEscalation: false\n");
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("k8s-privilege-escalation autofix: flips true to false", () => {
      const check = checkById("k8s-privilege-escalation");
      const vulnerable = k8s("      containers:\n        - name: app\n          securityContext:\n            allowPrivilegeEscalation: true\n");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("allowPrivilegeEscalation: false");
    });

    it("k8s-host-namespace-access: flags hostNetwork: true", () => {
      const check = checkById("k8s-host-namespace-access");
      const vulnerable = k8s("      hostNetwork: true\n      containers:\n        - name: app\n");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("k8s-host-namespace-access: flags hostPID and hostIPC too", () => {
      const check = checkById("k8s-host-namespace-access");
      const vulnerable = k8s("      hostPID: true\n      hostIPC: true\n      containers:\n        - name: app\n");
      expect(detect(check, vulnerable)).toHaveLength(2);
    });

    it("k8s-host-namespace-access: does not flag hostNetwork: false", () => {
      const check = checkById("k8s-host-namespace-access");
      const clean = k8s("      hostNetwork: false\n      containers:\n        - name: app\n");
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Fase 2 — IaC (Terraform)", () => {
    it("terraform-s3-block-public-access-disabled: flags block_public_acls = false", () => {
      const check = checkById("terraform-s3-block-public-access-disabled");
      const vulnerable = file("main.tf", 'resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}\n');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("terraform-s3-block-public-access-disabled: does not flag when all four flags are true", () => {
      const check = checkById("terraform-s3-block-public-access-disabled");
      const clean = file(
        "main.tf",
        'resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}\n'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("terraform-s3-block-public-access-disabled autofix: flips false to true", () => {
      const check = checkById("terraform-s3-block-public-access-disabled");
      const vulnerable = file("main.tf", 'resource "aws_s3_bucket_public_access_block" "example" {\n  block_public_acls = false\n}\n');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("block_public_acls = true");
    });

    it("terraform-iam-wildcard-policy: flags a statement with actions and resources both wildcard", () => {
      const check = checkById("terraform-iam-wildcard-policy");
      const vulnerable = file(
        "main.tf",
        'data "aws_iam_policy_document" "admin" {\n  statement {\n    effect    = "Allow"\n    actions   = ["*"]\n    resources = ["*"]\n  }\n}\n'
      );
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("terraform-iam-wildcard-policy: does not flag a statement scoped to specific actions/resources", () => {
      const check = checkById("terraform-iam-wildcard-policy");
      const clean = file(
        "main.tf",
        'data "aws_iam_policy_document" "readonly" {\n  statement {\n    effect    = "Allow"\n    actions   = ["s3:GetObject"]\n    resources = ["arn:aws:s3:::my-bucket/*"]\n  }\n}\n'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("terraform-iam-wildcard-policy: does not flag a wildcard action alone without a wildcard resource nearby", () => {
      const check = checkById("terraform-iam-wildcard-policy");
      const clean = file(
        "main.tf",
        'data "aws_iam_policy_document" "x" {\n  statement {\n    actions   = ["*"]\n    resources = ["arn:aws:s3:::my-bucket/*"]\n  }\n}\n'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Nuovo blocco — token generati con RNG debole", () => {
    it("weak-random-token: flags a reset token built with Math.random()", () => {
      const check = checkById("weak-random-token");
      const vulnerable = file("auth.ts", "const resetToken = Math.random().toString(36).slice(2);");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-random-token: flags a Python session id built with random.random()", () => {
      const check = checkById("weak-random-token");
      const vulnerable = file("auth.py", "session_id = str(random.random())");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-random-token: flags a PHP csrf token built with rand()", () => {
      const check = checkById("weak-random-token");
      const vulnerable = file("auth.php", "$csrfToken = rand();");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("weak-random-token: does not flag a token built with crypto.randomBytes", () => {
      const check = checkById("weak-random-token");
      const clean = file("auth.ts", 'const resetToken = crypto.randomBytes(32).toString("hex");');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("weak-random-token: does not flag Math.random() used for something that isn't security-sensitive", () => {
      const check = checkById("weak-random-token");
      const clean = file("ui.ts", "const shuffleSeed = Math.random();");
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Nuovo blocco — LDAP injection", () => {
    it("ldap-injection: flags a filter built with a template literal including req.body", () => {
      const check = checkById("ldap-injection");
      const vulnerable = file("auth.ts", "const filter = `(uid=${req.body.username})`;");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("ldap-injection: does not flag a filter built from a fixed, non-request value", () => {
      const check = checkById("ldap-injection");
      const clean = file("auth.ts", 'const filter = `(uid=${username})`;');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("ldap-injection: does not flag req.body used outside an LDAP filter", () => {
      const check = checkById("ldap-injection");
      const clean = file("auth.ts", "const name = `${req.body.username}`;");
      expect(detect(check, clean)).toHaveLength(0);
    });
  });
});