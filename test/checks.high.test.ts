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
});