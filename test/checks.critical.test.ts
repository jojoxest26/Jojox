import { describe, expect, it } from "vitest";
import { criticalChecks } from "../src/checks/critical.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = criticalChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("critical checks", () => {
  it("supabase-service-role-in-client: flags a public env var referencing the service role key in client code", () => {
    const check = checkById("supabase-service-role-in-client");
    const vulnerable = file(
      "src/components/Dashboard.tsx",
      "const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)"
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("supabase-service-role-in-client: does not flag the server-only usage", () => {
    const check = checkById("supabase-service-role-in-client");
    const clean = file(
      "src/api/admin/route.ts",
      "const supabase = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)"
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("supabase-service-role-in-client: does not flag an empty placeholder in .env.example", () => {
    const check = checkById("supabase-service-role-in-client");
    const clean = file(".env.example", "SUPABASE_SERVICE_ROLE_KEY=");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("hardcoded-secret: flags a literal Stripe secret key", () => {
    const check = checkById("hardcoded-secret");
    const vulnerable = file("src/payments.ts", 'const apiKey = "sk_live_51H8x9K2eZvKYlo2Cxxxxxxxxxxxxxxxx"');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("hardcoded-secret: does not flag a value read from process.env", () => {
    const check = checkById("hardcoded-secret");
    const clean = file("src/payments.ts", "const apiKey = process.env.STRIPE_SECRET_KEY");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("hardcoded-secret: flags other common secret-like variable names", () => {
    const check = checkById("hardcoded-secret");
    const names = ["clientSecret", "accessToken", "refreshToken", "privateKey", "dbPassword", "apiSecret"];
    for (const name of names) {
      const vulnerable = file("src/config.ts", `const ${name} = "abcdefghijklmnop123456"`);
      expect(detect(check, vulnerable), `expected ${name} to be flagged`).toHaveLength(1);
    }
  });

  it("hardcoded-secret autofix: replaces a hardcoded clientSecret with process.env, converted to SCREAMING_SNAKE_CASE", () => {
    const check = checkById("hardcoded-secret");
    const vulnerable = file("src/config.ts", 'const clientSecret = "abcdefghijklmnop123456"');
    const fixed = check.autofix?.(vulnerable);
    expect(fixed).toBe("const clientSecret = process.env.CLIENT_SECRET");
  });

  it("hardcoded-secret autofix: does not touch a value already read from process.env", () => {
    const check = checkById("hardcoded-secret");
    const clean = file("src/payments.ts", "const apiKey = process.env.STRIPE_SECRET_KEY");
    expect(check.autofix?.(clean)).toBeNull();
  });

  it("hardcoded-secret autofix: leaves format-detected keys (sk_live_…) alone — those must be revoked, not just removed", () => {
    const check = checkById("hardcoded-secret");
    const vulnerable = file("src/payments.ts", 'const apiKey = "sk_live_51H8x9K2eZvKYlo2Cxxxxxxxxxxxxxxxx"');
    expect(check.autofix?.(vulnerable)).toBeNull();
  });

  it("env-file-with-real-values: flags a committed .env with real values", () => {
    const check = checkById("env-file-with-real-values");
    const vulnerable = file(".env", "DATABASE_URL=postgres://user:realpassword@db.host/prod\nJWT_SECRET=abcdef123456");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("env-file-with-real-values: does not flag .env.example", () => {
    const check = checkById("env-file-with-real-values");
    const clean = file(".env.example", "DATABASE_URL=postgres://user:password@localhost/dev");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("missing-row-level-security: flags RLS explicitly disabled", () => {
    const check = checkById("missing-row-level-security");
    const vulnerable = file("supabase/migrations/001.sql", "ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("missing-row-level-security: does not flag a scoped policy", () => {
    const check = checkById("missing-row-level-security");
    const clean = file(
      "supabase/migrations/001.sql",
      'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "owners only" ON public.orders USING (auth.uid() = user_id);'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("sql-injection: flags a template-literal query", () => {
    const check = checkById("sql-injection");
    const vulnerable = file("src/db.ts", "db.query(`SELECT * FROM users WHERE email = '${email}'`)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("sql-injection: does not flag a parameterized query", () => {
    const check = checkById("sql-injection");
    const clean = file("src/db.ts", 'db.query("SELECT * FROM users WHERE email = $1", [email])');
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("plaintext-password-storage: flags a raw password saved without hashing anywhere in the file", () => {
    const check = checkById("plaintext-password-storage");
    const vulnerable = file("src/signup.ts", "await db.users.insert({ email, password: req.body.password })");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("plaintext-password-storage: does not flag when the file hashes the password first", () => {
    const check = checkById("plaintext-password-storage");
    const clean = file(
      "src/signup.ts",
      "const hashed = await bcrypt.hash(req.body.password, 12)\nawait db.users.insert({ email, password: hashed })"
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("hardcoded-jwt-secret: flags a literal signing secret", () => {
    const check = checkById("hardcoded-jwt-secret");
    const vulnerable = file("src/auth.ts", 'jwt.sign(payload, "super-secret-key-123")');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("hardcoded-jwt-secret: does not flag a secret read from the environment", () => {
    const check = checkById("hardcoded-jwt-secret");
    const clean = file("src/auth.ts", "jwt.sign(payload, process.env.JWT_SECRET)");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("command-injection: flags an interpolated shell command", () => {
    const check = checkById("command-injection");
    const vulnerable = file("src/convert.ts", "execSync(`convert ${filename} output.png`)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("command-injection: does not flag execFile with an argument array", () => {
    const check = checkById("command-injection");
    const clean = file("src/convert.ts", 'execFile("convert", [filename, "output.png"])');
    expect(detect(check, clean)).toHaveLength(0);
  });

  describe("Python", () => {
    it("hardcoded-secret: flags a snake_case secret, same as camelCase", () => {
      const check = checkById("hardcoded-secret");
      const vulnerable = file("app/config.py", 'api_secret = "abcdefghijklmnop123456"');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("hardcoded-secret: does not flag a value read with os.environ or os.getenv", () => {
      const check = checkById("hardcoded-secret");
      const clean1 = file("app/config.py", 'api_key = os.environ["STRIPE_SECRET_KEY"]');
      const clean2 = file("app/config.py", 'api_key = os.getenv("STRIPE_SECRET_KEY")');
      expect(detect(check, clean1)).toHaveLength(0);
      expect(detect(check, clean2)).toHaveLength(0);
    });

    it("hardcoded-secret autofix: replaces a hardcoded secret with os.environ, not process.env", () => {
      const check = checkById("hardcoded-secret");
      const vulnerable = file("app/config.py", 'client_secret = "abcdefghijklmnop123456"');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('client_secret = os.environ["CLIENT_SECRET"]');
    });

    it("sql-injection: flags an f-string query", () => {
      const check = checkById("sql-injection");
      const vulnerable = file("app/db.py", 'cursor.execute(f"SELECT * FROM users WHERE email = \'{email}\'")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sql-injection: flags string concatenation (same syntax as JS)", () => {
      const check = checkById("sql-injection");
      const vulnerable = file("app/db.py", 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sql-injection: does not flag a parameterized query", () => {
      const check = checkById("sql-injection");
      const clean = file("app/db.py", 'cursor.execute("SELECT * FROM users WHERE email = %s", (email,))');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("plaintext-password-storage: flags a Flask request.form password stored without hashing", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("app/signup.py", "user.password = request.form['password']");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("plaintext-password-storage: flags a Django request.POST password stored without hashing", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("app/views.py", "user.password = request.POST['password']");
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("plaintext-password-storage: does not flag when the file already hashes with werkzeug/passlib/bcrypt", () => {
      const check = checkById("plaintext-password-storage");
      const clean = file(
        "app/signup.py",
        "from werkzeug.security import generate_password_hash\nuser.password = generate_password_hash(request.form['password'])"
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("plaintext-password-storage autofix: wraps the raw value in bcrypt.hashpw", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("app/signup.py", "user.password = request.form['password']");
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain("bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())");
    });

    it("hardcoded-jwt-secret: flags a literal secret passed to PyJWT's encode/decode", () => {
      const check = checkById("hardcoded-jwt-secret");
      const vulnerable = file("app/auth.py", 'jwt.encode(payload, "super-secret-key-123", algorithm="HS256")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("hardcoded-jwt-secret: does not flag a secret read from os.environ", () => {
      const check = checkById("hardcoded-jwt-secret");
      const clean = file("app/auth.py", 'jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("hardcoded-jwt-secret autofix: replaces the literal with os.environ, not process.env", () => {
      const check = checkById("hardcoded-jwt-secret");
      const vulnerable = file("app/auth.py", 'jwt.encode(payload, "super-secret-key-123")');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('jwt.encode(payload, os.environ["JWT_SECRET"])');
    });

    it("command-injection: flags os.system with an interpolated f-string", () => {
      const check = checkById("command-injection");
      const vulnerable = file("app/convert.py", 'os.system(f"convert {filename} output.png")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("command-injection: flags subprocess.run with shell=True and string concatenation", () => {
      const check = checkById("command-injection");
      const vulnerable = file("app/convert.py", 'subprocess.run("convert " + filename, shell=True)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("command-injection: does not flag subprocess.run with an argument list (shell=False, the default)", () => {
      const check = checkById("command-injection");
      const clean = file("app/convert.py", 'subprocess.run(["convert", filename, "output.png"])');
      expect(detect(check, clean)).toHaveLength(0);
    });
  });

  describe("Go", () => {
    it("hardcoded-secret: flags a PascalCase secret (case-insensitive, same pattern as camelCase)", () => {
      const check = checkById("hardcoded-secret");
      const vulnerable = file("main.go", 'ApiSecret := "abcdefghijklmnop123456"');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("hardcoded-secret: does not flag a value read with os.Getenv", () => {
      const check = checkById("hardcoded-secret");
      const clean = file("main.go", 'apiKey := os.Getenv("STRIPE_SECRET_KEY")');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("hardcoded-secret autofix: replaces a hardcoded secret with os.Getenv, turning := into = (no longer a new declaration)", () => {
      const check = checkById("hardcoded-secret");
      const vulnerable = file("main.go", 'clientSecret := "abcdefghijklmnop123456"');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('clientSecret = os.Getenv("CLIENT_SECRET")');
    });

    it("sql-injection: flags a query built with fmt.Sprintf", () => {
      const check = checkById("sql-injection");
      const vulnerable = file("main.go", 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE email = \'%s\'", email))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("sql-injection: does not flag a parameterized query", () => {
      const check = checkById("sql-injection");
      const clean = file("main.go", 'db.Query("SELECT * FROM users WHERE email = $1", email)');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("plaintext-password-storage: flags a Gin c.PostForm password stored without hashing", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("main.go", 'user.Password = c.PostForm("password")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("plaintext-password-storage: flags a net/http r.FormValue password stored without hashing", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("main.go", 'user.Password = r.FormValue("password")');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("plaintext-password-storage: does not flag when the file already uses bcrypt", () => {
      const check = checkById("plaintext-password-storage");
      const clean = file(
        "main.go",
        'hashed, _ := bcrypt.GenerateFromPassword([]byte(c.PostForm("password")), bcrypt.DefaultCost)\nuser.Password = string(hashed)'
      );
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("plaintext-password-storage autofix: wraps the raw value in bcrypt.GenerateFromPassword, not JS/Python bcrypt", () => {
      const check = checkById("plaintext-password-storage");
      const vulnerable = file("main.go", 'user.Password = c.PostForm("password")');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toContain('bcrypt.GenerateFromPassword([]byte(c.PostForm("password")), bcrypt.DefaultCost)');
    });

    it("hardcoded-jwt-secret: flags a literal secret passed to golang-jwt's SignedString", () => {
      const check = checkById("hardcoded-jwt-secret");
      const vulnerable = file("main.go", 'tokenString, _ := token.SignedString([]byte("super-secret-key-123"))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("hardcoded-jwt-secret: does not flag a secret read from os.Getenv", () => {
      const check = checkById("hardcoded-jwt-secret");
      const clean = file("main.go", 'tokenString, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))');
      expect(detect(check, clean)).toHaveLength(0);
    });

    it("hardcoded-jwt-secret autofix: replaces the literal with os.Getenv, not process.env or os.environ", () => {
      const check = checkById("hardcoded-jwt-secret");
      const vulnerable = file("main.go", 'tokenString, _ := token.SignedString([]byte("super-secret-key-123"))');
      const fixed = check.autofix?.(vulnerable);
      expect(fixed).toBe('tokenString, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))');
    });

    it("command-injection: flags exec.Command invoking a shell with fmt.Sprintf", () => {
      const check = checkById("command-injection");
      const vulnerable = file("main.go", 'exec.Command("sh", "-c", fmt.Sprintf("convert %s output.png", filename))');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("command-injection: flags exec.Command invoking a shell with string concatenation", () => {
      const check = checkById("command-injection");
      const vulnerable = file("main.go", 'exec.Command("bash", "-c", "rm -rf " + path)');
      expect(detect(check, vulnerable)).toHaveLength(1);
    });

    it("command-injection: does not flag exec.Command with separate arguments (no shell involved)", () => {
      const check = checkById("command-injection");
      const clean = file("main.go", 'exec.Command("convert", filename, "output.png")');
      expect(detect(check, clean)).toHaveLength(0);
    });
  });
});