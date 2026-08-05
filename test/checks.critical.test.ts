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
});
