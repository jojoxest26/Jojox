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
});
