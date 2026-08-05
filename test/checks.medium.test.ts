import { describe, expect, it } from "vitest";
import { mediumChecks } from "../src/checks/medium.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = mediumChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("medium checks", () => {
  it("xss-dangerous-html: flags dangerouslySetInnerHTML", () => {
    const check = checkById("xss-dangerous-html");
    const vulnerable = file(
      "src/Comment.tsx",
      "<div dangerouslySetInnerHTML={{ __html: comment.text }} />"
    );
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("xss-dangerous-html: does not flag plain JSX text content", () => {
    const check = checkById("xss-dangerous-html");
    const clean = file("src/Comment.tsx", "<div>{comment.text}</div>");
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("public-storage-bucket: flags a bucket created as public", () => {
    const check = checkById("public-storage-bucket");
    const vulnerable = file("src/storage.ts", 'supabase.storage.createBucket("uploads", { public: true })');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("public-storage-bucket: does not flag a private bucket", () => {
    const check = checkById("public-storage-bucket");
    const clean = file("src/storage.ts", 'supabase.storage.createBucket("uploads", { public: false })');
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("csrf-state-changing-get: flags a GET route that deletes data", () => {
    const check = checkById("csrf-state-changing-get");
    const vulnerable = file("src/routes/posts.ts", 'router.get("/posts/:id/delete", deletePost)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("csrf-state-changing-get: does not flag a POST route", () => {
    const check = checkById("csrf-state-changing-get");
    const clean = file(
      "src/routes/posts.ts",
      'router.post("/posts/:id/delete", requireAuth, csrfProtection, deletePost)'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("insecure-token-storage: flags a token saved to localStorage", () => {
    const check = checkById("insecure-token-storage");
    const vulnerable = file("src/auth.ts", 'localStorage.setItem("authToken", token)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("insecure-token-storage: does not flag an httpOnly cookie", () => {
    const check = checkById("insecure-token-storage");
    const clean = file(
      "src/auth.ts",
      'res.cookie("authToken", token, { httpOnly: true, secure: true, sameSite: "strict" })'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("open-redirect: flags a redirect built from unsanitized query input", () => {
    const check = checkById("open-redirect");
    const vulnerable = file("src/routes/auth.ts", "res.redirect(req.query.next)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("open-redirect: does not flag a redirect validated against an allowlist", () => {
    const check = checkById("open-redirect");
    const clean = file(
      "src/routes/auth.ts",
      'const ALLOWED = new Set(["/dashboard", "/profile"])\nres.redirect(ALLOWED.has(req.query.next) ? req.query.next : "/dashboard")'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("idor: flags a lookup by params.id with no ownership check nearby", () => {
    const check = checkById("idor");
    const vulnerable = file("src/routes/orders.ts", "const order = await Order.findById(req.params.id)");
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("idor: does not flag when an ownership check follows the lookup", () => {
    const check = checkById("idor");
    const clean = file(
      "src/routes/orders.ts",
      'const order = await Order.findById(req.params.id)\nif (order.userId !== req.user.id) throw new Error("Forbidden")'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });
});
