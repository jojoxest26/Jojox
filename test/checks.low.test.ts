import { describe, expect, it } from "vitest";
import { lowChecks } from "../src/checks/low.js";
import { detect, file } from "./helpers.js";

const checkById = (id: string) => {
  const check = lowChecks.find((c) => c.id === id);
  if (!check) throw new Error(`check not found: ${id}`);
  return check;
};

describe("low checks", () => {
  it("no-login-rate-limit: flags a login route with no rate limiter in the file", () => {
    const check = checkById("no-login-rate-limit");
    const vulnerable = file("src/routes/auth.ts", 'router.post("/login", loginHandler)');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("no-login-rate-limit: does not flag a login route guarded by rate limiting", () => {
    const check = checkById("no-login-rate-limit");
    const clean = file(
      "src/routes/auth.ts",
      'import rateLimit from "express-rate-limit"\nconst loginLimiter = rateLimit({ windowMs: 900000, max: 5 })\nrouter.post("/login", loginLimiter, loginHandler)'
    );
    expect(detect(check, clean)).toHaveLength(0);
  });

  it("sensitive-data-in-logs: flags a password logged to the console", () => {
    const check = checkById("sensitive-data-in-logs");
    const vulnerable = file("src/routes/auth.ts", 'console.log("login attempt", { email, password })');
    expect(detect(check, vulnerable)).toHaveLength(1);
  });

  it("sensitive-data-in-logs: does not flag a log without sensitive fields", () => {
    const check = checkById("sensitive-data-in-logs");
    const clean = file("src/routes/auth.ts", 'console.log("login attempt", { email })');
    expect(detect(check, clean)).toHaveLength(0);
  });
});
