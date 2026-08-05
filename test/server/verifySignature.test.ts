import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyGithubSignature } from "../../src/server/github/verifySignature.js";

const SECRET = "test-webhook-secret";

function sign(payload: string, secret = SECRET): string {
  return "sha256=" + createHmac("sha256", secret).update(payload).digest("hex");
}

describe("verifyGithubSignature", () => {
  it("accepts a correctly signed payload", () => {
    const payload = JSON.stringify({ action: "opened" });
    expect(verifyGithubSignature(payload, sign(payload), SECRET)).toBe(true);
  });

  it("rejects a payload signed with the wrong secret", () => {
    const payload = JSON.stringify({ action: "opened" });
    expect(verifyGithubSignature(payload, sign(payload, "wrong-secret"), SECRET)).toBe(false);
  });

  it("rejects a tampered payload", () => {
    const original = JSON.stringify({ action: "opened" });
    const signature = sign(original);
    const tampered = JSON.stringify({ action: "closed" });
    expect(verifyGithubSignature(tampered, signature, SECRET)).toBe(false);
  });

  it("rejects a missing signature header", () => {
    expect(verifyGithubSignature("{}", undefined, SECRET)).toBe(false);
  });

  it("rejects a malformed signature without throwing", () => {
    expect(verifyGithubSignature("{}", "not-a-real-signature", SECRET)).toBe(false);
  });
});
