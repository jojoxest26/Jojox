import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { verifyStripeSignature } from "../../src/server/stripe/verifySignature.js";

const SECRET = "whsec_test";

function sign(payload: string, secret = SECRET, timestamp = Math.floor(Date.now() / 1000)): string {
  const signature = createHmac("sha256", secret).update(`${timestamp}.${payload}`).digest("hex");
  return `t=${timestamp},v1=${signature}`;
}

describe("verifyStripeSignature", () => {
  it("accepts a correctly signed payload", () => {
    const payload = JSON.stringify({ type: "customer.subscription.updated" });
    expect(verifyStripeSignature(payload, sign(payload), SECRET)).toBe(true);
  });

  it("rejects a payload signed with the wrong secret", () => {
    const payload = JSON.stringify({ type: "customer.subscription.updated" });
    expect(verifyStripeSignature(payload, sign(payload, "whsec_wrong"), SECRET)).toBe(false);
  });

  it("rejects a tampered payload", () => {
    const original = JSON.stringify({ type: "customer.subscription.updated" });
    const signature = sign(original);
    const tampered = JSON.stringify({ type: "customer.subscription.deleted" });
    expect(verifyStripeSignature(tampered, signature, SECRET)).toBe(false);
  });

  it("rejects a missing signature header", () => {
    expect(verifyStripeSignature("{}", undefined, SECRET)).toBe(false);
  });

  it("rejects a malformed signature without throwing", () => {
    expect(verifyStripeSignature("{}", "not-a-real-signature", SECRET)).toBe(false);
  });

  it("rejects a timestamp far in the past (replay protection)", () => {
    const payload = JSON.stringify({ type: "customer.subscription.updated" });
    const oldTimestamp = Math.floor(Date.now() / 1000) - 3600;
    expect(verifyStripeSignature(payload, sign(payload, SECRET, oldTimestamp), SECRET)).toBe(false);
  });
});