import { afterEach, describe, expect, it, vi } from "vitest";

async function loadClient() {
  vi.resetModules();
  return import("../../src/server/stripe/client.js");
}

describe("requireStripeSecretKey", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns the key when it's a normal ASCII string", async () => {
    vi.stubEnv("STRIPE_SECRET_KEY", "sk_test_abc123");
    const { requireStripeSecretKey } = await loadClient();
    expect(requireStripeSecretKey()).toBe("sk_test_abc123");
  });

  it("throws StripeNotConfiguredError when the key is missing", async () => {
    vi.stubEnv("STRIPE_SECRET_KEY", "");
    const { requireStripeSecretKey, StripeNotConfiguredError } = await loadClient();
    expect(() => requireStripeSecretKey()).toThrow(StripeNotConfiguredError);
  });

  it("throws a clear, specific error when the key contains a non-ASCII masking character", async () => {
    // "•" (bullet, U+2022) — ciò che resta da un copia-incolla incompleto su Railway.
    vi.stubEnv("STRIPE_SECRET_KEY", "sk_test_•bc123");
    const { requireStripeSecretKey, StripeNotConfiguredError } = await loadClient();
    expect(() => requireStripeSecretKey()).toThrow(/carattere non valido/);
    expect(() => requireStripeSecretKey()).not.toThrow(StripeNotConfiguredError);
  });
});
