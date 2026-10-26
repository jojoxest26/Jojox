import { afterEach, describe, expect, it, vi } from "vitest";

async function loadClient() {
  vi.resetModules();
  return import("../../src/server/stripe/client.js");
}

function mockStripeErrorResponse(status: number, error: { message: string; code?: string; param?: string }) {
  return vi.fn().mockResolvedValue({
    ok: false,
    status,
    json: () => Promise.resolve({ error }),
  } as Response);
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

describe("stripeRequest", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("throws a StripeApiError carrying Stripe's own code and param (e.g. a customer from a different account)", async () => {
    vi.stubEnv("STRIPE_SECRET_KEY", "sk_test_abc123");
    vi.stubGlobal(
      "fetch",
      mockStripeErrorResponse(404, { message: "No such customer: 'cus_abc'", code: "resource_missing", param: "customer" })
    );
    const { stripeRequest, StripeApiError } = await loadClient();

    await expect(stripeRequest("GET", "/customers/cus_abc")).rejects.toMatchObject(
      new StripeApiError("No such customer: 'cus_abc'", "resource_missing", "customer")
    );
  });
});
