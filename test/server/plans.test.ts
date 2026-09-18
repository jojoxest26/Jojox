import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

async function loadPlans() {
  vi.resetModules();
  return import("../../src/server/stripe/plans.js");
}

describe("stripe plans: priceIdForPlan / planForPriceId", () => {
  beforeEach(() => {
    vi.stubEnv("STRIPE_PRICE_ID_PRO", "price_pro_monthly");
    vi.stubEnv("STRIPE_PRICE_ID_TEAM", "price_team_monthly");
    vi.stubEnv("STRIPE_PRICE_ID_PRO_ANNUAL", "price_pro_annual");
    vi.stubEnv("STRIPE_PRICE_ID_TEAM_ANNUAL", "price_team_annual");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns the monthly price id by default", async () => {
    const { priceIdForPlan } = await loadPlans();
    expect(priceIdForPlan("pro")).toBe("price_pro_monthly");
    expect(priceIdForPlan("team")).toBe("price_team_monthly");
  });

  it("returns the monthly price id when explicitly requested", async () => {
    const { priceIdForPlan } = await loadPlans();
    expect(priceIdForPlan("pro", "monthly")).toBe("price_pro_monthly");
    expect(priceIdForPlan("team", "monthly")).toBe("price_team_monthly");
  });

  it("returns the annual price id when requested", async () => {
    const { priceIdForPlan } = await loadPlans();
    expect(priceIdForPlan("pro", "annual")).toBe("price_pro_annual");
    expect(priceIdForPlan("team", "annual")).toBe("price_team_annual");
  });

  it("returns null for the annual price when it isn't configured", async () => {
    vi.unstubAllEnvs();
    vi.stubEnv("STRIPE_PRICE_ID_PRO", "price_pro_monthly");
    vi.stubEnv("STRIPE_PRICE_ID_TEAM", "price_team_monthly");
    const { priceIdForPlan } = await loadPlans();
    expect(priceIdForPlan("pro", "annual")).toBeNull();
  });

  it("recognizes a plan from its monthly price id", async () => {
    const { planForPriceId } = await loadPlans();
    expect(planForPriceId("price_pro_monthly")).toBe("pro");
    expect(planForPriceId("price_team_monthly")).toBe("team");
  });

  it("recognizes a plan from its annual price id", async () => {
    const { planForPriceId } = await loadPlans();
    expect(planForPriceId("price_pro_annual")).toBe("pro");
    expect(planForPriceId("price_team_annual")).toBe("team");
  });

  it("returns null for an unrecognized price id", async () => {
    const { planForPriceId } = await loadPlans();
    expect(planForPriceId("price_totally_unknown")).toBeNull();
  });
});