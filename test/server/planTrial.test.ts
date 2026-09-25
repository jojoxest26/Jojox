import { describe, expect, it } from "vitest";
import { effectivePlan } from "../../src/server/plan.js";

const NOW = new Date("2026-06-15T12:00:00Z");

describe("effectivePlan", () => {
  it("restituisce il piano pagato quando non c'è nessuna prova", () => {
    expect(effectivePlan("free", null, NOW)).toBe("free");
    expect(effectivePlan("pro", null, NOW)).toBe("pro");
  });

  it("tratta un utente free con prova ancora attiva come pro", () => {
    const future = new Date(NOW.getTime() + 24 * 60 * 60 * 1000).toISOString();
    expect(effectivePlan("free", future, NOW)).toBe("pro");
  });

  it("torna a free quando la prova è scaduta", () => {
    const past = new Date(NOW.getTime() - 24 * 60 * 60 * 1000).toISOString();
    expect(effectivePlan("free", past, NOW)).toBe("free");
  });

  it("non declassa mai un piano già pagato, prova o no", () => {
    const future = new Date(NOW.getTime() + 24 * 60 * 60 * 1000).toISOString();
    expect(effectivePlan("pro", future, NOW)).toBe("pro");
    expect(effectivePlan("team", future, NOW)).toBe("team");
  });
});