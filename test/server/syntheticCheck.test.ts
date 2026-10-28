import { describe, expect, it } from "vitest";
import { diffCheckState, type CheckName, type CheckResult } from "../../src/server/syntheticCheck.js";

function ok(name: CheckName): CheckResult {
  return { name, ok: true };
}
function failing(name: CheckName, error = "boom"): CheckResult {
  return { name, ok: false, error };
}

describe("diffCheckState", () => {
  it("non segnala niente se tutto è a posto e lo era già", () => {
    const currentlyFailing = new Set<CheckName>();
    const { newlyFailing, recovered } = diffCheckState([ok("Stripe"), ok("Anthropic"), ok("GitHub")], currentlyFailing);
    expect(newlyFailing).toEqual([]);
    expect(recovered).toEqual([]);
    expect(currentlyFailing.size).toBe(0);
  });

  it("segnala un controllo che passa da ok a guasto", () => {
    const currentlyFailing = new Set<CheckName>();
    const { newlyFailing, recovered } = diffCheckState([failing("Anthropic")], currentlyFailing);
    expect(newlyFailing).toEqual([failing("Anthropic")]);
    expect(recovered).toEqual([]);
    expect(currentlyFailing.has("Anthropic")).toBe(true);
  });

  it("non manda un secondo avviso se il guasto è già noto dal giro precedente", () => {
    const currentlyFailing = new Set<CheckName>(["Anthropic"]);
    const { newlyFailing, recovered } = diffCheckState([failing("Anthropic")], currentlyFailing);
    expect(newlyFailing).toEqual([]);
    expect(recovered).toEqual([]);
    expect(currentlyFailing.has("Anthropic")).toBe(true);
  });

  it("segnala la ripresa quando un controllo guasto torna ok", () => {
    const currentlyFailing = new Set<CheckName>(["Stripe"]);
    const { newlyFailing, recovered } = diffCheckState([ok("Stripe")], currentlyFailing);
    expect(newlyFailing).toEqual([]);
    expect(recovered).toEqual([ok("Stripe")]);
    expect(currentlyFailing.has("Stripe")).toBe(false);
  });

  it("gestisce più controlli insieme, ognuno con il proprio stato", () => {
    const currentlyFailing = new Set<CheckName>(["GitHub"]);
    const { newlyFailing, recovered } = diffCheckState(
      [ok("Stripe"), failing("Anthropic"), ok("GitHub")],
      currentlyFailing
    );
    expect(newlyFailing).toEqual([failing("Anthropic")]);
    expect(recovered).toEqual([ok("GitHub")]);
    expect(currentlyFailing).toEqual(new Set(["Anthropic"]));
  });
});
