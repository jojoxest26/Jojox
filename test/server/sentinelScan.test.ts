import { describe, expect, it } from "vitest";
import { findingKey, newFindingKeys } from "../../src/server/sentinel/scan.js";
import type { Finding } from "../../src/types.js";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    checkId: "hardcoded-secret",
    severity: "critical",
    confidence: "confirmed",
    title: "Chiave segreta nel codice",
    description: "...",
    file: "src/index.ts",
    line: 10,
    snippet: "...",
    fix: { before: "", after: "" },
    ...overrides,
  };
}

describe("findingKey", () => {
  it("combina checkId, file e riga in una chiave stabile", () => {
    expect(findingKey(finding())).toBe("hardcoded-secret:src/index.ts:10");
  });

  it("produce chiavi diverse per righe diverse dello stesso file e controllo", () => {
    expect(findingKey(finding({ line: 10 }))).not.toBe(findingKey(finding({ line: 11 })));
  });
});

describe("newFindingKeys", () => {
  it("non segnala nulla come nuovo al primo scan di un repository (nessuno stato precedente)", () => {
    expect(newFindingKeys(null, ["a:1", "b:2"])).toEqual([]);
  });

  it("segnala solo le chiavi comparse rispetto allo scan precedente", () => {
    expect(newFindingKeys(["a:1"], ["a:1", "b:2"])).toEqual(["b:2"]);
  });

  it("non segnala nulla se le chiavi sono le stesse di ieri", () => {
    expect(newFindingKeys(["a:1", "b:2"], ["a:1", "b:2"])).toEqual([]);
  });

  it("non segnala nulla se un problema è stato risolto (chiave sparita, non nuova)", () => {
    expect(newFindingKeys(["a:1", "b:2"], ["a:1"])).toEqual([]);
  });

  it("gestisce un repository ripulito del tutto", () => {
    expect(newFindingKeys(["a:1"], [])).toEqual([]);
  });
});
