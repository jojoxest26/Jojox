import { describe, expect, it } from "vitest";
import { computeScore, summarizeBySeverity } from "../src/scoring.js";
import type { Finding } from "../src/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    checkId: "test-check",
    severity: "medium",
    confidence: "confirmed",
    title: "t",
    description: "d",
    file: "src/x.ts",
    line: 1,
    snippet: "…",
    fix: { before: "", after: "" },
    ...overrides,
  };
}

describe("computeScore", () => {
  it("returns 100 for no findings", () => {
    expect(computeScore([])).toBe(100);
  });

  it("subtracts the base weight for a single critical finding", () => {
    const score = computeScore([makeFinding({ severity: "critical" })]);
    expect(score).toBe(75); // 100 - 25
  });

  it("gives diminishing returns for repeated occurrences of the same check", () => {
    const oneOccurrence = computeScore([makeFinding({ checkId: "a", severity: "high" })]);
    const twoOccurrences = computeScore([
      makeFinding({ checkId: "a", severity: "high" }),
      makeFinding({ checkId: "a", severity: "high" }),
    ]);
    const tenOccurrences = computeScore(
      Array.from({ length: 10 }, () => makeFinding({ checkId: "a", severity: "high" }))
    );

    const firstDrop = 100 - oneOccurrence;
    const secondDrop = oneOccurrence - twoOccurrences;
    expect(secondDrop).toBeLessThan(firstDrop);
    // even with many occurrences of the same check, the deduction stays bounded
    expect(100 - tenOccurrences).toBeLessThan(2 * firstDrop + 1);
  });

  it("never goes below 0", () => {
    const manyFindings = Array.from({ length: 20 }, (_, i) =>
      makeFinding({ checkId: `check-${i}`, severity: "critical" })
    );
    expect(computeScore(manyFindings)).toBe(0);
  });

  it("never exceeds 100", () => {
    expect(computeScore([])).toBeLessThanOrEqual(100);
  });
});

describe("summarizeBySeverity", () => {
  it("counts findings per severity, including zero counts", () => {
    const summary = summarizeBySeverity([
      makeFinding({ severity: "critical" }),
      makeFinding({ severity: "critical" }),
      makeFinding({ severity: "low" }),
    ]);
    expect(summary).toEqual({ critical: 2, high: 0, medium: 0, low: 1 });
  });
});
