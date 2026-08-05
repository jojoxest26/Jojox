import { describe, expect, it } from "vitest";
import { checkRunConclusion, formatPrComment } from "../../src/server/github/report.js";
import type { AnalysisResult, Finding, Severity } from "../../src/types.js";

function makeFinding(severity: Severity, overrides: Partial<Finding> = {}): Finding {
  return {
    checkId: "test-check",
    severity,
    confidence: "confirmed",
    title: "Problema di esempio",
    description: "descrizione",
    file: "src/x.ts",
    line: 1,
    snippet: "…snippet…",
    fix: { before: "prima", after: "dopo" },
    ...overrides,
  };
}

function makeResult(findings: Finding[]): AnalysisResult {
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) summary[f.severity] += 1;
  return { score: 100 - findings.length * 10, findings, summary };
}

describe("checkRunConclusion", () => {
  it("succeeds when there are no findings", () => {
    expect(checkRunConclusion(makeResult([]))).toBe("success");
  });

  it("succeeds when only medium/low findings are present", () => {
    expect(checkRunConclusion(makeResult([makeFinding("medium"), makeFinding("low")]))).toBe("success");
  });

  it("fails when a critical finding is present", () => {
    expect(checkRunConclusion(makeResult([makeFinding("critical")]))).toBe("failure");
  });

  it("fails when a high finding is present, even without critical ones", () => {
    expect(checkRunConclusion(makeResult([makeFinding("high"), makeFinding("low")]))).toBe("failure");
  });
});

describe("formatPrComment", () => {
  it("reports a clean pass with no findings", () => {
    const comment = formatPrComment(makeResult([]));
    expect(comment).toContain("100/100");
    expect(comment).toContain("Nessun problema trovato");
  });

  it("groups findings by severity, most severe first", () => {
    const comment = formatPrComment(
      makeResult([makeFinding("low", { title: "problema basso" }), makeFinding("critical", { title: "problema critico" })])
    );
    const criticalIdx = comment.indexOf("Critico");
    const lowIdx = comment.indexOf("Basso");
    expect(criticalIdx).toBeGreaterThan(-1);
    expect(lowIdx).toBeGreaterThan(criticalIdx);
    expect(comment).toContain("problema critico");
    expect(comment).toContain("problema basso");
  });

  it("includes the file, line, and confidence tag for each finding", () => {
    const comment = formatPrComment(
      makeResult([makeFinding("high", { file: "src/server.ts", line: 42, confidence: "heuristic" })])
    );
    expect(comment).toContain("src/server.ts:42");
    expect(comment).toContain("da verificare");
  });
});
