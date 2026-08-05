import { describe, expect, it } from "vitest";
import { analyzeFiles, ALL_CHECKS } from "../src/analyze.js";

describe("analyzeFiles", () => {
  it("registers exactly 21 checks across the 4 severities", () => {
    expect(ALL_CHECKS).toHaveLength(21);
    const bySeverity = ALL_CHECKS.reduce<Record<string, number>>((acc, c) => {
      acc[c.severity] = (acc[c.severity] ?? 0) + 1;
      return acc;
    }, {});
    expect(bySeverity).toEqual({ critical: 8, high: 5, medium: 6, low: 2 });
  });

  it("returns a perfect score for a clean project", () => {
    const result = analyzeFiles([
      { path: "src/index.ts", content: 'export const greet = (name: string) => `Hello ${name}`' },
      { path: "README.md", content: "# demo" },
    ]);
    expect(result.score).toBe(100);
    expect(result.findings).toHaveLength(0);
  });

  it("finds issues across multiple files and lowers the score", () => {
    const result = analyzeFiles([
      { path: "src/payments.ts", content: 'const apiKey = "sk_live_51H8x9K2eZvKYlo2Cxxxxxxxxxxxxxxxx"' },
      { path: "src/server.ts", content: "app.use(cors())" },
      { path: "src/Comment.tsx", content: "<div dangerouslySetInnerHTML={{ __html: comment.text }} />" },
    ]);
    expect(result.score).toBeLessThan(100);
    expect(result.findings.map((f) => f.checkId).sort()).toEqual(
      ["hardcoded-secret", "permissive-cors", "xss-dangerous-html"].sort()
    );
    expect(result.summary).toEqual({ critical: 1, high: 1, medium: 1, low: 0 });
  });

  it("never returns the full source line as a snippet", () => {
    const secretLine =
      'const apiKey = "sk_live_51H8x9K2eZvKYlo2Cxxxxxxxxxxxxxxxx" // used by the billing webhook handler downstream';
    const result = analyzeFiles([{ path: "src/payments.ts", content: secretLine }]);
    const finding = result.findings.find((f) => f.checkId === "hardcoded-secret");
    expect(finding).toBeDefined();
    expect(finding!.snippet.length).toBeLessThan(secretLine.length);
    expect(finding!.snippet).not.toBe(secretLine);
  });

  it("skips files under node_modules and dist", () => {
    const result = analyzeFiles([
      { path: "node_modules/some-pkg/index.js", content: 'const apiKey = "sk_live_51H8x9K2eZvKYlo2Cxxxxxxxxxxxxxxxx"' },
      { path: "dist/bundle.js", content: "app.use(cors())" },
    ]);
    expect(result.findings).toHaveLength(0);
    expect(result.score).toBe(100);
  });
});
