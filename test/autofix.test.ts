import { describe, expect, it } from "vitest";
import { applyAutofixes } from "../src/autofix.js";

describe("applyAutofixes", () => {
  it("returns changedFiles as the subset of files whose content was actually modified", () => {
    const result = applyAutofixes([
      { path: "src/payments.ts", content: 'const apiSecret = "supersecretvaluethatislong"' },
      { path: "README.md", content: "# demo, nothing to fix here" },
    ]);

    expect(result.changedFiles.map((f) => f.path)).toEqual(["src/payments.ts"]);
    expect(result.changedFiles[0]!.content).not.toContain("supersecretvaluethatislong");
    expect(result.filesChanged).toBe(1);
  });

  it("returns an empty changedFiles array when nothing can be fixed automatically", () => {
    const result = applyAutofixes([{ path: "src/server.ts", content: "app.use(cors())" }]);

    expect(result.changedFiles).toEqual([]);
    expect(result.filesChanged).toBe(0);
    expect(result.manualCheckIds.has("permissive-cors")).toBe(true);
  });
});