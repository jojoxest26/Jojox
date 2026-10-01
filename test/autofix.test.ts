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

  describe("autofixOtherFile (es. .gitignore per env-file-with-real-values)", () => {
    const envFile = { path: ".env", content: "DATABASE_URL=postgres://user:realpassword@db.host/prod" };

    it("creates a new .gitignore when the project has none, only in full-project mode", () => {
      const result = applyAutofixes([envFile], { fullProject: true });

      const gitignore = result.files.find((f) => f.path === ".gitignore");
      expect(gitignore?.content).toBe(".env\n");
      expect(result.changedFiles.map((f) => f.path)).toContain(".gitignore");
      expect(result.fixedCheckIds.has("env-file-with-real-values")).toBe(true);
    });

    it("appends to an existing .gitignore without losing its other entries", () => {
      const result = applyAutofixes(
        [envFile, { path: ".gitignore", content: "node_modules\ndist\n" }],
        { fullProject: true }
      );

      const gitignore = result.files.find((f) => f.path === ".gitignore");
      expect(gitignore?.content).toBe("node_modules\ndist\n.env\n");
    });

    it("does nothing if the file is already listed in .gitignore", () => {
      const result = applyAutofixes([envFile, { path: ".gitignore", content: ".env\n" }], { fullProject: true });

      const gitignoreChanged = result.changedFiles.some((f) => f.path === ".gitignore");
      expect(gitignoreChanged).toBe(false);
      expect(result.manualCheckIds.has("env-file-with-real-values")).toBe(true);
    });

    it("never touches other files outside full-project mode (e.g. a PR-diff scan)", () => {
      const result = applyAutofixes([envFile]);

      expect(result.files.some((f) => f.path === ".gitignore")).toBe(false);
      expect(result.manualCheckIds.has("env-file-with-real-values")).toBe(true);
    });
  });
});