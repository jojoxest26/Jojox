import { describe, expect, it } from "vitest";
import { load as parseYaml } from "js-yaml";
import { applyAutofixes } from "../src/autofix.js";
import { criticalChecks } from "../src/checks/critical.js";

const ghaScriptInjection = criticalChecks.find((c) => c.id === "gha-script-injection")!;
const workflow = (stepsBody: string) =>
  `name: CI\non:\n  pull_request:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n${stepsBody}`;

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

  describe("gha-script-injection (riscrittura in env: + variabile)", () => {
    it("moves a single interpolated expression into env: and resolves the finding", () => {
      const before = {
        path: ".github/workflows/ci.yml",
        content: workflow('      - name: Build\n        run: echo "${{ github.event.pull_request.title }}"\n'),
      };
      const result = applyAutofixes([before], { fullProject: true });

      expect(result.fixedCheckIds.has("gha-script-injection")).toBe(true);
      const after = result.changedFiles.find((f) => f.path === before.path)!;
      expect(after).toBeDefined();

      // La riscrittura deve risolvere davvero il finding, non solo "sembrare giusta".
      expect(ghaScriptInjection.detect(after, [after])).toHaveLength(0);

      // E deve restare YAML valido, con la struttura attesa — non solo testo che sembra YAML.
      const parsed = parseYaml(after.content) as any;
      const step = parsed.jobs.build.steps[0];
      expect(step.env).toEqual({ PULL_REQUEST_TITLE: "${{ github.event.pull_request.title }}" });
      expect(step.run).toBe('echo "$PULL_REQUEST_TITLE"');
    });

    it("gives each distinct expression on the same line its own variable", () => {
      const before = {
        path: ".github/workflows/ci.yml",
        content: workflow(
          '      - name: Build\n        run: echo "${{ github.event.pull_request.title }}" "${{ github.event.pull_request.body }}"\n'
        ),
      };
      const result = applyAutofixes([before], { fullProject: true });
      const after = result.changedFiles.find((f) => f.path === before.path)!;

      expect(ghaScriptInjection.detect(after, [after])).toHaveLength(0);
      const parsed = parseYaml(after.content) as any;
      const step = parsed.jobs.build.steps[0];
      expect(step.env).toEqual({
        PULL_REQUEST_TITLE: "${{ github.event.pull_request.title }}",
        PULL_REQUEST_BODY: "${{ github.event.pull_request.body }}",
      });
      expect(step.run).toBe('echo "$PULL_REQUEST_TITLE" "$PULL_REQUEST_BODY"');
    });

    it("leaves a step that already has its own env: block untouched (manual)", () => {
      const before = {
        path: ".github/workflows/ci.yml",
        content: workflow(
          '      - name: Build\n        env:\n          EXISTING: value\n        run: echo "${{ github.event.pull_request.title }}"\n'
        ),
      };
      const result = applyAutofixes([before], { fullProject: true });

      expect(result.changedFiles.some((f) => f.path === before.path)).toBe(false);
      expect(result.manualCheckIds.has("gha-script-injection")).toBe(true);
    });

    it("leaves a multiline run: block untouched (manual)", () => {
      const before = {
        path: ".github/workflows/ci.yml",
        content: workflow('      - run: |\n          echo "building"\n          echo "${{ github.head_ref }}"\n'),
      };
      const result = applyAutofixes([before], { fullProject: true });

      expect(result.changedFiles.some((f) => f.path === before.path)).toBe(false);
      expect(result.manualCheckIds.has("gha-script-injection")).toBe(true);
    });

    it("leaves a step where run: is the first key untouched (manual)", () => {
      const before = {
        path: ".github/workflows/ci.yml",
        content: workflow('      - run: echo "${{ github.event.pull_request.title }}"\n'),
      };
      // Variante dove "run:" è davvero la prima (e unica) chiave del passo —
      // già vero nel fixture sopra: la riga comincia con "- run:".
      expect(before.content).toMatch(/^\s*- run:/m);
      const result = applyAutofixes([before], { fullProject: true });
      expect(result.changedFiles.some((f) => f.path === before.path)).toBe(false);
    });
  });
});