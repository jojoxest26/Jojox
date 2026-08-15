import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { blockingFindings, getStagedFiles, runPrecommitCheck } from "../src/precommit.js";
import type { Finding } from "../src/types.js";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    checkId: "hardcoded-secret",
    severity: "critical",
    confidence: "confirmed",
    title: "Test",
    description: "Test",
    file: "a.ts",
    line: 1,
    snippet: "...",
    fix: { before: "", after: "" },
    ...overrides,
  };
}

describe("blockingFindings", () => {
  it("keeps only critical findings", () => {
    const findings = [
      finding({ severity: "critical" }),
      finding({ severity: "high" }),
      finding({ severity: "medium" }),
      finding({ severity: "low" }),
    ];
    expect(blockingFindings(findings)).toHaveLength(1);
  });

  it("returns an empty array when nothing is critical", () => {
    const findings = [finding({ severity: "high" }), finding({ severity: "medium" })];
    expect(blockingFindings(findings)).toEqual([]);
  });

  it("returns an empty array for no findings", () => {
    expect(blockingFindings([])).toEqual([]);
  });

  it("keeps every critical finding when there are several", () => {
    const findings = [finding({ severity: "critical" }), finding({ severity: "critical" })];
    expect(blockingFindings(findings)).toHaveLength(2);
  });
});

describe("getStagedFiles / runPrecommitCheck (repository Git reale)", () => {
  let repo: string;

  beforeEach(() => {
    repo = mkdtempSync(join(tmpdir(), "jojox-precommit-test-"));
    execFileSync("git", ["init", "-q"], { cwd: repo });
    execFileSync("git", ["config", "user.email", "test@test.com"], { cwd: repo });
    execFileSync("git", ["config", "user.name", "Test"], { cwd: repo });
  });

  afterEach(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  it("legge il contenuto in staging, non quello sul disco", () => {
    writeFileSync(join(repo, "a.ts"), "const x = 1;\n");
    execFileSync("git", ["add", "a.ts"], { cwd: repo });
    // Modifica il file sul disco DOPO averlo messo in staging: il commit
    // userebbe comunque la versione già aggiunta, non questa.
    writeFileSync(join(repo, "a.ts"), "const x = 999;\n");

    const files = getStagedFiles(repo);
    expect(files).toEqual([{ path: "a.ts", content: "const x = 1;\n" }]);
  });

  it("ignora i file non ancora messi in staging", () => {
    writeFileSync(join(repo, "a.ts"), "const x = 1;\n");
    expect(getStagedFiles(repo)).toEqual([]);
  });

  it("blocca il commit quando trova un problema critico in staging", () => {
    writeFileSync(join(repo, "bad.js"), `const password = "correctHorseBatteryStaple123";\n`);
    execFileSync("git", ["add", "bad.js"], { cwd: repo });

    const { blocked, findings } = runPrecommitCheck(repo);
    expect(blocked).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe("critical");
  });

  it("non blocca un commit senza problemi critici", () => {
    writeFileSync(join(repo, "good.js"), "const apiKey = process.env.STRIPE_SECRET_KEY;\nconsole.log(apiKey);\n");
    execFileSync("git", ["add", "good.js"], { cwd: repo });

    const { blocked, findings } = runPrecommitCheck(repo);
    expect(blocked).toBe(false);
    expect(findings).toEqual([]);
  });

  it("non blocca quando non c'è nulla in staging", () => {
    const { blocked, findings } = runPrecommitCheck(repo);
    expect(blocked).toBe(false);
    expect(findings).toEqual([]);
  });
});