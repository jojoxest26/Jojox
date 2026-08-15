#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { analyzeFiles } from "./analyze.js";
import type { Finding, SourceFile } from "./types.js";

const SKIP_PATH = /(^|\/)(node_modules|\.git|dist|build|\.next|coverage)\//;

/** I file messi in staging (git add), con il contenuto esatto che finirà nel commit — non quello sul disco, che potrebbe avere modifiche non ancora aggiunte. */
export function getStagedFiles(cwd: string): SourceFile[] {
  const output = execFileSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACM"], {
    cwd,
    encoding: "utf8",
  });
  const paths = output.split("\n").filter((p) => p && !SKIP_PATH.test(p));

  const files: SourceFile[] = [];
  for (const path of paths) {
    try {
      const content = execFileSync("git", ["show", `:${path}`], { cwd, encoding: "utf8" });
      files.push({ path, content });
    } catch {
      // File binario o non leggibile come testo: lo saltiamo, non è qualcosa che i nostri controlli sanno leggere comunque.
    }
  }
  return files;
}

export function blockingFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.severity === "critical");
}

export function runPrecommitCheck(cwd: string): { blocked: boolean; findings: Finding[] } {
  const files = getStagedFiles(cwd);
  if (files.length === 0) return { blocked: false, findings: [] };

  const result = analyzeFiles(files);
  const critical = blockingFindings(result.findings);
  return { blocked: critical.length > 0, findings: critical };
}

function main() {
  const { blocked, findings } = runPrecommitCheck(process.cwd());
  if (!blocked) return;

  const summary =
    findings.length === 1 ? "1 problema critico trovato" : `${findings.length} problemi critici trovati`;
  console.error(`\n🛑 JoJoX ha bloccato il commit: ${summary}.\n`);
  for (const finding of findings) {
    console.error(`  ${finding.file}:${finding.line}  ${finding.title}`);
  }
  console.error(`\nCorreggi il problema, oppure salta il controllo con "git commit --no-verify" (sconsigliato).\n`);
  process.exitCode = 1;
}

// Gira solo se lanciato come script (`tsx precommit.ts`), non quando le
// funzioni sopra vengono importate altrove (es. dai test).
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main();
}