#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import fg from "fast-glob";
import { analyzeFiles } from "./analyze.js";
import type { Severity } from "./types.js";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICO",
  high: "ALTO",
  medium: "MEDIO",
  low: "BASSO",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

async function main() {
  const target = process.argv[2] ?? ".";
  const asJson = process.argv.includes("--json");
  const root = resolve(target);

  const relativePaths = await fg("**/*", {
    cwd: root,
    dot: true,
    onlyFiles: true,
    ignore: ["node_modules/**", ".git/**", "dist/**", "build/**", ".next/**", "coverage/**"],
  });

  const files = await Promise.all(
    relativePaths.map(async (path) => ({
      path,
      content: await readFile(resolve(root, path), "utf8").catch(() => ""),
    }))
  );

  const result = analyzeFiles(files.filter((f) => f.content !== ""));

  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(`\nJoJoX — Security Score: ${result.score}/100\n`);
  for (const severity of SEVERITY_ORDER) {
    const inSeverity = result.findings.filter((f) => f.severity === severity);
    if (inSeverity.length === 0) continue;
    console.log(`${SEVERITY_LABEL[severity]} (${inSeverity.length})`);
    for (const finding of inSeverity) {
      const confidenceTag = finding.confidence === "confirmed" ? "confermato" : "da verificare";
      console.log(`  ${finding.file}:${finding.line}  [${confidenceTag}]  ${finding.title}`);
      console.log(`    ${finding.snippet}`);
    }
    console.log("");
  }

  if (result.findings.length === 0) {
    console.log("Nessun problema trovato nei 21 controlli. 🎉\n");
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
