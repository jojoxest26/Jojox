#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import fg from "fast-glob";
import { analyzeFiles, applyAutofixes } from "./analyze.js";
import { ALL_CHECKS } from "./checks/index.js";
import type { Severity } from "./types.js";

const AUTOFIXABLE_CHECK_IDS = new Set(ALL_CHECKS.filter((c) => c.autofix).map((c) => c.id));

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
  const shouldFix = process.argv.includes("--fix");
  const root = resolve(target);

  const relativePaths = await fg("**/*", {
    cwd: root,
    dot: true,
    onlyFiles: true,
    ignore: ["node_modules/**", ".git/**", "dist/**", "build/**", ".next/**", "coverage/**"],
  });

  const files = (
    await Promise.all(
      relativePaths.map(async (path) => ({
        path,
        content: await readFile(resolve(root, path), "utf8").catch(() => ""),
      }))
    )
  ).filter((f) => f.content !== "");

  if (shouldFix) {
    await runFix(root, files, asJson);
    return;
  }

  const result = analyzeFiles(files);

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
  } else if (result.findings.some((f) => AUTOFIXABLE_CHECK_IDS.has(f.checkId))) {
    console.log("Suggerimento: rilancia con --fix per correggere in automatico quello che si può.\n");
  }
}

/**
 * Corregge i file in place sul disco (come `eslint --fix`): scrive solo i
 * file che il motore di correzione ha effettivamente cambiato.
 */
async function runFix(root: string, files: { path: string; content: string }[], asJson: boolean): Promise<void> {
  const before = analyzeFiles(files);
  const autofix = applyAutofixes(files);
  const changed = files
    .map((original, i) => ({ original, fixed: autofix.files[i] }))
    .filter(({ original, fixed }) => fixed.content !== original.content);

  await Promise.all(changed.map(({ fixed }) => writeFile(resolve(root, fixed.path), fixed.content, "utf8")));

  const after = analyzeFiles(autofix.files);

  if (asJson) {
    console.log(
      JSON.stringify(
        {
          scoreBefore: before.score,
          scoreAfter: after.score,
          filesChanged: changed.map(({ fixed }) => fixed.path),
          fixedCheckIds: [...autofix.fixedCheckIds],
          manualCheckIds: [...autofix.manualCheckIds],
        },
        null,
        2
      )
    );
    return;
  }

  if (changed.length === 0) {
    console.log("\nNessuna correzione automatica applicabile su questo codice.\n");
  } else {
    console.log(`\nJoJoX — corretti ${changed.length} file (punteggio: ${before.score} → ${after.score}/100)\n`);
    for (const { fixed } of changed) {
      console.log(`  ✓ ${fixed.path}`);
    }
    console.log("");
  }

  if (autofix.manualCheckIds.size > 0) {
    console.log(
      `${autofix.manualCheckIds.size} ${autofix.manualCheckIds.size === 1 ? "tipo di problema resta" : "tipi di problema restano"} da sistemare a mano — rilancia senza --fix per vederli in dettaglio.\n`
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});