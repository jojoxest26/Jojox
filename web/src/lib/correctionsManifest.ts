import type { Finding, SourceFile } from "../../../src/types.js";
import type { AutofixResult } from "../../../src/analyze.js";
import type { TranslationTree } from "../i18n/translations.js";
import { interpolate } from "../i18n/richText.js";

/**
 * Testo del file CORREZIONI.txt incluso nello zip scaricabile: elenca quali
 * file sono stati toccati (per sapere cosa copiare nel progetto reale) e
 * quali problemi restano da correggere a mano — `afterFindings` deve venire
 * da un'analisi rifatta sui file già corretti, non dal risultato originale,
 * altrimenti conterebbe anche le occorrenze che l'autofix ha già risolto.
 */
export function buildCorrectionsManifest(afterFindings: readonly Finding[], autofix: AutofixResult, t: TranslationTree): string {
  const m = t.common.correctionsManifest;
  const lines: string[] = [m.title, "", m.filesIntro, "", interpolate(m.filesHeader, { count: String(autofix.changedFiles.length) })];

  for (const file of autofix.changedFiles) {
    lines.push(`- ${file.path}`);
  }

  const remainingByCheck = new Map<string, { title: string; count: number }>();
  for (const finding of afterFindings) {
    const entry = remainingByCheck.get(finding.checkId);
    if (entry) entry.count++;
    else remainingByCheck.set(finding.checkId, { title: finding.title, count: 1 });
  }

  lines.push("");
  if (remainingByCheck.size === 0) {
    lines.push(m.manualNone);
  } else {
    lines.push(interpolate(m.manualHeader, { count: String(remainingByCheck.size) }));
    for (const { title, count } of remainingByCheck.values()) {
      lines.push(`- ${title} (${interpolate(m.occurrences, { count: String(count) })})`);
    }
  }

  return lines.join("\n");
}

/** I file da mettere nello zip scaricabile: solo quelli corretti, più il manifesto CORREZIONI.txt. */
export function buildCorrectionsZipEntries(afterFindings: readonly Finding[], autofix: AutofixResult, t: TranslationTree): SourceFile[] {
  return [...autofix.changedFiles, { path: "CORREZIONI.txt", content: buildCorrectionsManifest(afterFindings, autofix, t) }];
}