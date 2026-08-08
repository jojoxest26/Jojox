import type { SourceFile } from "./types.js";
import { ALL_CHECKS } from "./checks/index.js";

export interface AutofixResult {
  /** I file con le correzioni applicate — stessa forma dei file in ingresso. */
  files: SourceFile[];
  /** id dei controlli per cui è stata applicata almeno una correzione. */
  fixedCheckIds: Set<string>;
  /** id dei controlli con problemi trovati ma senza correzione automatica disponibile. */
  manualCheckIds: Set<string>;
  /** numero di file effettivamente modificati. */
  filesChanged: number;
}

/**
 * Applica in sequenza le correzioni automatiche di ogni controllo che ne ha
 * una. Ogni controllo lavora sul risultato del precedente, così più
 * correzioni sullo stesso file si sommano invece di sovrascriversi.
 */
export function applyAutofixes(files: readonly SourceFile[]): AutofixResult {
  const fixedCheckIds = new Set<string>();
  const manualCheckIds = new Set<string>();
  let filesChanged = 0;

  const result = files.map((file) => {
    let current = file;
    let fileWasChanged = false;

    for (const check of ALL_CHECKS) {
      const matches = check.detect(current, files);
      if (matches.length === 0) continue;

      if (!check.autofix) {
        manualCheckIds.add(check.id);
        continue;
      }

      const fixedContent = check.autofix(current);
      if (fixedContent === null || fixedContent === current.content) {
        manualCheckIds.add(check.id);
        continue;
      }

      current = { ...current, content: fixedContent };
      fixedCheckIds.add(check.id);
      fileWasChanged = true;
    }

    if (fileWasChanged) filesChanged++;
    return current;
  });

  return { files: result, fixedCheckIds, manualCheckIds, filesChanged };
}