import type { SourceFile } from "./types.js";
import { ALL_CHECKS } from "./checks/index.js";

export interface AutofixResult {
  /** I file con le correzioni applicate — stessa forma dei file in ingresso. */
  files: SourceFile[];
  /** Solo i file il cui contenuto è stato davvero modificato (sottoinsieme di `files`). */
  changedFiles: SourceFile[];
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
export interface AutofixOptions {
  /**
   * true quando `files` rappresenta l'intero progetto (scansione CLI, Full
   * Site Audit), false quando sono solo i file cambiati in una pull request
   * (monitoraggio continuo via GitHub App). Le correzioni che toccano un
   * file diverso da quello segnalato (`autofixOtherFile`, es. .gitignore)
   * girano solo quando è true: altrimenti, non avendo il vero contenuto
   * attuale di quel file dal resto del repository, rischieremmo di
   * sovrascriverlo per intero invece di aggiungerci solo una riga.
   */
  fullProject?: boolean;
}

export function applyAutofixes(files: readonly SourceFile[], options: AutofixOptions = {}): AutofixResult {
  const { fullProject = false } = options;
  const fixedCheckIds = new Set<string>();
  const manualCheckIds = new Set<string>();
  const changedFiles: SourceFile[] = [];
  let filesChanged = 0;

  // Correzioni che toccano un file diverso da quello in cui è stato trovato
  // il problema (es. aggiungere una riga al .gitignore) — raccolte a parte
  // e unite una sola volta a fine ciclo, non ad ogni file che le fa scattare.
  const otherFileUpdates = new Map<string, SourceFile>();

  const result = files.map((file) => {
    let current = file;
    let fileWasChanged = false;

    for (const check of ALL_CHECKS) {
      const matches = check.detect(current, files);
      if (matches.length === 0) continue;

      let fixedSomething = false;

      if (check.autofix) {
        const fixedContent = check.autofix(current);
        if (fixedContent !== null && fixedContent !== current.content) {
          current = { ...current, content: fixedContent };
          fileWasChanged = true;
          fixedSomething = true;
        }
      }

      if (check.autofixOtherFile && fullProject) {
        const updated = check.autofixOtherFile(current, files);
        if (updated) {
          otherFileUpdates.set(updated.path, updated);
          fixedSomething = true;
        }
      }

      if (fixedSomething) {
        fixedCheckIds.add(check.id);
      } else {
        manualCheckIds.add(check.id);
      }
    }

    if (fileWasChanged) {
      filesChanged++;
      changedFiles.push(current);
    }
    return current;
  });

  // Applica gli aggiornamenti ad altri file: sostituisce il file se esisteva
  // già nel progetto, altrimenti lo aggiunge (es. un .gitignore che prima non c'era).
  for (const updated of otherFileUpdates.values()) {
    const index = result.findIndex((f) => f.path === updated.path);
    if (index >= 0) {
      result[index] = updated;
    } else {
      result.push(updated);
    }
    changedFiles.push(updated);
    filesChanged++;
  }

  return { files: result, changedFiles, fixedCheckIds, manualCheckIds, filesChanged };
}