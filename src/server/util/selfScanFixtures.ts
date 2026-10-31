/**
 * Il nostro stesso repository (jojoxest26/jojox) ha la GitHub App di JoJoX
 * installata su se stesso — per CI sulle pull request, Sentinella 24/7 e
 * Full Site Audit. I file che DEFINISCONO i 64 controlli (src/checks/*.ts),
 * i loro test, e le loro descrizioni tradotte in 23 lingue
 * (web/src/i18n/checkTranslations.ts) contengono però, come parte necessaria
 * della loro stessa definizione, esempi letterali del pattern che ciascun
 * controllo cerca (es. "md5(password)", "createHash(\"md5\")",
 * "redirect(\"/\")" nei commenti che spiegano un'altra sintassi equivalente,
 * o lo stesso esempio di fix ripetuto in ogni lingua). Il motore è un
 * confronto testuale, non un'analisi semantica: non distingue "questo è un
 * esempio dentro la definizione del controllo stesso" da "questo è vero
 * codice vulnerabile". Senza questa esclusione, ogni scan sul nostro repo
 * trova centinaia di "vulnerabilità" nei propri esempi (verificato: senza
 * checkTranslations.ts escluso, ~190 risultati falsi sulle sole traduzioni)
 * e apre una pull request di autofix che riscrive l'esempio — e lo riscrive
 * di nuovo al giro successivo, perché il testo riscritto combacia ancora col
 * proprio pattern.
 *
 * Questa esclusione riguarda SOLO questo repository specifico: per qualunque
 * altro repository (il codice di un cliente vero), questi percorsi restano
 * analizzati normalmente — un cliente con una cartella o un file chiamato
 * allo stesso modo può benissimo avere vulnerabilità vere al suo interno.
 */
const SELF_REPO_OWNER = "jojoxest26";
const SELF_REPO_NAME = "jojox";

const SELF_SCAN_EXCLUDED_PATHS = /^(src\/checks\/|test\/|web\/src\/i18n\/checkTranslations\.ts$)/;

export function isSelfRepo(owner: string, repo: string): boolean {
  return owner.toLowerCase() === SELF_REPO_OWNER && repo.toLowerCase() === SELF_REPO_NAME;
}

/**
 * Filtra via, SOLO quando `owner`/`repo` sono il nostro stesso repository, i
 * file che definiscono o testano i controlli — altrimenti ritorna `files`
 * invariato. Va chiamata prima di `analyzeFiles`/`applyAutofixes` in ogni
 * punto che riceve file da un repository GitHub esterno (webhook sulle PR,
 * Sentinella 24/7, Full Site Audit con repository collegato).
 */
export function excludeSelfScanFixtures<T extends { path: string }>(files: T[], owner: string, repo: string): T[] {
  if (!isSelfRepo(owner, repo)) return files;
  return files.filter((f) => !SELF_SCAN_EXCLUDED_PATHS.test(f.path));
}
