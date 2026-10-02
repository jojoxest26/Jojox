/**
 * File che l'intero motore — controlli a pattern (analyze.ts) e dependency
 * scanning (depscan.ts) — non deve mai analizzare come codice sorgente.
 * Vive qui, separato da entrambi, per evitare un import circolare tra i due
 * (depscan.ts ha bisogno di sapere quali file ignorare, analyze.ts ha
 * bisogno di sapere il nome dei file "snapshot" che depscan.ts riconosce).
 */
export const SKIP_PATH = /(^|\/)(node_modules|\.git|dist|build|\.next|coverage)\//;