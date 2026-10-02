import type { CheckMatch, SourceFile } from "../types.js";

/** True per un file Python — usato dai controlli che riconoscono anche questo linguaggio, non solo JS/TS. */
export function isPythonFile(file: SourceFile): boolean {
  return /\.py$/.test(file.path);
}

/** True per un file Go — usato dai controlli che riconoscono anche questo linguaggio, non solo JS/TS/Python. */
export function isGoFile(file: SourceFile): boolean {
  return /\.go$/.test(file.path);
}

/** True per un file Java — usato dai controlli che riconoscono anche questo linguaggio, non solo JS/TS/Python/Go. */
export function isJavaFile(file: SourceFile): boolean {
  return /\.java$/.test(file.path);
}

/** True per un file PHP — usato dai controlli che riconoscono anche questo linguaggio, non solo JS/TS/Python/Go/Java. */
export function isPhpFile(file: SourceFile): boolean {
  return /\.php$/.test(file.path);
}

/** True per un Dockerfile — nome esatto "Dockerfile", con un suffisso tipo "Dockerfile.dev", o estensione ".dockerfile". Usato dai controlli IaC (Fase 2). */
export function isDockerfile(file: SourceFile): boolean {
  const basename = file.path.split("/").pop() ?? "";
  return /^Dockerfile(\.[\w-]+)?$/i.test(basename) || /\.dockerfile$/i.test(basename);
}

const CONTEXT_CHARS = 12;
const MASK_CHAR = "•";

/** Redacts the matched substring and trims the line to a short window around it — never the full line. */
export function redactLine(lineText: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - CONTEXT_CHARS);
  const end = Math.min(lineText.length, matchIndex + matchLength + CONTEXT_CHARS);
  const secret = lineText.slice(matchIndex, matchIndex + matchLength);

  let windowed = lineText.slice(start, end);
  if (secret.length > 8) {
    const masked = secret.slice(0, 3) + MASK_CHAR.repeat(Math.min(secret.length - 6, 24)) + secret.slice(-3);
    windowed = windowed.split(secret).join(masked);
  }

  return (start > 0 ? "…" : "") + windowed.trim() + (end < lineText.length ? "…" : "");
}

/** Scans a file line by line for a regex, returning one CheckMatch per match with a redacted snippet. */
export function scanLines(file: SourceFile, pattern: RegExp): CheckMatch[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  const lines = file.content.split("\n");
  const matches: CheckMatch[] = [];

  lines.forEach((lineText, idx) => {
    const re = new RegExp(pattern.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(lineText)) !== null) {
      matches.push({ line: idx + 1, snippet: redactLine(lineText, m.index, m[0].length) });
      if (m[0].length === 0) re.lastIndex++;
    }
  });

  return matches;
}

/** True if `pattern` matches anywhere in a window of `span` lines around `centerLine` (1-indexed). */
export function nearbyMatches(file: SourceFile, centerLine: number, span: number, pattern: RegExp): boolean {
  const lines = file.content.split("\n");
  const from = Math.max(0, centerLine - 1 - span);
  const to = Math.min(lines.length, centerLine - 1 + span + 1);
  const windowText = lines.slice(from, to).join("\n");
  return pattern.test(windowText);
}

export function fileMatch(file: SourceFile, pattern: RegExp): boolean {
  return pattern.test(file.content);
}

export function lineFromIndex(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

/**
 * Riscrive ogni riga che combacia con `pattern` usando `replacer`. Se
 * `replacer` ritorna `null` per una riga, quella riga resta invariata.
 * Ritorna il nuovo contenuto e `true` se è stata cambiata almeno una riga.
 */
export function replaceLines(
  content: string,
  pattern: RegExp,
  replacer: (lineText: string, match: RegExpExecArray) => string | null
): { content: string; changed: boolean } {
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  let changed = false;
  const lines = content.split("\n").map((lineText) => {
    const re = new RegExp(pattern.source, flags);
    const m = re.exec(lineText);
    if (!m) return lineText;
    const replaced = replacer(lineText, m);
    if (replaced === null) return lineText;
    changed = true;
    return replaced;
  });
  return { content: lines.join("\n"), changed };
}