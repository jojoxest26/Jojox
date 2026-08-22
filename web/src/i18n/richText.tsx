import type { ReactNode } from "react";

const TOKEN_PATTERN = /(\{\{\w+\}\})/g;

/**
 * Divide una stringa di traduzione contenente segnaposto tipo "{{nome}}" e
 * sostituisce ciascuno con l'elemento React corrispondente â€” usato per le
 * poche frasi che hanno bisogno di uno <span> o <code> in mezzo al testo,
 * senza dover mettere JSX dentro le tabelle di traduzione.
 */
export function renderWithTokens(template: string, tokens: Record<string, ReactNode>): ReactNode[] {
  return template.split(TOKEN_PATTERN).map((part, i) => {
    const match = part.match(/^\{\{(\w+)\}\}$/);
    if (match) return <span key={i}>{tokens[match[1]] ?? ""}</span>;
    return <span key={i}>{part}</span>;
  });
}

/** Come renderWithTokens, ma per i pochi casi (aria-label, title) dove serve una stringa semplice, non nodi React. */
export function interpolate(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => values[key] ?? "");
}