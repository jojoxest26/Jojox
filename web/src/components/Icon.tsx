import type { ReactNode } from "react";

/**
 * Set di icone proprie di JoJoX — sostituiscono le emoji usate finora in
 * Features e Audience. Stesso stile per tutte: outline, stroke arrotondato,
 * nessun riempimento — coerente con l'estetica "terminale" del resto del
 * sito invece di prendere in prestito lo stile illustrativo di qualcun altro.
 */
const icons: Record<string, ReactNode> = {
  shield: <path d="M12 2.5 4 5.5v6c0 5 3.4 8.7 8 9.9 4.6-1.2 8-4.9 8-9.9v-6L12 2.5Z M9 12l2 2 4-4.5" />,
  wrench: (
    <path d="M14.7 6.3a4 4 0 0 0-5.4 4.9L3 17.5 6.5 21l6.3-6.3a4 4 0 0 0 4.9-5.4l-2.8 2.8-2.1-2.1 2.9-2.7Z" />
  ),
  chart: <path d="M4 20V10M10 20V4M16 20v-7M21 20H3" />,
  developer: <path d="m8 9-4 4 4 4M16 9l4 4-4 4M14 5l-4 15" />,
  rocket: (
    <path d="M12 2c3 2 5 5.5 5 9.5 0 2-1 4-2 5.5l-3 3-3-3c-1-1.5-2-3.5-2-5.5C7 7.5 9 4 12 2Z M9 15.5 6 19l1-4 M15 15.5l3 3.5-1-4 M12 9.5a1.6 1.6 0 1 0 0-3.2 1.6 1.6 0 0 0 0 3.2Z" />
  ),
  team: (
    <path d="M9 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM3 20c0-3.3 2.7-6 6-6s6 2.7 6 6M17 11a3 3 0 1 0 0-6M15 14.2c2.9.4 5 2.9 5 5.8" />
  ),
  bot: (
    <>
      <rect x="5" y="9" width="14" height="11" rx="4" />
      <line x1="12" y1="9" x2="12" y2="4.5" />
      <circle cx="12" cy="3.2" r="1.3" fill="currentColor" stroke="none" />
      <line x1="9" y1="14" x2="9" y2="15.4" />
      <line x1="15" y1="14" x2="15" y2="15.4" />
      <path d="M9.5 18h5" />
      <line x1="2.5" y1="13" x2="5" y2="13" />
      <line x1="19" y1="13" x2="21.5" y2="13" />
    </>
  ),
};

export function Icon({ name, className }: { name: string; className?: string }) {
  const content = icons[name];
  if (!content) return null;
  return (
    <svg
      viewBox="0 0 24 24"
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {content}
    </svg>
  );
}
