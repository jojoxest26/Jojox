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
  database: (
    <>
      <ellipse cx="12" cy="5.5" rx="8" ry="3" />
      <path d="M4 5.5v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" />
      <path d="M4 11.5v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" />
    </>
  ),
  package: (
    <path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5v-9ZM3.8 7.3 12 12l8.2-4.7M12 12v9" />
  ),
  key: (
    <path d="M14.5 9.5a4 4 0 1 0-4 4 4 0 0 0 1.4-.25L14 16h2.5V18H19v2.5h2.5V18l-7.3-7.3A4 4 0 0 0 14.5 9.5Z" />
  ),
  bucket: <path d="M4 7h16l-1.5 13h-13L4 7Z M3 7c0-2 4-3 9-3s9 1 9 3-4 3-9 3-9-1-9-3Z" />,
  user: <path d="M12 12a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9ZM4 21c0-4.4 3.6-8 8-8s8 3.6 8 8" />,
  office: (
    <path d="M4 21V4h9v17M13 21V9h7v12M4 21h16M7.5 7.5h1.5M7.5 11h1.5M7.5 14.5h1.5M11 7.5h1M11 11h1M11 14.5h1M16.5 12.5h1.5M16.5 16h1.5" />
  ),
  globe: <path d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM3 12h18M12 3c2.8 2.3 2.8 15.7 0 18M12 3c-2.8 2.3-2.8 15.7 0 18" />,
  plus: <path d="M12 5v14M5 12h14" />,
  puzzle: (
    <path d="M9 4h4v2.2a1.8 1.8 0 1 0 0 3.6V12h2.2a1.8 1.8 0 1 1 0 3.6H15v4h-4v-2.2a1.8 1.8 0 1 0 0-3.6V12H8.8a1.8 1.8 0 1 1 0-3.6H9V4Z M9 4H5v4M15 4h4v4M5 8v4h4M19 8v4h-4M5 16v4h4M15 16h4v4h-4" />
  ),
  bricks: (
    <path d="M3 5h8v4H3zM11 5h10v4H11zM3 13h6v4H3zM9 13h8v4H9zM17 13h4v4h-4zM3 9h18M3 17h18" />
  ),
  brain: (
    <path d="M9 4.5a3 3 0 0 0-3 3V8a3 3 0 0 0-1 5.8V15a3 3 0 0 0 3 3h1M9 4.5a3 3 0 0 1 3 3v9a3 3 0 0 1-3 3M9 4.5c0-1 1-1.5 1.5-1.5M15 4.5a3 3 0 0 1 3 3V8a3 3 0 0 1 1 5.8V15a3 3 0 0 1-3 3h-1M15 4.5a3 3 0 0 0-3 3v9a3 3 0 0 0 3 3" />
  ),
  tag: <path d="M3 11.5 11.5 3H19a2 2 0 0 1 2 2v7.5L12.5 21 3 11.5Z M14.5 9a1.3 1.3 0 1 0 0-2.6A1.3 1.3 0 0 0 14.5 9Z" />,
  link: <path d="M9.5 14.5 14.5 9.5 M11 7.5l1.5-1.5a3.5 3.5 0 0 1 5 5L16 12.5 M13 16.5 11.5 18a3.5 3.5 0 0 1-5-5L8 11.5" />,
  terminal: <path d="M4 5h16v14H4zM7 9l3 3-3 3M12 15h5" />,
  webhook: (
    <path d="M7 16a4 4 0 1 1 3.5-6M14 8a4 4 0 0 1 2.2 7.3M9.5 10 13 16M17 18a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM7 20a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM13 6a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z" />
  ),
  bell: <path d="M6 9a6 6 0 1 1 12 0c0 4 1.5 5.5 1.5 5.5H4.5S6 13 6 9ZM9.5 17a2.5 2.5 0 0 0 5 0" />,
  gitBranch: (
    <path d="M6 3v12M18 9v9M6 15a3 3 0 1 0 0 6 3 3 0 0 0 0-6ZM6 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6ZM18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM9 6c4 0 9 1 9 3" />
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
