/**
 * Formato di un reel verticale (9:16) generato dalla chat dei contenuti
 * (/content). Il server lo fa scrivere al modello e lo valida; il sito lo
 * anima su un canvas e lo esporta come video. Tipi soltanto, nessun I/O:
 * condivisi da backend e frontend come src/types.ts.
 */

/** Colori del sito: dark = fondo #0a0c0f, light = bianco caldo #eef1f4, amber = giallo JoJoX #f5a623. */
export type ReelBackground = "dark" | "light" | "amber";
/** amber = colore principale di JoJoX; red e blue = i colori di gravità del sito (critico, basso). */
export type ReelAccent = "amber" | "red" | "blue";

export type ReelScene =
  /** Una o due parole grandi al centro, che entrano con uno scatto. */
  | { type: "word"; text: string; bg: ReelBackground; duration: number }
  /** Titolo in corsivo su due righe: la seconda nel colore d'accento. Etichette opzionali che fluttuano intorno. */
  | {
      type: "headline";
      line1: string;
      line2: string;
      chips?: string[];
      bg: ReelBackground;
      accent: ReelAccent;
      duration: number;
    }
  /** Parole in colonna: tutte barrate in rosso tranne l'ultima. */
  | { type: "strike"; words: string[]; bg: ReelBackground; duration: number }
  /** Grafico a barre che cresce. I valori sono altezze relative, mai mostrati come numeri. */
  | {
      type: "bars";
      title: string;
      bars: { label: string; value: number }[];
      bg: ReelBackground;
      accent: ReelAccent;
      duration: number;
    }
  /** Numero grande che conta fino al valore, con una didascalia sotto. */
  | { type: "stat"; value: number; suffix?: string; caption: string; bg: ReelBackground; accent: ReelAccent; duration: number }
  /** La Sentinella, la mascotte di JoJoX, che entra in scena e scansiona con il suo raggio. Testo facoltativo sotto. */
  | { type: "mascot"; text?: string; bg: ReelBackground; duration: number }
  /** Il punteggio di sicurezza 0-100 come sul sito: un cerchio che si riempie mentre il numero sale. */
  | { type: "score"; from: number; to: number; caption: string; bg: ReelBackground; duration: number }
  /** Un problema trovato come lo mostra JoJoX: riga evidenziata con l'etichetta CRITICO, poi la correzione prima/dopo. */
  | { type: "finding"; title: string; file: string; before: string; after: string; bg: ReelBackground; duration: number }
  /** Chiusura con il marchio JoJoX e un invito all'azione. */
  | { type: "cta"; text: string; sub?: string; bg: ReelBackground; accent: ReelAccent; duration: number };

export interface Reel {
  title: string;
  /** Testo da leggere come voce fuori campo, mentre scorrono le scene. */
  voiceover: string;
  /** Didascalia del post, con gli hashtag. */
  caption: string;
  scenes: ReelScene[];
}

export const REEL_MIN_SCENE_SECONDS = 0.4;
export const REEL_MAX_SCENE_SECONDS = 5;
export const REEL_MAX_SCENES = 40;

export function reelDuration(reel: Reel): number {
  return reel.scenes.reduce((sum, s) => sum + s.duration, 0);
}
