/**
 * Un copia-incolla incompleto su Railway (es. un campo non svuotato del
 * tutto prima di incollarci sopra) può lasciare in una variabile d'ambiente
 * un carattere di mascheramento "•" (bullet, non ASCII) invece del testo
 * vero. Usata in un'intestazione Authorization, quella variabile fa fallire
 * ogni chiamata con un TypeError criptico di fetch/undici sulla conversione
 * dell'intestazione — un messaggio che non dice nulla su dove cercare.
 * Controllarlo qui, una volta sola per ogni chiave segreta usata come
 * intestazione (Stripe, Anthropic, ...), trasforma quell'errore in uno che
 * dice esattamente cosa controllare.
 */
export function assertHeaderSafe(value: string, fieldName: string): void {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 255) {
      throw new Error(
        `${fieldName} contiene un carattere non valido (probabilmente un "•" di mascheramento rimasto da un copia-incolla incompleto) — svuota del tutto il campo su Railway prima di incollare di nuovo il valore.`
      );
    }
  }
}
