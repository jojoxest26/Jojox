import { useEffect, useRef } from "react";

/**
 * Prima di mandare l'utente su Stripe Checkout impostiamo uno stato "in
 * corso" (bottone disabilitato, "Apertura del pagamento...") e poi
 * navighiamo via con `window.location.href`: quello stato non viene mai
 * resettato nel codice, perché la pagina si scarica. Se il browser invece
 * di ricaricare questa pagina la ripristina dalla sua cache di
 * avanti/indietro (back/forward cache, premendo "Indietro" dopo il
 * checkout), React torna su con lo stato congelato esattamente a quel
 * momento — bottone disabilitato per sempre, senza che nessuna richiesta
 * sia più in corso davvero.
 */
export function useBfcacheReset(reset: () => void): void {
  const resetRef = useRef(reset);
  resetRef.current = reset;

  useEffect(() => {
    function handlePageShow(event: PageTransitionEvent) {
      if (event.persisted) resetRef.current();
    }
    window.addEventListener("pageshow", handlePageShow);
    return () => window.removeEventListener("pageshow", handlePageShow);
  }, []);
}
