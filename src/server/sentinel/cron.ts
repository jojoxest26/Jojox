import cron from "node-cron";
import { runSentinelScan } from "./scan.js";
import { reportError } from "../sentry.js";

// Un rescan completo di molti repository può durare più a lungo di quanto
// ci si aspetti con molte installazioni attive: questo flag evita di farne
// partire uno nuovo mentre il precedente è ancora in corso.
let running = false;

/** Avvia il cron interno della Sentinella 24/7: uno scan completo ogni notte alle 03:00 UTC. */
export function startSentinelCron(): void {
  cron.schedule("0 3 * * *", async () => {
    if (running) {
      console.warn("Sentinella 24/7: lo scan precedente è ancora in corso, salto questo giro");
      return;
    }
    running = true;
    try {
      await runSentinelScan();
    } catch (err) {
      console.error("Sentinella 24/7: errore durante lo scan notturno", err);
      reportError(err);
    } finally {
      running = false;
    }
  });
}
