import cron from "node-cron";
import { runSyntheticChecks } from "./syntheticCheck.js";
import { reportError } from "./sentry.js";

/** Punto 15 bis: un giro di controllo ogni 15 minuti su Stripe, Anthropic e GitHub. */
export function startSyntheticCheckCron(): void {
  cron.schedule("*/15 * * * *", async () => {
    try {
      await runSyntheticChecks();
    } catch (err) {
      console.error("Controllo sintetico: errore imprevisto nel giro programmato", err);
      reportError(err);
    }
  });
}
