import { env } from "./env.js";
import { createApp } from "./app.js";
import { startSentinelCron } from "./sentinel/cron.js";
import { initSentry } from "./sentry.js";

// Prima di costruire l'app e avviare il cron: cattura gli errori delle
// richieste e degli scan notturni, non quelli durante il caricamento stesso
// dei moduli (es. una variabile d'ambiente mancante) — quel caso è comunque
// visibile da solo nei log di deploy di Railway, prima ancora che il
// server risponda, ed è coperto dal controllo esterno del punto 15
// (es. UptimeRobot), non da Sentry.
initSentry();

const app = createApp();

app.listen(env.port, () => {
  console.log(`JoJoX backend in ascolto sulla porta ${env.port}`);
});

startSentinelCron();
