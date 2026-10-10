// Va importato prima di ogni rotta: intercetta le promise non gestite
// nei gestori async (Express 4 non lo fa da solo), così un errore inatteso
// risponde con un 500 invece di lasciare la richiesta in sospeso o far
// crashare il processo — e arriva comunque a Sentry più sotto.
import "express-async-errors";
import cors from "cors";
import express, { type Express } from "express";
import { env } from "./env.js";
import { Sentry } from "./sentry.js";
import { analyzeRouter } from "./routes/analyze.js";
import { analysesRouter } from "./routes/analyses.js";
import { waitlistRouter } from "./routes/waitlist.js";
import { badgeRouter } from "./routes/badge.js";
import { publicScoreRouter } from "./routes/publicScore.js";
import { guestAnalyzeRouter } from "./routes/guestAnalyze.js";
import { githubWebhookRouter } from "./routes/webhooks/github.js";
import { stripeWebhookRouter } from "./routes/webhooks/stripe.js";
import { stripeRouter } from "./routes/stripe.js";
import { profileRouter } from "./routes/profile.js";
import { githubRouter } from "./routes/github.js";
import { auditCreditsRouter } from "./routes/auditCredits.js";
import { analyzeAuditRouter } from "./routes/analyzeAudit.js";
import { planTrialRouter } from "./routes/planTrial.js";
import { teamRouter } from "./routes/team.js";
import { sentinelRouter } from "./routes/sentinel.js";

export function createApp(): Express {
  const app = express();

  // Railway mette il server dietro un proxy: senza questo, req.ip vedrebbe
  // sempre l'IP del proxy invece di quello di chi visita, e il limite di
  // un'analisi gratuita per IP (guestAnalyzeRouter) diventerebbe inutile —
  // un solo slot condiviso da chiunque.
  app.set("trust proxy", 1);

  // I webhook GitHub e Stripe verificano una firma HMAC sul corpo grezzo
  // della richiesta, quindi vanno montati prima del parser JSON generico
  // (che lo trasformerebbe).
  app.use(githubWebhookRouter);
  app.use(stripeWebhookRouter);

  app.use(
    cors({
      origin: env.allowedOrigins,
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
    })
  );

  // Un Full Site Audit carica un intero progetto, non poche modifiche: gli
  // serve un limite di corpo più alto del resto dell'API. Va montato prima
  // del parser generico, altrimenti quello con il limite più basso avrebbe
  // già troncato/rifiutato la richiesta.
  app.use("/api/analyze-audit", express.json({ limit: "20mb" }));
  app.use(express.json({ limit: "2mb" }));

  app.get("/api/health", (_req, res) => res.json({ ok: true }));
  app.use(analyzeRouter);
  app.use(analysesRouter);
  app.use(waitlistRouter);
  app.use(badgeRouter);
  app.use(publicScoreRouter);
  app.use(guestAnalyzeRouter);
  app.use(stripeRouter);
  app.use(profileRouter);
  app.use(githubRouter);
  app.use(auditCreditsRouter);
  app.use(analyzeAuditRouter);
  app.use(planTrialRouter);
  app.use(teamRouter);
  app.use(sentinelRouter);

  // Va montato dopo tutte le rotte (è lì che intercetta i loro errori) e
  // prima del nostro gestore finale, che chiude sempre la risposta — se
  // Sentry non è configurata, setupExpressErrorHandler non fa nulla di male,
  // ma lo chiamiamo solo quando c'è una DSN per restare coerenti con
  // initSentry().
  if (env.sentryDsn) Sentry.setupExpressErrorHandler(app);

  // Ultima rete di sicurezza: qualunque errore non gestito da una rotta
  // (anche senza Sentry configurata) riceve comunque una risposta pulita,
  // invece di lasciare la richiesta in sospeso.
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error("Errore non gestito in una rotta", err);
    if (res.headersSent) return;
    res.status(500).json({ error: "Errore interno del server" });
  });

  return app;
}