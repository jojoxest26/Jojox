import cors from "cors";
import express, { type Express } from "express";
import { env } from "./env.js";
import { analyzeRouter } from "./routes/analyze.js";
import { analysesRouter } from "./routes/analyses.js";
import { waitlistRouter } from "./routes/waitlist.js";
import { badgeRouter } from "./routes/badge.js";
import { guestAnalyzeRouter } from "./routes/guestAnalyze.js";
import { githubWebhookRouter } from "./routes/webhooks/github.js";
import { stripeWebhookRouter } from "./routes/webhooks/stripe.js";
import { stripeRouter } from "./routes/stripe.js";
import { profileRouter } from "./routes/profile.js";

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
      methods: ["GET", "POST"],
      allowedHeaders: ["Content-Type", "Authorization"],
    })
  );
  app.use(express.json({ limit: "2mb" }));

  app.get("/api/health", (_req, res) => res.json({ ok: true }));
  app.use(analyzeRouter);
  app.use(analysesRouter);
  app.use(waitlistRouter);
  app.use(badgeRouter);
  app.use(guestAnalyzeRouter);
  app.use(stripeRouter);
  app.use(profileRouter);

  return app;
}