import cors from "cors";
import express, { type Express } from "express";
import { env } from "./env.js";
import { analyzeRouter } from "./routes/analyze.js";
import { analysesRouter } from "./routes/analyses.js";
import { waitlistRouter } from "./routes/waitlist.js";
import { githubWebhookRouter } from "./routes/webhooks/github.js";

export function createApp(): Express {
  const app = express();

  // Il webhook GitHub verifica una firma HMAC sul corpo grezzo della richiesta,
  // quindi va montato prima del parser JSON generico (che lo trasformerebbe).
  app.use(githubWebhookRouter);

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

  return app;
}
