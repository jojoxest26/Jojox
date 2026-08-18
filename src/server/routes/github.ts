import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";

export const githubRouter = Router();

const SLACK_WEBHOOK_PATTERN = /^https:\/\/hooks\.slack\.com\/services\/.+/;

githubRouter.get("/api/github/installations", requireAuth, async (req: AuthedRequest, res) => {
  const { data, error } = await supabaseAdmin
    .from("github_installations")
    .select("installation_id, account_login, slack_webhook_url")
    .eq("installed_by", req.userId);

  if (error) {
    res.status(500).json({ error: "Errore nel recupero delle installazioni" });
    return;
  }

  res.json({ installations: data });
});

githubRouter.put("/api/github/installations/:installationId/slack-webhook", requireAuth, async (req: AuthedRequest, res) => {
  const installationId = Number(req.params.installationId);
  const slackWebhookUrl: string | null = req.body?.slackWebhookUrl || null;

  if (slackWebhookUrl && !SLACK_WEBHOOK_PATTERN.test(slackWebhookUrl)) {
    res.status(400).json({ error: "Non sembra un URL di webhook Slack valido (deve iniziare con https://hooks.slack.com/services/)" });
    return;
  }

  const { data: installation } = await supabaseAdmin
    .from("github_installations")
    .select("installed_by")
    .eq("installation_id", installationId)
    .single();

  if (!installation || installation.installed_by !== req.userId) {
    res.status(404).json({ error: "Installazione non trovata" });
    return;
  }

  const { error } = await supabaseAdmin
    .from("github_installations")
    .update({ slack_webhook_url: slackWebhookUrl })
    .eq("installation_id", installationId);

  if (error) {
    res.status(500).json({ error: "Errore nel salvataggio" });
    return;
  }

  res.json({ ok: true });
});