import { Router } from "express";
import { z } from "zod";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getGithubApp } from "../github/app.js";
import { listInstallationRepos } from "../github/auditFixPr.js";
import { getPlanForUser } from "../plan.js";
import { getTeamUserIds } from "../team.js";

export const githubRouter = Router();

const SLACK_WEBHOOK_PATTERN = /^https:\/\/hooks\.slack\.com\/services\/.+/;

// Unica vera differenza tra Pro e Team: quanti account/organizzazioni GitHub
// si possono collegare per il monitoraggio continuo. Team ne collega quanti
// vuole, Pro (e free) si fermano a uno.
const MAX_INSTALLATIONS_NON_TEAM = 1;

githubRouter.get("/api/github/installations", requireAuth, async (req: AuthedRequest, res) => {
  // Team condivide i repository collegati tra tutti i membri, non solo chi
  // li ha collegati di persona — è la dashboard condivisa del piano Team.
  const teamUserIds = await getTeamUserIds(req.userId!);
  const { data, error } = await supabaseAdmin
    .from("github_installations")
    .select("installation_id, account_login, slack_webhook_url")
    .in("installed_by", teamUserIds);

  if (error) {
    res.status(500).json({ error: "Errore nel recupero delle installazioni" });
    return;
  }

  res.json({ installations: data });
});

// Genera un token "state" monouso, valido 30 minuti, da passare a GitHub
// nell'URL di installazione — GitHub lo restituisce intatto nel redirect
// finale, e /claim lo richiede per verificare che chi completa il
// collegamento sia davvero chi ha cliccato "Connetti GitHub" qui, non
// chiunque altro riesca a indovinare l'installation_id (un intero piccolo).
githubRouter.post("/api/github/install-state", requireAuth, async (req: AuthedRequest, res) => {
  const { data, error } = await supabaseAdmin
    .from("github_install_states")
    .insert({ user_id: req.userId! })
    .select("state")
    .single();

  if (error || !data) {
    res.status(500).json({ error: "Errore nella generazione del collegamento" });
    return;
  }

  res.json({ state: data.state as string });
});

const STATE_MAX_AGE_MS = 30 * 60 * 1000;

// Collega un'installazione della GitHub App all'utente loggato. GitHub reindirizza
// qui (via "Setup URL" nelle impostazioni della App) subito dopo l'installazione,
// passando l'installation_id nell'URL — senza questo passaggio, il webhook che
// registra l'installazione non saprebbe a quale utente JoJoX appartiene.
const claimSchema = z.object({ state: z.string().uuid() });

githubRouter.post("/api/github/installations/:installationId/claim", requireAuth, async (req: AuthedRequest, res) => {
  const installationId = Number(req.params.installationId);

  const parsed = claimSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Collegamento non valido, riprova dal pulsante Connetti GitHub" });
    return;
  }

  // Consuma il token "state": una volta sola, solo se appartiene a questo
  // stesso utente ed è stato generato negli ultimi 30 minuti. Senza questo
  // controllo chiunque fosse loggato poteva rivendicare l'installazione di
  // un altro semplicemente indovinando l'installation_id nell'URL.
  const { data: consumedState, error: stateError } = await supabaseAdmin
    .from("github_install_states")
    .delete()
    .eq("state", parsed.data.state)
    .eq("user_id", req.userId!)
    .gte("created_at", new Date(Date.now() - STATE_MAX_AGE_MS).toISOString())
    .select("state");

  if (stateError) {
    res.status(500).json({ error: "Errore nel controllo del collegamento" });
    return;
  }

  if (!consumedState || consumedState.length === 0) {
    res.status(403).json({ error: "Collegamento scaduto o non valido, riprova dal pulsante Connetti GitHub" });
    return;
  }

  const { data: installation } = await supabaseAdmin
    .from("github_installations")
    .select("installed_by")
    .eq("installation_id", installationId)
    .single();

  if (!installation) {
    res.status(404).json({ error: "Installazione non trovata" });
    return;
  }

  // Già collegata a questo stesso utente: nessuna azione, va bene così.
  // Già collegata a un utente diverso: non la sovrascriviamo silenziosamente.
  if (installation.installed_by && installation.installed_by !== req.userId) {
    res.status(409).json({ error: "Questa installazione è già collegata a un altro account" });
    return;
  }

  // Un nuovo collegamento (non un ri-collegamento allo stesso account): il
  // piano Pro può averne al massimo uno, solo Team può collegarne quanti vuole.
  if (!installation.installed_by) {
    const plan = await getPlanForUser(req.userId!);
    if (plan !== "team" && plan !== "business") {
      const { count } = await supabaseAdmin
        .from("github_installations")
        .select("installation_id", { count: "exact", head: true })
        .eq("installed_by", req.userId);

      if ((count ?? 0) >= MAX_INSTALLATIONS_NON_TEAM) {
        res.status(403).json({
          error: "Il piano Pro può collegare un solo account/organizzazione GitHub. Passa a Team per collegarne quanti vuoi.",
        });
        return;
      }
    }
  }

  const { error } = await supabaseAdmin
    .from("github_installations")
    .update({ installed_by: req.userId })
    .eq("installation_id", installationId)
    .is("installed_by", null);

  if (error) {
    res.status(500).json({ error: "Errore nel collegamento dell'installazione" });
    return;
  }

  res.json({ ok: true });
});

// Elenca i repository accessibili a un'installazione dell'utente loggato —
// usato per lasciargli scegliere su quale repo aprire una Pull Request di
// correzione dopo un Full Site Audit.
githubRouter.get("/api/github/installations/:installationId/repos", requireAuth, async (req: AuthedRequest, res) => {
  const installationId = Number(req.params.installationId);

  const { data: installation } = await supabaseAdmin
    .from("github_installations")
    .select("installed_by")
    .eq("installation_id", installationId)
    .single();

  const teamUserIds = await getTeamUserIds(req.userId!);
  if (!installation || !installation.installed_by || !teamUserIds.includes(installation.installed_by)) {
    res.status(404).json({ error: "Installazione non trovata" });
    return;
  }

  try {
    const octokit = await getGithubApp().getInstallationOctokit(installationId);
    const repos = await listInstallationRepos(octokit);
    res.json({ repos });
  } catch (err) {
    console.error(`impossibile elencare i repository dell'installazione ${installationId}`, err);
    res.status(500).json({ error: "Errore nel recupero dei repository" });
  }
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

  const teamUserIds = await getTeamUserIds(req.userId!);
  if (!installation || !installation.installed_by || !teamUserIds.includes(installation.installed_by)) {
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