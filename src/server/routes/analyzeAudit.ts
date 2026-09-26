import { Router } from "express";
import { z } from "zod";
import { analyzeFiles, applyAutofixes } from "../../analyze.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { getGithubApp } from "../github/app.js";
import { openAuditFixPr, getRepoFilePaths } from "../github/auditFixPr.js";

// Sotto questa quota di file caricati già presenti nel repository scelto,
// consideriamo probabile uno scambio di repository (es. selezionato quello
// sbagliato dal menu) e non apriamo la Pull Request in automatico.
const MIN_REPO_OVERLAP_RATIO = 0.3;

// Un Full Site Audit copre un intero progetto, non poche modifiche: limite
// più alto dell'analisi normale (300), ma comunque un tetto per evitare
// richieste ingestibili. Il limite di byte per file resta lo stesso.
const MAX_FILES = 2000;
const MAX_FILE_BYTES = 200_000;

const requestSchema = z.object({
  files: z
    .array(
      z.object({
        path: z.string().min(1).max(500),
        content: z.string().max(MAX_FILE_BYTES),
      })
    )
    .min(1)
    .max(MAX_FILES),
  // Facoltativo: se il cliente sceglie un repository GitHub collegato, invece
  // (o oltre) di scaricare lo zip apriamo una Pull Request con le correzioni
  // automatiche direttamente su quel repository.
  githubTarget: z
    .object({
      installationId: z.number(),
      owner: z.string().min(1),
      repo: z.string().min(1),
    })
    .optional(),
});

export const analyzeAuditRouter = Router();

analyzeAuditRouter.post("/api/analyze-audit", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
  }

  const { githubTarget } = parsed.data;
  if (githubTarget) {
    const { data: installation } = await supabaseAdmin
      .from("github_installations")
      .select("installed_by")
      .eq("installation_id", githubTarget.installationId)
      .single();

    if (!installation || installation.installed_by !== req.userId) {
      res.status(403).json({ error: "Installazione GitHub non trovata o non collegata al tuo account" });
      return;
    }
  }

  const { data: credit, error: creditError } = await supabaseAdmin
    .from("audit_credits")
    .select("id")
    .eq("user_id", req.userId)
    .eq("status", "unused")
    .order("created_at", { ascending: true })
    .limit(1)
    .maybeSingle();

  if (creditError) {
    res.status(500).json({ error: "Errore nel controllo dei Full Site Audit disponibili" });
    return;
  }

  if (!credit) {
    res.status(402).json({ error: "Nessun Full Site Audit disponibile — acquistane uno per continuare." });
    return;
  }

  const result = analyzeFiles(parsed.data.files);

  // Segna il credito come usato prima di rispondere: se qualcosa fallisce
  // dopo, meglio un credito consumato senza risultato (raro, va contattato
  // il supporto) che uno stesso credito riusabile all'infinito per errore.
  await supabaseAdmin
    .from("audit_credits")
    .update({ status: "used", used_at: new Date().toISOString() })
    .eq("id", credit.id);

  await supabaseAdmin.from("analyses").insert({
    user_id: req.userId,
    source: "manual",
    score: result.score,
    summary: result.summary,
    findings: result.findings,
  });

  let prUrl: string | null = null;
  let prSkipped: "mismatch" | null = null;
  if (githubTarget) {
    // La correzione qui gira sempre lato server (a differenza dell'analisi
    // manuale nel browser): serve il contenuto corretto per poterlo davvero
    // pushare su GitHub tramite l'installazione della GitHub App.
    const autofix = applyAutofixes(parsed.data.files);
    const changedFiles = autofix.changedFiles;

    if (changedFiles.length > 0) {
      try {
        const octokit = await getGithubApp().getInstallationOctokit(githubTarget.installationId);

        // I file caricati dovrebbero essere il codice di quello stesso
        // repository: controlliamo la sovrapposizione prima di aprire una PR,
        // per non proporre correzioni a caso se è stato scelto il repository
        // sbagliato dal menu.
        const repoPaths = await getRepoFilePaths(octokit, { owner: githubTarget.owner, repo: githubTarget.repo });
        const overlap = parsed.data.files.filter((f) => repoPaths.has(f.path)).length / parsed.data.files.length;

        if (overlap < MIN_REPO_OVERLAP_RATIO) {
          prSkipped = "mismatch";
        } else {
          prUrl = await openAuditFixPr(octokit, {
            owner: githubTarget.owner,
            repo: githubTarget.repo,
            changedFiles,
            fixedCheckIds: autofix.fixedCheckIds,
            filesChanged: autofix.filesChanged,
          });
        }
      } catch (err) {
        console.error(
          `impossibile aprire la pull request di correzione su ${githubTarget.owner}/${githubTarget.repo}`,
          err
        );
        // Non facciamo fallire l'intera risposta per questo: l'analisi e il
        // credito sono comunque validi, l'utente ha comunque lo zip da scaricare.
      }
    }
  }

  res.json({ ...result, prUrl, prSkipped });
});