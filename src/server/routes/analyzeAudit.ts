import { Router } from "express";
import { z } from "zod";
import { analyzeFiles } from "../../analyze.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";

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
});

export const analyzeAuditRouter = Router();

analyzeAuditRouter.post("/api/analyze-audit", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
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

  res.json(result);
});