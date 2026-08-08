import { createHash } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { analyzeFiles } from "../../analyze.js";
import { supabaseAdmin } from "../db/supabase.js";

const MAX_FILES = 300;
const MAX_FILE_BYTES = 200_000;

export const requestSchema = z.object({
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

/**
 * Solo per distinguere le visite nella tabella guest_analyses, non per
 * identificare nessuno: l'IP grezzo non viene mai salvato.
 */
export function hashIp(ip: string): string {
  return createHash("sha256").update(ip).digest("hex");
}

export const guestAnalyzeRouter = Router();

guestAnalyzeRouter.post("/api/guest-analyze", async (req, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Richiesta non valida", details: parsed.error.flatten() });
    return;
  }

  const ipHash = hashIp(req.ip ?? "unknown");

  const { data: existing } = await supabaseAdmin
    .from("guest_analyses")
    .select("ip_hash")
    .eq("ip_hash", ipHash)
    .maybeSingle();

  if (existing) {
    res.status(429).json({
      error: "Hai già usato la tua analisi gratuita senza account. Accedi con l'email per continuare — 5 analisi gratuite al mese.",
    });
    return;
  }

  const result = analyzeFiles(parsed.data.files);

  // Registriamo l'uso solo dopo aver calcolato il risultato: se l'analisi
  // fallisce sopra, la visita non perde il suo unico tentativo gratuito.
  await supabaseAdmin.from("guest_analyses").insert({ ip_hash: ipHash });

  res.json(result);
});