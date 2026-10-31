import { createHash } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { analyzeFiles } from "../../analyze.js";
import { scanDependencies } from "../../depscan.js";
import { computeScore, summarizeBySeverity } from "../../scoring.js";
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

  // Riserviamo lo slot PRIMA di analizzare, non dopo: un controllo "esiste
  // già?" seguito da una scrittura solo a fine analisi lascia una finestra
  // (qui, una chiamata di rete a OSV.dev) in cui più richieste contemporanee
  // dallo stesso IP passano tutte il controllo — l'indice unico su ip_hash
  // (migrazione 0023) rende questo inserimento stesso la verifica atomica:
  // il codice 23505 è "era già qui", non un errore reale, stesso principio
  // usato per l'idempotenza dei pagamenti Stripe.
  const { error: reserveError } = await supabaseAdmin.from("guest_analyses").insert({ ip_hash: ipHash });

  if (reserveError) {
    if (reserveError.code === "23505") {
      res.status(429).json({
        error: "Hai già usato la tua analisi gratuita senza account. Accedi con l'email per continuare — 5 analisi gratuite al mese.",
      });
      return;
    }
    res.status(500).json({ error: "Errore nel controllo del limite, riprova" });
    return;
  }

  try {
    const depFindings = await scanDependencies(parsed.data.files);
    const findings = [...analyzeFiles(parsed.data.files).findings, ...depFindings];
    const result = { score: computeScore(findings), findings, summary: summarizeBySeverity(findings) };
    res.json(result);
  } catch (err) {
    // Lo slot è già riservato sopra: se l'analisi fallisce per un motivo
    // nostro (es. OSV.dev irraggiungibile), togliamo la riserva per non far
    // perdere al visitatore il suo unico tentativo gratuito per un errore
    // che non dipende da lui — stesso principio già usato per le revisioni AI.
    await supabaseAdmin.from("guest_analyses").delete().eq("ip_hash", ipHash);
    console.error("Errore nell'analisi gratuita senza account", err);
    res.status(500).json({ error: "Errore nell'analisi, riprova" });
  }
});