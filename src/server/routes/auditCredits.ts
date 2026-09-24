import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";

export const auditCreditsRouter = Router();

auditCreditsRouter.get("/api/audit-credits", requireAuth, async (req: AuthedRequest, res) => {
  const { count, error } = await supabaseAdmin
    .from("audit_credits")
    .select("id", { count: "exact", head: true })
    .eq("user_id", req.userId)
    .eq("status", "unused");

  if (error) {
    res.status(500).json({ error: "Errore nel controllo dei Full Site Audit disponibili" });
    return;
  }

  res.json({ available: count ?? 0 });
});