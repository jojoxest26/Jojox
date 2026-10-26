import { Router } from "express";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";

export const auditCreditsRouter = Router();

auditCreditsRouter.get("/api/audit-credits", requireAuth, async (req: AuthedRequest, res) => {
  const { data, error } = await supabaseAdmin
    .from("audit_credits")
    .select("tier")
    .eq("user_id", req.userId)
    .eq("status", "unused");

  if (error) {
    res.status(500).json({ error: "Errore nel controllo dei Full Site Audit disponibili" });
    return;
  }

  const availableBusiness = data.filter((row) => row.tier === "business").length;
  res.json({ available: data.length, availableBusiness });
});