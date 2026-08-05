import { Router } from "express";
import { z } from "zod";
import { supabaseAdmin } from "../db/supabase.js";

export const waitlistRouter = Router();

const requestSchema = z.object({ email: z.string().email().max(320) });

waitlistRouter.post("/api/waitlist", async (req, res) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Email non valida" });
    return;
  }

  const { error } = await supabaseAdmin
    .from("waitlist_emails")
    .upsert({ email: parsed.data.email }, { onConflict: "email", ignoreDuplicates: true });

  if (error) {
    res.status(500).json({ error: "Errore nel salvataggio" });
    return;
  }

  res.status(201).json({ joined: true });
});
