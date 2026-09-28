import { Router } from "express";
import { z } from "zod";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { ensureOwnTeam, MAX_TEAM_SEATS } from "../team.js";

export const teamRouter = Router();

async function getOwnTeamId(userId: string): Promise<string | null> {
  const { data } = await supabaseAdmin.from("teams").select("id").eq("owner_id", userId).maybeSingle();
  return data?.id ?? null;
}

async function getMemberTeamId(userId: string): Promise<string | null> {
  const { data } = await supabaseAdmin
    .from("team_members")
    .select("team_id")
    .eq("user_id", userId)
    .not("joined_at", "is", null)
    .maybeSingle();
  return data?.team_id ?? null;
}

teamRouter.get("/api/team", requireAuth, async (req: AuthedRequest, res) => {
  const ownedTeamId = await getOwnTeamId(req.userId!);
  const teamId = ownedTeamId ?? (await getMemberTeamId(req.userId!));
  if (!teamId) {
    res.json({ team: null });
    return;
  }

  const { data: members, error } = await supabaseAdmin
    .from("team_members")
    .select("email, role, invited_at, joined_at")
    .eq("team_id", teamId)
    .order("invited_at", { ascending: true });

  if (error) {
    res.status(500).json({ error: "Errore nel recupero del team" });
    return;
  }

  res.json({ team: { isOwner: ownedTeamId !== null, members } });
});

const inviteSchema = z.object({ email: z.string().email() });

teamRouter.post("/api/team/invite", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = inviteSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Email non valida" });
    return;
  }

  // Controllato sul piano grezzo del proprio profilo (non su getPlanForUser,
  // che per un membro invitato eredita "team" dal proprietario): solo chi ha
  // davvero acquistato il piano può invitare, non un membro già invitato.
  const { data: ownProfile } = await supabaseAdmin.from("profiles").select("plan").eq("id", req.userId!).single();
  if (ownProfile?.plan !== "team") {
    res.status(403).json({ error: "Solo chi ha acquistato il piano Team può invitare altre persone" });
    return;
  }

  const teamId = await ensureOwnTeam(req.userId!, req.userEmail!);

  const { count } = await supabaseAdmin
    .from("team_members")
    .select("email", { count: "exact", head: true })
    .eq("team_id", teamId);

  if ((count ?? 0) >= MAX_TEAM_SEATS) {
    res.status(409).json({ error: `Il piano Team include al massimo ${MAX_TEAM_SEATS} persone` });
    return;
  }

  const email = parsed.data.email.toLowerCase();
  const { error } = await supabaseAdmin.from("team_members").insert({ team_id: teamId, email, role: "member" });

  if (error) {
    if (error.code === "23505") {
      res.status(409).json({ error: "Questa persona è già stata invitata" });
      return;
    }
    // Scatta solo nella rara finestra in cui due inviti arrivano nello stesso
    // istante e superano il controllo sopra prima che l'altro abbia scritto:
    // il trigger a livello di database (migrazione 0010) blocca comunque il
    // sesto posto, qui traduciamo il suo errore in un messaggio leggibile.
    if (error.message?.includes("team seat limit reached")) {
      res.status(409).json({ error: `Il piano Team include al massimo ${MAX_TEAM_SEATS} persone` });
      return;
    }
    res.status(500).json({ error: "Errore nell'invito" });
    return;
  }

  res.json({ ok: true });
});

teamRouter.delete("/api/team/members/:email", requireAuth, async (req: AuthedRequest, res) => {
  const teamId = await getOwnTeamId(req.userId!);
  if (!teamId) {
    res.status(403).json({ error: "Solo chi ha creato il team può rimuovere membri" });
    return;
  }

  const email = req.params.email.toLowerCase();
  if (email === req.userEmail?.toLowerCase()) {
    res.status(400).json({ error: "Non puoi rimuovere te stesso, proprietario del team" });
    return;
  }

  const { error } = await supabaseAdmin.from("team_members").delete().eq("team_id", teamId).eq("email", email);

  if (error) {
    res.status(500).json({ error: "Errore nella rimozione" });
    return;
  }

  res.json({ ok: true });
});