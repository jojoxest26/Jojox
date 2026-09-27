import { supabaseAdmin } from "./db/supabase.js";

/** Quante persone (proprietario incluso) può includere un team — vedi punto 10 della lista. */
export const MAX_TEAM_SEATS = 5;

/**
 * Gli id utente che condividono la dashboard con `userId`: se fa parte di un
 * team (come proprietario o membro entrato), tutti i membri già entrati —
 * altrimenti solo se stesso. Usata per condividere repository collegati e
 * storico analisi tra i membri, la vera differenza tra Pro e Team.
 */
export async function getTeamUserIds(userId: string): Promise<string[]> {
  const { data: membership } = await supabaseAdmin
    .from("team_members")
    .select("team_id")
    .eq("user_id", userId)
    .not("joined_at", "is", null)
    .maybeSingle();

  if (!membership) return [userId];

  const { data: members } = await supabaseAdmin
    .from("team_members")
    .select("user_id")
    .eq("team_id", membership.team_id)
    .not("user_id", "is", null);

  const ids = (members ?? []).map((m) => m.user_id as string);
  return ids.length > 0 ? ids : [userId];
}

/**
 * Crea il team del proprietario se non esiste già (idempotente) — chiamata
 * solo da rotte che hanno già verificato che l'utente ha davvero il piano
 * Team, mai in automatico per chiunque.
 */
export async function ensureOwnTeam(ownerId: string, ownerEmail: string): Promise<string> {
  const { data: existing } = await supabaseAdmin.from("teams").select("id").eq("owner_id", ownerId).maybeSingle();
  if (existing) return existing.id;

  const { data: created, error } = await supabaseAdmin.from("teams").insert({ owner_id: ownerId }).select("id").single();
  if (error || !created) throw new Error(`impossibile creare il team per ${ownerId}: ${error?.message}`);

  await supabaseAdmin.from("team_members").insert({
    team_id: created.id,
    user_id: ownerId,
    email: ownerEmail.toLowerCase(),
    role: "owner",
    joined_at: new Date().toISOString(),
  });

  return created.id;
}

/**
 * Da chiamare a ogni login: se questa email ha un invito in sospeso (nessun
 * user_id collegato ancora), lo completa collegandolo all'account appena
 * autenticato. Non fa nulla se non c'è nessun invito — sicura da chiamare
 * sempre, anche per chi non è mai stato invitato.
 */
export async function claimPendingTeamInvite(userId: string, email: string | undefined): Promise<void> {
  if (!email) return;
  await supabaseAdmin
    .from("team_members")
    .update({ user_id: userId, joined_at: new Date().toISOString() })
    .eq("email", email.toLowerCase())
    .is("user_id", null);
}