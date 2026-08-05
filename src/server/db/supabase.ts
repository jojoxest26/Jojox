import { createClient } from "@supabase/supabase-js";
import { env } from "../env.js";

/**
 * Client con la service role key: bypassa la RLS. Va usato solo lato
 * server, mai esposto al browser — è per questo che l'engine segnala
 * come critico ogni service role key che finisce in codice client.
 */
export const supabaseAdmin = createClient(env.supabaseUrl, env.supabaseServiceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});
