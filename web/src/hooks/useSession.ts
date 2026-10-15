import { useEffect, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "../lib/supabaseClient.js";
import { claimInvite } from "../lib/api.js";

export function useSession() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const claimedForUserRef = useRef<string | null>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setLoading(false);
    });

    const { data: subscription } = supabase.auth.onAuthStateChange((_event, newSession) => {
      setSession(newSession);
    });

    return () => subscription.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!session || claimedForUserRef.current === session.user.id) return;
    claimedForUserRef.current = session.user.id;
    // Un eventuale invito Team in sospeso per questa email si completa qui,
    // una sola volta per sessione — non più dentro /api/profile, chiamato
    // da più pagine e anche più volte sulla stessa pagina. Non blocca
    // nient'altro: se capita nello stesso istante in cui qualcuno legge il
    // piano appena accettato un invito, quel primo caricamento potrebbe non
    // vederlo ancora — si sistema da solo al giro dopo, un compromesso
    // accettabile per non pagare questa richiesta in più ad ogni apertura
    // di chiunque, per un caso che càpita una sola volta per persona.
    claimInvite(session.access_token).catch(() => {});
  }, [session]);

  return { session, loading };
}
