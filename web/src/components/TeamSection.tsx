import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { fetchProfile, fetchTeam, inviteTeamMember, removeTeamMember, type Plan, type TeamInfo } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { interpolate } from "../i18n/richText.js";

const MAX_TEAM_SEATS = 5;

export function TeamSection({ session }: { session: Session | null }) {
  const { t } = useTranslation();
  const [plan, setPlan] = useState<Plan | null>(null);
  const [team, setTeam] = useState<TeamInfo | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [email, setEmail] = useState("");
  const [inviting, setInviting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!session) {
      setPlan(null);
      setTeam(null);
      setLoaded(false);
      return;
    }
    Promise.all([fetchProfile(session.access_token), fetchTeam(session.access_token)])
      .then(([p, tm]) => {
        setPlan(p);
        setTeam(tm);
      })
      .catch(() => {})
      .finally(() => setLoaded(true));
  }, [session]);

  async function refreshTeam() {
    if (!session) return;
    const tm = await fetchTeam(session.access_token).catch(() => null);
    setTeam(tm);
  }

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!session) return;
    setError(null);
    setInviting(true);
    try {
      await inviteTeamMember(email.trim(), session.access_token);
      setEmail("");
      await refreshTeam();
    } catch (err) {
      setError(err instanceof Error ? err.message : t.team.errorInvite);
    } finally {
      setInviting(false);
    }
  }

  async function handleRemove(memberEmail: string) {
    if (!session) return;
    setError(null);
    try {
      await removeTeamMember(memberEmail, session.access_token);
      await refreshTeam();
    } catch (err) {
      setError(err instanceof Error ? err.message : t.team.errorRemove);
    }
  }

  // Niente da mostrare se non è ancora arrivata la risposta, o se il piano
  // non è Team — questa sezione esiste solo per chi ha davvero i seat.
  if (!loaded || plan !== "team") return null;

  // Nessun team creato ancora (mai invitato nessuno): sei tu, il proprietario.
  const members = team?.members ?? [];
  const isOwner = team?.isOwner ?? true;
  const seatsUsed = Math.max(members.length, 1);

  return (
    <>
      <div className="section-divider container">
        <div className="trace"></div>
        <span className="tag">{t.dividers.team}</span>
        <div className="trace right"></div>
      </div>
      <section className="team-section container">
        <h2>{t.team.title}</h2>
        <p>{t.team.body}</p>

        <div className="card team-card">
          <p className="team-seats-count">{interpolate(t.team.seatsCount, { used: String(seatsUsed), max: String(MAX_TEAM_SEATS) })}</p>

          <ul className="team-member-list">
            {members.length === 0 && session?.user.email && (
              <li className="team-member-row">
                <span className="team-member-email">{session.user.email}</span>
                <span className="pill pill-mint">{t.team.roleOwner}</span>
              </li>
            )}
            {members.map((m) => (
              <li key={m.email} className="team-member-row">
                <span className="team-member-email">{m.email}</span>
                <span className="pill pill-mint">
                  {m.role === "owner" ? t.team.roleOwner : m.joinedAt ? t.team.roleMember : t.team.roleInvited}
                </span>
                {isOwner && m.role !== "owner" && (
                  <button type="button" className="team-member-remove" onClick={() => handleRemove(m.email)}>
                    {t.team.remove}
                  </button>
                )}
              </li>
            ))}
          </ul>

          {isOwner && seatsUsed < MAX_TEAM_SEATS && (
            <form className="team-invite-form" onSubmit={handleInvite}>
              <input
                type="email"
                required
                placeholder={t.team.invitePlaceholder}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <button type="submit" className="btn btn-primary hard-border hard-shadow-sm" disabled={inviting}>
                {inviting ? t.team.inviting : t.team.inviteCta}
              </button>
            </form>
          )}
          {isOwner && seatsUsed >= MAX_TEAM_SEATS && <p className="dropzone-hint">{t.team.seatsFull}</p>}
          {error && <p style={{ color: "var(--critical)" }}>{error}</p>}
        </div>
      </section>
    </>
  );
}