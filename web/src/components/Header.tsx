import { useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "../lib/supabaseClient.js";
import { LoginPanel } from "./LoginPanel.js";

const GITHUB_APP_SLUG = import.meta.env.VITE_GITHUB_APP_SLUG;

export function Header({ session }: { session: Session | null }) {
  const [loginOpen, setLoginOpen] = useState(false);

  return (
    <header className="header">
      <div className="container header-inner">
        <span className="logo">JoJoX</span>
        <div className="header-actions">
          <a
            className="btn btn-secondary"
            href={`https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`}
            target="_blank"
            rel="noreferrer"
          >
            Collega GitHub
          </a>
          {session ? (
            <>
              <span className="user-email">{session.user.email}</span>
              <button type="button" className="btn btn-secondary" onClick={() => supabase.auth.signOut()}>
                Esci
              </button>
            </>
          ) : (
            <div className="login-panel-anchor">
              <button type="button" className="btn btn-primary" onClick={() => setLoginOpen((v) => !v)}>
                Accedi
              </button>
              {loginOpen && <LoginPanel onClose={() => setLoginOpen(false)} />}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
