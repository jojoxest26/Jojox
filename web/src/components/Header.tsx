import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "../lib/supabaseClient.js";
import { LoginPanel } from "./LoginPanel.js";
import type { GithubInstallation } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import type { Lang } from "../i18n/translations.js";

const GITHUB_APP_SLUG = import.meta.env.VITE_GITHUB_APP_SLUG;

export function LanguageSwitcher() {
  const { lang, setLang } = useTranslation();

  function toggle(next: Lang) {
    if (next !== lang) setLang(next);
  }

  return (
    <div className="lang-switcher" role="group" aria-label="Lingua / Language">
      <button
        type="button"
        className={lang === "it" ? "lang-btn lang-btn-active" : "lang-btn"}
        onClick={() => toggle("it")}
      >
        IT
      </button>
      <button
        type="button"
        className={lang === "en" ? "lang-btn lang-btn-active" : "lang-btn"}
        onClick={() => toggle("en")}
      >
        EN
      </button>
    </div>
  );
}

export function Header({ session, installations }: { session: Session | null; installations: GithubInstallation[] | null }) {
  const { t } = useTranslation();
  const [loginOpen, setLoginOpen] = useState(false);
  const connected = installations !== null && installations.length > 0;

  useEffect(() => {
    if (session) return;
    const openLogin = () => setLoginOpen(true);
    window.addEventListener("jojox-open-login", openLogin);
    return () => window.removeEventListener("jojox-open-login", openLogin);
  }, [session]);

  return (
    <header className="header">
      <div className="container header-inner">
        <a
          className="logo-link"
          href="/"
          aria-label="JoJoX"
          onClick={(e) => {
            e.preventDefault();
            window.scrollTo({ top: 0, behavior: "smooth" });
          }}
        >
          <span className="logo font-logo">JoJoX</span>
        </a>
        <div className="header-actions">
          <LanguageSwitcher />
          <a
            className="btn btn-secondary hard-border hard-shadow-sm"
            href={`https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`}
            target="_blank"
            rel="noreferrer"
          >
            {connected ? t.header.connected : t.header.connect}
          </a>
          {session ? (
            <>
              <span className="user-email">{session.user.email}</span>
              <button
                type="button"
                className="btn btn-secondary hard-border hard-shadow-sm"
                onClick={() => supabase.auth.signOut()}
              >
                {t.header.logout}
              </button>
            </>
          ) : (
            <div className="login-panel-anchor">
              <button
                type="button"
                className="btn btn-primary hard-border hard-shadow-sm"
                onClick={() => setLoginOpen((v) => !v)}
              >
                {t.header.login}
              </button>
              {loginOpen && <LoginPanel onClose={() => setLoginOpen(false)} />}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}