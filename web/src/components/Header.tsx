import { useEffect, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "../lib/supabaseClient.js";
import { LoginPanel } from "./LoginPanel.js";
import { openGithubInstallUrl, type GithubInstallation } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { LANG_NAMES, type Lang } from "../i18n/translations.js";
import { Icon } from "./Icon.js";
import { ThemeToggle } from "./ThemeToggle.js";

const GITHUB_APP_SLUG = import.meta.env.VITE_GITHUB_APP_SLUG;

const LANG_OPTIONS = Object.keys(LANG_NAMES) as Lang[];

// Una bandiera per lingua, puramente decorativa (il nome nativo accanto resta
// il modo "vero" per riconoscere la propria lingua). Dove una lingua è
// parlata in più paesi, scegliamo lo stesso paese usato per il formato data
// in translations.ts, per coerenza interna.
const LANG_FLAGS: Record<Lang, string> = {
  it: "🇮🇹",
  en: "🇬🇧",
  es: "🇪🇸",
  fr: "🇫🇷",
  pt: "🇵🇹",
  zh: "🇨🇳",
  hi: "🇮🇳",
  ru: "🇷🇺",
  ar: "🇸🇦",
  bn: "🇧🇩",
  ur: "🇵🇰",
  id: "🇮🇩",
  de: "🇩🇪",
  fi: "🇫🇮",
  nl: "🇳🇱",
  pl: "🇵🇱",
  sv: "🇸🇪",
  da: "🇩🇰",
  nb: "🇳🇴",
  tr: "🇹🇷",
  uk: "🇺🇦",
  ja: "🇯🇵",
  ko: "🇰🇷",
};

export function LanguageSwitcher() {
  const { lang, setLang } = useTranslation();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(e: PointerEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  function choose(next: Lang) {
    setLang(next);
    setOpen(false);
  }

  return (
    <div className="lang-switcher" ref={rootRef}>
      <button
        type="button"
        className="lang-trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label="Lingua / Language"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="lang-flag">{LANG_FLAGS[lang]}</span>
        <span className="lang-code">{lang.toUpperCase()}</span>
        <Icon name="chevronDown" className={open ? "lang-chevron lang-chevron-open" : "lang-chevron"} />
      </button>
      {open && (
        <div className="lang-panel" role="listbox">
          {LANG_OPTIONS.map((code) => (
            <button
              type="button"
              key={code}
              role="option"
              aria-selected={code === lang}
              className={code === lang ? "lang-option lang-option-active" : "lang-option"}
              onClick={() => choose(code)}
            >
              <span className="lang-flag">{LANG_FLAGS[code]}</span>
              <span className="lang-name">{LANG_NAMES[code]}</span>
              {code === lang && <Icon name="check" className="lang-check" />}
            </button>
          ))}
        </div>
      )}
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
          <ThemeToggle />
          <LanguageSwitcher />
          <button
            type="button"
            className="btn btn-secondary hard-border hard-shadow-sm"
            onClick={() => (session ? openGithubInstallUrl(GITHUB_APP_SLUG, session.access_token) : setLoginOpen(true))}
          >
            {connected ? t.header.connected : t.header.connect}
          </button>
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