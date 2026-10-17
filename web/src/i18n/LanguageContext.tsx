import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { translations, RTL_LANGS, type Lang, type TranslationTree } from "./translations.js";

const STORAGE_KEY = "jojox_lang";
const SUPPORTED_LANGS = Object.keys(translations) as Lang[];

function isLang(value: string | null): value is Lang {
  return value !== null && (SUPPORTED_LANGS as string[]).includes(value);
}

function detectInitialLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (isLang(saved)) return saved;
  } catch {
    // localStorage non disponibile (es. modalità privata): va bene l'italiano di default.
  }
  const browserLang = navigator.language.toLowerCase().split("-")[0];
  if (browserLang === "zh") return "zh"; // zh-CN, zh-TW, ... → sempre il nostro cinese semplificato
  if (browserLang === "no") return "nb"; // "no" generico → il nostro norvegese bokmål
  if (isLang(browserLang)) return browserLang;
  return navigator.language.toLowerCase().startsWith("en") ? "en" : "it";
}

interface LanguageContextValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: TranslationTree;
}

const LanguageContext = createContext<LanguageContextValue | null>(null);

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detectInitialLang);

  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = RTL_LANGS.has(lang) ? "rtl" : "ltr";
    document.title = translations[lang].meta.title;
    const descriptionTag = document.querySelector('meta[name="description"]');
    if (descriptionTag) descriptionTag.setAttribute("content", translations[lang].meta.description);
  }, [lang]);

  function setLang(next: Lang) {
    setLangState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Nessun salvataggio persistente possibile: la scelta resta valida solo per questa visita.
    }
  }

  return (
    <LanguageContext.Provider value={{ lang, setLang, t: translations[lang] }}>{children}</LanguageContext.Provider>
  );
}

export function useTranslation(): LanguageContextValue {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error("useTranslation va usato dentro <LanguageProvider>");
  return ctx;
}