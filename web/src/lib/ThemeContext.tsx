import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

export type Theme = "dark" | "light";

const STORAGE_KEY = "jojox_theme";
const DEFAULT_THEME: Theme = "dark";

function isTheme(value: string | null): value is Theme {
  return value === "dark" || value === "light";
}

// Il tema di default resta scuro per chiunque non abbia mai scelto — non
// seguiamo prefers-color-scheme del sistema: è una scelta di marca (JoJoX
// nasce scuro), non un adattamento automatico. Chi vuole il chiaro lo sceglie
// esplicitamente con lo switch, e la scelta resta salvata per le visite dopo.
function detectInitialTheme(): Theme {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (isTheme(saved)) return saved;
  } catch {
    // localStorage non disponibile (es. modalità privata): va bene lo scuro di default.
  }
  return DEFAULT_THEME;
}

interface ThemeContextValue {
  theme: Theme;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(detectInitialTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  function toggleTheme() {
    setThemeState((prev) => {
      const next: Theme = prev === "dark" ? "light" : "dark";
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch {
        // Nessun salvataggio persistente possibile: la scelta resta valida solo per questa visita.
      }
      return next;
    });
  }

  return <ThemeContext.Provider value={{ theme, toggleTheme }}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme va usato dentro <ThemeProvider>");
  return ctx;
}
