import { useTheme } from "../lib/ThemeContext.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { Icon } from "./Icon.js";

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  const { t } = useTranslation();

  return (
    <button
      type="button"
      className="theme-toggle"
      role="switch"
      aria-checked={theme === "light"}
      aria-label={t.header.themeToggle}
      title={t.header.themeToggle}
      onClick={toggleTheme}
    >
      <Icon name={theme === "dark" ? "moon" : "sun"} className="theme-toggle-icon" />
    </button>
  );
}
