import type { MouseEvent } from "react";
import { useTranslation } from "../i18n/LanguageContext.js";
import { Icon } from "./Icon.js";

function goToChat(e: MouseEvent) {
  e.preventDefault();
  window.history.pushState({}, "", "/chat");
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.scrollTo({ top: 0 });
}

/** Bottone flottante sempre raggiungibile mentre si scorre la home — porta alla pagina intera di "Chiedi a JoJoX". */
export function ChatFab() {
  const { t } = useTranslation();
  return (
    <a href="/chat" onClick={goToChat} className="chat-fab" aria-label={t.chat.toggleOpen} title={t.chat.toggleOpen}>
      <Icon name="bot" />
    </a>
  );
}
