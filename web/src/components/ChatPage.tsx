import { useEffect, useRef, useState, type MouseEvent } from "react";
import type { Session } from "@supabase/supabase-js";
import type { AnalysisResult, Finding, Severity } from "../../../src/types.js";
import { sendChatMessage, fetchChatHistory, type ChatMessage } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { translateCheckText } from "../i18n/checkTranslations.js";
import { legalPages } from "../i18n/legalPages.js";
import { LanguageSwitcher } from "./Header.js";
import { Icon } from "./Icon.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const MAX_FINDINGS_SENT = 60;
// Stesso tetto del backend (chatRequestSchema in src/server/routes/chat.ts):
// più lo alziamo, più ogni messaggio nuovo costa (si rimanda tutta la
// cronologia ogni volta) — 40 copre conversazioni lunghe vere restando
// comunque limitato.
const MAX_HISTORY_SENT = 40;

function findingsForChat(findings: Finding[], lang: "it" | "en"): Finding[] {
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  return sorted.slice(0, MAX_FINDINGS_SENT).map((f) => {
    const text = translateCheckText(f.checkId, f, lang);
    return { ...f, title: text.title, description: text.description, fix: text.fix };
  });
}

function goHome(e: MouseEvent) {
  e.preventDefault();
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function openLogin() {
  window.dispatchEvent(new Event("jojox-open-login"));
}

/**
 * Pagina intera di "Chiedi a JoJoX" (punto 25a) — prima era un riquadro
 * piccolo in basso a destra, ma per una vera conversazione serve spazio
 * vero e una cronologia, non un widget. Se c'è un'analisi appena fatta
 * (result), risponde sui suoi findings; altrimenti risponde in modalità
 * generale su JoJoX stesso. Richiede login: niente accesso anonimo, sia
 * per tenere i costi dell'API sotto controllo sia per avere una vera
 * cronologia legata all'account.
 */
export function ChatPage({ result, session }: { result: AnalysisResult | null; session: Session | null }) {
  const { t, lang } = useTranslation();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(!!session);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!session) return;
    setLoadingHistory(true);
    fetchChatHistory(session.access_token)
      .then(setMessages)
      .catch(() => {})
      .finally(() => setLoadingHistory(false));
  }, [session?.access_token]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, sending]);

  async function handleSend() {
    const text = input.trim();
    if (!text || sending) return;

    const nextMessages: ChatMessage[] = [...messages, { role: "user", content: text }];
    setMessages(nextMessages);
    setInput("");
    setSending(true);
    setError(null);

    try {
      const findings = result ? findingsForChat(result.findings, lang) : [];
      const score = result ? result.score : null;
      const history = messages.slice(-MAX_HISTORY_SENT);
      const { reply } = await sendChatMessage(text, history, lang, findings, score, session!.access_token);
      setMessages([...nextMessages, { role: "assistant" as const, content: reply }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.chat.errorGeneric);
    } finally {
      setSending(false);
    }
  }

  function handleReset() {
    setMessages([]);
    setError(null);
  }

  return (
    <div className="chat-page">
      <div className="container chat-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          {legalPages[lang].backHome}
        </a>
        <LanguageSwitcher />
      </div>

      <div className="container chat-page-body">
        <div className="chat-page-head">
          <span className="chat-panel-icon">
            <Icon name="bot" />
          </span>
          <div className="chat-panel-head-text">
            <p className="chat-page-title">{t.chat.title}</p>
            <p className="chat-panel-subtitle">{result ? t.chat.subtitle : t.chat.subtitleGeneral}</p>
          </div>
          {session && messages.length > 0 && (
            <button type="button" className="chat-reset" onClick={handleReset} aria-label={t.chat.newConversation} title={t.chat.newConversation}>
              <Icon name="refresh" />
            </button>
          )}
        </div>

        {!session ? (
          <div className="card chat-gate">
            <strong>{t.chat.gateTitle}</strong>
            <p className="chat-gate-body">{t.chat.gateBody}</p>
            <button type="button" className="btn btn-primary hard-border hard-shadow-sm" onClick={openLogin}>
              {t.chat.gateCta}
            </button>
          </div>
        ) : (
          <>
            <div className="chat-page-messages">
              {loadingHistory ? (
                <p className="chat-empty-state">…</p>
              ) : messages.length === 0 ? (
                <p className="chat-empty-state">{result ? t.chat.emptyState : t.chat.emptyStateGeneral}</p>
              ) : (
                messages.map((m, i) => (
                  <div key={i} className={`chat-bubble chat-bubble-${m.role}`}>
                    {m.content}
                  </div>
                ))
              )}
              {sending && <div className="chat-bubble chat-bubble-assistant chat-bubble-pending">{t.chat.sending}</div>}
              <div ref={messagesEndRef} />
            </div>

            {error && <p className="chat-error">{error}</p>}

            <div className="chat-input-row chat-page-input-row">
              <input
                type="text"
                value={input}
                placeholder={result ? t.chat.placeholder : t.chat.placeholderGeneral}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleSend();
                }}
                disabled={sending}
                autoFocus
              />
              <button type="button" className="btn btn-primary" onClick={handleSend} disabled={sending || !input.trim()}>
                {t.chat.send}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
