import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import type { AnalysisResult, Finding, Severity } from "../../../src/types.js";
import { sendChatMessage, type ChatMessage } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { translateCheckText } from "../i18n/checkTranslations.js";
import { Icon } from "./Icon.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
// Stesso tetto del backend (chatRequestSchema in src/server/routes/chat.ts):
// mandarne di più verrebbe comunque rifiutato, meglio tagliare qui e
// rispondere comunque in fretta.
const MAX_FINDINGS_SENT = 60;
// Quante battute di conversazione precedenti mandare col prossimo messaggio
// (storico, non persistito sul server oltre al log usato per il limite
// giornaliero) — abbastanza per mantenere il contesto, poco per i costi.
const MAX_HISTORY_SENT = 10;

function findingsForChat(findings: Finding[], lang: "it" | "en"): Finding[] {
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  return sorted.slice(0, MAX_FINDINGS_SENT).map((f) => {
    const text = translateCheckText(f.checkId, f, lang);
    return { ...f, title: text.title, description: text.description, fix: text.fix };
  });
}

/**
 * Widget globale "Chiedi a JoJoX" — un bottone fisso in basso a destra,
 * sempre raggiungibile, più un'apertura diretta dal bottone nell'hero
 * (evento "jojox-open-chat"). Se c'è un'analisi appena fatta (result),
 * risponde su quei findings; altrimenti risponde in modalità generale su
 * JoJoX stesso. Funziona anche da ospite, senza login.
 */
export function ChatPanel({ result, session }: { result: AnalysisResult | null; session: Session | null }) {
  const { t, lang } = useTranslation();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handler = () => setOpen(true);
    window.addEventListener("jojox-open-chat", handler);
    return () => window.removeEventListener("jojox-open-chat", handler);
  }, []);

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
      const { reply } = await sendChatMessage(text, history, lang, findings, score, session?.access_token);
      setMessages([...nextMessages, { role: "assistant", content: reply }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.chat.errorGeneric);
    } finally {
      setSending(false);
    }
  }

  return (
    <>
      <button
        type="button"
        className="chat-fab"
        onClick={() => setOpen((v) => !v)}
        aria-label={open ? t.chat.toggleClose : t.chat.toggleOpen}
      >
        <Icon name="bot" />
      </button>

      {open && (
        <div className="card chat-panel-floating">
          <div className="chat-panel-head">
            <span className="chat-panel-icon">
              <Icon name="bot" />
            </span>
            <div className="chat-panel-head-text">
              <p className="chat-panel-title">{t.chat.title}</p>
              <p className="chat-panel-subtitle">{result ? t.chat.subtitle : t.chat.subtitleGeneral}</p>
            </div>
            <div className="chat-head-actions">
              {messages.length > 0 && (
                <button
                  type="button"
                  className="chat-reset"
                  onClick={() => {
                    setMessages([]);
                    setError(null);
                  }}
                  aria-label={t.chat.newConversation}
                  title={t.chat.newConversation}
                >
                  <Icon name="refresh" />
                </button>
              )}
              <button type="button" className="chat-close" onClick={() => setOpen(false)} aria-label={t.chat.toggleClose}>
                <Icon name="plus" />
              </button>
            </div>
          </div>

          <div className="chat-messages">
            {messages.length === 0 && (
              <p className="chat-empty-state">{result ? t.chat.emptyState : t.chat.emptyStateGeneral}</p>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`chat-bubble chat-bubble-${m.role}`}>
                {m.content}
              </div>
            ))}
            {sending && <div className="chat-bubble chat-bubble-assistant chat-bubble-pending">{t.chat.sending}</div>}
          </div>

          {error && <p className="chat-error">{error}</p>}

          <div className="chat-input-row">
            <input
              type="text"
              value={input}
              placeholder={result ? t.chat.placeholder : t.chat.placeholderGeneral}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSend();
              }}
              disabled={sending}
            />
            <button type="button" className="btn btn-primary" onClick={handleSend} disabled={sending || !input.trim()}>
              {t.chat.send}
            </button>
          </div>
        </div>
      )}
    </>
  );
}
