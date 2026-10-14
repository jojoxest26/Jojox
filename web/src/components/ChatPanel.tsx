import { useState } from "react";
import type { Session } from "@supabase/supabase-js";
import type { AnalysisResult, Finding, Severity } from "../../../src/types.js";
import { sendChatMessage, type ChatMessage } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { translateCheckText } from "../i18n/checkTranslations.js";
import { Icon } from "./Icon.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
// Stesso tetto del backend (chatRequestSchema in src/server/routes/chat.ts):
// mandarne di più verrebbe comunque rifiutato, meglio tagliare qui e
// avvisare che non tutto è stato visto.
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

export function ChatPanel({ result, session }: { result: AnalysisResult; session: Session }) {
  const { t, lang } = useTranslation();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSend() {
    const text = input.trim();
    if (!text || sending) return;

    const nextMessages: ChatMessage[] = [...messages, { role: "user", content: text }];
    setMessages(nextMessages);
    setInput("");
    setSending(true);
    setError(null);

    try {
      const findings = findingsForChat(result.findings, lang);
      const history = messages.slice(-MAX_HISTORY_SENT);
      const { reply } = await sendChatMessage(findings, result.score, text, history, lang, session.access_token);
      setMessages([...nextMessages, { role: "assistant", content: reply }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.chat.errorGeneric);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="chat-panel-wrap">
      <button type="button" className="btn btn-secondary hard-border hard-shadow-sm chat-toggle" onClick={() => setOpen((v) => !v)}>
        <Icon name="bot" className="chat-toggle-icon" />
        {open ? t.chat.toggleClose : t.chat.toggleOpen}
      </button>

      {open && (
        <div className="card chat-panel">
          <div className="chat-panel-head">
            <span className="chat-panel-icon">
              <Icon name="bot" />
            </span>
            <div>
              <p className="chat-panel-title">{t.chat.title}</p>
              <p className="chat-panel-subtitle">{t.chat.subtitle}</p>
            </div>
          </div>

          <div className="chat-messages">
            {messages.length === 0 && <p className="chat-empty-state">{t.chat.emptyState}</p>}
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
              placeholder={t.chat.placeholder}
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
    </div>
  );
}
