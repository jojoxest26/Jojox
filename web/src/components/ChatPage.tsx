import { useEffect, useRef, useState, type KeyboardEvent, type MouseEvent } from "react";
import type { Session } from "@supabase/supabase-js";
import type { AnalysisResult, Finding, Severity } from "../../../src/types.js";
import { sendChatMessage, fetchChatHistory, fetchProfile, type ChatMessage, type Plan } from "../lib/api.js";
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

function goToPricing(e: MouseEvent) {
  e.preventDefault();
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
  setTimeout(() => {
    document.getElementById("pricing")?.scrollIntoView({ behavior: "smooth" });
  }, 50);
}

const LANGUAGE_TAG = /^[a-zA-Z0-9+#.-]{0,20}$/;

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="chat-code-block">
      <button
        type="button"
        className="chat-code-copy"
        onClick={() => {
          navigator.clipboard?.writeText(code).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        {copied ? "✓" : <Icon name="copy" />}
      </button>
      <pre>
        <code>{code}</code>
      </pre>
    </div>
  );
}

/** Divide il testo di un messaggio sui blocchi ```codice``` e dà a ciascuno il rendering giusto — niente evidenziazione sintassi, ma almeno font monospace, sfondo distinto e un bottone per copiare. */
function MessageContent({ content }: { content: string }) {
  const parts = content.split("```");
  return (
    <>
      {parts.map((part, i) => {
        if (i % 2 === 0) {
          return part ? <span key={i}>{part}</span> : null;
        }
        const firstBreak = part.indexOf("\n");
        const firstLine = (firstBreak === -1 ? part : part.slice(0, firstBreak)).trim();
        const hasLangTag = firstBreak !== -1 && LANGUAGE_TAG.test(firstLine) && firstLine.length > 0;
        const code = (hasLangTag ? part.slice(firstBreak + 1) : part).replace(/\n$/, "");
        return <CodeBlock key={i} code={code} />;
      })}
    </>
  );
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
  const [plan, setPlan] = useState<Plan | null>(null);
  const [loadingPlan, setLoadingPlan] = useState(!!session);
  const [planError, setPlanError] = useState(false);
  const [planRetryCount, setPlanRetryCount] = useState(0);
  const [historyError, setHistoryError] = useState(false);
  const [historyRetryCount, setHistoryRetryCount] = useState(0);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const canUseChat = plan === "pro" || plan === "team";
  const sessionUserId = session?.user?.id ?? null;
  // Supabase rinnova l'access_token da solo ogni ora circa (e quando si
  // torna sulla tab), producendo un nuovo session con un nuovo
  // access_token anche se l'utente è sempre lo stesso. Prima questi due
  // effetti scattavano su ogni cambio di access_token e azzeravano piano e
  // cronologia già caricati, facendo "sparire" nel nulla una chat in corso
  // senza nessun errore (il vero bug dietro al blocco su "…"). Questi ref
  // tengono traccia di PER QUALE UTENTE abbiamo già caricato piano/storico,
  // così un refresh del token della stessa persona non tocca la UI.
  const planLoadedForUserRef = useRef<string | null>(null);
  const historyLoadedForUserRef = useRef<string | null>(null);

  useEffect(() => {
    if (!session) {
      planLoadedForUserRef.current = null;
      return;
    }
    let cancelled = false;
    const isFreshLoad = planLoadedForUserRef.current !== sessionUserId;
    if (isFreshLoad) {
      setLoadingPlan(true);
      setPlanError(false);
    }

    // Non deve mai restare bloccata in attesa per sempre: se la richiesta
    // non risponde entro un tempo ragionevole (rete lenta, un intoppo del
    // server, un'estensione del browser che interferisce...) mostriamo un
    // errore con un bottone per riprovare, invece di un "..." eterno.
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error("timeout")), 10000);
    });

    Promise.race([fetchProfile(session.access_token), timeout])
      .then((p) => {
        if (cancelled) return;
        planLoadedForUserRef.current = sessionUserId;
        setPlan(p);
      })
      .catch(() => {
        if (cancelled) return;
        // Se il piano era già stato caricato con successo per questo utente,
        // un refresh del token in background che fallisce non deve bloccare
        // una chat già aperta: restiamo con l'ultimo piano conosciuto.
        if (isFreshLoad) setPlanError(true);
      })
      .finally(() => {
        if (cancelled) return;
        if (isFreshLoad) setLoadingPlan(false);
      });

    return () => {
      cancelled = true;
    };
  }, [session?.access_token, sessionUserId, planRetryCount]);

  useEffect(() => {
    if (!session) {
      historyLoadedForUserRef.current = null;
      return;
    }
    // Parte insieme alla richiesta del piano, non dopo: aspettare che il
    // piano risponda prima di iniziare a caricare la cronologia mette in
    // fila due richieste autenticate invece di farle in parallelo, e
    // raddoppia l'attesa percepita. Per un account free questa richiesta
    // viene comunque rifiutata dal server (403, già gestito in silenzio
    // qui sotto) senza alcun costo reale: niente chiamate al modello.
    if (historyLoadedForUserRef.current === sessionUserId) return;
    let cancelled = false;
    setLoadingHistory(true);
    setHistoryError(false);

    // Stesso principio del caricamento del piano: senza un limite massimo,
    // un intoppo lascia "…" bloccato in eterno, senza errore e senza un
    // modo per riprovare — esattamente il tipo di blocco di stanotte.
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error("timeout")), 15000);
    });

    Promise.race([fetchChatHistory(session.access_token), timeout])
      .then((h) => {
        if (cancelled) return;
        historyLoadedForUserRef.current = sessionUserId;
        setMessages(h);
      })
      .catch(() => {
        if (cancelled) return;
        setHistoryError(true);
      })
      .finally(() => {
        if (cancelled) return;
        setLoadingHistory(false);
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.access_token, canUseChat, sessionUserId, historyRetryCount]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, sending]);

  async function handleSend() {
    const text = input.trim();
    if (!text || sending) return;

    const nextMessages: ChatMessage[] = [...messages, { role: "user", content: text }];
    setMessages(nextMessages);
    setInput("");
    if (textareaRef.current) textareaRef.current.style.height = "auto";
    setSending(true);
    setError(null);

    // In modalità generale una risposta può legittimamente arrivare a 16000
    // token e richiedere diverse decine di secondi — ma senza un limite
    // massimo, un intoppo di rete lascia "sending" bloccato per sempre:
    // niente errore, niente modo di scrivere un altro messaggio, la chat
    // sembra morta (esattamente quello che è successo stasera). 90 secondi
    // bastano a non tagliare mai una risposta vera, ma garantiscono comunque
    // una via d'uscita se qualcosa si è davvero inceppato.
    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(t.chat.errorGeneric)), 90000);
    });

    try {
      // La chat "Chiedi a JoJoX" risponde solo in IT/EN per ora: le altre
      // lingue del sito usano l'inglese come ripiego, invece di mandare al
      // backend un codice lingua che non riconosce.
      const chatLang = lang === "it" ? "it" : "en";
      const findings = result ? findingsForChat(result.findings, chatLang) : [];
      const score = result ? result.score : null;
      const history = messages.slice(-MAX_HISTORY_SENT);
      const { reply } = await Promise.race([
        sendChatMessage(text, history, chatLang, findings, score, session!.access_token),
        timeout,
      ]);
      setMessages([...nextMessages, { role: "assistant" as const, content: reply }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.chat.errorGeneric);
    } finally {
      setSending(false);
    }
  }

  function handleReset() {
    if (!window.confirm(t.chat.resetConfirm)) return;
    setMessages([]);
    setError(null);
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  function autoGrow(el: HTMLTextAreaElement) {
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 240)}px`;
  }

  return (
    <div className="chat-page">
      <div className="container chat-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          {legalPages[lang === "it" ? "it" : "en"].backHome}
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
            <button type="button" className="chat-reset" onClick={handleReset}>
              <Icon name="refresh" />
              {t.chat.newConversation}
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
        ) : planError ? (
          <div className="card chat-gate">
            <strong>{t.chat.planErrorTitle}</strong>
            <p className="chat-gate-body">{t.chat.planErrorBody}</p>
            <button
              type="button"
              className="btn btn-primary hard-border hard-shadow-sm"
              onClick={() => setPlanRetryCount((c) => c + 1)}
            >
              {t.chat.planErrorRetry}
            </button>
          </div>
        ) : loadingPlan ? (
          <p className="chat-empty-state">…</p>
        ) : !canUseChat ? (
          <div className="card chat-gate">
            <strong>{t.chat.planGateTitle}</strong>
            <p className="chat-gate-body">{t.chat.planGateBody}</p>
            <a href="/#pricing" onClick={goToPricing} className="btn btn-primary hard-border hard-shadow-sm">
              {t.chat.planGateCta}
            </a>
          </div>
        ) : (
          <>
            <div className="chat-page-messages">
              {loadingHistory ? (
                <p className="chat-empty-state">…</p>
              ) : historyError ? (
                <div className="chat-empty-state">
                  <p>{t.chat.historyErrorBody}</p>
                  <button
                    type="button"
                    className="btn btn-primary hard-border hard-shadow-sm"
                    onClick={() => setHistoryRetryCount((c) => c + 1)}
                  >
                    {t.chat.planErrorRetry}
                  </button>
                </div>
              ) : messages.length === 0 ? (
                <p className="chat-empty-state">{result ? t.chat.emptyState : t.chat.emptyStateGeneral}</p>
              ) : (
                messages.map((m, i) => (
                  <div key={i} className={`chat-bubble chat-bubble-${m.role}`} dir="auto">
                    <MessageContent content={m.content} />
                  </div>
                ))
              )}
              {sending && (
                <div className="chat-bubble chat-bubble-assistant chat-bubble-pending" dir="auto">
                  {t.chat.sending}
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {error && <p className="chat-error">{error}</p>}

            <div className="chat-input-row chat-page-input-row">
              <textarea
                ref={textareaRef}
                rows={1}
                value={input}
                placeholder={result ? t.chat.placeholder : t.chat.placeholderGeneral}
                onChange={(e) => {
                  setInput(e.target.value);
                  autoGrow(e.target);
                }}
                onKeyDown={handleKeyDown}
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
