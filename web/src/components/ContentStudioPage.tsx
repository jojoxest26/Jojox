import { useEffect, useRef, useState, type KeyboardEvent, type MouseEvent } from "react";
import type { Session } from "@supabase/supabase-js";
import "@fontsource/playfair-display/700-italic.css";
import type { Reel, ReelScene } from "../../../src/reel.js";
import { reelDuration } from "../../../src/reel.js";
import { fetchContentChatAccess, sendContentChatMessage, type ChatMessage } from "../lib/api.js";
import { drawReelFrame, exportReelVideo, loadReelFonts, REEL_HEIGHT, REEL_WIDTH, sceneAt, sceneStart } from "../lib/reelRenderer.js";
import { LoginPanel } from "./LoginPanel.js";
import { Icon } from "./Icon.js";

/**
 * Chat interna dei contenuti (/content): scrivi l'idea, l'AI scrive il
 * reel partendo da quello che dice il sito di JoJoX, la pagina lo anima e
 * lo esporta in video verticale. Pagina non linkata dal sito, e il server
 * la apre solo alle email in CONTENT_ADMIN_EMAILS. Testi solo in italiano:
 * è uno strumento interno, non una pagina per i clienti.
 */

interface StudioMessage extends ChatMessage {
  /** Il reel arrivato con questa risposta, per poter tornare a una versione precedente. */
  reel?: Reel | null;
}

const STORAGE_MESSAGES = "jojox-content-messages";
const STORAGE_REEL = "jojox-content-reel";
const MAX_HISTORY_SENT = 20;

const STARTERS = [
  "Reel: perché non basta chiedere all'AI se il codice è sicuro",
  "Reel: i 61 controlli di JoJoX in 20 secondi",
  "Reel: la Sentinella 24/7 che ricontrolla il codice ogni notte",
  "Reel: prova JoJoX gratis, senza nemmeno l'email",
];

function readStorage<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Spazio pieno o storage bloccato: la chat funziona comunque, solo senza memoria.
  }
}

function goHome(e: MouseEvent) {
  e.preventDefault();
  leaveToHome();
}

function leaveToHome() {
  window.history.pushState({}, "", "/");
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function sameReel(a: Reel | null | undefined, b: Reel | null): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b);
}

function sceneLabel(scene: ReelScene): string {
  switch (scene.type) {
    case "word":
      return scene.text;
    case "headline":
      return `${scene.line1} / ${scene.line2}`;
    case "strike":
      return scene.words.join(" · ");
    case "bars":
      return `Grafico: ${scene.title}`;
    case "stat":
      return `${scene.value}${scene.suffix ?? ""} ${scene.caption}`;
    case "cta":
      return scene.text;
  }
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-secondary content-small-btn"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? "✓ Copiato" : label}
    </button>
  );
}

function ReelPreview({ reel }: { reel: Reel }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [playing, setPlaying] = useState(true);
  const [time, setTime] = useState(0);
  const [exporting, setExporting] = useState<number | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const timeRef = useRef(0);
  const total = reelDuration(reel);

  // Un reel nuovo riparte sempre dall'inizio.
  useEffect(() => {
    timeRef.current = 0;
    setTime(0);
    setPlaying(true);
  }, [reel]);

  useEffect(() => {
    const ctx = canvasRef.current?.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    let last = performance.now();
    let cancelled = false;

    loadReelFonts().then(() => {
      if (cancelled) return;
      const tick = (now: number) => {
        const dt = (now - last) / 1000;
        last = now;
        if (playing) {
          timeRef.current += dt;
          if (timeRef.current > total) timeRef.current = 0;
          setTime(timeRef.current);
        }
        drawReelFrame(ctx, reel, timeRef.current);
        raf = requestAnimationFrame(tick);
      };
      last = performance.now();
      raf = requestAnimationFrame(tick);
    });

    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
    };
  }, [reel, playing, total]);

  function seek(t: number) {
    timeRef.current = Math.min(Math.max(0, t), total);
    setTime(timeRef.current);
  }

  async function handleExport() {
    setExportError(null);
    setPlaying(false);
    setExporting(0);
    try {
      const { blob, extension } = await exportReelVideo(reel, setExporting);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const slug = reel.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "reel";
      a.href = url;
      a.download = `jojox-${slug}.${extension}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Esportazione non riuscita");
    } finally {
      setExporting(null);
    }
  }

  const current = sceneAt(reel, time);

  return (
    <div className="content-preview">
      <canvas ref={canvasRef} width={REEL_WIDTH} height={REEL_HEIGHT} className="content-canvas" />

      <div className="content-controls">
        <button type="button" className="btn btn-secondary content-small-btn" onClick={() => setPlaying((p) => !p)}>
          {playing ? "❚❚ Pausa" : "▶ Play"}
        </button>
        <input
          type="range"
          min={0}
          max={total}
          step={0.05}
          value={time}
          onChange={(e) => {
            setPlaying(false);
            seek(Number(e.target.value));
          }}
          aria-label="Posizione nel video"
        />
        <span className="content-time">
          {time.toFixed(1)} / {total.toFixed(1)} s
        </span>
      </div>

      <button
        type="button"
        className="btn btn-primary hard-border hard-shadow-sm content-download"
        onClick={handleExport}
        disabled={exporting !== null}
      >
        {exporting !== null ? `Registrazione… ${Math.round(exporting * 100)}%` : "Scarica video"}
      </button>
      {exporting !== null && <p className="content-note">Tieni questa scheda aperta e in primo piano finché non finisce.</p>}
      {exportError && <p className="chat-error">{exportError}</p>}

      <details className="content-details" open>
        <summary>Voce fuori campo</summary>
        <p className="content-text">{reel.voiceover}</p>
        <CopyButton text={reel.voiceover} label="Copia testo" />
      </details>
      <details className="content-details">
        <summary>Didascalia del post</summary>
        <p className="content-text">{reel.caption}</p>
        <CopyButton text={reel.caption} label="Copia didascalia" />
      </details>
      <details className="content-details">
        <summary>Scene ({reel.scenes.length})</summary>
        <ol className="content-scenes">
          {reel.scenes.map((scene, i) => (
            <li key={i}>
              <button
                type="button"
                className={current?.index === i ? "active" : ""}
                onClick={() => {
                  setPlaying(false);
                  seek(sceneStart(reel, i) + 0.01);
                }}
              >
                <span className="content-scene-type">{scene.type}</span>
                <span className="content-scene-text">{sceneLabel(scene)}</span>
                <span className="content-scene-time">{scene.duration.toFixed(1)}s</span>
              </button>
            </li>
          ))}
        </ol>
      </details>
    </div>
  );
}

export function ContentStudioPage({ session }: { session: Session | null }) {
  const [allowed, setAllowed] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<StudioMessage[]>(() => readStorage(STORAGE_MESSAGES, []));
  const [reel, setReel] = useState<Reel | null>(() => readStorage(STORAGE_REEL, null));
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!session) return;
    fetchContentChatAccess(session.access_token)
      .then(setAllowed)
      .catch(() => setAllowed(false));
  }, [session?.user?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => writeStorage(STORAGE_MESSAGES, messages), [messages]);
  useEffect(() => writeStorage(STORAGE_REEL, reel), [reel]);
  useEffect(() => endRef.current?.scrollIntoView({ behavior: "smooth" }), [messages, sending]);

  async function send(text: string) {
    const message = text.trim();
    if (!message || sending || !session) return;
    const next: StudioMessage[] = [...messages, { role: "user", content: message }];
    setMessages(next);
    setInput("");
    setSending(true);
    setError(null);
    try {
      const history = messages.slice(-MAX_HISTORY_SENT).map(({ role, content }) => ({ role, content }));
      // La cronologia inviata deve iniziare con un messaggio dell'utente, come vuole l'API.
      while (history.length > 0 && history[0].role !== "user") history.shift();
      const { reply, reel: newReel } = await sendContentChatMessage(message, history, reel, session.access_token);
      setMessages([...next, { role: "assistant", content: reply, reel: newReel }]);
      if (newReel) setReel(newReel);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Errore nel generare la risposta, riprova.");
    } finally {
      setSending(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send(input);
    }
  }

  function handleReset() {
    if (!window.confirm("Cancellare la conversazione e il reel aperto?")) return;
    setMessages([]);
    setReel(null);
    setError(null);
  }

  return (
    <div className="chat-page">
      <div className="container chat-page-nav">
        <a href="/" onClick={goHome} className="legal-back">
          ← Torna al sito
        </a>
      </div>

      <div className="container content-page-body">
        <div className="chat-page-head">
          <span className="chat-panel-icon">
            <Icon name="bot" />
          </span>
          <div className="chat-panel-head-text">
            <p className="chat-page-title">Studio contenuti</p>
            <p className="chat-panel-subtitle">Reel verticali su JoJoX, scritti partendo da quello che dice il sito.</p>
          </div>
          {messages.length > 0 && (
            <button type="button" className="chat-reset" onClick={handleReset}>
              <Icon name="refresh" />
              Ricomincia
            </button>
          )}
        </div>

        {!session ? (
          <div className="card chat-gate">
            <strong>Accedi per usare lo studio contenuti</strong>
            <LoginPanel onClose={leaveToHome} />
          </div>
        ) : allowed === null ? (
          <p className="chat-empty-state">…</p>
        ) : !allowed ? (
          <div className="card chat-gate">
            <strong>Pagina riservata</strong>
            <p className="chat-gate-body">Questo account non ha accesso allo studio contenuti.</p>
          </div>
        ) : (
          <div className="content-layout">
            <div className="content-chat">
              <div className="chat-page-messages content-messages">
                {messages.length === 0 ? (
                  <div className="chat-empty-state">
                    <p>Scrivi l'idea del reel, o parti da una di queste:</p>
                    <div className="content-starters">
                      {STARTERS.map((s) => (
                        <button key={s} type="button" className="content-starter" onClick={() => send(s)}>
                          {s}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  messages.map((m, i) => (
                    <div key={i} className={`chat-bubble chat-bubble-${m.role}`} dir="auto">
                      <span>{m.content}</span>
                      {m.reel && !sameReel(m.reel, reel) && (
                        <button type="button" className="content-restore" onClick={() => setReel(m.reel!)}>
                          Riapri questa versione
                        </button>
                      )}
                    </div>
                  ))
                )}
                {sending && <div className="chat-bubble chat-bubble-assistant chat-bubble-pending">Sto scrivendo il reel…</div>}
                <div ref={endRef} />
              </div>

              {error && <p className="chat-error">{error}</p>}

              <div className="chat-input-row chat-page-input-row">
                <textarea
                  rows={2}
                  value={input}
                  placeholder={reel ? "Chiedi una modifica (es. gancio più forte, scena 3 più corta)…" : "Idea del reel…"}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  disabled={sending}
                />
                <button type="button" className="btn btn-primary" onClick={() => send(input)} disabled={sending || !input.trim()}>
                  Invia
                </button>
              </div>
            </div>

            {reel ? (
              <ReelPreview reel={reel} />
            ) : (
              <div className="content-preview content-preview-empty">
                <p>L'anteprima del reel compare qui.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
