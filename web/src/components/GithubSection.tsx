import { useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { saveSlackWebhook, type GithubInstallation } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { renderWithTokens } from "../i18n/richText.js";

const GITHUB_APP_SLUG = import.meta.env.VITE_GITHUB_APP_SLUG;
const API_URL = import.meta.env.VITE_API_URL;

function SlackWebhookForm({ installation, session }: { installation: GithubInstallation; session: Session }) {
  const { t } = useTranslation();
  const [value, setValue] = useState(installation.slack_webhook_url ?? "");
  const [status, setStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  async function handleSave() {
    setStatus("saving");
    setError(null);
    try {
      await saveSlackWebhook(installation.installation_id, value.trim() || null, session.access_token);
      setStatus("saved");
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : t.github.slackErrorGeneric);
    }
  }

  return (
    <div className="slack-webhook-row">
      <label className="slack-webhook-label" htmlFor={`slack-${installation.installation_id}`}>
        {installation.account_login}
      </label>
      <div className="slack-webhook-input-row">
        <input
          id={`slack-${installation.installation_id}`}
          type="url"
          placeholder="https://hooks.slack.com/services/..."
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setStatus("idle");
          }}
        />
        <button type="button" className="btn btn-secondary hard-border hard-shadow-sm" onClick={handleSave} disabled={status === "saving"}>
          {status === "saving" ? t.github.slackSaving : t.github.slackSave}
        </button>
      </div>
      {status === "saved" && <p className="slack-webhook-msg">{t.github.slackSaved}</p>}
      {status === "error" && <p className="slack-webhook-msg slack-webhook-msg-error">{error}</p>}
    </div>
  );
}

function SlackNotifications({ session, installations }: { session: Session; installations: GithubInstallation[] | null }) {
  const { t } = useTranslation();

  return (
    <div className="github-badge-howto">
      <p className="github-badge-title">{t.github.slackTitle}</p>
      {!installations || installations.length === 0 ? (
        <p>{t.github.slackConnectFirst}</p>
      ) : (
        <>
          <p>
            {renderWithTokens(t.github.slackBody, {
              link: (
                <a href="https://api.slack.com/messaging/webhooks" target="_blank" rel="noreferrer">
                  {t.github.slackLink}
                </a>
              ),
            })}
          </p>
          {installations.map((installation) => (
            <SlackWebhookForm key={installation.installation_id} installation={installation} session={session} />
          ))}
        </>
      )}
    </div>
  );
}

export function GithubSection({
  session,
  installations,
}: {
  session: Session | null;
  installations: GithubInstallation[] | null;
}) {
  const { t } = useTranslation();
  const [showDetails, setShowDetails] = useState(false);
  const connected = installations !== null && installations.length > 0;

  return (
    <section className="github-section container">
      <div className="card github-card">
        <div className="github-title">
          <h2>{t.github.title}</h2>
          <span className="pill pill-amber">{t.github.badge}</span>
        </div>
        <p>{t.github.body1}</p>
        <p>{t.github.body2}</p>
        <p className="github-note">{t.github.note}</p>
        {connected && (
          <p className="github-connected">
            <span className="pill pill-mint">{t.github.connectedLabel}</span>{" "}
            {installations!.map((i) => i.account_login).join(", ")}
          </p>
        )}
        <a
          className="btn btn-primary"
          href={`https://github.com/apps/${GITHUB_APP_SLUG}/installations/new`}
          target="_blank"
          rel="noreferrer"
        >
          {connected ? t.header.connectAnother : t.header.connect}
        </a>

        <button
          type="button"
          className="supabase-check-toggle github-details-toggle"
          onClick={() => setShowDetails((v) => !v)}
        >
          {showDetails ? t.github.toggleHide : t.github.toggleShow}
        </button>

        {showDetails && (
          <>
            <div className="github-badge-howto">
              <p className="github-badge-title">{t.github.badgeTitle}</p>
              <p>
                {renderWithTokens(t.github.badgeBody, {
                  readme: <code>README.md</code>,
                  repo: <code>proprietario/repo</code>,
                })}
              </p>
              <pre className="github-badge-snippet">
                {`![JoJoX](${API_URL}/badge/proprietario/repo.svg)`}
              </pre>
            </div>

            <div className="github-badge-howto">
              <p className="github-badge-title">{t.github.terminalTitle}</p>
              <p>
                {renderWithTokens(t.github.terminalBody, {
                  fix: <code>--fix</code>,
                  link: (
                    <a href="https://github.com/jojoxest26/Jojox#uso" target="_blank" rel="noreferrer">
                      {t.github.terminalLink}
                    </a>
                  ),
                })}
              </p>
            </div>

            <div className="github-badge-howto">
              <p className="github-badge-title">{t.github.hookTitle}</p>
              <p>{renderWithTokens(t.github.hookBody, { cmd: <code>install-hook</code> })}</p>
            </div>

            {session && <SlackNotifications session={session} installations={installations} />}
          </>
        )}
      </div>
    </section>
  );
}