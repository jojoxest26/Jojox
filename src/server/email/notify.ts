import { env } from "../env.js";
import { reportError } from "../sentry.js";

const FROM_ADDRESS = "JoJoX <avvisi@jojox.it>";

/**
 * Manda un'email transazionale tramite l'API di Resend — stesso dominio
 * jojox.it già verificato lì per l'SMTP di Supabase (punto 9 della
 * roadmap), quindi basta la chiave API per iniziare a mandarne di dirette
 * dal backend. Spenta di default: se RESEND_API_KEY non è impostata su
 * Railway, non fa nulla, come Sentry/Stripe/Anthropic. Non lancia mai un
 * errore verso chi la chiama — un'email che non parte non deve mai far
 * fallire lo scan notturno o il webhook GitHub che la richiede — ma un
 * fallimento va comunque su Sentry: altrimenti un avviso critico che non
 * parte (es. la Sentinella 24/7 che trova una vulnerabilità di notte)
 * sparirebbe in un log che nessuno legge, senza che l'utente né il team se
 * ne accorgano mai.
 */
export async function notifyEmail(to: string | null | undefined, subject: string, html: string): Promise<void> {
  if (!env.resendApiKey || !to) return;

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.resendApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ from: FROM_ADDRESS, to, subject, html }),
    });
    if (!response.ok) {
      console.error(`notifica email rifiutata (${response.status})`);
      reportError(new Error(`notifica email rifiutata (${response.status}) per "${subject}"`));
    }
  } catch (err) {
    console.error("errore nell'invio della notifica email", err);
    reportError(err);
  }
}

/** Stesso schema scuro + ambra del sito (punto 18) — un'email che non sembra arrivare da un altro prodotto. */
export function buildAlertEmailHtml(opts: { title: string; body: string; ctaLabel: string; ctaUrl: string }): string {
  return `<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#0a0a0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:#0a0a0f;padding:32px 16px;">
      <tr>
        <td align="center">
          <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="max-width:480px;background:#15151c;border-radius:12px;border:1px solid #2a2a35;overflow:hidden;">
            <tr>
              <td style="padding:28px 28px 0;">
                <span style="display:inline-block;background:#f5a623;color:#15151c;font-weight:800;font-size:14px;letter-spacing:0.04em;padding:4px 10px;border-radius:6px;">JOJOX</span>
              </td>
            </tr>
            <tr>
              <td style="padding:20px 28px 8px;">
                <h1 style="margin:0;color:#f5f5f7;font-size:20px;line-height:1.3;">${opts.title}</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 24px;">
                <p style="margin:0;color:#b4b4bd;font-size:15px;line-height:1.6;">${opts.body}</p>
              </td>
            </tr>
            <tr>
              <td style="padding:0 28px 32px;">
                <a href="${opts.ctaUrl}" style="display:inline-block;background:#f5a623;color:#15151c;font-weight:700;font-size:14px;padding:12px 20px;border-radius:8px;text-decoration:none;">${opts.ctaLabel}</a>
              </td>
            </tr>
          </table>
          <p style="margin:20px 0 0;color:#5a5a66;font-size:12px;">JoJoX — jojox.it</p>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}
