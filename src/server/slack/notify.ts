/**
 * Invia un messaggio testuale a un Incoming Webhook di Slack. Nessun SDK:
 * un webhook Slack è solo un URL a cui fare POST con {"text": "..."}.
 * Non lancia mai un errore verso chi la chiama — un avviso Slack che non
 * parte non deve mai far fallire l'elaborazione del webhook GitHub.
 */
export async function notifySlack(webhookUrl: string | null | undefined, text: string): Promise<void> {
  if (!webhookUrl) return;

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!response.ok) {
      console.error(`notifica Slack rifiutata (${response.status})`);
    }
  } catch (err) {
    console.error("errore nell'invio della notifica Slack", err);
  }
}