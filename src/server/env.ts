import "dotenv/config";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Variabile d'ambiente mancante: ${name}`);
  return value;
}

export const env = {
  port: Number(process.env.PORT ?? 3000),
  supabaseUrl: required("SUPABASE_URL"),
  supabaseServiceRoleKey: required("SUPABASE_SERVICE_ROLE_KEY"),
  githubAppId: required("GITHUB_APP_ID"),
  githubPrivateKey: Buffer.from(required("GITHUB_APP_PRIVATE_KEY_BASE64"), "base64").toString("utf8"),
  githubWebhookSecret: required("GITHUB_WEBHOOK_SECRET"),
  /**
   * Origini a cui è permesso chiamare l'API da browser (CORS). Nessun
   * default a "*": un backend con dati utente non deve mai accettare
   * richieste da qualunque sito — è letteralmente il controllo
   * "permissive-cors" che il nostro stesso motore segnala come critico.
   * In locale, se non impostata, permette solo la porta di sviluppo di Vite.
   */
  allowedOrigins: (process.env.ALLOWED_ORIGINS ?? "http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
};
