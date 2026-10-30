import { supabaseAdmin } from "./db/supabase.js";

/**
 * Registra il consumo di token di una chiamata Anthropic già andata a buon
 * fine (punto 18 quater). Non lancia mai un'eccezione — una riga di log
 * persa non deve mai rompere una risposta già inviata all'utente — e va
 * chiamata senza await (fire-and-forget), come saveChatExchange in chat.ts.
 */
export async function logAiUsage(params: {
  userId: string;
  route: "chat_general" | "chat_findings" | "ai_insight" | "content_chat";
  model: string;
  inputTokens: number;
  outputTokens: number;
}): Promise<void> {
  const { error } = await supabaseAdmin.from("ai_usage_log").insert({
    user_id: params.userId,
    route: params.route,
    model: params.model,
    input_tokens: params.inputTokens,
    output_tokens: params.outputTokens,
  });
  if (error) {
    // console.error("Errore nel log del consumo token AI", error);  // rimossa da JoJoX: registrava dati sensibili nei log
  }
}
