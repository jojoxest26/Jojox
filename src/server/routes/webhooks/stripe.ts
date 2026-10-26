import { Router, raw } from "express";
import { env } from "../../env.js";
import { verifyStripeSignature } from "../../stripe/verifySignature.js";
import { planForPriceId } from "../../stripe/plans.js";
import { stripeRequest, STRIPE_ACTIVE_SUBSCRIPTION_STATUSES } from "../../stripe/client.js";
import { supabaseAdmin } from "../../db/supabase.js";
import { reportError } from "../../sentry.js";
import { ANALYSIS_PACK_SIZE, type Plan } from "../../plan.js";

interface SubscriptionEventObject {
  customer: string;
  status: string;
  items: { data: { price: { id: string } }[] };
}

interface StripeSubscriptionList {
  data: { status: string; items: { data: { price: { id: string } }[] } }[];
}

interface CheckoutSessionEventObject {
  id: string;
  mode: string;
  metadata?: { supabase_user_id?: string; product?: string };
}

export const stripeWebhookRouter = Router();

stripeWebhookRouter.post("/webhooks/stripe", raw({ type: "application/json" }), async (req, res) => {
  if (!env.stripeWebhookSecret) {
    res.status(503).json({ error: "Webhook Stripe non configurato" });
    return;
  }

  const signature = req.header("stripe-signature");
  const payload = (req.body as Buffer).toString("utf8");

  if (!verifyStripeSignature(payload, signature, env.stripeWebhookSecret)) {
    res.status(401).json({ error: "Firma non valida" });
    return;
  }

  const event = JSON.parse(payload) as {
    type: string;
    data: { object: SubscriptionEventObject | CheckoutSessionEventObject };
  };

  try {
    if (
      event.type === "customer.subscription.created" ||
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      await resyncPlanForCustomer((event.data.object as SubscriptionEventObject).customer);
    } else if (event.type === "checkout.session.completed") {
      await handleCheckoutCompleted(event.data.object as CheckoutSessionEventObject);
    }
    res.json({ received: true });
  } catch (err) {
    console.error(`errore nell'elaborazione del webhook Stripe (${event.type})`, err);
    reportError(err);
    // 500 così Stripe ritenta: se è un problema temporaneo (es. Supabase giù), non vogliamo perdere l'evento.
    res.status(500).json({ error: "Errore nell'elaborazione dell'evento" });
  }
});

/**
 * Ricalcola il piano di un cliente guardando TUTTI i suoi abbonamenti Stripe
 * attivi, non solo quello coinvolto nell'evento appena arrivato — un cliente
 * può finire con più abbonamenti attivi insieme (es. passa da Pro a Team
 * senza cancellare il vecchio), e il piano giusto è sempre il più alto tra
 * quelli davvero attivi, mai semplicemente "l'ultimo evento ricevuto".
 * Tiene anche al riparo da eventi Stripe che arrivano fuori ordine.
 */
async function resyncPlanForCustomer(stripeCustomerId: string): Promise<void> {
  const subscriptions = await stripeRequest<StripeSubscriptionList>("GET", "/subscriptions", {
    customer: stripeCustomerId,
    status: "all",
    limit: 100,
  });

  // Ordine di importanza se per qualche motivo risultano più abbonamenti
  // attivi insieme: business > team > pro > free.
  const PLAN_RANK: Record<Plan, number> = { free: 0, pro: 1, team: 2, business: 3 };
  let highestPlan: Plan = "free";
  for (const subscription of subscriptions.data) {
    if (!STRIPE_ACTIVE_SUBSCRIPTION_STATUSES.has(subscription.status)) continue;
    const priceId = subscription.items.data[0]?.price.id;
    const plan = priceId ? planForPriceId(priceId) : null;
    if (plan && PLAN_RANK[plan] > PLAN_RANK[highestPlan]) highestPlan = plan;
    if (highestPlan === "business") break;
  }

  await setPlanForCustomer(stripeCustomerId, highestPlan);
}

async function setPlanForCustomer(stripeCustomerId: string, plan: Plan): Promise<void> {
  await supabaseAdmin.from("profiles").update({ plan }).eq("stripe_customer_id", stripeCustomerId);
}

/**
 * Pagamento singolo (mode "payment", non "subscription"), riconosciuto dai
 * metadata impostati alla creazione della sessione — un abbonamento normale
 * non ha mai `product` nei suoi metadata.
 */
async function handleCheckoutCompleted(session: CheckoutSessionEventObject): Promise<void> {
  if (session.mode !== "payment") return;

  const userId = session.metadata?.supabase_user_id;
  if (!userId) return;

  if (session.metadata?.product === "audit") {
    await grantAuditCredit(userId, session.id);
  } else if (session.metadata?.product === "analysis_pack") {
    await grantAnalysisPack(userId, session.id);
  }
}

async function grantAuditCredit(userId: string, sessionId: string): Promise<void> {
  const { error } = await supabaseAdmin.from("audit_credits").insert({
    user_id: userId,
    stripe_checkout_session_id: sessionId,
  });

  // Stripe dichiara esplicitamente che lo stesso evento webhook può arrivare
  // più di una volta: il codice 23505 (violazione del vincolo di unicità su
  // stripe_checkout_session_id) significa che questo pagamento è già stato
  // accreditato in precedenza — non è un errore, non va accreditato due
  // volte. Qualsiasi altro errore va invece rilanciato: la richiesta risponde
  // 500 e Stripe riprova, così un fallimento di rete o del database non
  // lascia un cliente che ha pagato senza il suo credito.
  if (error && error.code !== "23505") {
    throw new Error(`impossibile accreditare il Full Site Audit per la sessione ${sessionId}: ${error.message}`);
  }
}

/**
 * Un pacchetto crea più crediti insieme (ANALYSIS_PACK_SIZE), non uno solo
 * come l'audit: la deduplica (stesso ragionamento del codice 23505 sopra)
 * vive sulla riga "acquisto" — se quella non si crea perché già esiste,
 * non creiamo nemmeno i crediti che ne deriverebbero, evitando un doppio
 * accredito se Stripe consegna lo stesso evento due volte.
 */
async function grantAnalysisPack(userId: string, sessionId: string): Promise<void> {
  const { data: purchase, error } = await supabaseAdmin
    .from("analysis_credit_purchases")
    .insert({ user_id: userId, stripe_checkout_session_id: sessionId, credits: ANALYSIS_PACK_SIZE })
    .select("id")
    .single();

  if (error) {
    if (error.code === "23505") return;
    throw new Error(`impossibile registrare l'acquisto del pacchetto di analisi per la sessione ${sessionId}: ${error.message}`);
  }

  const rows = Array.from({ length: ANALYSIS_PACK_SIZE }, () => ({ user_id: userId, purchase_id: purchase.id }));
  const { error: creditsError } = await supabaseAdmin.from("analysis_credits").insert(rows);
  if (creditsError) {
    throw new Error(`impossibile creare i crediti del pacchetto di analisi per la sessione ${sessionId}: ${creditsError.message}`);
  }
}