import { Router, raw } from "express";
import { env } from "../../env.js";
import { verifyStripeSignature } from "../../stripe/verifySignature.js";
import { planForPriceId } from "../../stripe/plans.js";
import { supabaseAdmin } from "../../db/supabase.js";

interface SubscriptionEventObject {
  customer: string;
  status: string;
  items: { data: { price: { id: string } }[] };
}

interface CheckoutSessionEventObject {
  id: string;
  mode: string;
  metadata?: { supabase_user_id?: string; product?: string };
}

export const stripeWebhookRouter = Router();

const ACTIVE_STATUSES = new Set(["active", "trialing"]);

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
    if (event.type === "customer.subscription.created" || event.type === "customer.subscription.updated") {
      await syncPlanFromSubscription(event.data.object as SubscriptionEventObject);
    } else if (event.type === "customer.subscription.deleted") {
      await setPlanForCustomer((event.data.object as SubscriptionEventObject).customer, "free");
    } else if (event.type === "checkout.session.completed") {
      await handleCheckoutCompleted(event.data.object as CheckoutSessionEventObject);
    }
    res.json({ received: true });
  } catch (err) {
    console.error(`errore nell'elaborazione del webhook Stripe (${event.type})`, err);
    // 500 così Stripe ritenta: se è un problema temporaneo (es. Supabase giù), non vogliamo perdere l'evento.
    res.status(500).json({ error: "Errore nell'elaborazione dell'evento" });
  }
});

async function syncPlanFromSubscription(subscription: SubscriptionEventObject): Promise<void> {
  if (!ACTIVE_STATUSES.has(subscription.status)) {
    await setPlanForCustomer(subscription.customer, "free");
    return;
  }

  const priceId = subscription.items.data[0]?.price.id;
  const plan = priceId ? planForPriceId(priceId) : null;
  if (plan) await setPlanForCustomer(subscription.customer, plan);
}

async function setPlanForCustomer(stripeCustomerId: string, plan: "free" | "pro" | "team"): Promise<void> {
  await supabaseAdmin.from("profiles").update({ plan }).eq("stripe_customer_id", stripeCustomerId);
}

/**
 * Pagamento singolo per un Full Site Audit (mode "payment", non "subscription").
 * Riconosciuto dai metadata impostati alla creazione della sessione — un
 * abbonamento normale non ha mai product: "audit" nei suoi metadata.
 */
async function handleCheckoutCompleted(session: CheckoutSessionEventObject): Promise<void> {
  if (session.mode !== "payment" || session.metadata?.product !== "audit") return;

  const userId = session.metadata?.supabase_user_id;
  if (!userId) return;

  await supabaseAdmin.from("audit_credits").insert({
    user_id: userId,
    stripe_checkout_session_id: session.id,
  });
}