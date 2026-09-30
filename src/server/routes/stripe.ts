import { Router } from "express";
import { z } from "zod";
import { env } from "../env.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { stripeRequest, StripeNotConfiguredError, STRIPE_ACTIVE_SUBSCRIPTION_STATUSES } from "../stripe/client.js";
import { priceIdForPlan } from "../stripe/plans.js";

export const stripeRouter = Router();

const checkoutSchema = z.object({
  plan: z.enum(["pro", "team"]),
  interval: z.enum(["monthly", "annual"]).default("monthly"),
});

interface StripeCustomer {
  id: string;
}

interface StripeCheckoutSession {
  url: string;
}

interface StripeSubscriptionListItem {
  id: string;
  status: string;
  items: { data: { id: string; price: { id: string } }[] };
}

/**
 * L'abbonamento già attivo del cliente (Pro o Team), se esiste. Usata prima
 * di creare un nuovo checkout per capire se si tratta di un cambio di piano
 * (da aggiornare sull'abbonamento esistente) invece di un abbonamento nuovo —
 * senza questo controllo un cliente che passa da Pro a Team si ritroverebbe
 * con due abbonamenti attivi insieme, pagati entrambi ogni mese.
 */
async function findActiveSubscription(customerId: string): Promise<{ id: string; itemId: string } | null> {
  const subscriptions = await stripeRequest<{ data: StripeSubscriptionListItem[] }>("GET", "/subscriptions", {
    customer: customerId,
    status: "all",
    limit: 100,
  });

  const active = subscriptions.data.find((s) => STRIPE_ACTIVE_SUBSCRIPTION_STATUSES.has(s.status));
  const itemId = active?.items.data[0]?.id;
  return active && itemId ? { id: active.id, itemId } : null;
}

interface StripePortalSession {
  url: string;
}

/** Trova il customer Stripe già associato al profilo, o ne crea uno nuovo e lo salva. */
async function getOrCreateStripeCustomer(userId: string): Promise<string> {
  const { data: profile } = await supabaseAdmin
    .from("profiles")
    .select("stripe_customer_id")
    .eq("id", userId)
    .single();

  if (profile?.stripe_customer_id) return profile.stripe_customer_id as string;

  const { data: userData } = await supabaseAdmin.auth.admin.getUserById(userId);
  const email = userData.user?.email;

  const customer = await stripeRequest<StripeCustomer>("POST", "/customers", {
    email,
    metadata: { supabase_user_id: userId },
  });

  await supabaseAdmin.from("profiles").update({ stripe_customer_id: customer.id }).eq("id", userId);
  return customer.id;
}

stripeRouter.post("/api/stripe/create-checkout-session", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = checkoutSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Piano non valido" });
    return;
  }

  const priceId = priceIdForPlan(parsed.data.plan, parsed.data.interval);
  if (!priceId) {
    res.status(503).json({ error: "Pagamenti non ancora configurati" });
    return;
  }

  try {
    const customerId = await getOrCreateStripeCustomer(req.userId!);

    // Cliente già abbonato (Pro o Team): cambiamo il prezzo su quello stesso
    // abbonamento invece di aprire un nuovo checkout — niente carta da
    // inserire di nuovo, e soprattutto niente doppio abbonamento attivo.
    const existingSubscription = await findActiveSubscription(customerId);
    if (existingSubscription) {
      await stripeRequest("POST", `/subscriptions/${existingSubscription.id}`, {
        items: [{ id: existingSubscription.itemId, price: priceId }],
        proration_behavior: "create_prorations",
      });
      res.json({ url: `${env.appUrl}/?checkout=success` });
      return;
    }

    const session = await stripeRequest<StripeCheckoutSession>("POST", "/checkout/sessions", {
      customer: customerId,
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${env.appUrl}/?checkout=success`,
      cancel_url: `${env.appUrl}/?checkout=cancel`,
    });
    res.json({ url: session.url });
  } catch (err) {
    if (err instanceof StripeNotConfiguredError) {
      res.status(503).json({ error: err.message });
      return;
    }
    console.error("errore nella creazione della sessione di checkout Stripe", err);
    res.status(500).json({ error: "Errore nella creazione del pagamento" });
  }
});

stripeRouter.post("/api/stripe/create-audit-checkout-session", requireAuth, async (req: AuthedRequest, res) => {
  if (!env.stripePriceIdAudit) {
    res.status(503).json({ error: "Pagamenti non ancora configurati" });
    return;
  }

  try {
    const customerId = await getOrCreateStripeCustomer(req.userId!);
    const session = await stripeRequest<StripeCheckoutSession>("POST", "/checkout/sessions", {
      customer: customerId,
      mode: "payment",
      line_items: [{ price: env.stripePriceIdAudit, quantity: 1 }],
      // Pagamento singolo, non un piano: il webhook usa questi metadata per
      // capire che deve accreditare un Full Site Audit, non aggiornare un abbonamento.
      metadata: { supabase_user_id: req.userId!, product: "audit" },
      success_url: `${env.appUrl}/?audit=success`,
      cancel_url: `${env.appUrl}/?audit=cancel`,
    });
    res.json({ url: session.url });
  } catch (err) {
    if (err instanceof StripeNotConfiguredError) {
      res.status(503).json({ error: err.message });
      return;
    }
    console.error("errore nella creazione della sessione di checkout per il Full Site Audit", err);
    res.status(500).json({ error: "Errore nella creazione del pagamento" });
  }
});

stripeRouter.post("/api/stripe/create-portal-session", requireAuth, async (req: AuthedRequest, res) => {
  const { data: profile } = await supabaseAdmin
    .from("profiles")
    .select("stripe_customer_id")
    .eq("id", req.userId)
    .single();

  if (!profile?.stripe_customer_id) {
    res.status(400).json({ error: "Nessun abbonamento attivo da gestire" });
    return;
  }

  try {
    const session = await stripeRequest<StripePortalSession>("POST", "/billing_portal/sessions", {
      customer: profile.stripe_customer_id,
      return_url: env.appUrl,
    });
    res.json({ url: session.url });
  } catch (err) {
    if (err instanceof StripeNotConfiguredError) {
      res.status(503).json({ error: err.message });
      return;
    }
    console.error("errore nella creazione della sessione del portale Stripe", err);
    res.status(500).json({ error: "Errore nell'apertura del portale abbonamento" });
  }
});