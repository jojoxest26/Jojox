import { Router } from "express";
import { z } from "zod";
import { env } from "../env.js";
import { requireAuth, type AuthedRequest } from "../auth/middleware.js";
import { supabaseAdmin } from "../db/supabase.js";
import { stripeRequest, StripeNotConfiguredError } from "../stripe/client.js";
import { priceIdForPlan } from "../stripe/plans.js";

export const stripeRouter = Router();

const checkoutSchema = z.object({ plan: z.enum(["pro", "team"]) });

interface StripeCustomer {
  id: string;
}

interface StripeCheckoutSession {
  url: string;
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

  const priceId = priceIdForPlan(parsed.data.plan);
  if (!priceId) {
    res.status(503).json({ error: "Pagamenti non ancora configurati" });
    return;
  }

  try {
    const customerId = await getOrCreateStripeCustomer(req.userId!);
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