-- Impedisce di accreditare due volte lo stesso pagamento Stripe se il
-- webhook "checkout.session.completed" viene consegnato più di una volta
-- (Stripe dichiara esplicitamente che può succedere, non è un caso raro).
alter table public.audit_credits
  add constraint audit_credits_stripe_checkout_session_id_key unique (stripe_checkout_session_id);