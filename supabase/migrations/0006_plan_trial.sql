-- JoJoX — prova gratuita di 30 giorni del piano Pro, offerta dopo un Full
-- Site Audit per far vedere il monitoraggio continuo in azione. Un campo
-- solo: se è nel futuro, l'utente viene trattato come "pro" (vedi
-- getPlanForUser) anche se il piano pagato resta "free" — senza toccare
-- Stripe né la fatturazione.

alter table public.profiles
  add column plan_trial_expires_at timestamptz;