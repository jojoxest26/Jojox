import type { Lang } from "./translations.js";

export type LegalBlock = { type: "p"; text: string } | { type: "list"; items: string[] };

export interface LegalSection {
  heading: string;
  blocks: LegalBlock[];
}

export interface LegalDoc {
  title: string;
  lastUpdated: string;
  intro: string;
  sections: LegalSection[];
}

interface LegalPagesTree {
  backHome: string;
  privacy: LegalDoc;
  terms: LegalDoc;
}

function p(text: string): LegalBlock {
  return { type: "p", text };
}
function list(items: string[]): LegalBlock {
  return { type: "list", items };
}

const it: LegalPagesTree = {
  backHome: "← Torna a JoJoX",
  privacy: {
    title: "Informativa sulla Privacy",
    lastUpdated: "30 agosto 2026",
    intro:
      "Questa informativa spiega quali dati raccoglie JoJoX, per quali scopi, e quali diritti hai. È scritta per corrispondere esattamente a come funziona il servizio oggi: se cambia il modo in cui trattiamo i dati, aggiorniamo questa pagina e la data qui sopra.",
    sections: [
      {
        heading: "Titolare del trattamento",
        blocks: [
          p(
            "Il titolare del trattamento è [Nome e Cognome], persona fisica che sviluppa e gestisce JoJoX come attività individuale (al momento senza Partita IVA). Per qualsiasi richiesta relativa ai tuoi dati personali, o per esercitare i diritti descritti più sotto, scrivi a jojoxest26@gmail.com."
          ),
        ],
      },
      {
        heading: "Quali dati raccogliamo e perché",
        blocks: [
          p("JoJoX raccoglie solo i dati necessari a far funzionare il servizio che usi:"),
          list([
            "Account — se ti registri, Supabase (il nostro fornitore di autenticazione) conserva la tua email e la password in forma protetta. Servono per farti accedere e per collegare le analisi al tuo account.",
            "Analisi manuale da account — il codice che incolli o carichi viene inviato ai nostri server per essere analizzato. Se scegli di salvare il risultato nello storico, salviamo solo il punteggio, un riepilogo dei problemi trovati e un frammento minimo (poche parole) della riga interessata da ogni problema — mai la riga intera, mai il file completo.",
            "Modalità ospite (senza account) — il codice passa comunque dai nostri server per essere analizzato, perché serve a calcolare il risultato e ad applicare il limite di un tentativo gratuito per visitatore. Il codice non viene però mai salvato: resta solo il risultato mostrato a te, più un'impronta crittografica (hash SHA-256) del tuo indirizzo IP, che ci serve esclusivamente a riconoscere se hai già usato il tentativo gratuito e non permette di risalire né al codice analizzato né al tuo indirizzo IP originale.",
            "Integrazione GitHub — se colleghi un repository, ogni volta che c'è una nuova modifica il codice interessato viene inviato ai nostri server per l'analisi, con lo stesso trattamento dell'analisi manuale da account (si salvano solo punteggio, riepilogo e frammenti minimi).",
            "Pagamenti — l'elaborazione dei pagamenti è gestita interamente da Stripe. JoJoX non riceve né conserva mai il numero della tua carta o altri dati di pagamento: dal nostro lato vediamo solo l'identificativo cliente Stripe e il piano attivo.",
            "Lista d'attesa — se lasci la tua email per essere avvisato di una nuova funzionalità, la conserviamo solo per quello scopo.",
            "Dati di utilizzo del sito — usiamo Vercel Web Analytics, un servizio di analisi aggregata che non usa cookie e non traccia i singoli visitatori tra siti diversi.",
          ]),
        ],
      },
      {
        heading: "Base giuridica del trattamento",
        blocks: [
          list([
            "esecuzione di un contratto — per creare e gestire il tuo account, eseguire le analisi che richiedi ed erogare l'abbonamento che hai scelto;",
            "legittimo interesse — per prevenire un uso eccessivo del tentativo gratuito in modalità ospite, tramite l'impronta anonima dell'indirizzo IP;",
            "consenso — per l'iscrizione alla lista d'attesa; puoi ritirarlo in qualsiasi momento scrivendoci.",
          ]),
        ],
      },
      {
        heading: "Chi tratta i dati per nostro conto",
        blocks: [
          p(
            "Per far funzionare JoJoX ci appoggiamo ad alcuni fornitori esterni, che trattano i dati per nostro conto secondo i loro termini e le loro misure di sicurezza:"
          ),
          list([
            "Supabase — database, autenticazione e archiviazione dello storico delle analisi;",
            "Stripe — elaborazione dei pagamenti e degli abbonamenti;",
            "Railway — hosting del server che esegue le analisi;",
            "Vercel — hosting del sito e analisi di utilizzo aggregata (Web Analytics);",
            "GitHub — solo se attivi l'integrazione, per ricevere il codice delle modifiche ai repository collegati.",
          ]),
        ],
      },
      {
        heading: "Trasferimento dei dati fuori dall'Unione Europea",
        blocks: [
          p(
            "Alcuni dei fornitori elencati sopra possono trattare i dati su server situati fuori dallo Spazio Economico Europeo (ad esempio negli Stati Uniti). In questi casi, i fornitori si affidano alle clausole contrattuali standard approvate dalla Commissione Europea o ad altre garanzie equivalenti previste dal GDPR."
          ),
        ],
      },
      {
        heading: "Per quanto tempo conserviamo i dati",
        blocks: [
          list([
            "account e analisi salvate — finché non chiudi l'account o ce ne chiedi la cancellazione; oggi la cancellazione va richiesta scrivendoci, perché non è ancora disponibile un pulsante \"elimina account\" nel sito;",
            "impronta dell'IP in modalità ospite — resta finché applichiamo il limite del tentativo gratuito; non è ancora impostata una scadenza automatica, ma non contiene mai il codice analizzato né l'indirizzo IP originale;",
            "email della lista d'attesa — finché non ci chiedi di rimuoverla, o finché non ti contattiamo per la funzionalità richiesta.",
          ]),
        ],
      },
      {
        heading: "I tuoi diritti",
        blocks: [
          p("In quanto interessato, hai diritto a:"),
          list([
            "accedere ai dati che abbiamo su di te e ottenerne una copia;",
            "chiedere la correzione di dati inesatti;",
            "chiedere la cancellazione dei tuoi dati (\"diritto all'oblio\");",
            "chiedere la limitazione del trattamento;",
            "opporti al trattamento basato sul legittimo interesse;",
            "ricevere i tuoi dati in un formato strutturato (portabilità);",
            "proporre reclamo al Garante per la protezione dei dati personali (www.garanteprivacy.it).",
          ]),
          p("Per esercitare uno di questi diritti scrivi a jojoxest26@gmail.com: rispondiamo il prima possibile."),
        ],
      },
      {
        heading: "Sicurezza dei dati",
        blocks: [
          p(
            "Adottiamo misure tecniche ragionevoli per proteggere i tuoi dati (connessioni cifrate, accesso ai dati limitato tramite le policy di sicurezza di Supabase). Nessun sistema è sicuro al 100%: se dovessimo mai rilevare una violazione che riguarda i tuoi dati, te ne informeremmo come richiesto dalla legge."
          ),
        ],
      },
      {
        heading: "Cookie e tecnologie simili",
        blocks: [
          p(
            "JoJoX non usa cookie di profilazione o di tracciamento pubblicitario. Usiamo il local storage del browser solo per ricordare due preferenze tecniche: la lingua scelta e la sessione di accesso (gestita da Supabase Auth) — dati che restano sul tuo dispositivo e non vengono condivisi con terzi a scopo pubblicitario. Le statistiche di utilizzo del sito (Vercel Web Analytics) sono aggregate e anonime, e non usano cookie."
          ),
        ],
      },
      {
        heading: "Minori",
        blocks: [
          p(
            "JoJoX non è pensato per essere usato da minori di 16 anni. Se sei genitore o tutore e ritieni che un minore abbia creato un account senza il tuo consenso, scrivici e lo rimuoveremo."
          ),
        ],
      },
      {
        heading: "Modifiche a questa informativa",
        blocks: [
          p(
            "Possiamo aggiornare questa informativa se cambia il modo in cui trattiamo i dati. In caso di modifiche rilevanti, aggiorneremo la data in cima alla pagina."
          ),
        ],
      },
      {
        heading: "Contatti",
        blocks: [p("Per qualsiasi domanda su questa informativa o sul trattamento dei tuoi dati, scrivi a jojoxest26@gmail.com.")],
      },
    ],
  },
  terms: {
    title: "Termini di Servizio",
    lastUpdated: "30 agosto 2026",
    intro:
      "Usando JoJoX accetti questi termini. Sono scritti per corrispondere esattamente a come funziona il servizio oggi: se cambia qualcosa di rilevante, aggiorniamo questa pagina e la data qui sopra.",
    sections: [
      {
        heading: "Il servizio",
        blocks: [
          p(
            "JoJoX è uno strumento di analisi statica che scansiona codice sorgente (anche scritto con l'aiuto di un'intelligenza artificiale) alla ricerca di problemi di sicurezza noti, confrontandolo con pattern predefiniti (\"controlli\"). Non usa un modello di intelligenza artificiale per generare i risultati: ogni controllo è codice scritto e verificabile, elencato per intero nella sezione \"Tutti i controlli\" del sito."
          ),
        ],
      },
      {
        heading: "Cosa JoJoX non è",
        blocks: [
          p(
            "JoJoX è un aiuto, non una garanzia. I controlli disponibili individuano una parte dei problemi di sicurezza più comuni nel codice generato con AI, ma non possono individuare ogni possibile vulnerabilità, né sostituiscono un audit di sicurezza professionale, un penetration test o una revisione umana del codice. Usare JoJoX non elimina la tua responsabilità di verificare la sicurezza del software che pubblichi."
          ),
        ],
      },
      {
        heading: "Registrazione e account",
        blocks: [
          p(
            "Per salvare lo storico delle analisi, collegare un repository GitHub o attivare un piano a pagamento serve un account, creato con la tua email tramite Supabase Auth. Sei responsabile di mantenere riservate le tue credenziali di accesso."
          ),
        ],
      },
      {
        heading: "Piani e pagamenti",
        blocks: [
          list([
            "Ospite — un'analisi gratuita per visitatore, senza registrazione, senza salvataggio dello storico;",
            "Gratis — analisi illimitate accedendo con un account, con storico salvato;",
            "Pro e Team — funzionalità aggiuntive (come l'integrazione GitHub) a pagamento, con abbonamento gestito tramite Stripe.",
          ]),
          p(
            "Gli abbonamenti a pagamento si rinnovano automaticamente finché non li disdici. Puoi disdire in qualsiasi momento dal portale abbonamento, raggiungibile dal tuo account: la disdetta ha effetto alla fine del periodo già pagato, senza penali."
          ),
        ],
      },
      {
        heading: "Uso consentito",
        blocks: [
          p(
            "Puoi usare JoJoX per analizzare codice di cui hai il diritto (tuo, della tua azienda, o che sei autorizzato ad analizzare). È vietato usare JoJoX per analizzare codice altrui senza autorizzazione, per tentare di aggirare i limiti di utilizzo (ad esempio il tentativo gratuito in modalità ospite), o per qualunque uso illecito."
          ),
        ],
      },
      {
        heading: "Proprietà intellettuale",
        blocks: [
          p(
            "Il codice che analizzi resta di tua proprietà: JoJoX non ne acquisisce alcun diritto. Il software, il marchio JoJoX e i contenuti del sito restano di proprietà del titolare del servizio."
          ),
        ],
      },
      {
        heading: "Limitazione di responsabilità",
        blocks: [
          p(
            "Nei limiti consentiti dalla legge, JoJoX viene fornito \"così com'è\", senza garanzia che individui tutti i problemi di sicurezza presenti nel codice analizzato. Il titolare del servizio non risponde di danni indiretti derivanti dall'uso o dall'impossibilità di usare il servizio, salvo i casi in cui la legge non permette di limitare la responsabilità (ad esempio dolo o colpa grave)."
          ),
        ],
      },
      {
        heading: "Sospensione e cessazione del servizio",
        blocks: [
          p(
            "Ci riserviamo il diritto di sospendere o chiudere un account in caso di uso improprio del servizio (ad esempio tentativi di aggirare i limiti gratuiti o attività illecite). Puoi chiudere il tuo account in qualsiasi momento scrivendo a jojoxest26@gmail.com."
          ),
        ],
      },
      {
        heading: "Modifiche a questi termini",
        blocks: [
          p("Possiamo aggiornare questi termini quando cambia il servizio. Le modifiche rilevanti saranno indicate aggiornando la data in cima a questa pagina."),
        ],
      },
      {
        heading: "Legge applicabile",
        blocks: [
          p(
            "Questi termini sono regolati dalla legge italiana. Per qualsiasi controversia con un utente consumatore, resta fermo il foro del consumatore stabilito dalla legge."
          ),
        ],
      },
      {
        heading: "Contatti",
        blocks: [p("Per qualsiasi domanda su questi termini, scrivi a jojoxest26@gmail.com.")],
      },
    ],
  },
};

const en: LegalPagesTree = {
  backHome: "← Back to JoJoX",
  privacy: {
    title: "Privacy Policy",
    lastUpdated: "August 30, 2026",
    intro:
      "This policy explains what data JoJoX collects, why, and what rights you have. It's written to match exactly how the service works today: if how we handle data changes, we update this page and the date above.",
    sections: [
      {
        heading: "Data controller",
        blocks: [
          p(
            "The data controller is [Full Name], an individual who develops and runs JoJoX as a sole activity (currently without a registered VAT number). For any request about your personal data, or to exercise the rights described below, write to jojoxest26@gmail.com."
          ),
        ],
      },
      {
        heading: "What data we collect and why",
        blocks: [
          p("JoJoX only collects the data needed to run the part of the service you use:"),
          list([
            "Account — if you sign up, Supabase (our authentication provider) stores your email and a protected version of your password. This lets you log in and links your analyses to your account.",
            "Manual analysis while logged in — the code you paste or upload is sent to our servers to be analyzed. If you choose to save the result to your history, we only save the score, a summary of the issues found, and a minimal fragment (a few words) of the line affected by each issue — never the whole line, never the whole file.",
            "Guest mode (no account) — the code still goes through our servers to be analyzed, because that's needed to compute the result and enforce the one-free-try limit per visitor. The code itself is never saved: only the result shown to you is kept, plus a cryptographic fingerprint (SHA-256 hash) of your IP address, used solely to recognize whether you've already used your free try — it cannot be used to recover the analyzed code or your original IP address.",
            "GitHub integration — if you connect a repository, the changed code is sent to our servers for analysis every time there's a new change, handled the same way as manual analysis while logged in (only score, summary, and minimal fragments are saved).",
            "Payments — payment processing is handled entirely by Stripe. JoJoX never receives or stores your card number or other payment details: on our side we only see your Stripe customer ID and active plan.",
            "Waitlist — if you leave your email to be notified about a feature, we keep it only for that purpose.",
            "Site usage data — we use Vercel Web Analytics, an aggregate analytics service that doesn't use cookies and doesn't track individual visitors across sites.",
          ]),
        ],
      },
      {
        heading: "Legal basis for processing",
        blocks: [
          list([
            "performance of a contract — to create and manage your account, run the analyses you request, and deliver the plan you chose;",
            "legitimate interest — to prevent excessive use of the free guest-mode try, via the anonymous IP fingerprint;",
            "consent — for joining the waitlist; you can withdraw it at any time by writing to us.",
          ]),
        ],
      },
      {
        heading: "Who processes data on our behalf",
        blocks: [
          p("To run JoJoX we rely on a few external providers, who process data on our behalf under their own terms and security measures:"),
          list([
            "Supabase — database, authentication, and storage of your saved analysis history;",
            "Stripe — payment and subscription processing;",
            "Railway — hosting for the server that runs the analyses;",
            "Vercel — site hosting and aggregate usage analytics (Web Analytics);",
            "GitHub — only if you enable the integration, to receive the code from changes to connected repositories.",
          ]),
        ],
      },
      {
        heading: "Transfers of data outside the European Union",
        blocks: [
          p(
            "Some of the providers listed above may process data on servers located outside the European Economic Area (for example, in the United States). In those cases, they rely on the Standard Contractual Clauses approved by the European Commission or other equivalent safeguards under the GDPR."
          ),
        ],
      },
      {
        heading: "How long we keep data",
        blocks: [
          list([
            "account and saved analyses — until you close your account or ask us to delete it; today, account deletion has to be requested by email, since there isn't yet a self-service \"delete account\" button on the site;",
            "IP fingerprint in guest mode — kept for as long as we enforce the free-try limit; there's no automatic expiry set yet, but it never contains the analyzed code or your original IP address;",
            "waitlist email — until you ask us to remove it, or until we contact you about the feature you signed up for.",
          ]),
        ],
      },
      {
        heading: "Your rights",
        blocks: [
          p("As a data subject, you have the right to:"),
          list([
            "access the data we hold about you and get a copy of it;",
            "request correction of inaccurate data;",
            "request deletion of your data (\"right to be forgotten\");",
            "request restriction of processing;",
            "object to processing based on legitimate interest;",
            "receive your data in a structured format (portability);",
            "lodge a complaint with the Italian data protection authority, the Garante per la protezione dei dati personali (www.garanteprivacy.it).",
          ]),
          p("To exercise any of these rights, write to jojoxest26@gmail.com — we'll get back to you as soon as we can."),
        ],
      },
      {
        heading: "Data security",
        blocks: [
          p(
            "We use reasonable technical measures to protect your data (encrypted connections, access to data restricted through Supabase's security policies). No system is 100% secure: if we ever detect a breach affecting your data, we'll let you know as required by law."
          ),
        ],
      },
      {
        heading: "Cookies and similar technologies",
        blocks: [
          p(
            "JoJoX doesn't use profiling or advertising-tracking cookies. We use browser local storage only to remember two technical preferences: your chosen language and your login session (managed by Supabase Auth) — data that stays on your device and is never shared with third parties for advertising purposes. Site usage statistics (Vercel Web Analytics) are aggregate and anonymous, and don't use cookies."
          ),
        ],
      },
      {
        heading: "Children",
        blocks: [
          p(
            "JoJoX isn't intended for use by anyone under 16. If you're a parent or guardian and believe a minor created an account without your consent, contact us and we'll remove it."
          ),
        ],
      },
      {
        heading: "Changes to this policy",
        blocks: [
          p("We may update this policy if how we handle data changes. For any significant change, we'll update the date at the top of the page."),
        ],
      },
      {
        heading: "Contact",
        blocks: [p("For any question about this policy or how we handle your data, write to jojoxest26@gmail.com.")],
      },
    ],
  },
  terms: {
    title: "Terms of Service",
    lastUpdated: "August 30, 2026",
    intro:
      "By using JoJoX you agree to these terms. They're written to match exactly how the service works today: if anything meaningful changes, we update this page and the date above.",
    sections: [
      {
        heading: "The service",
        blocks: [
          p(
            "JoJoX is a static analysis tool that scans source code (including code written with the help of an AI) for known security issues, by matching it against predefined patterns (\"checks\"). It doesn't use an AI model to generate results: every check is written, verifiable code, listed in full in the \"All checks\" section of the site."
          ),
        ],
      },
      {
        heading: "What JoJoX isn't",
        blocks: [
          p(
            "JoJoX is a help, not a guarantee. The available checks catch a portion of the most common security issues in AI-generated code, but they can't catch every possible vulnerability, and they don't replace a professional security audit, a penetration test, or a human code review. Using JoJoX doesn't remove your responsibility to verify the security of the software you ship."
          ),
        ],
      },
      {
        heading: "Registration and accounts",
        blocks: [
          p(
            "To save your analysis history, connect a GitHub repository, or activate a paid plan, you need an account, created with your email through Supabase Auth. You're responsible for keeping your login credentials confidential."
          ),
        ],
      },
      {
        heading: "Plans and payments",
        blocks: [
          list([
            "Guest — one free analysis per visitor, no sign-up, no saved history;",
            "Free — unlimited analyses when logged in, with saved history;",
            "Pro and Team — additional paid features (like the GitHub integration), with subscriptions managed through Stripe.",
          ]),
          p(
            "Paid subscriptions renew automatically until cancelled. You can cancel at any time from the subscription portal, reachable from your account: cancellation takes effect at the end of the period you already paid for, with no penalty."
          ),
        ],
      },
      {
        heading: "Acceptable use",
        blocks: [
          p(
            "You may use JoJoX to analyze code you have the right to (your own, your company's, or code you're authorized to analyze). You may not use JoJoX to analyze other people's code without authorization, to try to bypass usage limits (such as the free guest-mode try), or for any unlawful purpose."
          ),
        ],
      },
      {
        heading: "Intellectual property",
        blocks: [
          p(
            "The code you analyze remains yours: JoJoX doesn't acquire any rights over it. The software, the JoJoX brand, and the site's content remain the property of the service's owner."
          ),
        ],
      },
      {
        heading: "Limitation of liability",
        blocks: [
          p(
            "To the extent permitted by law, JoJoX is provided \"as is\", with no guarantee that it identifies every security issue present in the analyzed code. The service's owner isn't liable for indirect damages arising from the use, or inability to use, the service, except where the law doesn't allow limiting liability (for example, intent or gross negligence)."
          ),
        ],
      },
      {
        heading: "Suspension and termination",
        blocks: [
          p(
            "We reserve the right to suspend or close an account in case of misuse of the service (for example, attempts to bypass free-tier limits or unlawful activity). You can close your account at any time by writing to jojoxest26@gmail.com."
          ),
        ],
      },
      {
        heading: "Changes to these terms",
        blocks: [
          p("We may update these terms when the service changes. Significant changes will be reflected by updating the date at the top of this page."),
        ],
      },
      {
        heading: "Governing law",
        blocks: [
          p(
            "These terms are governed by Italian law. For any dispute with a consumer user, the consumer's statutory forum protections continue to apply."
          ),
        ],
      },
      {
        heading: "Contact",
        blocks: [p("For any question about these terms, write to jojoxest26@gmail.com.")],
      },
    ],
  },
};

export const legalPages: Record<Lang, LegalPagesTree> = { it, en };
