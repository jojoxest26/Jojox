export type Lang = "it" | "en";

interface FeatureItem {
  icon: string;
  accent: string;
  title: string;
  text: string;
}

interface RoadmapItem {
  icon: string;
  title: string;
  text: string;
}

export interface TranslationTree {
  meta: {
    dateLocale: string;
    title: string;
  };
  common: {
    severity: { critical: string; high: string; medium: string; low: string };
    confirmed: string;
    heuristic: string;
    before: string;
    after: string;
  };
  header: {
    connect: string;
    connectAnother: string;
    connected: string;
    logout: string;
    login: string;
  };
  hero: {
    titleLine1: string;
    titleLine2Suffix: string;
    body: string;
    bodyMonitoring: string;
    bodyScore: string;
    sub: string;
    pill1: string;
    pill2: string;
    pill3: string;
    badge: string;
    cta: string;
    guestNote: string;
  };
  features: FeatureItem[];
  whyNotAi: {
    question: string;
    point1: string;
    point2: string;
    point3: string;
    closing: string;
  };
  pricing: {
    title: string;
    subtitle: string;
    noticeSuccess: string;
    noticeCancel: string;
    guestTitle: string;
    guestList: string[];
    guestCta: string;
    freeTitle: string;
    freeList: string[];
    freeCta: string;
    freeNote: string;
    proBadge: string;
    proTitle: string;
    proPer: string;
    proList: string[];
    proCta: string;
    proActivating: string;
    proNote: string;
    teamBadge: string;
    teamTitle: string;
    teamPer: string;
    teamList: string[];
    teamCta: string;
    teamActivating: string;
    teamNote: string;
    activePlan: string;
    manageSubscription: string;
    opening: string;
    errorActivation: string;
    errorPortal: string;
    disclaimer: string;
  };
  footer: {
    intro: string;
    items: string[];
  };
  checksList: {
    title: string;
    body: string;
    subLabel: string;
    note: string;
  };
  login: {
    sent: string;
    prompt: string;
    sending: string;
    send: string;
    error: string;
    close: string;
  };
  analyzer: {
    gateTitle: string;
    gateBody: string;
    gateCta: string;
    dropzoneCta: string;
    dropzoneHintLoggedIn: string;
    dropzoneHintGuest: string;
    dropzoneHintAny: string;
    moreFiles: string;
    analyzeButton: string;
    analyzeButtonCount: string;
    analyzing: string;
    errorGuestUsed: string;
    errorGeneric: string;
    autofixFixedOne: string;
    autofixFixedMany: string;
    autofixManualSuffix: string;
    autofixManualOnly: string;
    downloadZip: string;
    downloadPdf: string;
  };
  history: {
    title: string;
    manualSource: string;
    error: string;
  };
  scoreChart: {
    title: string;
    ariaLabel: string;
  };
  findingsList: {
    scoreLabel: string;
    emptyState: string;
  };
  github: {
    title: string;
    badge: string;
    body1: string;
    body2: string;
    note: string;
    connectedLabel: string;
    toggleShow: string;
    toggleHide: string;
    badgeTitle: string;
    badgeBody: string;
    terminalTitle: string;
    terminalBody: string;
    terminalLink: string;
    hookTitle: string;
    hookBody: string;
    slackTitle: string;
    slackConnectFirst: string;
    slackBody: string;
    slackLink: string;
    slackSaving: string;
    slackSave: string;
    slackSaved: string;
    slackErrorGeneric: string;
  };
  waitlist: {
    title: string;
    subtitle: string;
    roadmap: RoadmapItem[];
    emailPlaceholder: string;
    submit: string;
    done: string;
    error: string;
  };
  supabase: {
    title: string;
    badge: string;
    body1: string;
    body2: string;
    sqlEditor: string;
    toggleShow: string;
    toggleHide: string;
  };
  report: {
    brandSub: string;
    reportLabel: string;
    generatedOn: string;
    controlsNoLLM: string;
    filesScannedOne: string;
    filesScannedMany: string;
    projectFallback: string;
    noProblems: string;
    oneProblem: string;
    manyProblems: string;
    autofixNoteOne: string;
    autofixNoteMany: string;
    autofixNoteSuffix: string;
    resultsLabel: string;
    emptyState: string;
    printBtn: string;
    printHint: string;
    popupBlocked: string;
  };
}

const it: TranslationTree = {
  meta: {
    dateLocale: "it-IT",
    title: "JoJoX — Sicurezza per codice scritto dall'IA",
  },
  common: {
    severity: {
      critical: "Critico",
      high: "Alto",
      medium: "Medio",
      low: "Basso",
    },
    confirmed: "confermato",
    heuristic: "da verificare",
    before: "Prima",
    after: "Dopo",
  },
  header: {
    connect: "Collega GitHub",
    connectAnother: "Collega un altro account GitHub",
    connected: "✓ GitHub collegato",
    logout: "Esci",
    login: "Accedi",
  },
  hero: {
    titleLine1: "Il tuo agente AI scrive codice ogni giorno.",
    titleLine2Suffix: "lo sorveglia.",
    body: "Non un controllo una tantum. {{monitoring}}. 21 controlli pubblici sugli errori più comuni nel codice scritto dall'IA, un {{score}} chiaro, e correzioni pronte da copiare.",
    bodyMonitoring: "Monitoraggio continuo",
    bodyScore: "punteggio di sicurezza",
    sub: "Le verifiche che normalmente richiedono ore, automatizzate e sempre attive.",
    pill1: "Correzioni sempre nel tuo browser",
    pill2: "Nessuna registrazione per iniziare",
    pill3: "Gratis",
    badge: "Per progetti costruiti con Claude Code · Cursor · Lovable · Bolt",
    cta: "Analizza il tuo codice — gratis",
    guestNote: "1 analisi gratuita senza email. Poi basta la mail — 5 analisi/mese gratis.",
  },
  features: [
    {
      icon: "🛡️",
      accent: "blue",
      title: "Il codice non viene mai salvato",
      text: "L'analisi che carichi a mano passa dai nostri server (per salvare punteggio e storico), ma il testo dei file non viene mai conservato — solo i risultati. Le correzioni automatiche, invece, restano sempre e solo nel tuo browser.",
    },
    {
      icon: "🔧",
      accent: "amber",
      title: "Non solo l'errore, anche come risolverlo",
      text: "Ogni problema è accompagnato da un esempio di correzione, mostrato come un prima/dopo: capisci subito cosa cambiare.",
    },
    {
      icon: "📊",
      accent: "mint",
      title: "Punteggio di sicurezza + badge",
      text: "Un punteggio da 0 a 100, calcolato con una formula che vedi per intero, più un badge da mettere nel README del progetto.",
    },
  ],
  whyNotAi: {
    question: "Il mio agente AI già scrive il codice. Non può controllarlo anche lui?",
    point1: "Puoi chiederlo. Ma nella pratica quasi nessuno lo fa ogni volta, su ogni file, dopo ogni modifica — e basta dimenticarsene una volta per lasciare un buco aperto. JoJoX non aspetta che te ne ricordi: controlla da solo, a ogni push.",
    point2: "Chiedere \"è sicuro?\" a un modello è come chiedere un parere: cambia ogni volta e non lascia una prova. JoJoX esegue sempre gli stessi 21 controlli pubblici, identici per tutti, verificabili riga per riga nel codice — un responso, non un'opinione.",
    point3: "Nessun LLM, nessuna allucinazione, nessun costo che cresce con l'uso: pattern matching puro, istantaneo, pensato per girare su ogni pull request quante volte serve.",
    closing: "JoJoX non scrive il tuo codice. Lo sorveglia — sempre, allo stesso modo, senza che tu debba chiederlo.",
  },
  pricing: {
    title: "Paghi il monitoraggio continuo, non le singole analisi",
    subtitle: "Prova 1 analisi senza dare nulla. Poi basta l'email, nessuna password: fino a 5 analisi al mese gratis.",
    noticeSuccess: "✓ Pagamento ricevuto, stiamo attivando il piano — qualche secondo e questa pagina si aggiorna da sola.",
    noticeCancel: "Attivazione annullata, nessun addebito. Riprova quando vuoi.",
    guestTitle: "Modalità ospite",
    guestList: [
      "1 analisi gratuita, senza email",
      "Tutti i 21 controlli con esempi di correzione",
      "Punteggio di sicurezza",
      "Un solo tentativo per visitatore, imposto dal nostro server",
    ],
    guestCta: "Prova senza registrarti",
    freeTitle: "Gratis",
    freeList: [
      "5 analisi al mese",
      "Tutti i 21 controlli, con esempi di correzione",
      "Punteggio di sicurezza + badge da scaricare (.svg)",
      "Cronologia delle ultime 20 analisi",
    ],
    freeCta: "Inizia gratis",
    freeNote: "Per chi analizza progetti una tantum",
    proBadge: "MONITORING",
    proTitle: "Pro",
    proPer: "/mese",
    proList: [
      "Analisi e cronologia illimitate",
      "Integrazione con GitHub: controlla ogni push e blocca le modifiche più rischiose",
      "Commenti automatici sulle pull request",
      "Correzioni automatiche proposte come pull request",
      "Badge che si aggiorna da solo a ogni push",
    ],
    proCta: "Attiva Pro",
    proActivating: "Attivazione...",
    proNote: "Per monitoraggio continuo su ogni push",
    teamBadge: "TEAM",
    teamTitle: "Team",
    teamPer: "/mese",
    teamList: [
      "Analisi e cronologia illimitate",
      "Integrazione con GitHub: controlla ogni push e blocca le modifiche più rischiose",
      "Commenti automatici sulle pull request",
      "Correzioni automatiche proposte come pull request",
      "Badge che si aggiorna da solo a ogni push",
    ],
    teamCta: "Attiva Team",
    teamActivating: "Attivazione...",
    teamNote: "Per team con più repo",
    activePlan: "Piano attivo",
    manageSubscription: "Gestisci abbonamento",
    opening: "Apertura...",
    errorActivation: "Errore nell'attivazione del piano",
    errorPortal: "Errore nell'apertura del portale abbonamento",
    disclaimer: "Disdici quando vuoi, senza vincoli — l'abbonamento si gestisce da solo, direttamente dal tuo account.",
  },
  footer: {
    intro: "*Per l'analisi manuale:",
    items: [
      "Se salvi lo storico, inviamo solo un frammento minimo della riga interessata da ogni problema — mai la riga intera, mai il file.",
      "In modalità ospite, senza salvataggio, nulla lascia mai il tuo browser.",
      "L'integrazione GitHub, invece, elabora il codice sui nostri server.",
    ],
  },
  checksList: {
    title: "Tutti i controlli, senza segreti",
    body: "Il valore di JoJoX non sta nel nascondere come funziona, ma nel curare bene ogni controllo, testarlo e tenerlo aggiornato. Qui sotto trovi la lista completa: cosa controlliamo, quanto è grave ogni problema, e quanto siamo sicuri di ogni segnalazione.",
    subLabel: "{{count}} controlli, in 4 livelli di gravità",
    note: "«Confermato» = troviamo il problema per certo nel codice · «Da verificare» = sembra mancare una protezione, ma potrebbe essere gestita altrove: controlla prima di preoccuparti.",
  },
  login: {
    sent: "Controlla la tua email: ti abbiamo mandato un link per accedere. Puoi chiudere questo popup.",
    prompt: "Accedi con la tua email — nessuna password, ti mandiamo un link.",
    sending: "Invio…",
    send: "Invia link di accesso",
    error: "Qualcosa è andato storto. Riprova.",
    close: "Chiudi",
  },
  analyzer: {
    gateTitle: "Hai già usato la tua analisi gratuita senza email",
    gateBody: "Accedi con la tua email per continuare: nessuna password, 5 analisi gratuite al mese.",
    gateCta: "Accedi con la tua email",
    dropzoneCta: "Trascina qui i tuoi file, o clicca per sceglierli",
    dropzoneHintLoggedIn: "Sei loggato: l'analisi viene salvata nel tuo storico.",
    dropzoneHintGuest: "Modalità ospite: 1 analisi gratuita, senza email. Dopo, basta la mail per continuare (5 al mese, gratis).",
    dropzoneHintAny: "Funziona su qualsiasi codice — anche scritto interamente a mano, non solo generato dall'AI.",
    moreFiles: "+{{count}} altri",
    analyzeButton: "Analizza",
    analyzeButtonCount: "Analizza {{count}} file",
    analyzing: "Analisi in corso…",
    errorGuestUsed: "Risulta già usata l'analisi gratuita senza email (magari da un altro dispositivo sulla stessa rete). Accedi con la tua email per continuare — 5 analisi gratuite al mese.",
    errorGeneric: "Analisi fallita, riprova.",
    autofixFixedOne: "🔧 Ho corretto da solo {{files}} file per {{types}} tipo di problema.",
    autofixFixedMany: "🔧 Ho corretto da solo {{files}} file per {{types}} tipi di problema.",
    autofixManualSuffix: " Altri {{count}} restano da sistemare a mano — richiedono decisioni sul tuo progetto che non possiamo prendere al posto tuo.",
    autofixManualOnly: "I problemi trovati richiedono decisioni sul tuo progetto che non possiamo correggere in automatico — guarda gli esempi \"prima/dopo\" qui sotto.",
    downloadZip: "Scarica file corretti (.zip)",
    downloadPdf: "Scarica report PDF",
  },
  history: {
    title: "Il tuo storico",
    manualSource: "Analisi manuale",
    error: "Errore nel caricamento dello storico",
  },
  scoreChart: {
    title: "Andamento del punteggio",
    ariaLabel: "Andamento del punteggio di sicurezza nelle ultime {{count}} analisi: da {{from}} a {{to}} su 100",
  },
  findingsList: {
    scoreLabel: "Punteggio di sicurezza",
    emptyState: "Nessun problema trovato nei 21 controlli. 🎉",
  },
  github: {
    title: "GitHub App + CI",
    badge: "DISPONIBILE",
    body1: "Collega GitHub. A ogni push e a ogni pull request JoJoX controlla il codice. Se trova un problema critico, blocca la pull request e lascia un commento chiaro con il riepilogo.",
    body2: "Basta impostarlo come controllo obbligatorio nelle impostazioni del branch: le modifiche rischiose non potranno più essere unite.",
    note: "Stesso motore dell'analisi manuale, nessun LLM. Gira sui nostri server per poter intervenire in automatico a ogni push.",
    connectedLabel: "✓ COLLEGATO",
    toggleShow: "▼ Vedi anche: notifiche Slack, badge, CLI, VS Code e agenti AI",
    toggleHide: "▲ Nascondi dettagli avanzati",
    badgeTitle: "🏷️ Badge sempre aggiornato nel README",
    badgeBody: "Dopo aver collegato il repository, incolla questa riga nel tuo {{readme}} (sostituisci {{repo}} con i tuoi) — il punteggio si aggiorna da solo a ogni analisi, senza bisogno di rigenerarlo a mano:",
    terminalTitle: "🖥️ Anche da terminale, in VS Code e per agenti AI",
    terminalBody: "JoJoX si può usare anche senza sito: da riga di comando (con {{fix}} per correggere in automatico), come estensione VS Code che sottolinea i problemi mentre scrivi, o come strumento MCP per Claude Code e altri agenti AI, che così possono controllarsi da soli mentre scrivono codice. Istruzioni complete nel {{link}}.",
    terminalLink: "README del repository",
    hookTitle: "🪝 Blocco commit in locale",
    hookBody: "Un comando da terminale ({{cmd}}) installa un controllo che ferma il commit sul tuo computer, prima ancora che il codice arrivi su GitHub, se trova un problema critico — così il problema non entra mai nella cronologia del repository.",
    slackTitle: "🔔 Notifiche su Slack",
    slackConnectFirst: "Collega prima GitHub (bottone qui sopra) per poter impostare le notifiche Slack.",
    slackBody: "Incolla qui l'URL di un {{link}} per ricevere un avviso sul canale del team quando una pull request viene bloccata o corretta in automatico:",
    slackLink: "Incoming Webhook Slack",
    slackSaving: "Salvataggio...",
    slackSave: "Salva",
    slackSaved: "✓ Salvato",
    slackErrorGeneric: "Errore nel salvataggio",
  },
  waitlist: {
    title: "In arrivo",
    subtitle: "Ancora in lavorazione — te lo diciamo chiaramente, invece di fingere che esista già:",
    roadmap: [
      {
        icon: "👥",
        title: "Gestione team con più seat",
        text: "Più persone collegate a un solo abbonamento Team, con seat da aggiungere e dashboard condivisa — in arrivo a inizio settembre.",
      },
      {
        icon: "🌍",
        title: "Sito in più lingue",
        text: "Già disponibile in italiano e inglese, sito e i 21 controlli inclusi. Altre lingue in arrivo più avanti.",
      },
      {
        icon: "➕",
        title: "Correzioni che aggiungono codice mancante",
        text: "Oggi JoJoX corregge solo righe già presenti. In arrivo: la capacità di aggiungere da solo il codice che manca — una policy di sicurezza, un controllo assente — così ogni analisi diventa un progetto già pronto all'uso, non solo un elenco di cose da sistemare a mano.",
      },
      {
        icon: "🎨",
        title: "Nuovo stile del sito",
        text: "Stiamo lavorando a un nuovo look, più diretto — in arrivo, ancora non pubblicato.",
      },
    ],
    emailPlaceholder: "tua@email.com",
    submit: "Unisciti alla lista d'attesa",
    done: "✓ Sei in lista!",
    error: "Qualcosa è andato storto, riprova.",
  },
  supabase: {
    title: "Controllo Supabase",
    badge: "DISPONIBILE",
    body1: "Gli altri controlli leggono il codice e deducono cosa dovrebbe succedere a runtime. Questo invece si collega al tuo vero progetto Supabase e verifica cosa succede davvero: Row Level Security attiva o no, almeno una policy presente, bucket di storage pubblici o privati.",
    body2: "Non ti chiediamo mai le tue credenziali Supabase. Esegui tu stesso questa query di sola lettura (nessuna scrittura possibile) nell'{{sqlEditor}} del tuo progetto, copia il risultato in un file chiamato esattamente {{filename}}, e caricalo insieme al resto del codice nell'analyzer qui sopra — i risultati si aggiungono automaticamente a quelli degli altri 21 controlli.",
    sqlEditor: "SQL Editor",
    toggleShow: "▼ Mostra la query",
    toggleHide: "▲ Nascondi la query",
  },
  report: {
    brandSub: "Report di sicurezza del codice",
    reportLabel: "Report",
    generatedOn: "Generato il {{date}}",
    controlsNoLLM: "21 controlli · nessun LLM",
    filesScannedOne: "1 file analizzato",
    filesScannedMany: "{{count}} file analizzati",
    projectFallback: "Analisi codice",
    noProblems: "Nessun problema trovato",
    oneProblem: "1 problema trovato",
    manyProblems: "{{count}} problemi trovati, di gravità diversa",
    autofixNoteOne: "1 problema su {{total}} può essere corretto in automatico da JoJoX.",
    autofixNoteMany: "{{count}} problemi su {{total}} possono essere corretti in automatico da JoJoX.",
    autofixNoteSuffix: " Il file corretto è scaricabile dal sito come archivio .zip, separatamente da questo report.",
    resultsLabel: "Risultati",
    emptyState: "Nessun problema trovato nei 21 controlli.",
    printBtn: "Stampa / Salva come PDF",
    printHint: "Se la finestra di stampa non si apre da sola, usa Ctrl+P (Cmd+P su Mac).",
    popupBlocked: "Il browser ha bloccato l'apertura della finestra. Consenti i popup per questo sito e riprova.",
  },
};

const en: TranslationTree = {
  meta: {
    dateLocale: "en-GB",
    title: "JoJoX — Security for AI-written code",
  },
  common: {
    severity: {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
    },
    confirmed: "confirmed",
    heuristic: "to verify",
    before: "Before",
    after: "After",
  },
  header: {
    connect: "Connect GitHub",
    connectAnother: "Connect another GitHub account",
    connected: "✓ GitHub connected",
    logout: "Log out",
    login: "Log in",
  },
  hero: {
    titleLine1: "Your AI agent writes code every day.",
    titleLine2Suffix: "keeps watch.",
    body: "Not a one-off check. {{monitoring}}. 21 public checks for the most common mistakes in AI-written code, a clear {{score}}, and fixes ready to copy.",
    bodyMonitoring: "Continuous monitoring",
    bodyScore: "security score",
    sub: "The checks that normally take hours, automated and always on.",
    pill1: "Fixes always stay in your browser",
    pill2: "No sign-up to start",
    pill3: "Free",
    badge: "For projects built with Claude Code · Cursor · Lovable · Bolt",
    cta: "Analyze your code — free",
    guestNote: "1 free analysis with no email. Then just an email — 5 free analyses/month.",
  },
  features: [
    {
      icon: "🛡️",
      accent: "blue",
      title: "Your code is never stored",
      text: "The analysis you upload passes through our servers (to save the score and history), but the file contents are never kept — only the results. Automatic fixes, on the other hand, always stay in your browser.",
    },
    {
      icon: "🔧",
      accent: "amber",
      title: "Not just the problem, also how to fix it",
      text: "Every issue comes with a fix example, shown as a before/after: you immediately see what to change.",
    },
    {
      icon: "📊",
      accent: "mint",
      title: "Security score + badge",
      text: "A score from 0 to 100, calculated with a formula you can see in full, plus a badge to put in your project's README.",
    },
  ],
  whyNotAi: {
    question: "My AI agent already writes the code. Can't it check it too?",
    point1: "You can. But almost no one does it every time, on every file, after every change — and it only takes one missed check to leave a hole open. JoJoX doesn't wait for you to remember: it checks on its own, on every push.",
    point2: "Asking a model \"is this secure?\" is like asking for an opinion: it changes every time and leaves no proof. JoJoX runs the same 21 public checks every time, identical for everyone, verifiable line by line in the code — a verdict, not an opinion.",
    point3: "No LLM, no hallucinations, no cost that grows with usage: pure pattern matching, instant, built to run on every pull request as often as you need.",
    closing: "JoJoX doesn't write your code. It keeps watch — always, the same way, without you having to ask.",
  },
  pricing: {
    title: "You pay for continuous monitoring, not for individual analyses",
    subtitle: "Try 1 analysis with nothing to give. Then just an email, no password: up to 5 free analyses a month.",
    noticeSuccess: "✓ Payment received, we're activating your plan — this page will refresh itself in a few seconds.",
    noticeCancel: "Activation cancelled, no charge. Try again whenever you like.",
    guestTitle: "Guest mode",
    guestList: [
      "1 free analysis, no email",
      "All 21 checks with fix examples",
      "Security score",
      "One attempt per visitor, enforced by our server",
    ],
    guestCta: "Try it without signing up",
    freeTitle: "Free",
    freeList: [
      "5 analyses a month",
      "All 21 checks, with fix examples",
      "Security score + downloadable badge (.svg)",
      "History of the last 20 analyses",
    ],
    freeCta: "Start for free",
    freeNote: "For one-off project analyses",
    proBadge: "MONITORING",
    proTitle: "Pro",
    proPer: "/month",
    proList: [
      "Unlimited analyses and history",
      "GitHub integration: checks every push and blocks the riskiest changes",
      "Automatic comments on pull requests",
      "Automatic fixes proposed as pull requests",
      "Badge that updates itself on every push",
    ],
    proCta: "Activate Pro",
    proActivating: "Activating...",
    proNote: "For continuous monitoring on every push",
    teamBadge: "TEAM",
    teamTitle: "Team",
    teamPer: "/month",
    teamList: [
      "Unlimited analyses and history",
      "GitHub integration: checks every push and blocks the riskiest changes",
      "Automatic comments on pull requests",
      "Automatic fixes proposed as pull requests",
      "Badge that updates itself on every push",
    ],
    teamCta: "Activate Team",
    teamActivating: "Activating...",
    teamNote: "For teams with multiple repos",
    activePlan: "Active plan",
    manageSubscription: "Manage subscription",
    opening: "Opening...",
    errorActivation: "Error activating the plan",
    errorPortal: "Error opening the subscription portal",
    disclaimer: "Cancel anytime, no strings attached — the subscription manages itself, straight from your account.",
  },
  footer: {
    intro: "*For manual analysis:",
    items: [
      "If you save your history, we only send a minimal fragment of the line affected by each issue — never the whole line, never the file.",
      "In guest mode, without saving, nothing ever leaves your browser.",
      "The GitHub integration, instead, processes the code on our servers.",
    ],
  },
  checksList: {
    title: "Every check, no secrets",
    body: "JoJoX's value isn't in hiding how it works, but in taking good care of every check, testing it and keeping it up to date. Below is the full list: what we check, how severe each issue is, and how confident we are in each finding.",
    subLabel: "{{count}} checks, across 4 severity levels",
    note: "\"Confirmed\" = we find the problem for certain in the code · \"To verify\" = a protection seems to be missing, but it might be handled elsewhere: check before worrying.",
  },
  login: {
    sent: "Check your email: we've sent you a link to sign in. You can close this popup.",
    prompt: "Sign in with your email — no password, we'll send you a link.",
    sending: "Sending…",
    send: "Send sign-in link",
    error: "Something went wrong. Try again.",
    close: "Close",
  },
  analyzer: {
    gateTitle: "You've already used your free analysis without an email",
    gateBody: "Sign in with your email to continue: no password, 5 free analyses a month.",
    gateCta: "Sign in with your email",
    dropzoneCta: "Drag your files here, or click to choose them",
    dropzoneHintLoggedIn: "You're signed in: the analysis is saved to your history.",
    dropzoneHintGuest: "Guest mode: 1 free analysis, no email. After that, just an email to continue (5 a month, free).",
    dropzoneHintAny: "Works on any code — even written entirely by hand, not just AI-generated.",
    moreFiles: "+{{count}} more",
    analyzeButton: "Analyze",
    analyzeButtonCount: "Analyze {{count}} files",
    analyzing: "Analyzing…",
    errorGuestUsed: "The free analysis without email has already been used (maybe from another device on the same network). Sign in with your email to continue — 5 free analyses a month.",
    errorGeneric: "Analysis failed, try again.",
    autofixFixedOne: "🔧 I fixed {{files}} file myself for {{types}} type of issue.",
    autofixFixedMany: "🔧 I fixed {{files}} files myself for {{types}} types of issue.",
    autofixManualSuffix: " Another {{count}} still need fixing by hand — they need decisions about your project we can't make for you.",
    autofixManualOnly: "The issues found need decisions about your project we can't fix automatically — see the \"before/after\" examples below.",
    downloadZip: "Download fixed files (.zip)",
    downloadPdf: "Download PDF report",
  },
  history: {
    title: "Your history",
    manualSource: "Manual analysis",
    error: "Error loading history",
  },
  scoreChart: {
    title: "Score over time",
    ariaLabel: "Security score trend over the last {{count}} analyses: from {{from}} to {{to}} out of 100",
  },
  findingsList: {
    scoreLabel: "Security score",
    emptyState: "No problems found across the 21 checks. 🎉",
  },
  github: {
    title: "GitHub App + CI",
    badge: "AVAILABLE",
    body1: "Connect GitHub. On every push and every pull request, JoJoX checks the code. If it finds a critical issue, it blocks the pull request and leaves a clear comment with the summary.",
    body2: "Just set it as a required check in your branch settings: risky changes won't be mergeable anymore.",
    note: "Same engine as the manual analysis, no LLM. It runs on our servers so it can act automatically on every push.",
    connectedLabel: "✓ CONNECTED",
    toggleShow: "▼ Also see: Slack notifications, badge, CLI, VS Code and AI agents",
    toggleHide: "▲ Hide advanced details",
    badgeTitle: "🏷️ Always up-to-date badge in the README",
    badgeBody: "After connecting the repository, paste this line into your {{readme}} (replace {{repo}} with yours) — the score updates itself on every analysis, no need to regenerate it by hand:",
    terminalTitle: "🖥️ Also from the terminal, in VS Code, and for AI agents",
    terminalBody: "JoJoX can also be used without the website: from the command line (with {{fix}} to fix automatically), as a VS Code extension that underlines issues as you type, or as an MCP tool for Claude Code and other AI agents, so they can check themselves while writing code. Full instructions in the {{link}}.",
    terminalLink: "repository README",
    hookTitle: "🪝 Local commit blocking",
    hookBody: "A terminal command ({{cmd}}) installs a check that stops the commit on your computer, before the code even reaches GitHub, if it finds a critical issue — so the problem never enters the repository's history.",
    slackTitle: "🔔 Slack notifications",
    slackConnectFirst: "Connect GitHub first (button above) to set up Slack notifications.",
    slackBody: "Paste the URL of an {{link}} here to get an alert on the team channel when a pull request is blocked or automatically fixed:",
    slackLink: "Incoming Webhook Slack",
    slackSaving: "Saving...",
    slackSave: "Save",
    slackSaved: "✓ Saved",
    slackErrorGeneric: "Error saving",
  },
  waitlist: {
    title: "Coming soon",
    subtitle: "Still in progress — we tell you clearly, instead of pretending it already exists:",
    roadmap: [
      {
        icon: "👥",
        title: "Team management with more seats",
        text: "Multiple people connected to a single Team subscription, with seats to add and a shared dashboard — coming in early September.",
      },
      {
        icon: "🌍",
        title: "Site in more languages",
        text: "Already available in Italian and English, site and all 21 checks included. More languages coming later.",
      },
      {
        icon: "➕",
        title: "Fixes that add missing code",
        text: "Today JoJoX only fixes lines that already exist. Coming soon: the ability to add missing code on its own — a security policy, a missing check — so every analysis becomes a project that's already ready to use, not just a list of things to fix by hand.",
      },
      {
        icon: "🎨",
        title: "New site design",
        text: "We're working on a new look, more direct — coming soon, not published yet.",
      },
    ],
    emailPlaceholder: "you@email.com",
    submit: "Join the waitlist",
    done: "✓ You're on the list!",
    error: "Something went wrong, try again.",
  },
  supabase: {
    title: "Supabase check",
    badge: "AVAILABLE",
    body1: "The other checks read the code and infer what should happen at runtime. This one instead connects to your real Supabase project and verifies what actually happens: Row Level Security on or off, at least one policy present, storage buckets public or private.",
    body2: "We never ask for your Supabase credentials. Run this read-only query yourself (no writes possible) in your project's {{sqlEditor}}, copy the result into a file named exactly {{filename}}, and upload it together with the rest of the code in the analyzer above — the results are automatically added to the other 21 checks.",
    sqlEditor: "SQL Editor",
    toggleShow: "▼ Show the query",
    toggleHide: "▲ Hide the query",
  },
  report: {
    brandSub: "Code security report",
    reportLabel: "Report",
    generatedOn: "Generated on {{date}}",
    controlsNoLLM: "21 checks · no LLM",
    filesScannedOne: "1 file scanned",
    filesScannedMany: "{{count}} files scanned",
    projectFallback: "Code analysis",
    noProblems: "No problems found",
    oneProblem: "1 problem found",
    manyProblems: "{{count}} problems found, of varying severity",
    autofixNoteOne: "1 problem out of {{total}} can be fixed automatically by JoJoX.",
    autofixNoteMany: "{{count}} problems out of {{total}} can be fixed automatically by JoJoX.",
    autofixNoteSuffix: " The fixed file can be downloaded from the site as a .zip archive, separately from this report.",
    resultsLabel: "Results",
    emptyState: "No problems found across the 21 checks.",
    printBtn: "Print / Save as PDF",
    printHint: "If the print window doesn't open by itself, use Ctrl+P (Cmd+P on Mac).",
    popupBlocked: "Your browser blocked the popup window. Allow popups for this site and try again.",
  },
};

export const translations: Record<Lang, TranslationTree> = { it, en };