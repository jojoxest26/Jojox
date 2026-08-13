# Come mettere online JoJoX (sito + backend)

Il codice è pronto: motore di analisi, backend (API + integrazione GitHub) e
ora anche il sito vero in `web/` (non più solo un'anteprima statica).
Restano sei cose da fare — servono account reali (e il dominio, che hai già
comprato su GoDaddy), quindi tocca a te farle una volta, poi il resto lo
gestisco io. Segui l'ordine: **Supabase → GitHub App → Railway (backend) →
Vercel (sito) → dominio jojox.it → rifinitura** — ognuna ha bisogno di
valori generati dalla precedente, quindi non saltare l'ordine.

Alla fine di ogni sezione trovi **cosa mandarmi**. Appena ho tutti i valori,
li metto io nelle variabili d'ambiente e verifico che tutto funzioni.

---

## 1. Supabase (database + account utenti)

1. Vai su **supabase.com** → **Start your project** → accedi con GitHub
2. **New project**: dai un nome (es. `jojox`), scegli una password per il
   database (salvala da qualche parte, non serve a noi ma è tua), regione
   vicina a te (es. Frankfurt/EU), piano **Free**
3. Aspetta 1-2 minuti che il progetto si crei
4. Nel menu a sinistra vai su **SQL Editor** → **New query**
5. Apri il file `supabase/migrations/0001_init.sql` di questo repository,
   copia **tutto** il contenuto, incollalo nell'editor SQL e premi **Run**
   — questo crea le tabelle (profili, storico analisi, installazioni
   GitHub) con la sicurezza già configurata
6. Vai su **Project Settings** (icona ingranaggio in basso a sinistra) →
   **API**
7. Copia questi due valori:
   - **Project URL** (es. `https://xxxxx.supabase.co`)
   - **service_role key** (sotto "Project API keys" — è quella segreta,
     non la "anon public")

**Mandami:** Project URL + service_role key.

⚠️ La service_role key è quella che il nostro stesso controllo critico
("chiave segreta esposta al browser") individuerebbe se finisse nel posto
sbagliato — resta sempre e solo lato server, mai in un file che finisce nel
frontend.

---

## 2. GitHub App (l'integrazione che analizza le pull request)

Questa è un'app GitHub separata da JoJoX-il-prodotto — è quella che i
*futuri clienti* installeranno sui loro repository per farsi controllare il
codice automaticamente.

1. Vai su **github.com/settings/apps** → **New GitHub App**
2. Compila:
   - **GitHub App name**: `JoJoX` (se è già preso, `JoJoX Security` o simile)
   - **Homepage URL**: l'URL del sito JoJoX (anche provvisorio va bene)
   - **Webhook URL**: per ora scrivi un valore provvisorio tipo
     `https://example.com/webhooks/github` — lo aggiorneremo al punto 3,
     quando avremo l'indirizzo vero da Railway
   - **Webhook secret**: genera una stringa lunga e casuale (es. con
     `openssl rand -hex 32` da terminale) e salvala — è un valore segreto
     che dovrai rimandarmi
3. **Permissions** (sotto "Repository permissions"):
   - **Contents**: Read-only
   - **Metadata**: Read-only (di solito già selezionato in automatico)
   - **Pull requests**: Read and write
   - **Issues**: Read and write
   - **Checks**: Read and write
4. **Subscribe to events**: seleziona **Pull request** e **Installation**
5. In fondo, sotto "Where can this GitHub App be installed?", scegli
   **Any account** (così anche i clienti futuri potranno installarla)
6. Crea l'app
7. Nella pagina dell'app appena creata:
   - Prendi nota del **App ID** (numero in alto)
   - Scorri fino a **Private keys** → **Generate a private key** → si
     scarica un file `.pem`
8. Installa l'app su **questo** repository (il tuo, per fare da primo
   test): dalla pagina dell'app, menu a sinistra **Install App**, scegli
   il tuo account, seleziona il repository `Jojox` (o "All repositories"
   se preferisci)

**Mandami:** App ID, il file `.pem` scaricato, il webhook secret che hai
generato al punto 2, e lo **slug** dell'app — è l'ultima parte dell'URL
della sua pagina pubblica (`github.com/apps/<questo-qui>`), serve al sito
per il bottone "Collega GitHub".

---

## 3. Railway (dove gira il backend)

1. Vai su **railway.app** → accedi con GitHub
2. **New Project** → **Deploy from GitHub repo** → autorizza Railway ad
   accedere ai tuoi repository (se richiesto) → seleziona **Jojox**
3. Railway inizia subito una build (fallirà finché non impostiamo le
   variabili d'ambiente — è normale, si risistema da solo al prossimo
   deploy)
4. Vai sulla scheda **Variables** del progetto e aggiungi queste chiavi
   (i valori te li fornirò io una volta ricevuto quanto sopra, oppure li
   inseriamo insieme):
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `GITHUB_APP_ID`
   - `GITHUB_APP_PRIVATE_KEY_BASE64` (il contenuto del file `.pem`,
     convertito in base64 su una riga sola — comando:
     `base64 -i nome-del-file.pem | tr -d '\n'`)
   - `GITHUB_WEBHOOK_SECRET`
   - `ALLOWED_ORIGINS` — per ora lascialo vuoto o su
     `http://localhost:5173`, lo aggiorniamo al punto 4 col dominio vero
     del sito (finché non lo fai, il sito online non riesce a parlare col
     backend — è una protezione voluta, non un bug)
5. Railway assegna in automatico anche `PORT` — non serve toccarla
6. Vai su **Settings** → **Networking** → **Generate Domain** per avere
   un URL pubblico (tipo `jojox-production.up.railway.app`)
7. **Torna alla GitHub App** (punto 2) → **Edit** → aggiorna il campo
   **Webhook URL** con `https://<il-tuo-dominio-railway>/webhooks/github`

**Mandami:** l'URL pubblico che Railway ti ha assegnato.

---

## 4. Vercel (il sito vero)

1. Vai su **vercel.com** → accedi con GitHub
2. **Add New** → **Project** → seleziona il repository **Jojox**
3. Vercel riconosce Vite da solo, ma verifica questi due campi:
   - **Root Directory**: `web` (importante — il sito vive in quella
     sottocartella, non nella radice del repository)
   - **Framework Preset**: Vite
4. Prima di fare deploy, apri **Environment Variables** e aggiungi:
   - `VITE_API_URL` — l'URL di Railway dal punto 3 (es.
     `https://jojox-production.up.railway.app`, senza slash finale)
   - `VITE_SUPABASE_URL` — lo stesso Project URL del punto 1
   - `VITE_SUPABASE_ANON_KEY` — da Supabase, **Project Settings → API**,
     questa volta la chiave **"anon public"** (non la service_role — questa
     è fatta apposta per finire nel browser)
   - `VITE_GITHUB_APP_SLUG` — lo slug della GitHub App dal punto 2
5. **Deploy**
6. Una volta online, prendi nota del dominio che Vercel ti assegna (es.
   `jojox.vercel.app` — puoi collegare un dominio vero tuo in seguito da
   **Settings → Domains**)
7. **Torna su Railway** (punto 3) → **Variables** → aggiorna
   `ALLOWED_ORIGINS` con l'URL vero del sito Vercel (es.
   `https://jojox.vercel.app`) → Railway rifà il deploy da solo

**Mandami:** l'URL che Vercel ti ha assegnato.

---

## 5. Dominio jojox.it (da GoDaddy a Vercel)

1. Su **Vercel**, nel progetto del sito → **Settings** → **Domains** →
   scrivi `jojox.it` → **Add**
2. Vercel ti mostra uno o più record DNS da impostare (tipicamente un
   record **A** per `jojox.it` e un record **CNAME** per `www.jojox.it` —
   i valori esatti te li dà Vercel in quel momento, possono cambiare nel
   tempo, quindi copia quelli che vedi tu, non quelli di una guida)
3. Vai su **godaddy.com** → **I miei prodotti** → **Domini** → cerca
   `jojox.it` → **DNS** (o "Gestisci DNS")
4. Aggiungi/modifica i record con **esattamente** i valori che ti ha dato
   Vercel al punto 2:
   - Se c'è già un record **A** su `@` (host vuoto o `@`), modificalo
     invece di aggiungerne uno nuovo
   - Aggiungi il record **CNAME** per `www` che punta a Vercel
5. Salva. La propagazione DNS può metterci da qualche minuto a un paio
   d'ore (raramente di più)
6. Torna su Vercel: quando il dominio passa da "Invalid Configuration" a
   ✅ verde, `jojox.it` è online
7. Su Vercel, in **Settings → Domains**, imposta `jojox.it` come dominio
   primario e fai in modo che `www.jojox.it` reindirizzi a `jojox.it` (o
   viceversa, a tua scelta — basta sceglierne uno "ufficiale")

## 6. Rifinitura: far combaciare tutto col dominio vero

Finché questi tre punti non sono aggiornati, il sito su jojox.it carica ma
login e chiamate al backend non funzionano — non è un errore, è la stessa
protezione (CORS, redirect autorizzati) che impedisce a siti finti di
impersonare il tuo.

1. **Railway** → **Variables** → `ALLOWED_ORIGINS` → imposta
   `https://jojox.it,https://www.jojox.it`
2. **Supabase** → **Authentication** → **URL Configuration**:
   - **Site URL**: `https://jojox.it`
   - **Redirect URLs**: aggiungi `https://jojox.it/**` (permette al link
     di accesso via email di riportarti sul sito vero)
3. **GitHub App** (pagina della tua app, **General**) → aggiorna
   **Homepage URL** con `https://jojox.it`

Da questo momento jojox.it è il sito vero e proprio, non più
un'anteprima: login, storico, integrazione GitHub, tutto attivo su quel
dominio.
## 7. Stripe (abbonamento self-service)

A differenza delle sezioni precedenti, qui le chiavi **non me le mandi in
chat**: vanno impostate direttamente su Railway da te, perché sono credenziali
che muovono soldi veri — stesso principio della service_role key di
Supabase, ma ancora più delicato.

1. Vai su **stripe.com** → crea l'account (se non l'hai già fatto) →
   assicurati che l'interruttore **Test mode** in alto a destra sia attivo:
   con le chiavi di test si prova tutto con carte finte, senza soldi veri e
   senza dover completare subito la verifica legale dell'azienda
2. **Product catalog** → **Add product** → crea due prodotti con un prezzo
   **ricorrente mensile**:
   - "JoJoX Pro" — 9,99€/mese
   - "JoJoX Team" — 24,99€/mese
   Per ognuno, apri il prezzo appena creato e copia il suo **ID** (inizia
   con `price_`)
3. **Settings → Billing → Customer portal**: attiva la possibilità per i
   clienti di **cancellare l'abbonamento** e di **cambiare piano** (aggiungi
   entrambi i prezzi appena creati come opzioni disponibili) — è quello che
   rende l'abbonamento davvero "self-service": una volta lì dentro, gestisce
   tutto Stripe stesso (disdetta, upgrade, downgrade, metodo di pagamento),
   JoJoX si limita ad aprire la porta
4. **Developers → Webhooks → Add endpoint**:
   - **Endpoint URL**: `https://<il-tuo-dominio-railway>/webhooks/stripe`
   - **Eventi da ascoltare**: `customer.subscription.created`,
     `customer.subscription.updated`, `customer.subscription.deleted`
   - Crea l'endpoint, poi apri **Signing secret** e copialo (inizia con
     `whsec_`)
5. **Developers → API keys** → copia la **Secret key** (in modalità test
   inizia con `sk_test_`)
6. Vai su **Railway** → il progetto del backend → **Variables** → aggiungi
   tu stesso queste chiavi (non a me):
   - `STRIPE_SECRET_KEY` — la secret key del punto 5
   - `STRIPE_WEBHOOK_SECRET` — il signing secret del punto 4
   - `STRIPE_PRICE_ID_PRO` — l'ID del prezzo "Pro" dal punto 2
   - `STRIPE_PRICE_ID_TEAM` — l'ID del prezzo "Team" dal punto 2
   - `APP_URL` — il dominio vero del sito (es. `https://jojox.it`, o quello
     provvisorio di Vercel se non ci sei ancora arrivato)
7. Prova subito: sul sito, da loggato, clicca **Attiva Pro** → nel checkout
   Stripe usa la carta di prova `4242 4242 4242 4242`, una data futura
   qualsiasi e un CVC qualsiasi → dopo il pagamento dovresti tornare sul
   sito con il piano attivato in pochi secondi

Quando tutto funziona in modalità test e sei pronto per i clienti veri: su
Stripe disattiva **Test mode**, ripeti i punti 2-5 in modalità live (i
prodotti/prezzi/webhook vanno ricreati, sono separati da quelli di test), e
aggiorna le 4 variabili su Railway con i valori "live".


---

## Come verifichiamo che funziona tutto

**Sul sito** (su `https://jojox.it` una volta fatto il punto 5-6, o sul
dominio Vercel provvisorio se non ci sei ancora arrivato):
1. Trascina un file con un problema banale (es. una password scritta in
   chiaro) nella zona di analisi — punteggio e correzioni compaiono subito,
   senza bisogno di login (gira nel tuo browser)
2. Clicca **Accedi**, inserisci la tua email, apri il link che ricevi —
   dovresti tornare sul sito loggato
3. Rifai un'analisi da loggato: dovrebbe comparire nel tuo storico più in
   basso nella pagina (prova di funzionamento del backend + database)

**Sull'integrazione GitHub:**
1. Apri una pull request di prova su un repository dove hai installato
   l'app JoJoX, con dentro un problema banale
2. Entro qualche secondo dovresti vedere: un **check** JoJoX nella PR con
   il punteggio, e un **commento automatico** con l'elenco dei problemi
   trovati e i suggerimenti di correzione
3. Se il problema è critico o alto, il check risulta "failed" — è quello
   che, con un controllo obbligatorio sul branch (impostazione che si fa
   dalle impostazioni del repository, non da JoJoX), blocca il merge

Se qualcosa non torna in questi test, mandami uno screenshot (o il log di
Railway/Vercel) e sistemiamo insieme.
