import { useEffect, useState } from "react";
import { Header } from "./components/Header.js";
import { Hero } from "./components/Hero.js";
import { HowItWorks } from "./components/HowItWorks.js";
import { Features } from "./components/Features.js";
import { WhyNotAiSection } from "./components/WhyNotAiSection.js";
import { AudienceSection } from "./components/AudienceSection.js";
import { Analyzer } from "./components/Analyzer.js";
import { HistoryPanel } from "./components/HistoryPanel.js";
import { Pricing } from "./components/Pricing.js";
import { GithubSection } from "./components/GithubSection.js";
import { TeamSection } from "./components/TeamSection.js";
import { CloudChecksSection } from "./components/CloudChecksSection.js";
import { WaitlistForm } from "./components/WaitlistForm.js";
import { ChecksList } from "./components/ChecksList.js";
import { Footer } from "./components/Footer.js";
import { PrivacyPolicyPage, TermsOfServicePage, SecurityPolicyPage } from "./components/LegalPage.js";
import { PublicScorePage } from "./components/PublicScorePage.js";
import { FullSiteAudit } from "./components/FullSiteAudit.js";
import { Reveal } from "./components/Reveal.js";
import { ChatPanel } from "./components/ChatPanel.js";
import { useSession } from "./hooks/useSession.js";
import { claimGithubInstallation, fetchGithubInstallations, type GithubInstallation } from "./lib/api.js";
import type { AnalysisResult } from "../../src/types.js";

function App() {
  const { session, loading } = useSession();
  const [path, setPath] = useState(window.location.pathname);
  const [analyzerOpen, setAnalyzerOpen] = useState(false);
  const [pendingScroll, setPendingScroll] = useState(false);
  const [githubClaimError, setGithubClaimError] = useState<string | null>(null);
  // Incrementato a ogni analisi salvata: HistoryPanel lo osserva per
  // ricaricare storico e grafico senza dover ricaricare la pagina.
  const [historyVersion, setHistoryVersion] = useState(0);
  // Caricate qui (non nei singoli componenti) così Header e GithubSection
  // mostrano sempre lo stesso stato "collegato o no", senza disallinearsi.
  const [installations, setInstallations] = useState<GithubInstallation[] | null>(null);
  // Ultima analisi fatta, per dare contesto al widget globale "Chiedi a
  // JoJoX" — se è null, la chat resta in modalità generale su JoJoX stesso.
  const [chatResult, setChatResult] = useState<AnalysisResult | null>(null);

  useEffect(() => {
    if (!session) {
      setInstallations(null);
      return;
    }
    fetchGithubInstallations(session.access_token)
      .then(setInstallations)
      .catch(() => setInstallations([]));
  }, [session]);

  // Chi è già loggato vede sempre l'analyzer, ma senza lo scatto dello
  // scroll automatico al caricamento della pagina.
  useEffect(() => {
    if (session) setAnalyzerOpen(true);
  }, [session]);

  // I 4 pulsanti nella sezione Prezzi (Ospite/Gratis/Pro/Team) sono l'unico
  // modo per aprire l'analyzer: quello ospite lo apre subito, gli altri tre
  // passano dal login (e l'effect sopra lo apre non appena la sessione arriva).
  useEffect(() => {
    const handler = () => {
      setAnalyzerOpen(true);
      setPendingScroll(true);
    };
    window.addEventListener("jojox-open-analyzer", handler);
    return () => window.removeEventListener("jojox-open-analyzer", handler);
  }, []);

  useEffect(() => {
    if (analyzerOpen && pendingScroll) {
      document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" });
      setPendingScroll(false);
    }
  }, [analyzerOpen, pendingScroll]);

  // GitHub reindirizza qui (via "Setup URL" nelle impostazioni della App)
  // subito dopo che qualcuno installa la GitHub App, passando l'installation_id
  // nell'URL. Lo usiamo per collegare quell'installazione all'utente loggato.
  useEffect(() => {
    if (!session) return;
    const params = new URLSearchParams(window.location.search);
    const installationId = params.get("installation_id");
    if (!installationId) return;

    claimGithubInstallation(Number(installationId), session.access_token)
      .then(() => fetchGithubInstallations(session.access_token).then(setInstallations))
      .catch((err) => setGithubClaimError(err instanceof Error ? err.message : null))
      .finally(() => {
        params.delete("installation_id");
        params.delete("setup_action");
        const query = params.toString();
        window.history.replaceState({}, "", window.location.pathname + (query ? `?${query}` : ""));
      });
  }, [session]);

  // Il sito non usa un router: privacy, termini, sicurezza e il punteggio
  // pubblico sono le uniche altre pagine, raggiunte anche da link diretti,
  // quindi bastano pathname + popstate.
  useEffect(() => {
    const onPopState = () => setPath(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  if (loading) return null;

  if (path === "/privacy") return <PrivacyPolicyPage />;
  if (path === "/termini") return <TermsOfServicePage />;
  if (path === "/sicurezza") return <SecurityPolicyPage />;
  if (path.startsWith("/r/")) {
    const [owner, repo] = path.slice(3).split("/");
    if (owner && repo) return <PublicScorePage owner={owner} repo={repo} />;
  }

  return (
    <>
      <Header session={session} installations={installations} />
      <Hero />
      <Reveal>
        <HowItWorks />
      </Reveal>
      <Reveal>
        <Features />
      </Reveal>
      <Reveal>
        <WhyNotAiSection />
      </Reveal>
      <Reveal>
        <AudienceSection />
      </Reveal>
      <Reveal>
        <Pricing session={session} />
      </Reveal>
      <Reveal>
        <FullSiteAudit session={session} />
      </Reveal>
      {analyzerOpen && (
        <>
          <Analyzer session={session} onAnalysisSaved={() => setHistoryVersion((v) => v + 1)} onResult={setChatResult} />
          {session && <HistoryPanel session={session} refreshKey={historyVersion} />}
        </>
      )}
      <Reveal>
        <GithubSection session={session} installations={installations} claimError={githubClaimError} />
      </Reveal>
      <Reveal>
        <TeamSection session={session} />
      </Reveal>
      <Reveal>
        <CloudChecksSection />
      </Reveal>
      <Reveal>
        <WaitlistForm />
      </Reveal>
      <Reveal>
        <ChecksList />
      </Reveal>
      <Footer />
      <ChatPanel result={chatResult} session={session} />
    </>
  );
}

export default App;