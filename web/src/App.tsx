import { useEffect, useState } from "react";
import { Header } from "./components/Header.js";
import { Hero } from "./components/Hero.js";
import { Features } from "./components/Features.js";
import { WhyNotAiSection } from "./components/WhyNotAiSection.js";
import { Analyzer } from "./components/Analyzer.js";
import { HistoryPanel } from "./components/HistoryPanel.js";
import { Pricing } from "./components/Pricing.js";
import { GithubSection } from "./components/GithubSection.js";
import { SupabaseCheckSection } from "./components/SupabaseCheckSection.js";
import { WaitlistForm } from "./components/WaitlistForm.js";
import { ChecksList } from "./components/ChecksList.js";
import { Footer } from "./components/Footer.js";
import { PrivacyPolicyPage, TermsOfServicePage } from "./components/LegalPage.js";
import { useSession } from "./hooks/useSession.js";
import { claimGithubInstallation, fetchGithubInstallations, type GithubInstallation } from "./lib/api.js";

function App() {
  const { session, loading } = useSession();
  const [path, setPath] = useState(window.location.pathname);
  const [analyzerOpen, setAnalyzerOpen] = useState(false);
  const [pendingScroll, setPendingScroll] = useState(false);
  // Incrementato a ogni analisi salvata: HistoryPanel lo osserva per
  // ricaricare storico e grafico senza dover ricaricare la pagina.
  const [historyVersion, setHistoryVersion] = useState(0);
  // Caricate qui (non nei singoli componenti) così Header e GithubSection
  // mostrano sempre lo stesso stato "collegato o no", senza disallinearsi.
  const [installations, setInstallations] = useState<GithubInstallation[] | null>(null);

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
      .catch(() => {})
      .finally(() => {
        params.delete("installation_id");
        params.delete("setup_action");
        const query = params.toString();
        window.history.replaceState({}, "", window.location.pathname + (query ? `?${query}` : ""));
      });
  }, [session]);

  // Il sito non usa un router: privacy e termini sono le uniche altre pagine,
  // raggiunte anche da link diretti, quindi bastano pathname + popstate.
  useEffect(() => {
    const onPopState = () => setPath(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  if (loading) return null;

  if (path === "/privacy") return <PrivacyPolicyPage />;
  if (path === "/termini") return <TermsOfServicePage />;

  return (
    <>
      <Header session={session} installations={installations} />
      <Hero />
      <Features />
      <WhyNotAiSection />
      <Pricing session={session} />
      {analyzerOpen && (
        <>
          <Analyzer session={session} onAnalysisSaved={() => setHistoryVersion((v) => v + 1)} />
          {session && <HistoryPanel session={session} refreshKey={historyVersion} />}
        </>
      )}
      <GithubSection session={session} installations={installations} />
      <SupabaseCheckSection />
      <WaitlistForm />
      <ChecksList />
      <Footer />
    </>
  );
}

export default App;