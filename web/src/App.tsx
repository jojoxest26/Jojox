import { useEffect, useState } from "react";
import { Header } from "./components/Header.js";
import { Hero } from "./components/Hero.js";
import { Features } from "./components/Features.js";
import { Analyzer } from "./components/Analyzer.js";
import { HistoryPanel } from "./components/HistoryPanel.js";
import { Pricing } from "./components/Pricing.js";
import { GithubSection } from "./components/GithubSection.js";
import { SupabaseCheckSection } from "./components/SupabaseCheckSection.js";
import { WaitlistForm } from "./components/WaitlistForm.js";
import { ChecksList } from "./components/ChecksList.js";
import { Footer } from "./components/Footer.js";
import { useSession } from "./hooks/useSession.js";

function App() {
  const { session, loading } = useSession();
  const [analyzerOpen, setAnalyzerOpen] = useState(false);
  const [pendingScroll, setPendingScroll] = useState(false);
  // Incrementato a ogni analisi salvata: HistoryPanel lo osserva per
  // ricaricare storico e grafico senza dover ricaricare la pagina.
  const [historyVersion, setHistoryVersion] = useState(0);

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

  if (loading) return null;

  return (
    <>
      <Header session={session} />
      <Hero />
      <Features />
      <Pricing session={session} />
      {analyzerOpen && (
        <>
          <Analyzer session={session} onAnalysisSaved={() => setHistoryVersion((v) => v + 1)} />
          {session && <HistoryPanel session={session} refreshKey={historyVersion} />}
        </>
      )}
      <GithubSection session={session} />
      <SupabaseCheckSection />
      <WaitlistForm />
      <ChecksList />
      <Footer />
    </>
  );
}

export default App;