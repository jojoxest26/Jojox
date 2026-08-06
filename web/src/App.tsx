import { Header } from "./components/Header.js";
import { Hero } from "./components/Hero.js";
import { Features } from "./components/Features.js";
import { Analyzer } from "./components/Analyzer.js";
import { HistoryPanel } from "./components/HistoryPanel.js";
import { Pricing } from "./components/Pricing.js";
import { GithubSection } from "./components/GithubSection.js";
import { WaitlistForm } from "./components/WaitlistForm.js";
import { ChecksList } from "./components/ChecksList.js";
import { Footer } from "./components/Footer.js";
import { useSession } from "./hooks/useSession.js";

function App() {
  const { session, loading } = useSession();

  if (loading) return null;

  return (
    <>
      <Header session={session} />
      <Hero />
      <Features />
      <Analyzer session={session} />
      {session && <HistoryPanel session={session} />}
      <Pricing />
      <GithubSection />
      <WaitlistForm />
      <ChecksList />
      <Footer />
    </>
  );
}

export default App;