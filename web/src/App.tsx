import { Header } from "./components/Header.js";
import { Hero } from "./components/Hero.js";
import { Analyzer } from "./components/Analyzer.js";
import { HistoryPanel } from "./components/HistoryPanel.js";
import { ChecksList } from "./components/ChecksList.js";
import { Pricing } from "./components/Pricing.js";
import { WaitlistForm } from "./components/WaitlistForm.js";
import { Footer } from "./components/Footer.js";
import { useSession } from "./hooks/useSession.js";

function App() {
  const { session, loading } = useSession();

  if (loading) return null;

  return (
    <>
      <Header session={session} />
      <Hero />
      <Analyzer session={session} />
      {session && <HistoryPanel session={session} />}
      <ChecksList />
      <Pricing />
      <WaitlistForm />
      <Footer />
    </>
  );
}

export default App;
