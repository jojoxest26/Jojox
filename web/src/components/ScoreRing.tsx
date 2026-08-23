import { useEffect, useState } from "react";
import { useTranslation } from "../i18n/LanguageContext.js";

const RADIUS = 42;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function ScoreRing({ score }: { score: number }) {
  const { t } = useTranslation();
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    const id = requestAnimationFrame(() => setAnimated(score));
    return () => cancelAnimationFrame(id);
  }, [score]);

  const offset = CIRCUMFERENCE * (1 - animated / 100);

  return (
    <svg width="96" height="96" viewBox="0 0 96 96" role="img" aria-label={`${t.findingsList.scoreLabel}: ${score} / 100`}>
      <circle cx="48" cy="48" r={RADIUS} fill="none" stroke="var(--border)" strokeWidth="8" />
      <circle
        cx="48"
        cy="48"
        r={RADIUS}
        fill="none"
        stroke="var(--accent)"
        strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={CIRCUMFERENCE}
        strokeDashoffset={offset}
        transform="rotate(-90 48 48)"
        style={{ transition: "stroke-dashoffset 1s cubic-bezier(0.16, 1, 0.3, 1)" }}
      />
      <text x="48" y="54" textAnchor="middle" fontSize="24" fontWeight="800" fill="var(--text)">
        {score}
      </text>
    </svg>
  );
}