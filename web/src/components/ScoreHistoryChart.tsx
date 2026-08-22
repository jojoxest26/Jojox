import { useRef, useState } from "react";
import type { AnalysisHistoryEntry } from "../lib/api.js";
import { useTranslation } from "../i18n/LanguageContext.js";
import { interpolate } from "../i18n/richText.js";

const WIDTH = 600;
const HEIGHT = 100;
const PAD_LEFT = 30;
const PAD_RIGHT = 10;
const PAD_TOP = 10;
const PAD_BOTTOM = 20;

function formatShortDate(iso: string, dateLocale: string): string {
  return new Date(iso).toLocaleDateString(dateLocale, { day: "2-digit", month: "2-digit" });
}

export function ScoreHistoryChart({ history }: { history: AnalysisHistoryEntry[] }) {
  const { t } = useTranslation();
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);

  // L'API ritorna le analisi piÃ¹ recenti per prime: il grafico si legge da
  // sinistra (piÃ¹ vecchia) a destra (piÃ¹ recente).
  const points = [...history].reverse();
  if (points.length < 2) return null;

  const plotWidth = WIDTH - PAD_LEFT - PAD_RIGHT;
  const plotHeight = HEIGHT - PAD_TOP - PAD_BOTTOM;
  const stepX = plotWidth / (points.length - 1);

  const xAt = (i: number) => PAD_LEFT + i * stepX;
  const yAt = (score: number) => PAD_TOP + (1 - score / 100) * plotHeight;

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${xAt(i)} ${yAt(p.score)}`).join(" ");
  const areaPath = `${linePath} L ${xAt(points.length - 1)} ${PAD_TOP + plotHeight} L ${xAt(0)} ${PAD_TOP + plotHeight} Z`;

  const lastPoint = points[points.length - 1];
  const shown = hoverIndex !== null ? points[hoverIndex] : lastPoint;

  function handlePointerMove(e: React.PointerEvent<SVGRectElement>) {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const relativeX = ((e.clientX - rect.left) / rect.width) * WIDTH;
    const index = Math.round((relativeX - PAD_LEFT) / stepX);
    setHoverIndex(Math.min(points.length - 1, Math.max(0, index)));
  }

  return (
    <div className="score-chart">
      <div className="score-chart-header">
        <p className="score-chart-title">{t.scoreChart.title}</p>
        <p className="score-chart-readout">
          <strong>{shown.score}/100</strong> Â· {formatShortDate(shown.created_at, t.meta.dateLocale)}
        </p>
      </div>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="score-chart-svg"
        role="img"
        aria-label={interpolate(t.scoreChart.ariaLabel, {
          count: String(points.length),
          from: String(points[0].score),
          to: String(lastPoint.score),
        })}
      >
        {[0, 50, 100].map((tick) => (
          <g key={tick}>
            <line x1={PAD_LEFT} x2={WIDTH - PAD_RIGHT} y1={yAt(tick)} y2={yAt(tick)} className="score-chart-grid" />
            <text x={PAD_LEFT - 8} y={yAt(tick)} className="score-chart-tick" textAnchor="end" dominantBaseline="middle">
              {tick}
            </text>
          </g>
        ))}

        <path d={areaPath} className="score-chart-area" />
        <path d={linePath} className="score-chart-line" />

        {hoverIndex !== null && (
          <line
            x1={xAt(hoverIndex)}
            x2={xAt(hoverIndex)}
            y1={PAD_TOP}
            y2={PAD_TOP + plotHeight}
            className="score-chart-crosshair"
          />
        )}

        {points.map((p, i) => {
          const isLast = i === points.length - 1;
          const isHovered = i === hoverIndex;
          if (!isLast && !isHovered) return null;
          return (
            <circle key={p.id} cx={xAt(i)} cy={yAt(p.score)} r={5} className="score-chart-dot">
              <title>{`${formatShortDate(p.created_at, t.meta.dateLocale)} â€” ${p.score}/100`}</title>
            </circle>
          );
        })}

        <text x={xAt(0)} y={HEIGHT - 6} className="score-chart-axis-label" textAnchor="start">
          {formatShortDate(points[0].created_at, t.meta.dateLocale)}
        </text>
        <text x={xAt(points.length - 1)} y={HEIGHT - 6} className="score-chart-axis-label" textAnchor="end">
          {formatShortDate(lastPoint.created_at, t.meta.dateLocale)}
        </text>

        <rect
          x={PAD_LEFT}
          y={PAD_TOP}
          width={plotWidth}
          height={plotHeight}
          fill="transparent"
          onPointerMove={handlePointerMove}
          onPointerLeave={() => setHoverIndex(null)}
        />
      </svg>
    </div>
  );
}