import { Router } from "express";
import { supabaseAdmin } from "../db/supabase.js";

export const badgeRouter = Router();

const LABEL = "JoJoX";
const NO_DATA_TEXT = "nessuna analisi";

export function colorForScore(score: number): string {
  if (score >= 90) return "#2ea44f";
  if (score >= 70) return "#f59e0b";
  return "#e05353";
}

// Stima larghezza carattere ~6.2px a 11px di font, come i badge shields.io.
function textWidth(text: string): number {
  return Math.round(text.length * 6.2) + 10;
}

export function renderBadge(label: string, value: string, color: string): string {
  const labelWidth = textWidth(label);
  const valueWidth = textWidth(value);
  const totalWidth = labelWidth + valueWidth;
  const labelX = labelWidth / 2;
  const valueX = labelWidth + valueWidth / 2;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${value}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#171717"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelX}" y="14">${label}</text>
    <text x="${valueX}" y="14">${value}</text>
  </g>
</svg>`;
}

badgeRouter.get("/badge/:owner/:repo.svg", async (req, res) => {
  const repoFullName = `${req.params.owner}/${req.params.repo}`;

  const { data } = await supabaseAdmin
    .from("analyses")
    .select("score")
    .eq("repo_full_name", repoFullName)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  const svg =
    data == null
      ? renderBadge(LABEL, NO_DATA_TEXT, "#9ca3af")
      : renderBadge(LABEL, `${data.score}/100`, colorForScore(data.score));

  res.setHeader("Content-Type", "image/svg+xml");
  res.setHeader("Cache-Control", "max-age=300, s-maxage=300");
  res.send(svg);
});