import type { Reel, ReelAccent, ReelBackground, ReelScene } from "../../../src/reel.js";
import { reelDuration } from "../../../src/reel.js";

/**
 * Disegna un reel (src/reel.ts) su un canvas 1080x1920, fotogramma per
 * fotogramma: la stessa funzione serve all'anteprima e all'export video,
 * così quello che vedi è esattamente quello che scarichi. Stile "testo
 * cinetico": tagli netti tra le scene, parole che entrano con uno scatto.
 */

export const REEL_WIDTH = 1080;
export const REEL_HEIGHT = 1920;

const SANS = '"Inter", -apple-system, "Segoe UI", Roboto, sans-serif';
const SERIF = '"Playfair Display", Georgia, "Times New Roman", serif';
const MONO = '"JetBrains Mono", ui-monospace, monospace';

/**
 * Colori del sito (web/src/index.css): fondo #0a0c0f, testo #eef1f4,
 * ambra #f5a623 come accento principale, rosso #ff6b6b e azzurro #6ea8fe
 * dei livelli di gravità. Ogni sfondo ha la sua variante dell'accento, per
 * restare leggibile: l'ambra pura su bianco o su ambra non si vedrebbe.
 */
interface Palette {
  bg: string;
  fg: string;
  chipFill: string;
  accent: string;
  /** Testo sopra una pillola piena del colore d'accento. */
  onAccent: string;
  strike: string;
  grid: string;
}

const ACCENTS_BY_BG: Record<ReelBackground, Record<ReelAccent, string>> = {
  dark: { amber: "#f5a623", red: "#ff6b6b", blue: "#6ea8fe" },
  light: { amber: "#b86e00", red: "#d93636", blue: "#2a64d6" },
  amber: { amber: "#ffffff", red: "#ffffff", blue: "#ffffff" },
};

function palette(bg: ReelBackground, accent: ReelAccent = "amber"): Palette {
  const a = ACCENTS_BY_BG[bg][accent];
  if (bg === "dark") {
    return { bg: "#0a0c0f", fg: "#eef1f4", chipFill: "#14171c", accent: a, onAccent: accent === "amber" ? "#171310" : "#0a0c0f", strike: "#ff6b6b", grid: "rgba(245,166,35,0.22)" };
  }
  if (bg === "light") {
    return { bg: "#eef1f4", fg: "#0a0c0f", chipFill: "#ffffff", accent: a, onAccent: "#ffffff", strike: "#d93636", grid: "rgba(10,12,15,0.12)" };
  }
  return { bg: "#f5a623", fg: "#171310", chipFill: "#171310", accent: a, onAccent: "#171310", strike: "#171310", grid: "rgba(23,19,16,0.18)" };
}

/** Font da caricare prima di disegnare: senza, il primo fotogramma esce con un font di ripiego. */
export const REEL_FONTS = [`800 100px ${SANS}`, `600 100px ${SANS}`, `italic 700 100px ${SERIF}`, `700 100px ${MONO}`];

export async function loadReelFonts(): Promise<void> {
  try {
    await Promise.all(REEL_FONTS.map((f) => document.fonts.load(f)));
  } catch {
    // Se un font non si carica si usa quello di ripiego: meglio che bloccare l'anteprima.
  }
}

const clamp01 = (n: number) => Math.min(1, Math.max(0, n));
const easeOutCubic = (p: number) => 1 - Math.pow(1 - clamp01(p), 3);
const easeOutBack = (p: number) => {
  const x = clamp01(p);
  const c1 = 1.70158;
  const c3 = c1 + 1;
  return 1 + c3 * Math.pow(x - 1, 3) + c1 * Math.pow(x - 1, 2);
};

export interface SceneAt {
  scene: ReelScene;
  index: number;
  /** Secondi dall'inizio della scena. */
  local: number;
  start: number;
}

export function sceneAt(reel: Reel, t: number): SceneAt | null {
  let start = 0;
  for (let i = 0; i < reel.scenes.length; i++) {
    const scene = reel.scenes[i];
    if (t < start + scene.duration || i === reel.scenes.length - 1) {
      return { scene, index: i, local: Math.max(0, t - start), start };
    }
    start += scene.duration;
  }
  return null;
}

export function sceneStart(reel: Reel, index: number): number {
  return reel.scenes.slice(0, index).reduce((sum, s) => sum + s.duration, 0);
}

/** Dimensione del font più grande (tra min e max) con cui il testo sta nella larghezza data. */
function fitFont(ctx: CanvasRenderingContext2D, text: string, font: (size: number) => string, maxWidth: number, max: number, min: number): number {
  for (let size = max; size > min; size -= 4) {
    ctx.font = font(size);
    if (ctx.measureText(text).width <= maxWidth) return size;
  }
  return min;
}

/** Divide in due righe vicino al centro, quando una frase non sta su una riga nemmeno al font minimo. */
function splitInTwo(text: string): string[] {
  const words = text.split(" ");
  if (words.length < 2) return [text];
  let best = 1;
  let bestDiff = Infinity;
  for (let i = 1; i < words.length; i++) {
    const diff = Math.abs(words.slice(0, i).join(" ").length - words.slice(i).join(" ").length);
    if (diff < bestDiff) {
      bestDiff = diff;
      best = i;
    }
  }
  return [words.slice(0, best).join(" "), words.slice(best).join(" ")];
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function drawPill(ctx: CanvasRenderingContext2D, text: string, cx: number, cy: number, opts: { size: number; fill: string; stroke: string; color: string }) {
  ctx.font = `600 ${opts.size}px ${SANS}`;
  const w = ctx.measureText(text).width + opts.size * 1.4;
  const h = opts.size * 1.9;
  roundRect(ctx, cx - w / 2, cy - h / 2, w, h, h / 2);
  ctx.fillStyle = opts.fill;
  ctx.fill();
  ctx.lineWidth = 3;
  ctx.strokeStyle = opts.stroke;
  ctx.stroke();
  ctx.fillStyle = opts.color;
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(text, cx, cy + 2);
}

function drawDotGrid(ctx: CanvasRenderingContext2D, color: string) {
  const step = 36;
  const cx = REEL_WIDTH / 2;
  const cy = REEL_HEIGHT / 2;
  const maxDist = 700;
  for (let x = step / 2; x < REEL_WIDTH; x += step) {
    for (let y = step / 2; y < REEL_HEIGHT; y += step) {
      const fade = 1 - Math.hypot(x - cx, y - cy) / maxDist;
      if (fade <= 0) continue;
      ctx.globalAlpha = fade;
      ctx.fillStyle = color;
      ctx.fillRect(x, y, 3, 3);
    }
  }
  ctx.globalAlpha = 1;
}

// Posizioni delle etichette intorno al titolo (frazioni di larghezza/altezza), come nel riferimento.
const CHIP_SLOTS: [number, number][] = [
  [0.3, 0.3],
  [0.74, 0.27],
  [0.26, 0.66],
  [0.72, 0.69],
  [0.5, 0.18],
  [0.5, 0.79],
];

function drawScene(ctx: CanvasRenderingContext2D, scene: ReelScene, local: number) {
  const theme = palette(scene.bg, "accent" in scene ? scene.accent : "amber");
  const W = REEL_WIDTH;
  const H = REEL_HEIGHT;
  ctx.fillStyle = theme.bg;
  ctx.fillRect(0, 0, W, H);
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";

  switch (scene.type) {
    case "word": {
      const font = (s: number) => `800 ${s}px ${SANS}`;
      let lines = [scene.text];
      let size = fitFont(ctx, scene.text, font, W * 0.84, 170, 90);
      ctx.font = font(size);
      if (ctx.measureText(scene.text).width > W * 0.84) {
        lines = splitInTwo(scene.text);
        size = Math.min(...lines.map((l) => fitFont(ctx, l, font, W * 0.84, 150, 60)));
      }
      const scale = 0.82 + 0.18 * easeOutBack(local / 0.2);
      ctx.save();
      ctx.globalAlpha = clamp01(local / 0.06);
      ctx.translate(W / 2, H / 2);
      ctx.scale(scale, scale);
      ctx.font = font(size);
      ctx.fillStyle = theme.fg;
      lines.forEach((line, i) => ctx.fillText(line, 0, (i - (lines.length - 1) / 2) * size * 1.1));
      ctx.restore();
      break;
    }

    case "headline": {
      const accent = theme.accent;
      (scene.chips ?? []).slice(0, CHIP_SLOTS.length).forEach((chip, i) => {
        const appear = easeOutBack((local - 0.08 * i) / 0.35);
        if (appear <= 0) return;
        const [fx, fy] = CHIP_SLOTS[i];
        const float = Math.sin(local * 1.6 + i * 1.3) * 14;
        ctx.save();
        ctx.globalAlpha = clamp01(appear);
        ctx.translate(fx * W, fy * H + float);
        ctx.scale(appear, appear);
        drawPill(ctx, chip, 0, 0, { size: 44, fill: theme.chipFill, stroke: accent, color: scene.bg === "amber" ? "#ffffff" : theme.fg });
        ctx.restore();
      });

      const font = (s: number) => `italic 700 ${s}px ${SERIF}`;
      const l1 = scene.line1.toUpperCase();
      const l2 = scene.line2.toUpperCase();
      const size = Math.min(fitFont(ctx, l1, font, W * 0.84, 120, 50), fitFont(ctx, l2, font, W * 0.84, 120, 50));
      const zoom = 1 + 0.04 * (local / scene.duration);
      ctx.save();
      ctx.translate(W / 2, H / 2);
      ctx.scale(zoom, zoom);
      ctx.font = font(size);
      [
        { text: l1, color: theme.fg, delay: 0 },
        { text: l2, color: accent, delay: 0.14 },
      ].forEach(({ text, color, delay }, i) => {
        const p = easeOutCubic((local - delay) / 0.35);
        ctx.globalAlpha = p;
        ctx.fillStyle = color;
        ctx.fillText(text, 0, (i - 0.5) * size * 1.02 + (1 - p) * 50);
      });
      ctx.restore();
      break;
    }

    case "strike": {
      if (scene.bg !== "light") drawDotGrid(ctx, theme.grid);
      const n = scene.words.length;
      const step = (scene.duration * 0.75) / n;
      const font = (s: number) => `italic 700 ${s}px ${SERIF}`;
      const size = Math.min(...scene.words.map((w) => fitFont(ctx, w, font, W * 0.8, 110, 50)));
      const gap = size * 1.5;
      scene.words.forEach((word, i) => {
        const t0 = i * step;
        const p = easeOutCubic((local - t0) / 0.25);
        if (p <= 0) return;
        const y = H / 2 + (i - (n - 1) / 2) * gap;
        ctx.save();
        ctx.globalAlpha = p;
        ctx.font = font(size);
        ctx.fillStyle = theme.fg;
        ctx.fillText(word, W / 2, y + (1 - p) * 30);
        ctx.restore();

        if (i === n - 1) return;
        const strikeP = easeOutCubic((local - t0 - 0.3) / 0.2);
        if (strikeP <= 0) return;
        const half = ctx.measureText(word).width / 2 + 20;
        ctx.save();
        ctx.translate(W / 2, y);
        ctx.rotate(0.06);
        ctx.fillStyle = theme.strike;
        ctx.fillRect(-half, -9, half * 2 * strikeP, 18);
        ctx.restore();
      });
      break;
    }

    case "bars": {
      const accent = theme.accent;
      const left = 140;
      const right = W - 120;
      const top = 620;
      const bottom = 1320;
      ctx.strokeStyle = theme.fg;
      ctx.lineWidth = 4;
      ctx.beginPath();
      ctx.moveTo(left, top - 40);
      ctx.lineTo(left, bottom);
      ctx.lineTo(right, bottom);
      ctx.stroke();
      ctx.font = `600 54px ${SANS}`;
      ctx.fillStyle = theme.fg;
      ctx.textAlign = "left";
      ctx.fillText(scene.title, left + 10, top - 90);
      ctx.textAlign = "center";

      const n = scene.bars.length;
      const slot = (right - left) / n;
      const barW = Math.min(110, slot * 0.45);
      const max = Math.max(...scene.bars.map((b) => b.value), 1);
      scene.bars.forEach((bar, i) => {
        const p = easeOutCubic((local - 0.1 - i * 0.12) / 0.6);
        const cx = left + slot * (i + 0.5);
        const h = (bar.value / max) * (bottom - top) * p;
        // Le superfici piene restano nel colore pieno del sito anche su fondo chiaro: la variante scura serve solo ai testi.
        ctx.fillStyle = scene.bg === "light" ? ACCENTS_BY_BG.dark[scene.accent] : accent;
        ctx.fillRect(cx - barW / 2, bottom - h, barW, h);
        drawPill(ctx, bar.label, cx, bottom + 70, { size: Math.min(34, 260 / n), fill: ctx.fillStyle as string, stroke: ctx.fillStyle as string, color: scene.bg === "light" ? "#171310" : theme.onAccent });
      });
      break;
    }

    case "stat": {
      const accent = theme.accent;
      const p = easeOutCubic(local / Math.max(0.3, scene.duration * 0.55));
      const shown = Math.round(scene.value * p);
      const text = `${shown.toLocaleString("it-IT")}${scene.suffix ?? ""}`;
      const final = `${scene.value.toLocaleString("it-IT")}${scene.suffix ?? ""}`;
      const font = (s: number) => `800 ${s}px ${SANS}`;
      const size = fitFont(ctx, final, font, W * 0.86, 400, 120);
      const scale = 0.9 + 0.1 * easeOutBack(local / 0.3);
      ctx.save();
      ctx.translate(W / 2, H / 2 - 80);
      ctx.scale(scale, scale);
      ctx.font = font(size);
      ctx.fillStyle = accent;
      ctx.fillText(text, 0, 0);
      ctx.restore();
      const cp = easeOutCubic((local - 0.25) / 0.35);
      ctx.globalAlpha = cp;
      ctx.font = `600 ${fitFont(ctx, scene.caption, (s) => `600 ${s}px ${SANS}`, W * 0.84, 72, 36)}px ${SANS}`;
      ctx.fillStyle = theme.fg;
      ctx.fillText(scene.caption, W / 2, H / 2 + size * 0.45 + (1 - cp) * 30);
      ctx.globalAlpha = 1;
      break;
    }

    case "cta": {
      const accent = theme.accent;
      const logoP = easeOutBack(local / 0.35);
      ctx.save();
      ctx.translate(W / 2, H / 2 - 200);
      ctx.scale(logoP, logoP);
      ctx.font = `700 170px ${MONO}`;
      const jojoW = ctx.measureText("JoJo").width;
      const xW = ctx.measureText("X").width;
      ctx.textAlign = "left";
      ctx.fillStyle = theme.fg;
      ctx.fillText("JoJo", -(jojoW + xW) / 2, 0);
      ctx.fillStyle = accent;
      ctx.fillText("X", -(jojoW + xW) / 2 + jojoW, 0);
      ctx.restore();
      ctx.textAlign = "center";

      const tp = easeOutCubic((local - 0.25) / 0.35);
      ctx.globalAlpha = tp;
      const size = fitFont(ctx, scene.text, (s) => `800 ${s}px ${SANS}`, W * 0.86, 110, 50);
      ctx.font = `800 ${size}px ${SANS}`;
      ctx.fillStyle = theme.fg;
      ctx.fillText(scene.text, W / 2, H / 2 + 40 + (1 - tp) * 30);
      if (scene.sub) {
        const pulse = 1 + 0.03 * Math.sin(local * 5);
        drawPill(ctx, scene.sub, W / 2, H / 2 + 220, { size: 56 * pulse, fill: accent, stroke: accent, color: theme.onAccent });
      }
      ctx.globalAlpha = 1;
      break;
    }
  }
}

export function drawReelFrame(ctx: CanvasRenderingContext2D, reel: Reel, t: number): void {
  const at = sceneAt(reel, Math.min(t, reelDuration(reel)));
  ctx.save();
  if (at) drawScene(ctx, at.scene, at.local);
  else {
    ctx.fillStyle = palette("dark").bg;
    ctx.fillRect(0, 0, REEL_WIDTH, REEL_HEIGHT);
  }
  ctx.restore();
}

/** Primo formato video che il browser sa registrare: mp4 se possibile (accettato ovunque dai social), altrimenti webm. */
export function pickRecordingMimeType(): string | null {
  if (typeof MediaRecorder === "undefined") return null;
  const candidates = ["video/mp4;codecs=avc1", "video/mp4", "video/webm;codecs=vp9", "video/webm;codecs=vp8", "video/webm"];
  return candidates.find((type) => MediaRecorder.isTypeSupported(type)) ?? null;
}

/**
 * Registra il reel in tempo reale dal canvas e restituisce il file video.
 * Il canvas deve restare in una scheda visibile: i browser rallentano il
 * disegno nelle schede in background e il video uscirebbe a scatti.
 */
export async function exportReelVideo(reel: Reel, onProgress?: (p: number) => void): Promise<{ blob: Blob; extension: string }> {
  const mimeType = pickRecordingMimeType();
  if (!mimeType) throw new Error("Questo browser non sa registrare video dal canvas. Prova con Chrome o Edge aggiornati.");
  await loadReelFonts();

  const canvas = document.createElement("canvas");
  canvas.width = REEL_WIDTH;
  canvas.height = REEL_HEIGHT;
  const ctx = canvas.getContext("2d")!;
  drawReelFrame(ctx, reel, 0);

  const stream = canvas.captureStream(30);
  const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 8_000_000 });
  const chunks: Blob[] = [];
  recorder.ondataavailable = (e) => {
    if (e.data.size > 0) chunks.push(e.data);
  };
  const stopped = new Promise<void>((resolve) => {
    recorder.onstop = () => resolve();
  });

  const total = reelDuration(reel);
  recorder.start(250);
  const startedAt = performance.now();
  await new Promise<void>((resolve) => {
    const tick = () => {
      const t = (performance.now() - startedAt) / 1000;
      drawReelFrame(ctx, reel, t);
      onProgress?.(clamp01(t / total));
      if (t >= total + 0.3) resolve();
      else requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  recorder.stop();
  await stopped;
  stream.getTracks().forEach((track) => track.stop());

  const baseType = mimeType.split(";")[0];
  return { blob: new Blob(chunks, { type: baseType }), extension: baseType === "video/mp4" ? "mp4" : "webm" };
}
