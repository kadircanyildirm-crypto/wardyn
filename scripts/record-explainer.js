// Records docs/inside-the-syscall.html playing one trace, as the GIF the
// README shows under "How it works".
//
//   npm i --no-save --no-package-lock playwright gifsicle
//   node scripts/record-explainer.js docs/inside-the-syscall.html docs/wardyn-inside-the-syscall.gif [track]
//
// Not a screen recording. Screen capture of a browser gives ten-ish distinct
// frames a second whatever rate it claims, and enough encoder noise that no
// two frames are ever identical — a GIF of that is both jerky and large. So
// the page gets a virtual clock instead: performance.now, setTimeout,
// requestAnimationFrame and every CSS animation advance only when this
// script says, exactly 1/FPS s at a time, and one screenshot is taken per
// step. Motion is smooth by construction, and a region that did not change
// is byte-identical between frames, which is what lets gifsicle make the
// file small.
//
// Needs Google Chrome, ffmpeg on PATH, and gifsicle (the npm package, or one
// on PATH). The frame is measured from the page rather than hard-coded, so a
// layout change cannot silently cut off a box.
"use strict";
const { chromium } = require("playwright");
const { execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const [html, gif, track = "deny"] = process.argv.slice(2);
if (!html || !gif) {
  console.error("usage: node scripts/record-explainer.js <explainer.html> <out.gif> [track]");
  process.exit(2);
}

const WIDTH = 820;       // README column
const FPS = 20;
const STEP_MS = 1000 / FPS;
const REST_S = 1.2;      // at rest before Play
const HOLD_S = 2.2;      // on the verdict at the end
const VIEW = { width: 1280, height: 1040 };

// Installed before any page script runs. Everything time-based in the page
// goes through here; __vt.tick(ms) moves the clock and runs what came due.
const VIRTUAL_CLOCK = `(() => {
  let now = 0, nextId = 1;
  const timers = new Map(), rafs = new Map(), seen = new WeakSet();
  performance.now = () => now;
  Date.now = () => now;
  window.requestAnimationFrame = (cb) => { const id = nextId++; rafs.set(id, cb); return id; };
  window.cancelAnimationFrame = (id) => { rafs.delete(id); };
  window.setTimeout = (cb, ms, ...args) => {
    const id = nextId++; timers.set(id, { at: now + Math.max(0, ms | 0), cb, args }); return id;
  };
  window.setInterval = (cb, ms, ...args) => {
    const id = nextId++; timers.set(id, { at: now + Math.max(1, ms | 0), cb, args, every: Math.max(1, ms | 0) }); return id;
  };
  window.clearTimeout = window.clearInterval = (id) => { timers.delete(id); };
  window.__vt = {
    tick(ms) {
      const target = now + ms;
      for (;;) {
        let due = null;
        for (const [id, t] of timers) if (t.at <= target && (!due || t.at < due.t.at)) due = { id, t };
        if (!due) break;
        now = Math.max(now, due.t.at);
        if (due.t.every) due.t.at += due.t.every; else timers.delete(due.id);
        if (typeof due.t.cb === "function") due.t.cb(...due.t.args);
      }
      now = target;
      const cbs = [...rafs.values()]; rafs.clear();
      for (const cb of cbs) cb(now);
      // CSS animations and transitions live on the compositor's clock; step
      // them by hand so a .6 s ping spans exactly .6 s of frames.
      for (const a of document.getAnimations()) {
        if (!seen.has(a)) { seen.add(a); a.pause(); a.currentTime = 0; }
        if (a.playState !== "finished") a.currentTime = (a.currentTime || 0) + ms;
      }
      return now;
    }
  };
})();`;

function gifsicle() {
  try { return require("gifsicle").default || require("gifsicle"); } catch (_) { return "gifsicle"; }
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wardyn-explainer-"));
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || "chrome" });
  const ctx = await browser.newContext({ viewport: VIEW, colorScheme: "dark", deviceScaleFactor: 1 });
  await ctx.addInitScript(VIRTUAL_CLOCK);
  const page = await ctx.newPage();
  await page.goto("file:///" + path.resolve(html).replace(/\\/g, "/"), { waitUntil: "domcontentloaded" });
  // web fonts come from Google; wait for them, but a slow fetch must not hang
  // the run (the timeout has to live here: the page's own setTimeout is virtual now)
  await Promise.race([page.evaluate(() => document.fonts.ready), page.waitForTimeout(8000)]);

  // No scrollbar, and no ambient background traffic: those drifting dots are
  // decoration, and they would change every frame of an otherwise still scene.
  await page.addStyleTag({ content: "html{scrollbar-width:none} ::-webkit-scrollbar{display:none} #ambient{display:none}" });
  await page.evaluate(() => {
    const t = document.querySelector("#s1 .transport").getBoundingClientRect();
    window.scrollBy(0, t.top - 14);
  });
  const clip = await page.evaluate(() => {
    const t = document.querySelector("#s1 .transport").getBoundingClientRect();
    const s = document.querySelector("#s1 .stage").getBoundingClientRect();
    const w = document.querySelector(".wrap").getBoundingClientRect();
    return { x: Math.floor(w.left), y: Math.floor(t.top) - 8, width: Math.ceil(w.width), height: Math.ceil(s.bottom - t.top) + 4 };
  });
  if (track !== "deny") await page.click('.tracks button[data-track="' + track + '"]');

  let n = 0;
  const frame = async () => {
    await page.evaluate((ms) => window.__vt.tick(ms), STEP_MS);
    await page.screenshot({ path: path.join(tmp, "f" + String(n++).padStart(4, "0") + ".png"), clip });
  };
  for (let i = 0; i < REST_S * FPS; i++) await frame();
  await page.click("#play");
  const done = () => page.evaluate(() => /complete/.test(document.querySelector("#tick").textContent));
  for (let i = 0; i < 120 * FPS && !(await done()); i++) await frame();
  if (!(await done())) throw new Error("the trace never completed — did the page's markup change?");
  for (let i = 0; i < HOLD_S * FPS; i++) await frame();
  await browser.close();

  const pal = path.join(tmp, "pal.png"), raw = path.join(tmp, "raw.gif"), seq = path.join(tmp, "f%04d.png");
  const vf = `scale=${WIDTH}:-1:flags=lanczos`;
  execFileSync("ffmpeg", ["-v", "error", "-y", "-framerate", String(FPS), "-i", seq, "-vf", `${vf},palettegen=max_colors=128:stats_mode=diff`, pal]);
  execFileSync("ffmpeg", ["-v", "error", "-y", "-framerate", String(FPS), "-i", seq, "-i", pal, "-lavfi", `${vf} [x]; [x][1:v] paletteuse=dither=none:diff_mode=rectangle`, "-loop", "0", raw]);
  execFileSync(gifsicle(), ["-O3", "--lossy=40", raw, "-o", gif]);
  const kb = Math.round(fs.statSync(gif).size / 1024);
  console.log(`${gif}: ${kb} KiB, ${n} frames at ${FPS} fps (${(n / FPS).toFixed(1)} s), ${clip.width}x${clip.height} scaled to ${WIDTH}px wide`);
  if (kb > 3072) console.warn("over the ~3 MB README budget — see docs/RECORDING.md");
  fs.rmSync(tmp, { recursive: true, force: true });
})().catch((e) => { console.error(e.message || e); process.exit(1); });
