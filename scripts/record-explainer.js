// Records docs/inside-the-syscall.html playing one trace, as the GIF the
// README shows under "How it works".
//
//   npm i --no-save playwright gifsicle
//   node scripts/record-explainer.js docs/inside-the-syscall.html docs/wardyn-inside-the-syscall.gif [track]
//
// Playwright drives Google Chrome (headless, dark scheme) and records a webm;
// ffmpeg (on PATH) crops it to the transport row + diagram + readout and
// quantises it; gifsicle (the npm package, or one on PATH) makes it small
// enough for a README. The frame is measured from the page, not hard-coded,
// so a layout change in the explainer does not silently cut off a box.
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
const FPS = 10;
const VIEW = { width: 1280, height: 1040 };

function gifsicle() {
  try { return require("gifsicle").default || require("gifsicle"); } catch (_) { return "gifsicle"; }
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wardyn-explainer-"));
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || "chrome" });
  const ctx = await browser.newContext({
    viewport: VIEW, colorScheme: "dark", deviceScaleFactor: 1,
    recordVideo: { dir: tmp, size: VIEW },
  });
  const t0 = Date.now(); // the video clock starts with the context
  const page = await ctx.newPage();
  await page.goto("file:///" + path.resolve(html).replace(/\\/g, "/"), { waitUntil: "domcontentloaded" });
  // web fonts come from Google; wait for them, but a slow fetch must not hang the recording
  await page.evaluate(() => Promise.race([document.fonts.ready, new Promise((r) => setTimeout(r, 6000))]));
  await page.waitForTimeout(600);

  await page.addStyleTag({ content: "html{scrollbar-width:none} ::-webkit-scrollbar{display:none}" });
  await page.evaluate(() => {
    const t = document.querySelector("#s1 .transport").getBoundingClientRect();
    window.scrollBy(0, t.top - 14);
  });
  await page.waitForTimeout(400);
  const box = await page.evaluate(() => {
    const t = document.querySelector("#s1 .transport").getBoundingClientRect();
    const s = document.querySelector("#s1 .stage").getBoundingClientRect();
    const w = document.querySelector(".wrap").getBoundingClientRect();
    return { x: Math.floor(w.left), y: Math.floor(t.top) - 8, w: Math.ceil(w.width), h: Math.ceil(s.bottom - t.top) + 4 };
  });

  if (track !== "deny") await page.click('.tracks button[data-track="' + track + '"]');
  // the GIF starts 1.2 s before Play: one frame at rest, none of the blank
  // loading time Playwright recorded before the page had painted
  const ss = Math.max(0, (Date.now() - t0) / 1000 + 0.2);
  await page.waitForTimeout(1400);
  await page.click("#play");
  await page.waitForFunction(() => /complete/.test(document.querySelector("#tick").textContent), null, { timeout: 120000 });
  await page.waitForTimeout(2200); // hold the verdict
  await ctx.close();
  await browser.close();

  const webm = fs.readdirSync(tmp).map((f) => path.join(tmp, f)).find((f) => f.endsWith(".webm"));
  const pal = path.join(tmp, "pal.png"), raw = path.join(tmp, "raw.gif");
  const vf = `crop=${box.w}:${box.h}:${box.x}:${box.y},fps=${FPS},scale=${WIDTH}:-1:flags=lanczos`;
  const from = ss.toFixed(2);
  execFileSync("ffmpeg", ["-v", "error", "-y", "-ss", from, "-i", webm, "-vf", `${vf},palettegen=max_colors=128:stats_mode=diff`, pal]);
  execFileSync("ffmpeg", ["-v", "error", "-y", "-ss", from, "-i", webm, "-i", pal, "-lavfi", `${vf} [x]; [x][1:v] paletteuse=dither=none:diff_mode=rectangle`, "-loop", "0", raw]);
  execFileSync(gifsicle(), ["-O3", "--lossy=80", raw, "-o", gif]);
  const kb = Math.round(fs.statSync(gif).size / 1024);
  console.log(`${gif}: ${kb} KiB, ${box.w}x${box.h} cropped to ${WIDTH}px wide, ${FPS} fps`);
  if (kb > 3072) console.warn("over the ~3 MB README budget — see docs/RECORDING.md");
  fs.rmSync(tmp, { recursive: true, force: true });
})().catch((e) => { console.error(e.message || e); process.exit(1); });
