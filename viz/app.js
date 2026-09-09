// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The 3-D kernel view. Every mark on this scene comes from a real record in
// wardyn's `--format json` stream or from the kernel keys `--dry-run` reports;
// nothing here is generated to look busy. If the run denies nothing, nothing
// turns red.
//
// The world, from the top down:
//
//   y = +6    USERSPACE   one tower per program, grown by its own traffic
//   y =  0    the syscall boundary, a grid plane
//   y = -4    HOOKS       the tracepoint (observes) and the LSM/cgroup hook
//                         (decides) — kept apart, because that distinction is
//                         the one wardyn refuses to blur
//   y = -9    MAPS        one tile per kernel block key, lit when it fires
//
// A syscall is a particle. It falls from its tower, crosses the boundary, and
// either passes the hook plane and continues down (allowed) or is turned around
// at it and thrown back up in red (denied).
//
// The tour is a scripted camera and a card, nothing more: it points at the
// live scene and explains what is already there. It never fakes an event.

import * as THREE from "./vendor/three.module.min.js";

const $ = (id) => document.getElementById(id);

const COL = {
  signal:  0xE8A33D,
  deny:    0xF0575D,
  allow:   0x47D18E,
  observe: 0x5AB0E8,
  wire:    0x1E2A38,
  wireHot: 0x33465C,
  ground:  0x05070B,
};

const Y_USER = 6.0;   // tower bases
const Y_BOUND = 0.0;  // syscall boundary
const Y_HOOK = -4.0;  // where a verdict is returned
const Y_MAP = -9.0;   // the block-key lattice

// ── scene ──────────────────────────────────────────────────────────────────

const scene = new THREE.Scene();
scene.background = new THREE.Color(COL.ground);
scene.fog = new THREE.Fog(COL.ground, 30, 70);

const camera = new THREE.PerspectiveCamera(46, innerWidth / innerHeight, 0.1, 200);

const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
renderer.setPixelRatio(Math.min(devicePixelRatio, 1.5));
renderer.setSize(innerWidth, innerHeight);
$("scene").appendChild(renderer.domElement);

scene.add(new THREE.AmbientLight(0xffffff, 0.55));
const key = new THREE.DirectionalLight(0xffffff, 0.7);
key.position.set(8, 14, 10);
scene.add(key);
const under = new THREE.PointLight(COL.signal, 18, 30, 2);
under.position.set(0, Y_HOOK - 1.2, 0);
scene.add(under);

// ── focus / dimming ────────────────────────────────────────────────────────
//
// Every drawn thing belongs to a group. The tour asks for one or two groups to
// be in focus; everything else fades to a fraction of its normal brightness,
// and fades back when the tour moves on. Particles are never dimmed — they are
// the data.

const dimmables = [];   // { mat, base, group, prop }
function dimmable(mat, group, prop) {
  prop = prop || "opacity";
  mat.transparent = true;
  dimmables.push({ mat, base: mat[prop], group, prop });
}
let focus = null;   // null = everything at full brightness
function inFocus(group) { return !focus || focus.includes(group); }

// ── the two planes that define the world ───────────────────────────────────

function plane(y, size, div, color, opacity, group) {
  const g = new THREE.GridHelper(size, div, color, color);
  g.position.y = y;
  g.material.transparent = true;
  g.material.opacity = opacity;
  scene.add(g);
  dimmable(g.material, group);
  return g;
}

// The syscall boundary: brighter, because it is the line the whole tool is about.
plane(Y_BOUND, 30, 30, COL.wireHot, 0.42, "boundary");
plane(Y_MAP - 0.02, 30, 15, COL.wire, 0.3, "tiles");

// A faint slab under the boundary so "kernel" reads as a solid region.
const slab = new THREE.Mesh(
  new THREE.BoxGeometry(30, 0.06, 30),
  new THREE.MeshBasicMaterial({ color: 0x0A1018, transparent: true, opacity: 0.55 })
);
slab.position.y = Y_BOUND - 0.05;
scene.add(slab);
dimmable(slab.material, "boundary");

// ── the hook plane: two discs, observer and decider ────────────────────────

function disc(radius, y, color, opacity, group) {
  const m = new THREE.Mesh(
    new THREE.RingGeometry(radius * 0.62, radius, 64),
    new THREE.MeshBasicMaterial({ color, transparent: true, opacity, side: THREE.DoubleSide })
  );
  m.rotation.x = -Math.PI / 2;
  m.position.y = y;
  scene.add(m);
  dimmable(m.material, group);
  return m;
}

const traceRing = disc(7.2, Y_HOOK + 1.7, COL.observe, 0.3, "trace");   // sees, cannot deny
const hookRing = disc(6.0, Y_HOOK, COL.signal, 0.42, "hook");           // decides

// ── the EVENTS ring buffer ─────────────────────────────────────────────────
//
// A torus between the hook and the maps: the path a *report* takes to
// userspace, as opposed to the verdict, which never leaves the syscall. It
// flashes red when events are lost — wardyn's own drops, or this page's
// coalescing — because a drop that nobody sees is the failure this whole thing
// is built to avoid.

const ringBuf = new THREE.Mesh(
  new THREE.TorusGeometry(9.6, 0.14, 10, 96),
  new THREE.MeshBasicMaterial({ color: COL.observe, transparent: true, opacity: 0.26 })
);
ringBuf.rotation.x = Math.PI / 2;
ringBuf.position.y = Y_HOOK - 2.3;
scene.add(ringBuf);
dimmable(ringBuf.material, "ringbuf");
let ringBufHot = 0;
function ringBufFlash() { ringBufHot = 1; }

// ── the Landlock hull ──────────────────────────────────────────────────────
//
// `allow_paths:` is a second boundary, and a different kind: an allowlist,
// enforced by Landlock rather than eBPF, inherited by every descendant and
// impossible to undo. Drawn as a dashed hull around userspace. Whether it is
// ACTIVE comes from `--dry-run`, and the hull is drawn faint and labelled "not
// in this policy" when it is not — a hull shown as active for a policy without
// one would be the page lying about the boundary.

const hullBox = new THREE.BoxGeometry(24, 8.6, 24);
const hullEdges = new THREE.LineSegments(
  new THREE.EdgesGeometry(hullBox),
  new THREE.LineDashedMaterial({ color: COL.signal, dashSize: 0.5, gapSize: 0.32, transparent: true, opacity: 0.1 })
);
hullEdges.computeLineDistances();
hullEdges.position.y = Y_USER + 3.1;
scene.add(hullEdges);
dimmable(hullEdges.material, "hull");
const hullFill = new THREE.Mesh(
  hullBox,
  new THREE.MeshBasicMaterial({ color: COL.signal, transparent: true, opacity: 0.0, side: THREE.BackSide })
);
hullFill.position.y = Y_USER + 3.1;
scene.add(hullFill);
dimmable(hullFill.material, "hull");
let hullActive = false;
let hullLabel = null;
function setHull(active, ports) {
  hullActive = !!active;
  hullEdges.material.opacity = hullActive ? 0.55 : 0.1;
  hullFill.material.opacity = hullActive ? 0.035 : 0.0;
  const d = dimmables.find((x) => x.mat === hullEdges.material); if (d) d.base = hullEdges.material.opacity;
  const f = dimmables.find((x) => x.mat === hullFill.material); if (f) f.base = hullFill.material.opacity;
  const text = hullActive
    ? "LANDLOCK CONTAINMENT · ACTIVE" + (ports ? " · TCP " + ports : "")
    : "LANDLOCK CONTAINMENT · not in this policy";
  if (!hullLabel) hullLabel = makeLabel(text, 0, Y_USER + 7.9, 0, "hull");
  hullLabel.el.textContent = text;
  hullLabel.el.classList.toggle("off", !hullActive);
}

// ── userspace towers, one per PROGRAM ──────────────────────────────────────
//
// Not one per pid. A shell loop spawns a fresh `cat` every iteration, and a pid
// tower gives you four hundred of them in a minute — the scene became a forest
// with the kernel hidden somewhere behind it. Grouping by `comm` is bounded by
// how many distinct programs the agent actually runs, which is the thing worth
// looking at anyway: bash, cat, gcc, node.

const towerGeo = new THREE.BoxGeometry(1.05, 1, 1.05);
const towerMat = new THREE.MeshStandardMaterial({
  color: 0x18222F, emissive: COL.wireHot, emissiveIntensity: 0.22,
  roughness: 0.8, metalness: 0.08, transparent: true, opacity: 1,
});
const towerHot = new THREE.MeshStandardMaterial({
  color: 0x241C22, emissive: COL.deny, emissiveIntensity: 0.5,
  roughness: 0.8, metalness: 0.08, transparent: true, opacity: 1,
});
dimmable(towerMat, "towers");
dimmable(towerHot, "towers");

const progs = new Map();   // comm -> { mesh, x, z, n, denies, pids:Set, label, h }
let progSlot = 0;

function progPos(slot) {
  const per = 8, ring = Math.floor(slot / per), k = slot % per;
  const r = 5.6 + ring * 3.4;
  const a = (k / per) * Math.PI * 2 + ring * 0.42;
  return [Math.cos(a) * r, Math.sin(a) * r];
}

function pidFor(ev) {
  const name = (ev.comm || "?").slice(0, 12);
  let p = progs.get(name);
  if (!p) {
    const [x, z] = progPos(progSlot++);
    const mesh = new THREE.Mesh(towerGeo, towerMat);
    mesh.position.set(x, Y_USER, z);
    scene.add(mesh);
    p = { mesh, x, z, n: 0, denies: 0, pids: new Set(), label: null, h: 1 };
    progs.set(name, p);
    p.label = makeLabel(name, x, Y_USER, z);
  }
  p.n += 1;
  p.pids.add(ev.pid);
  if (ev.action === "block") {
    p.denies += 1;
    p.mesh.material = towerHot;
  }
  const h = Math.min(0.7 + Math.log2(p.n + 1) * 0.42, 4.2);
  p.h = h;
  p.mesh.scale.y = h;
  p.mesh.position.y = Y_USER + h / 2 - 0.5;
  if (p.label) {
    p.label.el.textContent = p.pids.size > 1 ? name + " ×" + p.pids.size : name;
    p.label.el.classList.toggle("hot", p.denies > 0);
    p.label.v.y = Y_USER + h + 0.5;
  }
  return p;
}

// ── the map lattice: one tile per real kernel block key ────────────────────

const tiles = new Map();   // key string -> mesh
function buildKeys(keys) {
  const box = $("keys");
  box.innerHTML = "";
  if (!keys || !keys.length) {
    box.innerHTML = '<span class="key"><span class="ax">—</span><span>no kernel-enforceable block keys in this policy</span></span>';
    return;
  }
  const cols = Math.ceil(Math.sqrt(keys.length));
  keys.forEach((k, i) => {
    const gx = (i % cols) - (cols - 1) / 2;
    const gz = Math.floor(i / cols) - (cols - 1) / 2;
    const mat = new THREE.MeshStandardMaterial({
      color: 0x1B2A3A, emissive: COL.wireHot, emissiveIntensity: 1.1, roughness: 0.85,
      transparent: true, opacity: 1,
    });
    const mesh = new THREE.Mesh(new THREE.BoxGeometry(1.7, 0.22, 1.7), mat);
    mesh.position.set(gx * 2.0, Y_MAP, gz * 2.0);
    scene.add(mesh);
    dimmable(mat, "tiles");
    tiles.set(k.key, mesh);

    const row = document.createElement("span");
    row.className = "key";
    row.dataset.key = k.key;
    const ax = document.createElement("span");
    ax.className = "ax";
    ax.textContent = k.axis;
    const nm = document.createElement("span");
    nm.textContent = k.key;
    row.append(ax, nm);
    box.appendChild(row);
  });
}

function fireKey(matched) {
  if (!matched) return;
  let mesh = tiles.get(matched);
  if (!mesh) {
    for (const [k, m] of tiles) {
      if (k.endsWith(matched) || matched.endsWith(k)) { mesh = m; break; }
    }
  }
  if (mesh) {
    mesh.material.emissive.setHex(COL.deny);
    mesh.material.emissiveIntensity = 2.6;
    mesh.scale.y = 3.4;
  }
  document.querySelectorAll(".key").forEach((el) => {
    if (el.dataset.key === matched) el.classList.add("fired");
  });
}

// ── labels drawn in HTML over the canvas ───────────────────────────────────

const labels = [];
let labelsOn = true;
function makeLabel(text, x, y, z, cls) {
  const el = document.createElement("div");
  el.className = "lbl" + (cls ? " " + cls : "");
  el.textContent = text;
  document.body.appendChild(el);
  const rec = { el, v: new THREE.Vector3(x, y, z), ttl: null };
  labels.push(rec);
  return rec;
}
// A label that lives briefly and removes itself — the receipt flying back.
function flashLabel(text, x, y, z, cls, ttl) {
  const rec = makeLabel(text, x, y, z, cls);
  rec.ttl = ttl;
  return rec;
}

function placeLabels(dt) {
  for (let i = labels.length - 1; i >= 0; i--) {
    const l = labels[i];
    if (l.ttl != null) {
      l.ttl -= dt;
      if (l.ttl <= 0) { l.el.remove(); labels.splice(i, 1); continue; }
    }
    if (!labelsOn && !l.el.classList.contains("receipt")) { l.el.style.display = "none"; continue; }
    const p = l.v.clone().project(camera);
    const vis = p.z < 1;
    l.el.style.display = vis ? "block" : "none";
    l.el.style.left = ((p.x * 0.5 + 0.5) * innerWidth) + "px";
    l.el.style.top = ((-p.y * 0.5 + 0.5) * innerHeight) + "px";
  }
}

// ── particles: a fixed pool, shared materials ──────────────────────────────
//
// A real run pushes ~110 events a second through here, and the first version
// allocated a mesh, a geometry, a line and two materials for every one of them.
// The tab locked up inside four seconds — which is a fair description of what
// wardyn's own ring buffer does under load, except wardyn *says* so.
//
// So: a fixed pool, three shared materials, no per-particle geometry. When
// events outrun the pool they are coalesced, and the count of coalesced events
// is shown rather than quietly discarded.

const POOL = 260;
const partGeo = new THREE.SphereGeometry(0.13, 8, 8);
const MAT = {
  deny:    new THREE.MeshBasicMaterial({ color: COL.deny,    transparent: true }),
  allow:   new THREE.MeshBasicMaterial({ color: COL.signal,  transparent: true }),
  observe: new THREE.MeshBasicMaterial({ color: COL.observe, transparent: true }),
};

const pool = [];
const free = [];
for (let i = 0; i < POOL; i++) {
  const m = new THREE.Mesh(partGeo, MAT.observe);
  m.visible = false;
  m.frustumCulled = false;
  scene.add(m);
  pool.push(m);
  free.push(i);
}
const live = [];
let coalesced = 0;

function spawn(ev) {
  const p = pidFor(ev);
  const denied = ev.action === "block";
  const observed = ev.source === "observed";

  if (!free.length) { coalesced += 1; ringBufFlash(); return; }
  const idx = free.pop();
  const mesh = pool[idx];
  mesh.material = denied ? MAT.deny : (observed ? MAT.observe : MAT.allow);
  mesh.visible = true;
  mesh.position.set(p.x, Y_USER + 0.4, p.z);

  live.push({
    idx, mesh, x: p.x, z: p.z, t: 0, denied, prog: p, receipted: false,
    bottom: denied ? Y_HOOK : Y_MAP - 1.6,
  });
  if (denied) flash(hookRing, COL.deny);
}

function release(k) {
  const p = live[k];
  p.mesh.visible = false;
  free.push(p.idx);
  live.splice(k, 1);
}

let ringPulse = [];
function flash(ring, color) {
  ring.material.color.setHex(color);
  ringPulse.push({ ring, t: 0, base: ring.material.opacity });
}

// ── the stream ─────────────────────────────────────────────────────────────

let nEv = 0, nOk = 0, nDn = 0, nKn = 0;
const rows = $("rows");

// The DOM cannot take 110 insertions a second either. Queue them and let the
// render loop drain a few per frame; the newest is always on top, so a burst
// costs latency rather than correctness.
const rowQueue = [];
function addRow(ev) { rowQueue.push(ev); if (rowQueue.length > 60) rowQueue.shift(); }

function drainRows() {
  let n = 0;
  while (rowQueue.length && n < 3) { renderRow(rowQueue.shift()); n++; }
}

function renderRow(ev) {
  const el = document.createElement("div");
  const cls = ev.action === "block" ? "block" : ev.action === "warn" ? "warn" : "allow";
  el.className = "row " + cls + (ev.source === "kernel" ? " k" : "");
  const mk = (t, c) => { const s = document.createElement("span"); s.className = c; s.textContent = t; return s; };
  el.append(
    mk(String(ev.pid), "p"),
    mk((ev.comm || "").slice(0, 9), "c"),
    mk(ev.action === "block" ? (ev.enforced ? "BLOCK" : "block~") : ev.action, "a"),
    mk(ev.detail || "", "d")
  );
  rows.insertBefore(el, rows.firstChild);
  while (rows.children.length > 14) rows.removeChild(rows.lastChild);
}

let lastDenied = null;   // the most recent real denial, for the tour's status line
function onEvent(ev) {
  nEv++;
  if (ev.action === "block") { nDn++; fireKey(ev.matched_key); lastDenied = ev; } else { nOk++; }
  if (ev.source === "kernel") nKn++;
  $("c-ev").textContent = nEv;
  $("c-ok").textContent = nOk;
  $("c-dn").textContent = nDn;
  $("c-kn").textContent = nKn;
  spawn(ev);
  addRow(ev);
}

let policyInfo = null;
const es = new EventSource("/stream");
es.onopen = () => { $("dot").classList.add("on"); $("livetxt").textContent = "STREAMING"; };
es.onerror = () => { $("dot").classList.remove("on"); $("livetxt").textContent = "STREAM CLOSED"; };
es.onmessage = (m) => {
  let d;
  try { d = JSON.parse(m.data); } catch { return; }
  if (d.kind === "event") onEvent(d.event);
  else if (d.kind === "notice") notice(d.text);
  else if (d.kind === "meta") {
    $("target").textContent = "enforcing=" + d.meta.enforcing + " · schema v" + d.meta.schema_version;
  } else if (d.kind === "boot") {
    policyInfo = d.policy || null;
    if (d.policy) {
      buildKeys(d.policy.keys);
      if (d.policy.summary) $("target").textContent = d.policy.summary;
      setHull(d.policy.contained, d.policy.ports);
    } else {
      setHull(false, null);
    }
    (d.notices || []).forEach(notice);
  }
};

const seenNotices = new Set();
function notice(text) {
  const t = text.replace(/^wardyn:\s*/, "");
  if (seenNotices.has(t)) return;
  seenNotices.add(t);
  if (/dropped by a full ring buffer/i.test(t)) ringBufFlash();
  const box = $("notice");
  if (box.textContent === "—") box.textContent = "";
  const p = document.createElement("div");
  if (/WARNING|refus|could not|dropped/i.test(t)) {
    const b = document.createElement("b");
    b.textContent = "· " + t;
    p.appendChild(b);
  } else {
    p.textContent = "· " + t;
  }
  box.insertBefore(p, box.firstChild);
  while (box.children.length > 14) box.removeChild(box.lastChild);
}

// ── camera ─────────────────────────────────────────────────────────────────
//
// Two regimes. Orbit: the default, a slow turn the viewer can grab. Tour: a
// scripted flight between keyframes, eased, that the viewer can also grab —
// dragging during the tour pauses it rather than fighting it.

let spin = true;
let theta = 0.72, phi = 0.46, dist = 31;
const camPos = new THREE.Vector3(18, 10, 22);
const camLook = new THREE.Vector3(0, -2, 0);
const flight = { on: false, from: null, to: null, t: 0, dur: 2.4 };

function orbitTarget() {
  return {
    pos: new THREE.Vector3(
      Math.cos(theta) * Math.cos(phi) * dist,
      Math.sin(phi) * dist + 1.5,
      Math.sin(theta) * Math.cos(phi) * dist
    ),
    look: new THREE.Vector3(0, -2.2, 0),
  };
}
function flyTo(pos, look, dur) {
  flight.on = true;
  flight.from = { pos: camPos.clone(), look: camLook.clone() };
  flight.to = { pos: new THREE.Vector3(...pos), look: new THREE.Vector3(...look) };
  flight.t = 0;
  flight.dur = dur || 2.4;
}
const ease = (u) => (u < 0.5 ? 4 * u * u * u : 1 - Math.pow(-2 * u + 2, 3) / 2);
function orbitFromCamera() {
  theta = Math.atan2(camPos.z, camPos.x);
  dist = Math.max(11, Math.min(48, camPos.length()));
  phi = Math.max(-0.15, Math.min(1.32, Math.asin(Math.max(-1, Math.min(1, (camPos.y - 1.5) / dist)))));
}

// ── the tour ───────────────────────────────────────────────────────────────
//
// Every chapter names a camera keyframe, the groups to keep in focus, and a
// caption. The `status` hook lets a chapter report something live — the last
// real denial, whether containment is actually on — so the card never states
// more than the run has shown.

const TOUR = [
  {
    title: "An agent with a shell",
    body: "Every tower is a program the agent has run; the count on it is live pids. Wardyn launched the whole tree <em>dropped to a normal user</em>, with <code>NO_NEW_PRIVS</code> set — it cannot get root back, not through <code>sudo</code>, not through a setuid binary.",
    cam: [[0, 17, 27], [0, 4.5, 0]], focus: ["towers"], hold: 9,
    status: () => `${progs.size} program(s) seen so far · ${nEv} event(s)`,
  },
  {
    title: "The boundary",
    body: "Every <code>open</code>, <code>exec</code> and <code>connect</code> crosses this plane. Past it the agent has no say: it cannot see wardyn, unload it, or race it. Wardyn's programs are attached to the kernel's <em>own</em> hooks — not wrapped around the process from outside.",
    cam: [[23, 2.2, 7], [0, 0.4, 0]], focus: ["boundary", "towers"], hold: 9,
  },
  {
    title: "Seeing is not deciding",
    body: "The blue ring is the tracepoint: <code>sys_enter_openat</code>, <code>execve</code>, <code>connect</code>. It reports every call — the allow rows too — so the feed shows what the agent actually did, not only what went wrong. It has <em>no verdict to give</em>, and wardyn never lets it pretend otherwise.",
    cam: [[9.5, 0.2, 12], [0, Y_HOOK + 1.7, 0]], focus: ["trace"], hold: 10,
    status: () => `${nEv - nKn} observed row(s) · the blue particles`,
  },
  {
    title: "The verdict, inside the syscall",
    body: "The amber ring is the LSM hook — <code>file_open</code>, <code>bprm_check_security</code>, <code>inode_unlink</code> — and <code>cgroup/connect4</code> for egress. The kernel calls it <em>while deciding</em> the operation; what it returns is the answer. <code>-EPERM</code> before the descriptor exists, before a packet is built.",
    cam: [[7.5, -3.2, 9], [0, Y_HOOK, 0]], focus: ["hook"], hold: 10,
    status: () => `${nKn} verdict(s) reported by the kernel itself so far`,
  },
  {
    title: "Identity, not names",
    body: "These tiles are the keys sitting in the BPF maps <em>right now</em>, read from <code>--dry-run</code>. A <code>path:</code> rule keys on <code>(dev, ino)</code> — the object, not what it is called. Rename the file, hard-link it into the project, move the whole directory: the inode is unchanged, and so is the verdict.",
    cam: [[7, -5.6, 9.5], [0, Y_MAP + 0.3, 0]], focus: ["tiles"], hold: 10,
    hud: ["card-keys"],
    status: () => policyInfo && policyInfo.keys ? `${policyInfo.keys.length} key(s) loaded — ${policyInfo.keys.filter(k => k.key.startsWith("ino=")).length} by inode` : "",
  },
  {
    title: "A denial",
    body: "Watch for red. A call falls, reaches the amber ring, and is <em>turned around</em> — thrown back to the tower it came from. Nothing to unwind, nothing to kill: the open simply never happened. The tower turns red too, so a program that has been refused stays marked.",
    cam: [[13, 3.5, 13], [0, -0.5, 0]], focus: ["hook", "towers"], hold: 11,
    status: () => lastDenied
      ? `last real denial: <b>${lastDenied.comm}</b> → ${lastDenied.detail}${lastDenied.matched_key ? " · key " + lastDenied.matched_key : ""}`
      : "<b class=no>no denial yet in this run — the policy has not been crossed</b>",
  },
  {
    title: "The agent is told why",
    body: "A bare <code>EPERM</code> teaches an agent nothing, so it retries, or reaches for <code>sudo</code>, or codes around the block. Wardyn hands it a <em>receipt</em> — <code>WARDYN_DENIALS</code> in its environment — naming the rule that fired, so it reports to its operator instead of flailing.",
    cam: [[10, 9.5, 14.5], [0, 6.2, 0]], focus: ["towers"], hold: 9,
    status: () => `${nDn} denial(s) receipted so far`,
  },
  {
    title: "What can be outrun, and what cannot",
    body: "The verdict is decided in the syscall. The <em>report</em> travels this ring to userspace, and a ring can fill. This page has a particle pool that can fill too. Both count what they dropped instead of hiding it — a clean log that means nothing is the real failure.",
    cam: [[14.5, -5.5, 10.5], [0, -6.4, 0]], focus: ["ringbuf", "hook"], hold: 10,
    hud: ["co-wrap", "card-notice"],
    status: () => coalesced ? `this page coalesced <b>${coalesced}</b> event(s) it could not draw` : "nothing dropped yet — the run is keeping up",
  },
  {
    title: "Containment",
    body: "<code>allow_paths:</code> draws a second boundary, of a different kind. Landlock — not eBPF — confines the agent to the hierarchies the policy lists and nothing else: unprivileged, inherited by every descendant, impossible to undo. <code>allow_ports:</code> does the same for TCP.",
    cam: [[21, 13, 21], [0, 5.5, 0]], focus: ["hull", "towers"], hold: 10,
    status: () => policyInfo && policyInfo.contained
      ? `<b>active</b> in this policy` + (policyInfo.ports ? ` · TCP confined to ${policyInfo.ports}` : "")
      : "<b class=no>not in this policy</b> — the hull is drawn faint, because it is not there",
  },
  {
    title: "Measured, not claimed",
    body: "Eight bypass attempts stopped, out of eight. Fourteen attacks on the warden itself refused, out of fifteen — the one that worked changed nothing. About fifteen microseconds per open. Thirteen thousand events dropped under forty thousand opens, every one of them <em>counted</em>, while the boundary held. The recordings are in <code>docs/stress/</code>.",
    cam: [[18, 10, 22], [0, -2.2, 0]], focus: null, hold: 12,
  },
];

const tour = { on: false, i: -1, t: 0, paused: false };
const tourEl = $("tour");

function tourGo(i) {
  if (i < 0 || i >= TOUR.length) { tourEnd(); return; }
  tour.on = true; tour.i = i; tour.t = 0; tour.paused = false;
  const c = TOUR[i];
  flyTo(c.cam[0], c.cam[1], 2.4);
  focus = c.focus;
  spin = false; $("b-spin").setAttribute("aria-pressed", "false");

  $("tour-k").textContent = `CHAPTER ${i + 1} / ${TOUR.length}`;
  $("tour-title").textContent = c.title;
  $("tour-body").innerHTML = c.body;
  $("tour-status").innerHTML = ""; statusLast = ""; statusClock = 1;
  $("t-pause").textContent = "❙❙ pause";
  tourEl.classList.add("on");

  document.querySelectorAll(".st").forEach((el) => {
    const g = el.dataset.g;
    el.classList.toggle("on", !!(c.focus && c.focus.includes(g)));
    el.classList.toggle("off", !!(c.focus && !c.focus.includes(g)));
  });
  document.querySelectorAll(".card, .ctr").forEach((el) => el.classList.remove("hl"));
  (c.hud || []).forEach((id) => { const el = $(id); if (el) el.classList.add("hl"); });

  const dots = $("tour-dots");
  dots.innerHTML = "";
  TOUR.forEach((_, k) => {
    const d = document.createElement("i");
    if (k < i) d.className = "done"; else if (k === i) d.className = "now";
    dots.appendChild(d);
  });
}

function tourEnd() {
  tour.on = false; tour.i = -1;
  focus = null;
  tourEl.classList.remove("on");
  document.querySelectorAll(".st").forEach((el) => el.classList.remove("on", "off"));
  document.querySelectorAll(".card, .ctr").forEach((el) => el.classList.remove("hl"));
  flight.on = false;
  spin = true; $("b-spin").setAttribute("aria-pressed", "true");
  orbitFromCamera();   // pick the orbit up from here rather than snapping
}

let statusClock = 0, statusLast = "";
function tourTick(dt) {
  if (!tour.on) return;
  const c = TOUR[tour.i];
  statusClock += dt;
  if (c.status && statusClock > 0.25) {
    statusClock = 0;
    const txt = c.status() || "";
    if (txt !== statusLast) { statusLast = txt; $("tour-status").innerHTML = txt; }
  }
  if (tour.paused) return;
  tour.t += dt;
  $("tour-bar").style.width = Math.min(100, (tour.t / c.hold) * 100) + "%";
  if (tour.t >= c.hold) tourGo(tour.i + 1);
}

$("b-tour").onclick = () => tourGo(0);
$("t-next").onclick = () => tourGo(tour.i + 1);
$("t-prev").onclick = () => tourGo(Math.max(0, tour.i - 1));
$("t-exit").onclick = tourEnd;
$("t-pause").onclick = () => {
  tour.paused = !tour.paused;
  $("t-pause").textContent = tour.paused ? "▶ resume" : "❙❙ pause";
};
addEventListener("keydown", (e) => {
  if (!tour.on) { if (e.key === "t" || e.key === "T") tourGo(0); return; }
  if (e.key === "ArrowRight") tourGo(tour.i + 1);
  else if (e.key === "ArrowLeft") tourGo(Math.max(0, tour.i - 1));
  else if (e.key === " ") { e.preventDefault(); $("t-pause").click(); }
  else if (e.key === "Escape") tourEnd();
});

// ── controls ───────────────────────────────────────────────────────────────

$("b-spin").onclick = (e) => {
  spin = !spin;
  e.currentTarget.setAttribute("aria-pressed", String(spin));
};
$("b-labels").onclick = (e) => {
  labelsOn = !labelsOn;
  e.currentTarget.setAttribute("aria-pressed", String(labelsOn));
};
$("b-clear").onclick = () => { rows.innerHTML = ""; };

// Drag to orbit, wheel to dolly — enough to inspect the scene without pulling in
// a controls module. Grabbing the scene mid-tour pauses the tour.
let drag = null;
renderer.domElement.addEventListener("pointerdown", (e) => {
  drag = { x: e.clientX, y: e.clientY };
  if (tour.on) { tour.paused = true; $("t-pause").textContent = "▶ resume"; flight.on = false; }
  spin = false;
  $("b-spin").setAttribute("aria-pressed", "false");
  orbitFromCamera();   // continue from the current camera so a grab does not jump
});
addEventListener("pointerup", () => { drag = null; });
addEventListener("pointermove", (e) => {
  if (!drag) return;
  theta -= (e.clientX - drag.x) * 0.005;
  phi = Math.max(-0.15, Math.min(1.32, phi + (e.clientY - drag.y) * 0.004));
  drag = { x: e.clientX, y: e.clientY };
});
renderer.domElement.addEventListener("wheel", (e) => {
  e.preventDefault();
  if (flight.on) { flight.on = false; orbitFromCamera(); }
  dist = Math.max(11, Math.min(48, dist + e.deltaY * 0.02));
}, { passive: false });

addEventListener("resize", () => {
  camera.aspect = innerWidth / innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(innerWidth, innerHeight);
});

// ── loop ───────────────────────────────────────────────────────────────────

const clock = new THREE.Clock();

function tick() {
  requestAnimationFrame(tick);
  const dt = Math.min(clock.getDelta(), 0.05);

  // camera
  if (flight.on) {
    flight.t += dt;
    const u = ease(Math.min(1, flight.t / flight.dur));
    camPos.lerpVectors(flight.from.pos, flight.to.pos, u);
    camLook.lerpVectors(flight.from.look, flight.to.look, u);
    if (flight.t >= flight.dur) flight.on = false;
  } else if (!tour.on || drag) {
    if (spin) theta += dt * 0.085;
    const o = orbitTarget();
    const k = 1 - Math.exp(-dt * 3.2);
    camPos.lerp(o.pos, k);
    camLook.lerp(o.look, k);
  }
  camera.position.copy(camPos);
  camera.lookAt(camLook);

  // focus dimming
  for (const d of dimmables) {
    const target = inFocus(d.group) ? d.base : d.base * 0.16;
    d.mat[d.prop] += (target - d.mat[d.prop]) * Math.min(1, dt * 4);
  }

  // particles
  for (let i = live.length - 1; i >= 0; i--) {
    const p = live[i];
    p.t += dt;
    let y;
    if (!p.denied) {
      y = Y_USER + 0.4 - p.t * 9.0;
      if (y < p.bottom) { release(i); continue; }
    } else {
      // down to the hook, then thrown back — the turn IS the denial
      const fall = (Y_USER + 0.4 - Y_HOOK) / 9.0;
      if (p.t < fall) {
        y = Y_USER + 0.4 - p.t * 9.0;
      } else {
        const u = p.t - fall;
        y = Y_HOOK + u * 7.0;
        // the moment it re-enters userspace, the receipt lands on its tower
        if (!p.receipted && y >= Y_USER) {
          p.receipted = true;
          flashLabel("-EPERM · receipt", p.x, Y_USER + p.prog.h + 1.2, p.z, "receipt", 1.7);
        }
        if (y > Y_USER + 3) { release(i); continue; }
      }
    }
    p.mesh.position.y = y;
  }

  // hook-plane flashes settle back
  for (let i = ringPulse.length - 1; i >= 0; i--) {
    const r = ringPulse[i];
    r.t += dt;
    const base = r.ring.userData.dim || (r.ring.userData.dim = dimmables.find((x) => x.mat === r.ring.material));
    const rest = base ? (inFocus(base.group) ? base.base : base.base * 0.16) : r.base;
    r.ring.material.opacity = rest + Math.max(0, 0.5 - r.t * 1.4);
    if (r.t > 0.45) {
      r.ring.material.color.setHex(r.ring === hookRing ? COL.signal : COL.observe);
      ringPulse.splice(i, 1);
    }
  }

  // the ring buffer cools from red back to blue
  if (ringBufHot > 0) {
    ringBufHot = Math.max(0, ringBufHot - dt * 0.9);
    ringBuf.material.color.setHex(ringBufHot > 0.02 ? COL.deny : COL.observe);
  }

  // fired map tiles cool off
  for (const m of tiles.values()) {
    if (m.scale.y > 1.02) {
      m.scale.y += (1 - m.scale.y) * dt * 1.6;
      m.material.emissiveIntensity += (1.1 - m.material.emissiveIntensity) * dt * 1.6;
    }
  }

  drainRows();
  if (coalesced) {
    $("c-co").textContent = coalesced;
    $("co-wrap").style.display = "";
  }
  tourTick(dt);
  placeLabels(dt);
  renderer.render(scene, camera);
}
tick();

// The tour starts itself once, a beat after the stream has had a chance to
// populate the scene — a tour of an empty world explains nothing. `T` or the
// button replays it.
setTimeout(() => { if (!tour.on) tourGo(0); }, 2600);
