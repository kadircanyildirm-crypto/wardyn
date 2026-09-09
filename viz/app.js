// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The 3-D kernel view. Every mark on this scene comes from a real record in
// wardyn's `--format json` stream or from the kernel keys `--dry-run` reports;
// nothing here is generated to look busy. If the run denies nothing, nothing
// turns red.
//
// The world, from the top down:
//
//   y = +6    USERSPACE   one pillar per watched pid, grown by its own traffic
//   y =  0    the syscall boundary, a grid plane
//   y = -4    HOOKS       the tracepoint (observes) and the LSM/cgroup hook
//                         (decides) — kept apart, because that distinction is
//                         the one wardyn refuses to blur
//   y = -9    MAPS        one tile per kernel block key, lit when it fires
//
// A syscall is a particle. It falls from its pillar, crosses the boundary, and
// either passes the hook plane and continues down (allowed) or is turned around
// at it and thrown back up in red (denied).

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

const Y_USER = 6.0;   // pillar bases
const Y_BOUND = 0.0;  // syscall boundary
const Y_HOOK = -4.0;  // where a verdict is returned
const Y_MAP = -9.0;   // the block-key lattice

// ── scene ──────────────────────────────────────────────────────────────────

const scene = new THREE.Scene();
scene.background = new THREE.Color(COL.ground);
scene.fog = new THREE.Fog(COL.ground, 26, 62);

const camera = new THREE.PerspectiveCamera(46, innerWidth / innerHeight, 0.1, 200);
camera.position.set(15.5, 7.5, 18.5);
camera.lookAt(0, -1.5, 0);

const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
renderer.setSize(innerWidth, innerHeight);
$("scene").appendChild(renderer.domElement);

scene.add(new THREE.AmbientLight(0xffffff, 0.55));
const key = new THREE.DirectionalLight(0xffffff, 0.7);
key.position.set(8, 14, 10);
scene.add(key);
const under = new THREE.PointLight(COL.signal, 18, 30, 2);
under.position.set(0, Y_HOOK - 1.2, 0);
scene.add(under);

// ── the two planes that define the world ───────────────────────────────────

function plane(y, size, div, color, opacity) {
  const g = new THREE.GridHelper(size, div, color, color);
  g.position.y = y;
  g.material.transparent = true;
  g.material.opacity = opacity;
  scene.add(g);
  return g;
}

// The syscall boundary: brighter, because it is the line the whole tool is about.
plane(Y_BOUND, 30, 30, COL.wireHot, 0.42);
plane(Y_MAP - 0.02, 30, 15, COL.wire, 0.3);

// A faint slab under the boundary so "kernel" reads as a solid region.
const slab = new THREE.Mesh(
  new THREE.BoxGeometry(30, 0.06, 30),
  new THREE.MeshBasicMaterial({ color: 0x0A1018, transparent: true, opacity: 0.55 })
);
slab.position.y = Y_BOUND - 0.05;
scene.add(slab);

// ── the hook plane: two discs, observer and decider ────────────────────────

function disc(radius, y, color, opacity) {
  const m = new THREE.Mesh(
    new THREE.RingGeometry(radius * 0.62, radius, 64),
    new THREE.MeshBasicMaterial({ color, transparent: true, opacity, side: THREE.DoubleSide })
  );
  m.rotation.x = -Math.PI / 2;
  m.position.y = y;
  scene.add(m);
  return m;
}

const traceRing = disc(7.2, Y_HOOK + 1.7, COL.observe, 0.3);   // sees, cannot deny
const hookRing = disc(6.0, Y_HOOK, COL.signal, 0.42);          // decides

// ── userspace towers, one per PROGRAM ──────────────────────────────────────
//
// Not one per pid. A shell loop spawns a fresh `cat` every iteration, and a pid
// tower gives you four hundred of them in a minute — the scene became a forest
// with the kernel hidden somewhere behind it. Grouping by `comm` is bounded by
// how many distinct programs the agent actually runs, which is the thing worth
// looking at anyway: bash, cat, gcc, node.
//
// The live pid count is kept per program and shown on the label, so nothing
// about the process tree is lost by not drawing each one.

const towerGeo = new THREE.BoxGeometry(1.05, 1, 1.05);
const towerMat = new THREE.MeshStandardMaterial({
  color: 0x18222F, emissive: COL.wireHot, emissiveIntensity: 0.22,
  roughness: 0.8, metalness: 0.08,
});
const towerHot = new THREE.MeshStandardMaterial({
  color: 0x241C22, emissive: COL.deny, emissiveIntensity: 0.5,
  roughness: 0.8, metalness: 0.08,
});

const progs = new Map();   // comm -> { mesh, x, z, n, denies, pids:Set, label }
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
    p = { mesh, x, z, n: 0, denies: 0, pids: new Set(), label: null };
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
  p.mesh.scale.y = h;
  p.mesh.position.y = Y_USER + h / 2 - 0.5;
  if (p.label) {
    p.label.el.textContent = p.pids.size > 1
      ? name + " ×" + p.pids.size
      : name;
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
    const mesh = new THREE.Mesh(
      new THREE.BoxGeometry(1.7, 0.22, 1.7),
      new THREE.MeshStandardMaterial({
        color: 0x1B2A3A, emissive: COL.wireHot, emissiveIntensity: 1.1, roughness: 0.85,
      })
    );
    mesh.position.set(gx * 2.0, Y_MAP, gz * 2.0);
    scene.add(mesh);
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
  // `matched_key` arrives as `name=.env`, `ino=…`, `dir=…`; the dry-run keys use
  // the same shape, so a direct hit is the common case and a suffix match covers
  // the rest rather than inventing a mapping.
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
function makeLabel(text, x, y, z) {
  const el = document.createElement("div");
  el.className = "lbl";
  el.textContent = text;
  document.body.appendChild(el);
  const rec = { el, v: new THREE.Vector3(x, y, z) };
  labels.push(rec);
  return rec;
}

function placeLabels() {
  for (const l of labels) {
    if (!labelsOn) { l.el.style.display = "none"; continue; }
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

  if (!free.length) { coalesced += 1; return; }
  const idx = free.pop();
  const mesh = pool[idx];
  mesh.material = denied ? MAT.deny : (observed ? MAT.observe : MAT.allow);
  mesh.visible = true;
  mesh.position.set(p.x, Y_USER + 0.4, p.z);

  live.push({
    idx, mesh, x: p.x, z: p.z, t: 0, denied,
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

function onEvent(ev) {
  nEv++;
  if (ev.action === "block") { nDn++; fireKey(ev.matched_key); } else { nOk++; }
  if (ev.source === "kernel") nKn++;
  $("c-ev").textContent = nEv;
  $("c-ok").textContent = nOk;
  $("c-dn").textContent = nDn;
  $("c-kn").textContent = nKn;
  spawn(ev);
  addRow(ev);
}

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
    if (d.policy) {
      buildKeys(d.policy.keys);
      if (d.policy.summary) $("target").textContent = d.policy.summary;
    }
    (d.notices || []).forEach(notice);
  }
};

const seenNotices = new Set();
function notice(text) {
  const t = text.replace(/^wardyn:\s*/, "");
  if (seenNotices.has(t)) return;
  seenNotices.add(t);
  const box = $("notice");
  if (box.textContent === "—") box.textContent = "";
  const p = document.createElement("div");
  p.textContent = "· " + t;
  if (/WARNING|refus|could not|dropped/i.test(t)) {
    const b = document.createElement("b");
    b.textContent = "· " + t;
    p.textContent = "";
    p.appendChild(b);
  }
  box.insertBefore(p, box.firstChild);
  while (box.children.length > 14) box.removeChild(box.lastChild);
}

// ── controls ───────────────────────────────────────────────────────────────

let spin = true;
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
// a controls module.
let drag = null, theta = 0.72, phi = 0.46, dist = 31;
renderer.domElement.addEventListener("pointerdown", (e) => {
  drag = { x: e.clientX, y: e.clientY };
  spin = false;
  $("b-spin").setAttribute("aria-pressed", "false");
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

  if (spin) theta += dt * 0.085;
  camera.position.set(
    Math.cos(theta) * Math.cos(phi) * dist,
    Math.sin(phi) * dist + 1.5,
    Math.sin(theta) * Math.cos(phi) * dist
  );
  camera.lookAt(0, -2.2, 0);

  // particles
  for (let i = live.length - 1; i >= 0; i--) {
    const p = live[i];
    p.t += dt;
    let y;
    if (!p.denied) {
      y = Y_USER + 0.4 - p.t * 9.0;
      if (y < p.bottom) { release(i); continue; }
      p.mesh.material.opacity = 0.95;
    } else {
      // down to the hook, then thrown back — the turn IS the denial
      const fall = (Y_USER + 0.4 - Y_HOOK) / 9.0;
      if (p.t < fall) {
        y = Y_USER + 0.4 - p.t * 9.0;
      } else {
        const u = p.t - fall;
        y = Y_HOOK + u * 7.0;
        if (y > Y_USER + 3) { release(i); continue; }
      }
    }
    p.mesh.position.y = y;
  }

  // hook-plane flashes settle back
  for (let i = ringPulse.length - 1; i >= 0; i--) {
    const r = ringPulse[i];
    r.t += dt;
    r.ring.material.opacity = r.base + Math.max(0, 0.5 - r.t * 1.4);
    if (r.t > 0.45) {
      r.ring.material.opacity = r.base;
      r.ring.material.color.setHex(r.ring === hookRing ? COL.signal : COL.observe);
      ringPulse.splice(i, 1);
    }
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
  placeLabels();
  renderer.render(scene, camera);
}
tick();
