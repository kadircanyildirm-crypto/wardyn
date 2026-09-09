#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Serve the 3-D kernel view, fed by a real wardyn run.

There is no simulation here. The page is driven by wardyn's own
`--format json` stream — the same records that go to the audit log — and by the
kernel keys `--dry-run` reports, which are the keys actually loaded into the BPF
maps. If the kernel denies nothing, the page shows nothing being denied.

    sudo python3 viz/serve.py -- bash scripts/stress/01-escape.sh
    sudo python3 viz/serve.py --policy policies/strict.yaml -- npm install
    python3 viz/serve.py --replay /tmp/wardyn-audit.jsonl        # no root needed

Then open http://localhost:8787 (works from Windows too — WSL2 forwards it).

Root is needed for the live mode because wardyn needs it to load eBPF. `--replay`
reads a JSONL file that was captured earlier and needs nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# Every connected browser gets its own queue; the reader thread fans out to all
# of them. A slow tab drops its own events rather than stalling the run — the
# same trade wardyn makes with its ring buffer, and worth being explicit about.
CLIENTS: list[queue.Queue] = []
CLIENTS_LOCK = threading.Lock()
STATE: dict = {"policy": None, "notices": [], "meta": {}, "dropped": 0}

# A short tail of what already happened, replayed to a browser that connects
# mid-run. Without it, opening the page a second after the agent started shows
# an empty scene and a zero counter — which reads as "wardyn saw nothing", the
# one thing this page must never say by accident.
from collections import deque

HISTORY: deque = deque(maxlen=400)


def broadcast(obj: dict) -> None:
    payload = json.dumps(obj, separators=(",", ":"))
    if obj.get("kind") == "event":
        HISTORY.append(payload)
    with CLIENTS_LOCK:
        for q in CLIENTS:
            try:
                q.put_nowait(payload)
            except queue.Full:
                STATE["dropped"] += 1


def read_policy(policy: str | None, wardyn: str) -> dict:
    """The kernel keys this policy really compiles to, straight from --dry-run.

    Parsed rather than re-derived: re-implementing the reduction here would give
    the page a second opinion about what the kernel holds, and a visualisation
    that disagrees with the tool is worse than no visualisation.
    """
    cmd = [wardyn, "--dry-run"]
    if policy:
        cmd += ["--policy", policy]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=ROOT)
    except (OSError, subprocess.SubprocessError) as e:
        return {"error": str(e), "keys": []}

    keys, fingerprint, summary = [], None, None
    for line in out.stdout.splitlines():
        s = line.strip()
        if s.startswith("policy:"):
            summary = s[len("policy:"):].strip()
        elif s.startswith("fingerprint:"):
            fingerprint = s.split()[1]
        # `  file  name=.env    denies opening ANY file named `.env`` and friends
        elif ("  " in s) and ("=" in s.split()[1] if len(s.split()) > 1 else False):
            parts = s.split(None, 2)
            if len(parts) >= 2 and parts[0] in ("file", "exec", "net"):
                kind, key = parts[0], parts[1]
                keys.append({"axis": kind, "key": key, "why": parts[2] if len(parts) > 2 else ""})
    return {
        "keys": keys,
        "fingerprint": fingerprint,
        "summary": summary,
        "stderr": out.stderr[-2000:] if out.returncode else "",
    }


def pump(stream, is_stderr: bool) -> None:
    """One line at a time, forever. Notices go to the page as their own kind."""
    for raw in iter(stream.readline, ""):
        line = raw.rstrip("\n")
        if not line:
            continue
        if is_stderr:
            STATE["notices"].append(line)
            broadcast({"kind": "notice", "text": line})
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            broadcast({"kind": "notice", "text": line})
            continue
        if obj.get("wardyn") == "event-stream":
            STATE["meta"] = obj
            broadcast({"kind": "meta", "meta": obj})
        else:
            broadcast({"kind": "event", "event": obj})
    stream.close()


def start_live(wardyn: str, policy: str | None, audit: str, argv: list[str]) -> subprocess.Popen:
    if os.geteuid() != 0:
        sys.exit("live mode needs root (wardyn loads eBPF). Use --replay for a captured file.")
    # Only one wardyn can hold the cgroup egress programs at a time
    # (`CgroupAttachMode::Single`), and the second one's failure to attach reads
    # as an unrelated error several lines later. Check before starting.
    try:
        other = subprocess.run(["pgrep", "-x", "wardyn"], capture_output=True, text=True)
        if other.returncode == 0 and other.stdout.strip():
            sys.exit("another wardyn is already running (pid "
                     + other.stdout.split()[0]
                     + ") — only one can hold the cgroup programs. Stop it first.")
    except FileNotFoundError:
        pass
    cmd = [wardyn, "--format", "json", "--enforce", "--audit", audit]
    if policy:
        cmd += ["--policy", policy]
    cmd += ["run", "--"] + argv
    print("running:", " ".join(cmd), flush=True)
    p = subprocess.Popen(
        cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    threading.Thread(target=pump, args=(p.stdout, False), daemon=True).start()
    threading.Thread(target=pump, args=(p.stderr, True), daemon=True).start()
    return p


def start_replay(path: str, speed: float) -> None:
    """Re-run a captured JSONL at wall-clock pace, so the page can be shown
    without root and without re-running an agent."""
    import time

    def run():
        prev = None
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as e:
            # The audit log is deliberately root-owned and 0600 — a security
            # record a second party can edit is not a record. So replaying one
            # as an ordinary user is *expected* to fail, and saying which file
            # and why beats a traceback in a log nobody reads.
            msg = f"cannot replay {path}: {e.strerror}."
            if isinstance(e, PermissionError):
                msg += (" wardyn's audit log is root-owned and 0600 on purpose."
                        " Run this with sudo, or copy the file somewhere readable first.")
            print(msg, file=sys.stderr, flush=True)
            broadcast({"kind": "notice", "text": msg})
            return
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = obj.get("ts")
                if prev and ts and speed > 0:
                    try:
                        from datetime import datetime
                        a = datetime.fromisoformat(prev.replace("Z", "+00:00"))
                        b = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        gap = (b - a).total_seconds() / speed
                        time.sleep(min(max(gap, 0.0), 1.5))
                    except ValueError:
                        pass
                prev = ts or prev
                broadcast({"kind": "event", "event": obj})
        broadcast({"kind": "notice", "text": "replay finished: " + path})

    threading.Thread(target=run, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A003 - quiet by default
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]

        if path == "/stream":
            q: queue.Queue = queue.Queue(maxsize=4000)
            with CLIENTS_LOCK:
                CLIENTS.append(q)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                boot = {"kind": "boot", "policy": STATE["policy"],
                        "meta": STATE["meta"], "notices": STATE["notices"][-40:],
                        "replayed": len(HISTORY)}
                self.wfile.write(b"data: " + json.dumps(boot).encode() + b"\n\n")
                # Catch the newcomer up before joining it to the live fan-out.
                for past in list(HISTORY):
                    self.wfile.write(b"data: " + past.encode() + b"\n\n")
                self.wfile.flush()
                while True:
                    try:
                        item = q.get(timeout=15)
                        self.wfile.write(b"data: " + item.encode() + b"\n\n")
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with CLIENTS_LOCK:
                    if q in CLIENTS:
                        CLIENTS.remove(q)
            return

        rel = "index.html" if path == "/" else path.lstrip("/")
        target = (HERE / rel).resolve()
        if HERE not in target.parents and target != HERE:
            self._send(403, b"forbidden", "text/plain")
            return
        if not target.is_file():
            self._send(404, b"not found", "text/plain")
            return
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
        }.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--policy", default=None)
    ap.add_argument("--audit", default="/tmp/wardyn-viz.jsonl")
    ap.add_argument("--replay", default=None, help="a captured JSONL, instead of a live run")
    ap.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier")
    ap.add_argument("--wardyn", default=str(ROOT / "target/release/wardyn"))
    ap.add_argument("argv", nargs="*", help="the command to watch, after --")
    args = ap.parse_args()

    if not args.replay and not shutil.which(args.wardyn) and not Path(args.wardyn).is_file():
        return int(bool(sys.stderr.write(
            f"no wardyn binary at {args.wardyn} — `cargo build --release` first\n")))

    STATE["policy"] = read_policy(args.policy, args.wardyn) if Path(args.wardyn).is_file() else None

    child = None
    if args.replay:
        start_replay(args.replay, args.speed)
    else:
        if not args.argv:
            return int(bool(sys.stderr.write("nothing to watch — pass a command after --\n")))
        child = start_live(args.wardyn, args.policy, args.audit, args.argv)

    ThreadingHTTPServer.allow_reuse_address = True
    try:
        srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    except OSError as e:
        sys.stderr.write(
            f"port {args.port} is busy ({e}) — another viz server is probably still up.\n"
            f"  fuser -k {args.port}/tcp   # or pick another --port\n"
        )
        return 1
    srv.daemon_threads = True
    print(f"kernel view on http://localhost:{args.port}", flush=True)

    def bye(*_):
        # `shutdown()` blocks until `serve_forever()` returns, and a signal
        # handler runs ON the main thread — the one sitting inside
        # `serve_forever()`. Calling it directly deadlocks, which is exactly how
        # this server survived every SIGTERM sent at it and went on holding the
        # port after its wardyn child had died. Hand it to another thread.
        if child and child.poll() is None:
            child.terminate()
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, bye)
    signal.signal(signal.SIGTERM, bye)
    try:
        srv.serve_forever()
    finally:
        if child and child.poll() is None:
            child.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
