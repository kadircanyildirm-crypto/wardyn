# Wardyn demo — live TUI (the "hero" GIF)
# ---------------------------------------------------------------------------
# Reproducible README GIF via charmbracelet/vhs. Run INSIDE the Wardyn VM,
# from the REPO ROOT, after `cargo build --release`:
#
#     sudo -v && vhs docs/demo.tape          # sudo -v caches creds so the
#                                            # typed `sudo` below never prompts
#
# Output lands at docs/wardyn-demo.gif (+ .mp4 for Twitter/X). Keep the GIF
# under ~3 MB — see the gifsicle note at the bottom.
# ---------------------------------------------------------------------------

Output docs/wardyn-demo.gif
Output docs/wardyn-demo.mp4

# ── look & feel ────────────────────────────────────────────────────────────
Set Shell        "bash"
Set FontSize     20
Set FontFamily   "JetBrains Mono"   # VHS's bundled default; falls back if absent
Set Width        1280
Set Height       760
Set Padding      20
Set Margin       20
Set MarginFill   "#1e1e2e"          # framed backdrop (Catppuccin base)
Set BorderRadius 10
Set WindowBar    Colorful           # fake macOS title bar — delete for a bare term
Set Theme        "Catppuccin Mocha" # good reds for the ⛔BLOCK lines
Set TypingSpeed  50ms

# ── scene 1 · set the stage ───────────────────────────────────────────────
Type "# Wardyn: run an agent-like workload under --enforce, watch secret reads & unknown egress get BLOCKED"
Sleep 800ms
Enter
Sleep 700ms

# ── scene 2 · launch it ───────────────────────────────────────────────────
Type "sudo ./target/release/wardyn --enforce run -- bash scripts/demo.sh"
Sleep 500ms
Enter

# ── scene 3 · let the live feed stream allow / warn / ⛔BLOCK ──────────────
# demo.sh loops ~9s then exits; Wardyn auto-quits and prints its summary line.
# Overshoot a little so the final "N policy violation(s)" frame is captured.
Sleep 12s
