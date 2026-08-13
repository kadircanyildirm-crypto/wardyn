# Wardyn demo — plain scrolling table (safe fallback)
# ---------------------------------------------------------------------------
# Same run, but `--plain` forces the line printer instead of the full-screen
# TUI. The result reads exactly like the console block in README.md and never
# flickers in a GIF — use this if the TUI capture looks jittery.
#
#     sudo -v && vhs docs/demo-plain.tape    # from the repo root, in the VM
# ---------------------------------------------------------------------------

Output docs/wardyn-demo.gif
Output docs/wardyn-demo.mp4

Set Shell        "bash"
Set FontSize     20
Set FontFamily   "JetBrains Mono"
Set Width        1280
Set Height       720
Set Padding      20
Set Margin       20
Set MarginFill   "#1e1e2e"
Set BorderRadius 10
Set WindowBar    Colorful
Set Theme        "Catppuccin Mocha"
Set TypingSpeed  50ms

Type "# Wardyn: --enforce blocks .env / .ssh reads and unknown-IP egress in real time, at the syscall boundary"
Sleep 800ms
Enter
Sleep 700ms

# --plain and --enforce are global flags — both go BEFORE `run`.
Type "sudo ./target/release/wardyn --enforce --plain run -- bash scripts/demo.sh"
Sleep 500ms
Enter
Sleep 12s
