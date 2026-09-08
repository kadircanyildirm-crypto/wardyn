# Wardyn stress suite — 01-escape
# ---------------------------------------------------------------------------
# One scenario, one recording. Run INSIDE the lab VM from the repo root, after
# `cargo build --release` and `bash scripts/stress/setup.sh`:
#
#     sudo -v && vhs docs/stress/01-escape.tape
#
# The scenario scripts are the same ones `just stress` runs; nothing here is
# staged for the camera.
# ---------------------------------------------------------------------------

Output docs/stress/wardyn-stress-escape.gif
Output docs/stress/wardyn-stress-escape.mp4

Set Shell        "bash"
Set FontSize     16
Set FontFamily   "JetBrains Mono"
Set Width        1280
Set Height       900
Set Padding      20
Set Margin       20
Set MarginFill   "#1e1e2e"
Set BorderRadius 10
Set WindowBar    Colorful
Set Theme        "Catppuccin Mocha"
Set TypingSpeed  20ms

# Fixtures off-camera: the policy blocks writing into the vault, so a run that
# built its own would be denied by the rule it is there to test.
Hide
Type "bash scripts/stress/setup.sh >/dev/null && clear"
Enter
Sleep 2s
Show

Type "# STRESS 1 — an agent trying every known way around a secret-file rule"
Sleep 700ms
Enter
Sleep 500ms

Type "sudo ./target/release/wardyn --plain --enforce --policy scripts/stress/policy.yaml --audit /tmp/stress.jsonl run -- bash scripts/stress/01-escape.sh 2>&1 | grep -E 'GOT THROUGH|read denied|setup denied|✓ allowed|BROKEN|attacks,|LEAKED'"
Sleep 500ms
Enter
Sleep 14s

# The control. Without it, "8 blocked" says nothing about WHY — a name rule that
# happened to cover the same file would look identical. Same attacks, same
# fixtures, same wardyn; the only change is `path:` (dev,ino) becoming a glob.
Type ""
Enter
Type "# and the control: the SAME attacks against name rules instead of (dev,ino)"
Sleep 700ms
Enter
Type "bash scripts/stress/setup.sh >/dev/null"
Enter
Sleep 1s
Type "sudo ./target/release/wardyn --plain --enforce --policy scripts/stress/control.yaml --audit /tmp/stress-c.jsonl run -- bash scripts/stress/01-escape.sh 2>&1 | grep -E 'GOT THROUGH|read denied|setup denied|✓ allowed|BROKEN|attacks,|LEAKED'"
Sleep 500ms
Enter
Sleep 14s
