# Wardyn stress suite — 04-realwork
# ---------------------------------------------------------------------------
# One scenario, one recording. Run INSIDE the lab VM from the repo root, after
# `cargo build --release` and `bash scripts/stress/setup.sh`:
#
#     sudo -v && vhs docs/stress/04-realwork.tape
#
# The scenario scripts are the same ones `just stress` runs; nothing here is
# staged for the camera.
# ---------------------------------------------------------------------------

Output docs/stress/wardyn-stress-realwork.gif
Output docs/stress/wardyn-stress-realwork.mp4

Set Shell        "bash"
Set FontSize     16
Set FontFamily   "JetBrains Mono"
Set Width        1280
Set Height       800
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

Type "# STRESS 4 — git, gcc, make, python: does real work still happen?"
Sleep 700ms
Enter
Sleep 500ms

Type "sudo ./target/release/wardyn --plain --enforce --policy scripts/stress/policy.yaml --audit /tmp/stress.jsonl run -- bash scripts/stress/04-realwork.sh 2>&1 | grep -E '── |✓|✗|∼|ordinary|skipped|wardyn: (kernel denials|WARNING|[0-9]+ (policy|denial)|[0-9]+ of those)'"
Sleep 500ms
Enter
Sleep 38s
