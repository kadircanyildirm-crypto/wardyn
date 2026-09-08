# Wardyn containment demo — `allow_paths:` confining an agent to one project.
#
# The second GIF, kept separate from docs/demo.tape rather than appended to it:
# the two show different SHAPES. That one is a blocklist denying named objects;
# this one is a boundary, and the interesting frame is a directory the agent
# cannot enter for no reason other than that nobody listed it.
#
#     sudo -v && vhs docs/demo-contained.tape
#
# Output: docs/wardyn-contained.gif (+ .mp4). See docs/RECORDING.md.

Output docs/wardyn-contained.gif
Output docs/wardyn-contained.mp4

Set Shell        "bash"
# 18 for the same reason as the other tape: at 20 the header's counters fall off
# the right edge.
Set FontSize     18
Set FontFamily   "JetBrains Mono"
Set Width        1280
Set Height       760
Set Padding      20
Set Margin       20
Set MarginFill   "#1e1e2e"
Set BorderRadius 10
Set WindowBar    Colorful
Set Theme        "Catppuccin Mocha"
Set TypingSpeed  25ms

# Fixtures off-camera. They have to be: under `allow_paths:` the agent can only
# read what the policy grants, and that includes its own script.
Hide
Type "bash scripts/demo-setup.sh"
Enter
Sleep 2s
Type "clear"
Enter
Show

Type "# allow_paths: the agent reaches ONE project directory. Everything else is not blocked — it is unreachable."
Sleep 800ms
Enter
Sleep 700ms

Type "sudo ./target/release/wardyn --enforce --policy /tmp/wardyn-demo-contained.yaml run -- bash ~/wardyn-demo/project/demo-contained.sh"
Sleep 500ms
Enter

# demo-contained.sh loops 4× with a 2s pause, so the BLOCK rows rest on screen
# long enough to read which hierarchy each one fell outside of.
Sleep 18s
