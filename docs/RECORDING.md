# Recording the demo GIF

`docs/wardyn-demo.gif` is checked in and shown at the top of the README. This is
how to re-record it when the feed changes.

Record it **on a BPF-LSM kernel** — otherwise the file and lifecycle hooks never
attach, the `⛔BLOCK` rows for `.env` / `rm` / `touch` are absent, and the GIF
advertises enforcement the recording did not actually do. `just check-lsm` says
whether the machine qualifies; [`WSL2.md`](./WSL2.md) covers getting there on
Windows.

Two things the tapes depend on, both learned the hard way:

- **Fixtures are created off-camera** by `scripts/demo-setup.sh`. The demo policy
  blocks creating files under `~/.ssh`, so a script that made its own fixtures
  from inside the watched tree would be denied by the rule it exists to
  demonstrate — the GIF would show wardyn stopping its own setup.
- **`scripts/demo.sh` forces `LC_ALL=C`.** Every `exec` calls `setlocale`, and
  under a UTF-8 locale glibc opens ~30 files per process to find it. That is real
  activity and the feed is right to show it, but in a 20-second recording it is
  all anyone sees.

A good ~20s script: launch an agent-like workload under `--enforce` and let the
viewer watch `.env` / `.ssh` reads and unknown-IP connects turn red.

```bash
# in the VM, a real terminal:
bash scripts/demo-setup.sh
sudo ./target/release/wardyn --enforce run -- bash scripts/demo.sh
```

## Option A — asciinema + agg (crisp, small)

```bash
sudo apt-get install -y asciinema
cargo install --git https://github.com/asciinema/agg   # or grab a release binary

asciinema rec demo.cast -c 'sudo ./target/release/wardyn --enforce run -- bash scripts/demo.sh'
agg --font-size 22 --theme monokai demo.cast docs/wardyn-demo.gif
```

## Option B — VHS (scripted, deterministic) — recommended

[charmbracelet/vhs](https://github.com/charmbracelet/vhs) renders a GIF from a
`.tape` script — reproducible, no manual timing. Two ready-made tapes are
checked in:

- [`demo.tape`](./demo.tape) — the live colored **TUI** (the hero GIF).
- [`demo-plain.tape`](./demo-plain.tape) — `--plain` scrolling table; use it if
  the full-screen TUI capture looks jittery in the GIF.

Install VHS + ffmpeg, then **from the repo root, inside the VM** (after
`cargo build --release`):

```bash
# in the VM: install vhs (see charmbracelet/vhs releases)
sudo apt-get install -y ffmpeg ttyd fonts-jetbrains-mono fonts-noto-color-emoji
sudo -v && vhs docs/demo.tape        # sudo -v caches creds so the tape's
                                     # typed `sudo` never blocks on a prompt
```

VHS drives a headless Chromium, which on a minimal server image needs its usual
shared libraries (`libnss3`, `libgbm1`, `libasound2t64`, and friends) — it will
name the missing one and exit. The fonts are not optional either: without
`fonts-jetbrains-mono` the terminal falls back to a proportional face and every
character is spaced apart, and without an emoji font the `⚠` / `⛔` markers
render as empty boxes.

`sudo -v` primes sudo's credential cache (valid ~15 min) so recording is
non-interactive. If it still prompts mid-tape, add a scoped NOPASSWD rule:

```bash
echo "$USER ALL=(root) NOPASSWD: $(pwd)/target/release/wardyn" \
  | sudo tee /etc/sudoers.d/wardyn-demo
```

Each tape writes both `docs/wardyn-demo.gif` and `docs/wardyn-demo.mp4` (the mp4
is far smaller — handy for Twitter/X). Keep the GIF under ~3 MB so it loads fast
on the README; if it's over, shrink it losslessly:

```bash
gifsicle -O3 --colors 128 docs/wardyn-demo.gif -o docs/wardyn-demo.gif
```
