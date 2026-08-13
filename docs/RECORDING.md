# Recording the demo GIF

The README references `docs/wardyn-demo.gif`. Record it **inside the Wardyn VM** (a
real terminal, so the TUI renders), then drop the file at `docs/wardyn-demo.gif`
and uncomment the `<img>` in `README.md`.

A good ~20s script: launch an agent-like workload under `--enforce` and let the
viewer watch `.env` / `.ssh` reads and unknown-IP connects turn red.

```bash
# in the VM, a real terminal:
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
# in the VM: install vhs (see charmbracelet/vhs releases) + ffmpeg
sudo -v && vhs docs/demo.tape        # sudo -v caches creds so the tape's
                                     # typed `sudo` never blocks on a prompt
```

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
