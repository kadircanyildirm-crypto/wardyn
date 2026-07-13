# Recording the demo GIF

The README references `docs/leash-demo.gif`. Record it **inside the Leash VM** (a
real terminal, so the TUI renders), then drop the file at `docs/leash-demo.gif`
and uncomment the `<img>` in `README.md`.

A good ~20s script: launch an agent-like workload under `--enforce` and let the
viewer watch `.env` / `.ssh` reads and unknown-IP connects turn red.

```bash
# in the VM, a real terminal:
sudo ./target/release/leash --enforce run -- bash scripts/demo.sh
```

## Option A — asciinema + agg (crisp, small)

```bash
sudo apt-get install -y asciinema
cargo install --git https://github.com/asciinema/agg   # or grab a release binary

asciinema rec demo.cast -c 'sudo ./target/release/leash --enforce run -- bash scripts/demo.sh'
agg --font-size 22 --theme monokai demo.cast docs/leash-demo.gif
```

## Option B — VHS (scripted, deterministic)

[charmbracelet/vhs](https://github.com/charmbracelet/vhs) renders a GIF from a
`.tape` script — reproducible, no manual timing. A starting `demo.tape`:

```tape
Output docs/leash-demo.gif
Set FontSize 22
Set Width 1200
Set Height 700
Type "sudo ./target/release/leash --enforce run -- bash scripts/demo.sh"
Enter
Sleep 10s
```

```bash
vhs demo.tape
```

Keep the GIF under ~3 MB (trim length / palette) so it loads fast on the README.
