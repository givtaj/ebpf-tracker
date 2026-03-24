# Postcard Generator Rust

This example renders a visual postcard with plain Rust so `eBPF_tracker` can
show the full file, network, process, and output activity of one small command.

What it does:

- reads postcard content from `input/`
- reads an HTML template from `templates/`
- opens a loopback TCP connection to a local "stamp office"
- spawns `date -u` to stamp the postcard with a visible timestamp
- writes `dist/postcard.svg`, `dist/postcard.html`, and `dist/summary.json`

Run it from the repo root:

```bash
cargo demo postcard-generator-rust
```

Machine-readable trace stream:

```bash
cargo demo --emit jsonl postcard-generator-rust
```

After the run, open:

- `examples/postcard-generator-rust/dist/postcard.html`
- `examples/postcard-generator-rust/dist/postcard.svg`

Look for trace lines that show the visual workflow:

- `openat` against `input/title.txt`, `input/message.txt`, `input/palette.txt`
- `openat` against `templates/postcard.html.tpl`
- `connect` to `127.0.0.1`
- `execve` for `cargo`, the demo binary, and `date`
- `write` calls into `dist/`
