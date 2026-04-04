# Postcard Generator Rust

This example renders a visual postcard with plain Rust so `ebpf-tracker` can
show the full file, network, process, and output activity of one small command.
The generated HTML, SVG, and summary JSON carry the demo's product and sponsor
branding, so the artifact itself can double as a product-facing demo.

Manifest for this example:

```toml
runtime = "rust"
command = ["cargo", "run", "--quiet"]
product_name = "ebpf-tracker"
product_tagline = "Trace the full command session, then replay it."
sponsor_name = "ebpf-tracker"
sponsor_message = "Replayable syscall demos for Rust and Node."
sponsor_url = "https://github.com/givtaj/ebpf-tracker"
```

What it does:

- reads postcard content from `input/`
- reads an HTML template from `templates/`
- loads demo branding from `ebpf-demo.toml` and optional `EBPF_TRACKER_DEMO_*` environment overrides
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
- `examples/postcard-generator-rust/dist/summary.json`

Look for trace lines that show the visual workflow:

- `openat` against `input/title.txt`, `input/message.txt`, `input/palette.txt`
- `openat` against `templates/postcard.html.tpl`
- `connect` to `127.0.0.1`
- `execve` for `cargo`, the demo binary, and `date`
- `write` calls into `dist/`

The HTML preview embeds the same postcard summary JSON that is written to
`dist/summary.json`, so the rendered page and the stored artifact stay in sync.
