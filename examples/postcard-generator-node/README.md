# Postcard Generator Node

This example mirrors the Rust postcard demo with plain Node.js so you can trace
the same visible workflow in a separate runtime.
Like the Rust version, the generated HTML, SVG, and summary JSON carry the
demo's product and sponsor branding so the visible artifact still advertises
the product after the trace is over.

Manifest for this example:

```toml
runtime = "node"
command = ["npm", "run", "generate"]
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
cargo demo postcard-generator-node
```

Machine-readable trace stream:

```bash
cargo demo --emit jsonl postcard-generator-node
```

After the run, open:

- `examples/postcard-generator-node/dist/postcard.html`
- `examples/postcard-generator-node/dist/postcard.svg`
- `examples/postcard-generator-node/dist/summary.json`

Look for trace lines that show the visual workflow:

- `openat` against `package.json`, `input/*`, and `templates/postcard.html.tpl`
- `connect` to `127.0.0.1`
- `execve` for `npm`, `node`, and `date`
- `write` calls into `dist/`

The HTML preview embeds the same postcard summary JSON that is written to
`dist/summary.json`, so the rendered page and the stored artifact stay in sync.
