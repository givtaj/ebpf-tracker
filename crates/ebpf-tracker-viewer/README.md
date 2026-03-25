# ebpf-tracker-viewer

Viewer crate for `ebpf-tracker`.

This crate owns the live matrix dashboard and replay viewer assets. The root
CLI launches it for `--dashboard`, and it can also be run directly to replay
stored JSONL or mixed trace logs:

```bash
cargo run -p ebpf-tracker-viewer -- --replay logs/ebpf-tracker-YYYYMMDD-HHMMSS.log
```

The intended model is Wireshark-like trace review:

- a live producer emits JSONL syscall events
- demo manifests can inject typed `session` records with product/sponsor branding
- dashboard mode keeps a stored session log for later analysis
- replay mode can restart, pause, step, move backward, and move forward through
  the recorded stream while rebuilding viewer state from the log

Today the viewer is still a Node-hosted dashboard asset. The workspace boundary
is now explicit, though: viewer behavior belongs in this crate rather than in
the root CLI package.
