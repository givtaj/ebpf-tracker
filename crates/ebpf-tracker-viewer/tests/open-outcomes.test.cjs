const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const {
  createState, handleTraceRecord, buildSnapshot, clearTraceState, openOutcome, renderHtml
} = require("../assets/live-trace-matrix.js");

function open(fields = {}) {
  return { type: "syscall", kind: "open_at", timestamp_unix_ms: 100, pid: 42,
    comm: "axum-fixture", file: "/data/template.txt", ...fields };
}

function record(state, event) {
  handleTraceRecord(event, state, { broadcast: false });
}

test("open results distinguish success, named failure, and unobserved or invalid outcomes", () => {
  const state = createState();
  const known = [
    open({ return_value: -2, errno: 2 }),
    open({ return_value: -13, errno: 13 }),
    open({ return_value: 0, errno: 0 }),
    open({ return_value: 5, errno: 0 })
  ];
  const unknown = [
    open(), open({ return_value: 3 }), open({ errno: 2 }),
    open({ return_value: -2, errno: 0 }), open({ return_value: 3, errno: 2 }),
    open({ return_value: "3", errno: 0 }), open({ return_value: null, errno: null }),
    open({ return_value: 0.5, errno: 0 })
  ];
  [...known, ...unknown].forEach(event => record(state, event));
  const snapshot = buildSnapshot(state);
  assert.deepEqual(snapshot.openOutcomes, { succeeded: 2, failed: 2, unknown: 8 });
  assert.match(snapshot.recentOpenFailures[0].open_outcome.label, /EACCES \(13\): Permission denied/);
  assert.match(snapshot.recentOpenFailures[1].text, /ENOENT \(2\): No such file or directory/);
  assert.match(openOutcome(known[2]).label, /opened \(fd 0\)/);
  for (const event of unknown) assert.equal(openOutcome(event).status, "unknown");
  assert.match(openOutcome(open({ return_value: -122, errno: 122 })).label, /errno 122/);
});

test("failure evidence survives subsequent activity, stays bounded, and resets on rewind", () => {
  const state = createState();
  record(state, open({ return_value: -2, errno: 2, file: "/data/missing-template.txt" }));
  for (let i = 0; i < 250; i++) {
    record(state, { type: "syscall", kind: "write", comm: "axum-fixture", pid: 42, bytes: 4 });
  }
  assert.equal(buildSnapshot(state).recentEvents.some(event => event.kind === "open_at"), false);
  assert.equal(buildSnapshot(state).recentOpenFailures[0].file, "/data/missing-template.txt");
  for (let i = 0; i < 40; i++) {
    record(state, open({ file: `/data/missing-${i}`, return_value: -2, errno: 2 }));
  }
  const snapshot = buildSnapshot(state);
  assert.equal(snapshot.openOutcomes.failed, 41);
  assert.equal(snapshot.recentOpenFailures.length, 32);
  assert.equal(snapshot.recentOpenFailures[0].file, "/data/missing-39");
  clearTraceState(state);
  assert.deepEqual(buildSnapshot(state).openOutcomes, { succeeded: 0, failed: 0, unknown: 0 });
  assert.deepEqual(buildSnapshot(state).recentOpenFailures, []);
});

// Execute the actual inline UI script with a minimal DOM surface. This checks
// the rendered failure evidence and escaping without a browser dependency.
function browser() {
  const elements = new Map();
  const callbacks = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      innerHTML: "", textContent: "", value: "1", style: { setProperty() {} },
      classList: { toggle() {} }, addEventListener() {}, setAttribute() {}, removeAttribute() {},
      querySelector() { return null; }, getContext() { return { setTransform() {}, clearRect() {} }; }
    });
    return elements.get(id);
  }
  const context = vm.createContext({
    document: { getElementById: element },
    window: { innerWidth: 1024, innerHeight: 768, devicePixelRatio: 1, addEventListener() {},
      matchMedia() { return { matches: true, addEventListener() {} }; } },
    EventSource: class { addEventListener(name, handler) { callbacks.set(name, handler); } },
    requestAnimationFrame() {}, console
  });
  const script = renderHtml().match(/<script>([\s\S]*?)<\/script>/)[1];
  vm.runInContext(script, context);
  return { element, show(snapshot) { callbacks.get("snapshot")({ data: JSON.stringify(snapshot) }); } };
}

test("replay UI shows full path, process, error, legacy unknown count and escaped untrusted text", () => {
  const state = createState();
  const maliciousPath = '/data/<img src=x onerror="alert(1)">.txt';
  record(state, open({ file: maliciousPath, comm: '<script>alert(2)</script>', return_value: -2, errno: 2 }));
  record(state, open({ return_value: 0, errno: 0 }));
  record(state, open());
  const ui = browser();
  ui.show(buildSnapshot(state));
  const failures = ui.element("open-failures").innerHTML;
  assert.match(failures, /ENOENT \(2\): No such file or directory/);
  assert.match(failures, /pid 42/);
  assert.match(failures, /return -2/);
  assert.match(failures, /No such file or directory<br>&lt;script&gt;alert\(2\)&lt;\/script&gt; pid 42/);
  assert.match(failures, /class="open-failure-detail"/);
  assert.match(renderHtml(), /#open-failures \.open-failure-detail\s*\{\s*min-width: 0;\s*overflow-wrap: anywhere;/);
  assert.ok(failures.includes('/data/&lt;img src=x onerror=&quot;alert(1)&quot;&gt;.txt'));
  assert.ok(failures.includes('&lt;script&gt;alert(2)&lt;/script&gt;'));
  assert.equal(failures.includes("<img"), false);
  assert.equal(failures.includes("<script"), false);
  assert.equal(ui.element("open-outcome-summary").textContent, "1 failed · 1 succeeded · 1 outcome unknown");
  assert.match(ui.element("recent-events").innerHTML, /attempt \(outcome unknown\)/);
  clearTraceState(state);
  record(state, open());
  ui.show(buildSnapshot(state));
  assert.equal(ui.element("open-outcome-summary").textContent, "0 failed · 0 succeeded · 1 outcome unknown");
  assert.match(ui.element("open-failures").innerHTML, /unknown outcomes are not counted as successful/);
});

test("session journey never turns a failed or unknown open into a read", () => {
  const ui = browser();
  for (const [fields, expected] of [
    [{ return_value: -2, errno: 2 }, /failed: ENOENT \(2\)/],
    [{ return_value: 7, errno: 0 }, /opened \(fd 7\)/],
    [{}, /attempt: unknown/],
  ]) {
    const state = createState();
    record(state, open({ file: "/data/templates/input.txt", ...fields }));
    ui.show(buildSnapshot(state));
    const journey = ui.element("trace-map").innerHTML;
    assert.match(journey, expected);
    assert.doesNotMatch(journey, /template read|input read|artifact open/);
    assert.match(ui.element("story-signal-detail").textContent, /open attempts/);
  }
  const state = createState();
  record(state, open({ file: "/data/result.html", return_value: -2, errno: 2 }));
  ui.show(buildSnapshot(state));
  assert.match(ui.element("story-outcome-detail").textContent, /creation is not established/);
});
