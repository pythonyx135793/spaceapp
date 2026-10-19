import assert from "node:assert/strict";
import test from "node:test";
import { NATIVE_TOOLCHAIN_VERSIONS, observeNativeToolchain, validateNativeToolchain, nativeEngineIdentity, nativeEngineResources, nativeEngineStorageFacts, validateNativeEngineInfo } from "./native-host-prereqs.mjs";

const GIB = 1024 ** 3;
const expected = { version: "6.1.4", commit: "464c15fec06f0074c916f9eff87c4806869c2833", runtime: "/usr/sbin/runc", required: { cpuCount: 4, memoryBytes: 7 * GIB } };
// Version, paths, security booleans and controllers follow the retained original
// run's allowlisted observations. CPU/RAM are explicit synthetic boundary data:
// the original guard short-circuited and did not export its real CPU/RAM values.
const info = () => ({ version: { Version: expected.version, GitCommit: expected.commit },
  host: { security: { rootless: true, seccompEnabled: true, apparmorEnabled: false, selinuxEnabled: false },
    cgroupVersion: "v2", cgroupManager: "systemd", cgroupControllers: ["cpu", "memory", "pids"],
    ociRuntime: { path: expected.runtime }, cpus: 4, memTotal: 7 * GIB },
  store: { graphRoot: "/home/runner/.local/share/containers/storage", runRoot: "/run/user/1001/containers",
    graphDriverName: "overlay", graphStatus: { "Backing Filesystem": "extfs", "Native Overlay Diff": "true", "Supports d_type": "true" }, graphOptions: {} } });

test("required rootless false-AppArmor info and unchanged numeric boundaries pass the pure CI predicate", () => {
  validateNativeEngineInfo(info(), info(), expected);
});

test("the old positive AppArmor conjunct contradicts that same rootless info", () => {
  const local = info();
  const oldPredicate = local.host.security.seccompEnabled === true && local.host.security.apparmorEnabled === true && local.host.cpus >= expected.required.cpuCount && local.host.memTotal >= expected.required.memoryBytes;
  assert.equal(oldPredicate, false);
  validateNativeEngineInfo(local, info(), expected);
});

test("controller enumeration order and additional delegated controllers are not identity", () => {
  const api = info(); api.host.cgroupControllers = ["memory", "pids", "cpu", "io"];
  validateNativeEngineInfo(info(), api, expected);
});

for (const [name, change] of [
  ["different version", (x) => { x.version.Version = "6.1.5"; }],
  ["different commit", (x) => { x.version.GitCommit = "0".repeat(40); }],
  ["unknown version", (x) => { delete x.version.Version; }],
  ["unknown commit", (x) => { delete x.version.GitCommit; }],
  ["different graphroot", (x) => { x.store.graphRoot += "-other"; }],
  ["different runroot", (x) => { x.store.runRoot += "-other"; }],
  ["different OCI runtime", (x) => { x.host.ociRuntime.path = "/usr/bin/crun"; }],
  ["different cgroup version", (x) => { x.host.cgroupVersion = "v1"; }],
  ["different cgroup manager", (x) => { x.host.cgroupManager = "cgroupfs"; }],
  ["rootful context", (x) => { x.host.security.rootless = false; }],
  ["unknown rootless context", (x) => { delete x.host.security.rootless; }],
  ["missing host", (x) => { delete x.host; }],
  ["missing security", (x) => { delete x.host.security; }]
]) test(`native/API identity refuses ${name}`, () => {
  const api = info(); change(api);
  assert.throws(() => validateNativeEngineInfo(info(), api, expected), /Native CLI\/API/);
});

for (const [name, change] of [
  ["both unreviewed versions", (x) => { x.version.Version = "6.1.5"; }],
  ["both unreviewed commits", (x) => { x.version.GitCommit = "0".repeat(40); }],
  ["both unreviewed runtimes", (x) => { x.host.ociRuntime.path = "/usr/bin/crun"; }],
  ["both rootful", (x) => { x.host.security.rootless = false; }],
  ["both string-valued rootless", (x) => { x.host.security.rootless = "true"; }]
]) test(`matching native/API values do not excuse ${name}`, () => {
  const local = info(), api = info(); change(local); change(api);
  assert.throws(() => validateNativeEngineInfo(local, api, expected), /Native CLI\/API/);
});

for (const side of ["native", "api"]) for (const [name, change, message] of [
  ["disabled seccomp", (x) => { x.host.security.seccompEnabled = false; }, /security prerequisites/],
  ["unknown seccomp", (x) => { delete x.host.security.seccompEnabled; }, /security prerequisites/],
  ["string seccomp", (x) => { x.host.security.seccompEnabled = "true"; }, /security prerequisites/],
  ["inconsistent AppArmor true", (x) => { x.host.security.apparmorEnabled = true; }, /security prerequisites/],
  ["unknown AppArmor", (x) => { delete x.host.security.apparmorEnabled; }, /security prerequisites/],
  ["string AppArmor false", (x) => { x.host.security.apparmorEnabled = "false"; }, /security prerequisites/],
  ["missing memory controller", (x) => { x.host.cgroupControllers = ["cpu"]; }, /controllers/],
  ["missing CPU controller", (x) => { x.host.cgroupControllers = ["memory"]; }, /controllers/],
  ["unknown controllers", (x) => { delete x.host.cgroupControllers; }, /controllers/],
  ["CPU below small", (x) => { x.host.cpus = 3; }, /CPU\/memory/],
  ["RAM below small", (x) => { x.host.memTotal--; }, /CPU\/memory/],
  ["unknown CPU", (x) => { delete x.host.cpus; }, /CPU\/memory/],
  ["unknown RAM", (x) => { delete x.host.memTotal; }, /CPU\/memory/],
  ["string CPU", (x) => { x.host.cpus = "4"; }, /CPU\/memory/],
  ["nonfinite RAM", (x) => { x.host.memTotal = Infinity; }, /CPU\/memory/]
]) test(`${side} refuses ${name}`, () => {
  const local = info(), api = info(); change(side === "native" ? local : api);
  assert.throws(() => validateNativeEngineInfo(local, api, expected), message);
});

test("identity projection preserves exactly the existing version/store/runtime identity keys", () => {
  assert.deepEqual(Object.keys(nativeEngineIdentity(info())), ["version", "commit", "rootless", "cgroupVersion", "cgroupManager", "graphRoot", "runRoot", "runtime"]);
});

test("numeric observations are bounded JSON numbers and retain missing as unknown", () => {
  assert.deepEqual(nativeEngineResources(info()), { cpuCount: 4, memoryBytes: 7 * GIB });
  assert.deepEqual(nativeEngineResources(undefined), { cpuCount: null, memoryBytes: null });
  for (const invalid of [undefined, null, "4", -1, 0.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
    const value = info(); value.host.cpus = value.host.memTotal = invalid;
    assert.deepEqual(nativeEngineResources(value), { cpuCount: null, memoryBytes: null });
  }
  const value = info(); value.host.cpus = value.host.memTotal = 0;
  assert.deepEqual(nativeEngineResources(value), { cpuCount: 0, memoryBytes: 0 });
  assert.throws(() => validateNativeEngineInfo(value, info(), expected), /CPU\/memory/);
});

test("storage observations retain false feature results without declaring storage accepted", () => {
  const value = info(); value.store.graphStatus["Native Overlay Diff"] = "false";
  value.store.graphOptions = { "overlay.mount_program": { Executable: "/private/NOT_FOR_EXPORT" }, "overlay.ignore_chown_errors": "true" };
  const facts = nativeEngineStorageFacts(value);
  assert.equal(facts.nativeOverlayDiff, "false"); assert.equal(facts.hasMountProgramOption, true); assert.equal(facts.hasIgnoredChownErrors, true);
  assert.ok(!JSON.stringify(facts).includes("NOT_FOR_EXPORT"));
});

test("unknown storage values export null without leaking arbitrary text", () => {
  const value = info(); value.store.graphDriverName = value.store.graphStatus["Backing Filesystem"] = value.store.graphStatus["Native Overlay Diff"] = value.store.graphStatus["Supports d_type"] = "PRIVATE_SENTINEL";
  const facts = nativeEngineStorageFacts(value);
  assert.deepEqual(facts, { driver: null, backingFilesystem: null, nativeOverlayDiff: null, supportsDType: null, hasMountProgramOption: false, hasIgnoredChownErrors: false });
  assert.ok(!JSON.stringify(facts).includes("PRIVATE_SENTINEL"));
});

// Go/Rust text is copied from original C19 artifact12213478944. Cargo was not
// invoked there: its full line below is synthetic, using only the reviewed
// image's published exact version. These are predicate/ordering controls.
const toolchain = () => ({ go: "go version go1.26.9 linux/amd64",
  rustc: "rustc 1.99.1 (58cf8f9c3 2026-10-13)", cargo: "cargo 1.99.1 (synthetic-image-version-control)" });

test("toolchain exact reviewed compiler pair and unchanged Go pin pass", () => {
  assert.deepEqual(NATIVE_TOOLCHAIN_VERSIONS, { go: "go1.26.9", rustc: "1.99.1", cargo: "1.99.1" });
  assert.equal(Object.isFrozen(NATIVE_TOOLCHAIN_VERSIONS), true);
  validateNativeToolchain(toolchain());
});

for (const [name, change, message] of [
  ["old rustc", (x) => { x.rustc = "rustc 1.99.0 (old)"; }, /rustc1\.99\.1/],
  ["old cargo", (x) => { x.cargo = "cargo 1.99.0 (old)"; }, /cargo1\.99\.1/],
  ["future rustc patch", (x) => { x.rustc = "rustc 1.99.2 (unreviewed)"; }, /rustc1\.99\.1/],
  ["future cargo minor", (x) => { x.cargo = "cargo 1.100.0 (unreviewed)"; }, /cargo1\.99\.1/],
  ["rustc nightly", (x) => { x.rustc = "rustc 1.99.1-nightly (unreviewed)"; }, /rustc1\.99\.1/],
  ["cargo nightly", (x) => { x.cargo = "cargo 1.99.1-nightly (unreviewed)"; }, /cargo1\.99\.1/],
  ["rustc substring match", (x) => { x.rustc = "rustc 1.99.10 (unreviewed)"; }, /rustc1\.99\.1/],
  ["wrong rustc identity", (x) => { x.rustc = "cargo 1.99.1 (wrong tool)"; }, /rustc1\.99\.1/],
  ["wrong cargo identity", (x) => { x.cargo = "rustc 1.99.1 (wrong tool)"; }, /cargo1\.99\.1/],
  ["unknown cargo", (x) => { delete x.cargo; }, /cargo1\.99\.1/],
  ["unknown rustc", (x) => { delete x.rustc; }, /rustc1\.99\.1/],
  ["empty cargo", (x) => { x.cargo = ""; }, /cargo1\.99\.1/],
  ["nontext cargo", (x) => { x.cargo = 1.99; }, /cargo1\.99\.1/],
  ["old Go", (x) => { x.go = "go version go1.26.8 linux/amd64"; }, /Go1\.26\.9/],
  ["wrong Go identity", (x) => { x.go = "cargo version go1.26.9 linux/amd64"; }, /Go1\.26\.9/],
  ["unknown Go", (x) => { delete x.go; }, /Go1\.26\.9/]
]) test(`toolchain refuses ${name} without ranges or fallback`, () => {
  const facts = toolchain(); change(facts);
  assert.throws(() => validateNativeToolchain(facts), message);
});

test("toolchain absent version facts stay rejected", () => {
  assert.throws(() => validateNativeToolchain(undefined), /Go1\.26\.9/);
});

test("toolchain successful reads publish immutable snapshots before validation", async () => {
  const calls = [], snapshots = [], facts = toolchain();
  const result = await observeNativeToolchain(async (name, args) => { calls.push([name, args]); return facts[name]; }, async (value) => { snapshots.push(value); });
  assert.deepEqual(calls, [["go", ["version"]], ["rustc", ["--version"]], ["cargo", ["--version"]]]);
  assert.deepEqual(snapshots, [{ go: facts.go }, { go: facts.go, rustc: facts.rustc }, facts]);
  assert.deepEqual(result, facts); result.cargo = "changed-after-record";
  assert.equal(snapshots[2].cargo, facts.cargo);
});

for (const executable of ["go", "rustc", "cargo"]) test(`toolchain ${executable} pin rejection still records every successful version`, async () => {
  const calls = [], snapshots = [], facts = toolchain(); facts[executable] = "unreviewed version";
  await assert.rejects(observeNativeToolchain(async (name) => { calls.push(name); return facts[name]; }, async (value) => { snapshots.push(value); }), /Pinned existing/);
  assert.deepEqual(calls, ["go", "rustc", "cargo"]);
  assert.deepEqual(snapshots[2], facts);
});

for (const [executable, code, expectedCalls, expectedKeys] of [
  ["go", "ENOENT", ["go"], []],
  ["rustc", "EACCES", ["go", "rustc"], ["go"]],
  ["cargo", 124, ["go", "rustc", "cargo"], ["go", "rustc"]]
]) test(`toolchain propagates exact ${code} from ${executable}, retaining only completed facts`, async () => {
  const calls = [], snapshots = [], facts = toolchain(), failure = Object.assign(new Error("synthetic command failure"), { code });
  await assert.rejects(observeNativeToolchain(async (name) => { calls.push(name); if (name === executable) throw failure; return facts[name]; }, async (value) => { snapshots.push(value); }), (error) => error === failure);
  assert.deepEqual(calls, expectedCalls);
  assert.deepEqual(Object.keys(snapshots.at(-1) ?? {}), expectedKeys);
  assert.equal(snapshots.length, expectedKeys.length);
});

test("toolchain evidence-write failure stops before another executable", async () => {
  const calls = [], failure = new Error("synthetic evidence-write failure");
  await assert.rejects(observeNativeToolchain(async (name) => { calls.push(name); return toolchain()[name]; }, async () => { throw failure; }), (error) => error === failure);
  assert.deepEqual(calls, ["go"]);
});
