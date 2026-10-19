import assert from "node:assert/strict";
import test from "node:test";
import { nativeEngineIdentity, nativeEngineResources, nativeEngineStorageFacts, validateNativeEngineInfo } from "./native-host-prereqs.mjs";

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
