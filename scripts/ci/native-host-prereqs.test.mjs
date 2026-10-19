import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import "./native-engine-info.test.mjs";
import { analyzeSubordinateRanges, analyzeVendorProfile, NATIVE_APPARMOR_VERSION, NATIVE_EXECUTABLES, nativePolicyObservation, nativeRuntimeConfig, validateNativeDestinations, validateNativeMappings, validateNativePolicies, validateNativeSessionAndStorage } from "./native-host-prereqs.mjs";

// Exact Canonical835ca4d0785bc87bfc44b46a6124644310a31bfe policy fixtures.
const profile = (name, path) => `# This profile allows everything and only exists to give the
# application a name instead of having the label "unconfined"

abi <abi/4.0>,
include <tunables/global>

profile ${name} ${path} flags=(unconfined) {
  userns,

  # Site-specific additions and overrides. See local/README for details.
  include if exists <local/${name}>
}
`;
const originals = Object.fromEntries(Object.entries(NATIVE_EXECUTABLES).map(([name, spec]) => [name, profile(name, spec.path)]));
const regular = (path, bytes = 334) => ({ exists: true, type: "regular", canonical: path, uid: 0, gid: 0, mode: 0o644, bytes });
const expanded = (name) => "@{HOMEDIRS}=/home/\n" + originals[name].split("\n").filter((line) => !line.startsWith("abi ") && !line.startsWith("include ") && !line.trim().startsWith("include if ")).join("\n");
const policyFacts = () => ({ apparmorEnabled: "Y", restrictedUserns: "1", packageVersion: NATIVE_APPARMOR_VERSION,
  profiles: Object.fromEntries(Object.entries(NATIVE_EXECUTABLES).map(([name, spec]) => [name, nativePolicyObservation(spec, regular(spec.policy, Buffer.byteLength(originals[name])), originals[name], expanded(name), name, spec.md5, "unconfined", { exists: false })])) });
const clone = (value) => structuredClone(value);

test("exact two official policies retain their pinned bytes and pass the real predicate", () => {
  assert.equal(Buffer.byteLength(originals.podman), 339); assert.equal(Buffer.byteLength(originals.runc), 334);
  for (const [name, spec] of Object.entries(NATIVE_EXECUTABLES)) assert.equal(createHash("sha256").update(originals[name]).digest("hex"), spec.sha256);
  validateNativePolicies(policyFacts());
});

test("the fixed runtime config and executable specification agree", () => {
  assert.equal(NATIVE_EXECUTABLES.podman.path, "/usr/bin/podman");
  assert.equal(NATIVE_EXECUTABLES.runc.path, "/usr/sbin/runc");
  assert.match(nativeRuntimeConfig(), /runc = \["\/usr\/sbin\/runc"\]/);
  assert.ok(!nativeRuntimeConfig().includes("/usr/bin/runc"));
  assert.ok(Object.isFrozen(NATIVE_EXECUTABLES) && Object.isFrozen(NATIVE_EXECUTABLES.runc));
});

const badExpanded = [
  ["wrong old executable path", (text) => text.replace("/usr/sbin/runc", "/usr/bin/runc"), "runc"],
  ["wrong profile name", (text) => text.replace("profile runc ", "profile arbitrary "), "arbitrary"],
  ["comment-only valid header", () => "# profile runc /usr/sbin/runc flags=(unconfined) {\n# userns,\n# }\n", "runc"],
  ["valid header comment decoy beside wrong attachment", (text) => "# profile runc /usr/sbin/runc flags=(unconfined) {\n" + text.replace("/usr/sbin/runc", "/usr/bin/runc"), "runc"],
  ["multiple profile declarations", (text) => text + text, "runc\nrunc"],
  ["missing header opening brace", (text) => text.replace("flags=(unconfined) {", "flags=(unconfined)"), "runc"],
  ["missing closing brace", (text) => text.replace(/}\s*$/, ""), "runc"],
  ["missing user namespace grant", (text) => text.replace("  userns,", ""), "runc"],
  ["comment-only user namespace grant", (text) => text.replace("  userns,", "  # userns,"), "runc"],
  ["conflicting user namespace denial", (text) => text.replace("  userns,", "  userns,\n  deny userns,"), "runc"],
  ["unreviewed profile flags", (text) => text.replace("flags=(unconfined)", "flags=(complain)"), "runc"],
  ["parser reports a different name", (text) => text, "podman"],
  ["parser reports no name", (text) => text, ""]
];
for (const [name, change, names] of badExpanded) test(`policy rejects ${name}`, () => {
  const facts = policyFacts(); facts.profiles.runc.expanded = analyzeVendorProfile(change(expanded("runc")), names);
  assert.throws(() => validateNativePolicies(facts), /attachment differs/);
});

for (const [name, change] of [
  ["package version drift", (x) => { x.packageVersion += ".next"; }],
  ["disabled AppArmor", (x) => { x.apparmorEnabled = "N"; }],
  ["disabled user namespace restrictions", (x) => { x.restrictedUserns = "0"; }],
  ["world-writable policy", (x) => { x.profiles.runc.file.mode = 0o666; }],
  ["symlink policy", (x) => { x.profiles.runc.file.type = "symlink"; }],
  ["different canonical policy file", (x) => { x.profiles.runc.file.canonical += ".other"; }],
  ["wrong policy owner", (x) => { x.profiles.runc.file.uid = 1001; }],
  ["incorrect policy SHA", (x) => { x.profiles.runc.sha256 = "0".repeat(64); }],
  ["incorrect registered package digest", (x) => { x.profiles.runc.registeredMd5 = "0".repeat(32); }],
  ["unloaded policy", (x) => { x.profiles.runc.loadedProfile = null; }],
  ["complain policy", (x) => { x.profiles.runc.loadedMode = "complain"; }],
  ["nonempty local override", (x) => { x.profiles.runc.localInclude = regular("/etc/apparmor.d/local/runc", 10); }],
  ["inconsistent executable wiring", (x) => { x.profiles.runc.expectedExecutable = "/usr/bin/runc"; }]
]) test(`policy refuses ${name}`, () => { const facts = policyFacts(); change(facts); assert.throws(() => validateNativePolicies(facts)); });

test("private unexpected header text and local include contents are not exported", () => {
  const secret = "PRIVATE_SENTINEL_NOT_FOR_ARTIFACTS";
  const facts = analyzeVendorProfile(`profile unknown /private/${secret} flags=(unconfined) {\n userns,\n}\n`, secret);
  assert.ok(!JSON.stringify(facts).includes(secret)); assert.ok(facts.unknownHeaderSha256 && facts.unknownNamesSha256);
});

const mappingFacts = () => Object.fromEntries(["uid", "gid"].map((kind) => [kind, { source: regular(`/etc/sub${kind}`, 40), helper: { ...regular(`/usr/bin/new${kind}map`, 40000), mode: 0o4755 }, capabilityEffective: false, ranges: analyzeSubordinateRanges("other:200000:65536\nrunner:100000:65536\n", 1001, "runner") }]));
test("real subordinate range predicate accepts disjoint caller ranges and normal mapping helpers", () => validateNativeMappings(mappingFacts()));
for (const [name, change] of [
  ["overlapping allocation", (x) => { x.uid.ranges = analyzeSubordinateRanges("private-user:100010:65536\nrunner:100000:65536\n", 1001, "runner"); }],
  ["malformed allocation", (x) => { x.uid.ranges = analyzeSubordinateRanges("runner:1.5:65536\n", 1001, "runner"); }],
  ["insufficient allocation", (x) => { x.uid.ranges = analyzeSubordinateRanges("runner:100000:1000\n", 1001, "runner"); }],
  ["missing helper privilege", (x) => { x.uid.helper.mode = 0o755; }],
  ["writable subordinate file", (x) => { x.gid.source.mode = 0o666; }]
]) test(`mapping refuses ${name}`, () => { const facts = mappingFacts(); change(facts); assert.throws(() => validateNativeMappings(facts)); });
test("noncaller subordinate names never enter the exported range facts", () => assert.ok(!JSON.stringify(analyzeSubordinateRanges("PRIVATE_NONCALLER:200000:65536\nrunner:100000:65536\n", 1001, "runner")).includes("PRIVATE_NONCALLER")));

const destinations = () => Object.fromEntries(Object.entries(NATIVE_EXECUTABLES).map(([name, spec]) => [name, { path: spec.path, parent: { exists: true, type: "directory", canonical: spec.path.slice(0, spec.path.lastIndexOf("/")), uid: 0, mode: 0o755 }, file: { exists: false }, packageOwner: null }]));
test("reviewed fixed absent runtime destinations pass", () => validateNativeDestinations(destinations()));
test("an existing regular root-owned runc package preimage passes", () => { const facts = destinations(); facts.runc.file = { ...regular(NATIVE_EXECUTABLES.runc.path, 20000), mode: 0o755, sha256: "a".repeat(64) }; facts.runc.packageOwner = "runc"; validateNativeDestinations(facts); });
for (const [name, change] of [
  ["old mismatched install target", (x) => { x.runc.path = "/usr/bin/runc"; }],
  ["writable parent", (x) => { x.runc.parent.mode = 0o777; }],
  ["unknown parent mode", (x) => { delete x.runc.parent.mode; }],
  ["symlink runtime alias", (x) => { x.runc.file = { ...regular(NATIVE_EXECUTABLES.runc.path), type: "symlink" }; }],
  ["unrelated runtime package", (x) => { x.runc.file = { ...regular(NATIVE_EXECUTABLES.runc.path, 20000), sha256: "a".repeat(64) }; x.runc.packageOwner = "containerd.io"; }]
]) test(`destination refuses ${name}`, () => { const facts = destinations(); change(facts); assert.throws(() => validateNativeDestinations(facts)); });

const required = { cpuCount: 4, memoryBytes: 7 * 1024 ** 3, freshDiskBytes: 6.5 * 1024 ** 3 }, headroom = 512 * 1024 ** 2;
const session = () => ({ runtimePath: "/run/user/1001", busSocket: true, homeOwned: true, userService: "inactive", userSocket: "inactive", userConfigAbsent: true, userUnitsAbsent: true,
  delegation: { pid: 1234, ownedPid: true, identityStable: true, controlGroup: "/user.slice/user-1001.slice/user@1001.service", delegate: "yes", controllers: ["cpu", "memory", "pids"], capacity: { path: "/user.slice/user-1001.slice/user@1001.service/init.scope", cpuLimit: null, memoryLimit: null, memoryFree: null } },
  storage: { fresh: true, filesystemType: 0xef53, freeBytes: 20 * 1024 ** 3, freeInodes: 500000 } });
test("reviewed user session/delegation/native storage predicate passes", () => validateNativeSessionAndStorage(session(), 1001, required, headroom));
for (const [name, change] of [
  ["missing user bus", (x) => { x.busSocket = false; }],
  ["active unrelated socket", (x) => { x.userSocket = "active"; }],
  ["existing user config", (x) => { x.userConfigAbsent = false; }],
  ["missing CPU controller", (x) => { x.delegation.controllers = ["memory"]; }],
  ["wrong manager UID", (x) => { x.delegation.ownedPid = false; }],
  ["changed manager identity", (x) => { x.delegation.identityStable = false; }],
  ["unrelated capacity cgroup", (x) => { x.delegation.capacity.path = "/unrelated"; }],
  ["insufficient CPU quota", (x) => { x.delegation.capacity.cpuLimit = 2; }],
  ["unknown CPU quota", (x) => { delete x.delegation.capacity.cpuLimit; }],
  ["insufficient manager memory", (x) => { x.delegation.capacity.memoryLimit = 6 * 1024 ** 3; }],
  ["non-native overlay parent", (x) => { x.storage.filesystemType = 0x794c7630; }],
  ["insufficient storage", (x) => { x.storage.freeBytes = required.freshDiskBytes; }]
]) test(`session/storage refuses ${name}`, () => { const facts = clone(session()); change(facts); assert.throws(() => validateNativeSessionAndStorage(facts, 1001, required, headroom)); });
