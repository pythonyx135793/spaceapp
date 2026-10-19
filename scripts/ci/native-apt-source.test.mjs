import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { NATIVE_APT_INPUTS, NATIVE_APT_KEYRING, nativeAptInputFacts, planOwnedNativeAptSources, validateNativeAptInputs } from "./native-apt-source.mjs";

// Synthetic inputs derived from official runner-image commit 7e7dc1b, blob b3f5b2b.
// These are neither observed runner bytes nor a real signing-key/ownership proof.
const MIRROR = "mirror+file:/etc/apt/apt-mirrors.txt";
const ROOT = "/var/tmp/spaceapp-native-apt-39279795261-1-aB123Z";
const PREFIX = "spaceapp-native-apt-39279795261-1-";
const SOURCE = `# Preserve this comment: ${MIRROR}\r\nTypes: deb\r\nURIs: ${MIRROR}\r\nSuites: noble noble-updates noble-backports\r\nComponents: main restricted universe multiverse\r\nSigned-By: ${NATIVE_APT_INPUTS.keyring.path}\r\n\r\nTypes: deb\r\nURIs:\r\n ${MIRROR}\r\nSuites: noble-security\r\nComponents: main restricted universe multiverse\r\nSigned-By: ${NATIVE_APT_INPUTS.keyring.path}\r\n`;
const MIRRORS = "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\nhttps://archive.ubuntu.com/ubuntu/\tpriority:2\nhttps://security.ubuntu.com/ubuntu/\tpriority:3\n";
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
function input(kind, value) {
  const bytes = Buffer.from(value), before = { dev: 2049, ino: 812, mode: 0o100644, uid: 0, gid: 0, size: bytes.length, mtimeMs: 10, ctimeMs: 11, regular: true, symlink: false };
  return { path: NATIVE_APT_INPUTS[kind].path, realpath: NATIVE_APT_INPUTS[kind].path, afterRealpath: NATIVE_APT_INPUTS[kind].path, before, opened: { ...before }, after: { ...before }, bytes, sha256: sha(bytes) };
}
function fixture() { return { source: input("source", SOURCE), mirror: input("mirror", MIRRORS), keyring: input("keyring", "synthetic-keyring-bytes-not-a-signing-proof") }; }
function source(value) { return { ...fixture(), source: input("source", value) }; }
function mirror(value) { return { ...fixture(), mirror: input("mirror", value) }; }
function reject(inputs, code) { assert.throws(() => validateNativeAptInputs(inputs), { code }); }

test("reviewed synthetic mirror inputs preserve exact bytes, priorities and comments in an owned copy", () => {
  const inputs = fixture(), before = JSON.stringify(inputs), plan = planOwnedNativeAptSources(inputs, { root: ROOT, prefix: PREFIX });
  const expected = SOURCE.replace(`URIs: ${MIRROR}`, `URIs: mirror+file:${ROOT}/apt-mirrors.txt`).replace(`URIs:\r\n ${MIRROR}`, `URIs:\r\n mirror+file:${ROOT}/apt-mirrors.txt`).replaceAll(`Signed-By: ${NATIVE_APT_INPUTS.keyring.path}`, `Signed-By: ${ROOT}/${NATIVE_APT_KEYRING.keyringName}`);
  assert.equal(plan.sourceBytes.toString(), expected); assert.deepEqual(plan.mirrorBytes, inputs.mirror.bytes);
  assert.equal(plan.sourcePath, `${ROOT}/sources/ubuntu.sources`); assert.equal(plan.mirrorPath, `${ROOT}/apt-mirrors.txt`);
  assert.equal(plan.copiedMirrorSha256, inputs.mirror.sha256); assert.equal(plan.copiedSourceSha256, sha(Buffer.from(expected)));
  assert.equal(plan.keyringPath, `${ROOT}/${NATIVE_APT_KEYRING.keyringName}`); assert.equal(plan.hostKeyringUsed, false);
  assert.equal(JSON.stringify(inputs), before); assert.notEqual(plan.mirrorBytes, inputs.mirror.bytes);
});
test("reviewed direct Ubuntu sources do not require or copy an unused mirror input", () => {
  const inputs = source(SOURCE.replaceAll(MIRROR, "https://archive.ubuntu.com/ubuntu/")); delete inputs.mirror;
  const plan = planOwnedNativeAptSources(inputs, { root: ROOT, prefix: PREFIX });
  assert.equal(plan.usesMirror, false); assert.equal(plan.mirrorBytes, null); assert.equal(plan.mirrorPath, null);
  assert.equal(plan.sourceBytes.toString(), inputs.source.bytes.toString().replaceAll(`Signed-By: ${NATIVE_APT_INPUTS.keyring.path}`, `Signed-By: ${ROOT}/${NATIVE_APT_KEYRING.keyringName}`));
});
for (const uri of [
  "mirror+file:/tmp/apt-mirrors.txt", "mirror+file://localhost/etc/apt/apt-mirrors.txt", "mirror+file:/etc/apt/../apt/apt-mirrors.txt",
  "mirror+file:/etc/apt/%61pt-mirrors.txt", `${MIRROR}?a=1`, `${MIRROR}#fragment`, "file:/etc/apt/apt-mirrors.txt",
  "https://archive.ubuntu.com:443/ubuntu/", "https://archive.ubuntu.com/ubuntu/../ubuntu/", "https://archive.ubuntu.com/ubuntu/?credential=SECRET_QUERY",
  "https://USER_SECRET:PASSWORD_SECRET@archive.ubuntu.com/ubuntu/", "https://archive.ubuntu.com/ubuntu/#SECRET_FRAGMENT", "https://archive.ubuntu.com.evil.invalid/ubuntu/", "https://security.ubuntu.com/other/"
]) test(`reject unreviewed source URI syntax: ${uri.replace(/SECRET_[A-Z]+|[A-Z]+_SECRET/g, "[synthetic]")}`, () => reject(source(SOURCE.replaceAll(MIRROR, uri)), "unreviewed-apt-source-uri"));
for (const kind of ["source", "mirror"]) {
  test(`reject ${kind} ownership, writable mode, symlink, nonregular or alias`, () => {
    for (const alteration of [
      (record) => { for (const when of ["before", "opened", "after"]) record[when].uid = 1000; },
      (record) => { for (const when of ["before", "opened", "after"]) record[when].mode |= 0o020; },
      (record) => { for (const when of ["before", "opened", "after"]) record[when].mode |= 0o002; },
      (record) => { for (const when of ["before", "opened", "after"]) record[when].symlink = true; },
      (record) => { for (const when of ["before", "opened", "after"]) record[when].regular = false; },
      (record) => { for (const when of ["before", "opened", "after"]) delete record[when].ino; },
      (record) => { for (const when of ["before", "opened", "after"]) record[when].mtimeMs = NaN; },
      (record) => { for (const when of ["before", "opened", "after"]) record[when].size = 0; },
      (record) => { record.realpath = "/unreviewed/path"; }, (record) => { record.afterRealpath = "/unreviewed/path"; }
    ]) { const inputs = fixture(); alteration(inputs[kind]); assert.throws(() => validateNativeAptInputs(inputs)); }
  });
  test(`reject ${kind} replacement, metadata race, oversized input and modified bytes`, () => {
    for (const alteration of [
      (record) => { record.opened.ino += 1; }, (record) => { record.after.dev += 1; },
      (record) => { record.after.mtimeMs += 1; }, (record) => { record.after.ctimeMs += 1; },
      (record) => { record.after.mode ^= 0o020; }, (record) => { record.opened.uid = 1000; },
      (record) => { for (const when of ["before", "opened", "after"]) record[when].size = NATIVE_APT_INPUTS[kind].maximum + 1; },
      (record) => { record.bytes[0] ^= 1; }, (record) => { delete record.bytes; }
    ]) { const inputs = fixture(); alteration(inputs[kind]); assert.throws(() => validateNativeAptInputs(inputs)); }
  });
}
test("unsafe host-keyring observations never become trust or copied content", () => {
  const inputs = fixture();
  inputs.keyring = input("keyring", "UNTRUSTED_HOST_KEYRING_CONTENT");
  for (const when of ["before", "opened", "after"]) { inputs.keyring[when].mode = 0o100777; inputs.keyring[when].uid = 1000; }
  const facts = nativeAptInputFacts(inputs), plan = planOwnedNativeAptSources(inputs, { root: ROOT, prefix: PREFIX });
  assert.equal(facts.keyring.contentsRead, false); assert.equal(facts.keyring.sha256, null);
  assert.equal(plan.hostKeyringUsed, false); assert.equal(plan.expectedKeyringSha256, NATIVE_APT_KEYRING.keyringSha256);
  assert.ok(!plan.sourceBytes.toString().includes("UNTRUSTED_HOST_KEYRING_CONTENT"));
  assert.ok(!JSON.stringify(facts).includes("UNTRUSTED_HOST_KEYRING_CONTENT"));
});
test("owned signing-keyring rewrite changes fields only and cannot select a caller-supplied path", () => {
  const value = SOURCE.replace("# Preserve this comment:", `# ${NATIVE_APT_INPUTS.keyring.path} Preserve this comment:`), inputs = source(value);
  const plan = planOwnedNativeAptSources(inputs, { root: ROOT, prefix: PREFIX, keyringPath: "/tmp/untrusted-keyring" });
  assert.ok(plan.sourceBytes.toString().startsWith(`# ${NATIVE_APT_INPUTS.keyring.path} Preserve this comment:`));
  assert.equal(plan.keyringPath, `${ROOT}/${NATIVE_APT_KEYRING.keyringName}`); assert.ok(!plan.sourceBytes.toString().includes("/tmp/untrusted-keyring"));
  for (const changed of [NATIVE_APT_INPUTS.keyring.path + " other.gpg", "/tmp/untrusted-keyring", NATIVE_APT_INPUTS.keyring.path.replace("/keyrings/", "/keyrings/../keyrings/")]) assert.throws(() => validateNativeAptInputs(source(SOURCE.replaceAll(NATIVE_APT_INPUTS.keyring.path, changed))));
});
for (const [name, value] of [
  ["missing origin", MIRRORS.split("\n").slice(0, 2).join("\n")],
  ["duplicate origin", MIRRORS.replace("https://archive.ubuntu.com/ubuntu/", "http://azure.archive.ubuntu.com/ubuntu/")],
  ["changed priority", MIRRORS.replace("priority:2", "priority:1")],
  ["unknown priority", MIRRORS.replace("priority:2", "priority:99")],
  ["additional option", MIRRORS.replace("priority:2", "priority:2 trusted=yes")],
  ["unknown host", MIRRORS.replace("archive.ubuntu.com/ubuntu/\tpriority:2", "evil.invalid/ubuntu/\tpriority:2")],
  ["default port normalization", MIRRORS.replace("https://archive.ubuntu.com/", "https://archive.ubuntu.com:443/")],
  ["URL credentials", MIRRORS.replace("https://archive.ubuntu.com/", "https://SYNTHETIC_PASSWORD@archive.ubuntu.com/")],
  ["reordered priority origins", MIRRORS.split("\n").filter(Boolean).reverse().join("\n")]
]) test(`reject mirror ${name}`, () => assert.throws(() => validateNativeAptInputs(mirror(value))));
for (const [name, value] of [
  ["duplicate field with different case", SOURCE.replace("Types: deb", "Types: deb\r\ntypes: deb")],
  ["orphan continuation", ` invalid\n${SOURCE}`], ["malformed field", SOURCE.replace("Types: deb", "Types deb")],
  ["unsigned keyring", SOURCE.replaceAll(NATIVE_APT_INPUTS.keyring.path, "/tmp/unreviewed.gpg")],
  ["Trusted override", `${SOURCE}Trusted: yes\n`], ["Allow-Insecure override", `${SOURCE}Allow-Insecure: yes\n`],
  ["Allow-Weak override", `${SOURCE}Allow-Weak: yes\n`], ["Check-Valid-Until override", `${SOURCE}Check-Valid-Until: no\n`],
  ["unknown field", `${SOURCE}Unreviewed: value\n`], ["empty type", SOURCE.replace("Types: deb", "Types:")],
  ["empty URI", SOURCE.replace(`URIs: ${MIRROR}`, "URIs:")], ["empty suite", SOURCE.replace("Suites: noble-security", "Suites:")],
  ["unknown distribution", SOURCE.replace("Suites: noble-security", "Suites: jammy-security")],
  ["unknown component", SOURCE.replace("Components: main", "Components: evil")],
  ["duplicate suite", SOURCE.replace("Suites: noble-security", "Suites: noble-security noble-security")],
  ["empty document", "# no repository\n"], ["NUL", `${SOURCE}\0`], ["bare CR", `${SOURCE}\rfield`],
  ["invalid UTF8", Buffer.concat([Buffer.from(SOURCE), Buffer.from([0xff])])]
]) test(`reject source ${name}`, () => assert.throws(() => validateNativeAptInputs(source(value))));
test("source mutation after validation is rechecked before rendering an owned source", () => {
  const inputs = fixture(); validateNativeAptInputs(inputs); inputs.source.bytes[0] ^= 1;
  assert.throws(() => planOwnedNativeAptSources(inputs, { root: ROOT, prefix: PREFIX }), { code: "changed-or-unavailable-source-bytes" });
});
test("safe observations precede policy acceptance without exposing rejected values", () => {
  const inputs = source(SOURCE.replaceAll(MIRROR, "https://USER_SECRET:PASSWORD_SECRET@archive.ubuntu.com/SECRET_PATH?SECRET_QUERY#SECRET_FRAGMENT") + "Secret-Field: SECRET_VALUE\n");
  const facts = JSON.stringify(nativeAptInputFacts(inputs));
  for (const secret of ["USER_SECRET", "PASSWORD_SECRET", "SECRET_PATH", "SECRET_QUERY", "SECRET_FRAGMENT", "Secret-Field", "SECRET_VALUE"]) assert.ok(!facts.includes(secret));
  assert.ok(facts.includes("unreviewedValueSuppressed")); assert.ok(facts.includes(inputs.source.sha256));
  assert.throws(() => validateNativeAptInputs(inputs));
});
test("malformed source observations suppress unparsed values and still retain their byte identity", () => {
  const inputs = source(`${SOURCE}SECRET_FIELD: SECRET_VALUE\n`), facts = nativeAptInputFacts(inputs);
  assert.equal(facts.source.malformedOrUnavailable, true); assert.equal(facts.source.sha256, inputs.source.sha256);
  assert.ok(!JSON.stringify(facts).includes("SECRET_VALUE")); assert.throws(() => validateNativeAptInputs(inputs));
});
test("owned-copy target rejects traversal, arbitrary parents, prefix confusion and malformed suffixes", () => {
  for (const root of ["/tmp/spaceapp-native-apt-39279795261-1-aB123Z", `${ROOT}/../other`, `${ROOT}/nested`, `${ROOT}0`, "/var/tmp/spaceapp-native-apt-39279795262-1-aB123Z", "/var/tmp/spaceapp-native-apt-39279795261-1-"]) {
    assert.throws(() => planOwnedNativeAptSources(fixture(), { root, prefix: PREFIX }), { code: "unreviewed-owned-apt-target" });
  }
  assert.throws(() => planOwnedNativeAptSources(fixture(), { root: ROOT, prefix: "spaceapp-native-apt-.*" }), { code: "unreviewed-owned-apt-target" });
});
