// The native bootstrap accepts only reviewed Ubuntu inputs; this module never runs APT.
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";

export const NATIVE_APT_INPUTS = Object.freeze({
  source: Object.freeze({ path: "/etc/apt/sources.list.d/ubuntu.sources", maximum: 64 * 1024 }),
  mirror: Object.freeze({ path: "/etc/apt/apt-mirrors.txt", maximum: 16 * 1024 }),
  keyring: Object.freeze({ path: "/usr/share/keyrings/ubuntu-archive-keyring.gpg", maximum: 2 * 1024 * 1024 })
});
// Canonical's Noble package digest and the independently inspected member.
export const NATIVE_APT_KEYRING = Object.freeze({
  url: "https://archive.ubuntu.com/ubuntu/pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1_all.deb",
  packageName: "ubuntu-keyring_2023.11.28.1_all.deb", packageBytes: 11124,
  packageSha256: "36de43b15853ccae0028e9a767613770c704833f82586f28eb262f0311adb8a8",
  keyringName: "ubuntu-archive-keyring.gpg", keyringBytes: 3607,
  keyringSha256: "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
});
const MIRROR_URI = "mirror+file:/etc/apt/apt-mirrors.txt";
const ORIGINS = Object.freeze([
  "http://azure.archive.ubuntu.com/ubuntu/",
  "https://archive.ubuntu.com/ubuntu/",
  "https://security.ubuntu.com/ubuntu/"
]);
const FIELDS = ["types", "uris", "suites", "components", "signed-by"];
const SNAPSHOT_FIELDS = ["dev", "ino", "mode", "uid", "gid", "size", "mtimeMs", "ctimeMs", "regular", "symlink"];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const requireInput = (condition, code) => { if (!condition) throw Object.assign(new Error(code), { code }); };
function metadata(file) {
  return Object.fromEntries([...SNAPSHOT_FIELDS.slice(0, -2).map((key) => [key, file[key]]), ["regular", file.isFile()], ["symlink", file.isSymbolicLink()]]);
}
function trusted(file, maximum) {
  return file && file.regular === true && file.symlink === false && file.uid === 0 &&
    ["dev", "ino", "uid", "gid", "mode", "size"].every((key) => Number.isSafeInteger(file[key]) && file[key] >= 0) &&
    ["mtimeMs", "ctimeMs"].every((key) => Number.isFinite(file[key]) && file[key] >= 0) &&
    (file.mode & 0o170000) === 0o100000 && !(file.mode & 0o022) && file.size > 0 && file.size <= maximum;
}
function consistent(record) {
  return record.before && record.opened && record.after && SNAPSHOT_FIELDS.every((key) => record.before[key] === record.opened[key] && record.before[key] === record.after[key]);
}
function validateSnapshot(record, kind) {
  const expected = NATIVE_APT_INPUTS[kind];
  requireInput(record?.path === expected.path && record.realpath === expected.path && record.afterRealpath === expected.path, `untrusted-${kind}-path`);
  requireInput(!record.error && trusted(record.before, expected.maximum) && consistent(record), `untrusted-or-changing-${kind}-metadata`);
  requireInput(Buffer.isBuffer(record.bytes) && record.bytes.length === record.before.size && record.bytes.length <= expected.maximum && record.sha256 === sha256(record.bytes), `changed-or-unavailable-${kind}-bytes`);
}
async function readInput(kind) {
  const { path, maximum } = NATIVE_APT_INPUTS[kind];
  const result = { path }; let handle;
  try {
    result.before = metadata(await lstat(path)); result.realpath = await realpath(path);
    requireInput(result.realpath === path && trusted(result.before, maximum), `untrusted-${kind}-input`);
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    result.opened = metadata(await handle.stat());
    requireInput(SNAPSHOT_FIELDS.every((key) => result.before[key] === result.opened[key]), `changed-${kind}-input`);
    // A growing input cannot cause an unbounded allocation or read.
    const buffer = Buffer.alloc(maximum + 1); let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break; length += bytesRead;
    }
    result.bytes = Buffer.from(buffer.subarray(0, length)); result.sha256 = sha256(result.bytes);
    result.opened = metadata(await handle.stat()); result.after = metadata(await lstat(path)); result.afterRealpath = await realpath(path);
    validateSnapshot(result, kind);
  } catch {
    result.error = "fixed-input-unavailable-untrusted-or-changing"; delete result.bytes;
  } finally { await handle?.close(); }
  return result;
}
export async function readNativeAptInputs() {
  requireInput(process.platform === "linux", "native-apt-inputs-require-linux");
  // The host keyring is observational metadata only. Its contents are never
  // opened or trusted, even if its mode differs from the observed runner0777.
  const keyring = { path: NATIVE_APT_INPUTS.keyring.path, metadataOnly: true };
  try {
    keyring.before = metadata(await lstat(keyring.path)); keyring.realpath = await realpath(keyring.path);
    keyring.after = metadata(await lstat(keyring.path)); keyring.afterRealpath = await realpath(keyring.path);
  } catch { keyring.error = "fixed-input-unavailable-untrusted-or-changing"; }
  return { source: await readInput("source"), mirror: await readInput("mirror"), keyring };
}
function text(bytes) {
  let value;
  try { value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { requireInput(false, "invalid-apt-input-utf8"); }
  requireInput(!value.includes("\0") && !/\r(?!\n)/.test(value) && Buffer.from(value).equals(bytes), "invalid-apt-input-text");
  return value;
}
function parseSources(bytes) {
  const value = text(bytes), stanzas = [], fieldTokens = [];
  let fields = {}, previous, offset = 0;
  const flush = () => { if (Object.keys(fields).length) stanzas.push(fields); fields = {}; previous = undefined; };
  for (const raw of value.match(/[^\n]*(?:\n|$)/g).filter(Boolean)) {
    const line = raw.replace(/\r?\n$/, ""); let key, content, start;
    if (/^[ \t]*$/.test(line)) { flush(); offset += raw.length; continue; }
    if (/^[ \t]*#/.test(line)) { offset += raw.length; continue; }
    if (/^[ \t]/.test(line)) {
      requireInput(previous, "orphan-apt-field-continuation"); key = previous;
      start = line.match(/^[ \t]*/)[0].length; content = line.slice(start);
      fields[key] += ` ${content.trim()}`;
    } else {
      const match = line.match(/^([A-Za-z][A-Za-z-]*):[ \t]*(.*)$/);
      requireInput(match, "malformed-apt-source-field"); key = match[1].toLowerCase();
      requireInput(!Object.hasOwn(fields, key), "duplicate-apt-source-field");
      start = line.length - match[2].length; content = match[2]; fields[key] = content.trim(); previous = key;
    }
    if (["uris", "signed-by"].includes(key)) for (const token of content.matchAll(/\S+/g)) fieldTokens.push({ field: key, value: token[0], start: offset + start + token.index, end: offset + start + token.index + token[0].length });
    offset += raw.length;
  }
  flush(); requireInput(stanzas.length > 0 && stanzas.length <= 4, "unexpected-apt-source-stanza-count");
  return { value, stanzas, fieldTokens };
}
function tokens(value, allowed, code) {
  const result = value?.split(/\s+/).filter(Boolean) ?? [];
  requireInput(result.length > 0 && new Set(result).size === result.length && result.every((token) => allowed.includes(token)), code);
  return result;
}
function validateMirror(bytes) {
  const lines = text(bytes).split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith("#"));
  requireInput(lines.length === ORIGINS.length, "unexpected-apt-mirror-entry-count");
  lines.forEach((line, index) => {
    const values = line.trim().split(/[ \t]+/);
    requireInput(values.length === 2 && values[0] === ORIGINS[index] && values[1] === `priority:${index + 1}`, "unreviewed-apt-mirror-origin-priority-or-option");
  });
}
export function validateNativeAptInputs(inputs) {
  validateSnapshot(inputs?.source, "source");
  const parsed = parseSources(inputs.source.bytes); let usesMirror = false;
  for (const fields of parsed.stanzas) {
    requireInput(Object.keys(fields).length === FIELDS.length && Object.keys(fields).every((key) => FIELDS.includes(key)), "unreviewed-apt-policy-field");
    tokens(fields.types, ["deb", "deb-src"], "unreviewed-apt-source-type");
    tokens(fields.suites, ["noble", "noble-updates", "noble-security", "noble-backports"], "unreviewed-apt-source-suite");
    tokens(fields.components, ["main", "restricted", "universe", "multiverse"], "unreviewed-apt-source-component");
    requireInput(fields["signed-by"] === NATIVE_APT_INPUTS.keyring.path, "unreviewed-apt-signing-keyring");
    const uris = tokens(fields.uris, [MIRROR_URI, ...ORIGINS], "unreviewed-apt-source-uri");
    usesMirror ||= uris.includes(MIRROR_URI);
  }
  if (usesMirror) { validateSnapshot(inputs.mirror, "mirror"); validateMirror(inputs.mirror.bytes); }
  return { usesMirror, sourceSha256: inputs.source.sha256, mirrorSha256: usesMirror ? inputs.mirror.sha256 : null, hostKeyringUsed: false, expectedKeyringSha256: NATIVE_APT_KEYRING.keyringSha256 };
}
function safeUri(value) {
  if (value === MIRROR_URI || ORIGINS.includes(value)) return { value, reviewedPublicSyntax: true };
  try {
    const url = new URL(value);
    return { scheme: ["http:", "https:", "mirror+file:"].includes(url.protocol) ? url.protocol : "unreviewed-scheme", hostname: ["azure.archive.ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com"].includes(url.hostname) ? url.hostname : "unreviewed-host", credentialsOrQueryPresent: Boolean(url.username || url.password || url.search || url.hash), unreviewedValueSuppressed: true };
  } catch { return { malformed: true, unreviewedValueSuppressed: true }; }
}
function snapshotFacts(record, kind) {
  const expected = NATIVE_APT_INPUTS[kind], file = record?.before;
  const stable = kind === "keyring" ? file && record.after && SNAPSHOT_FIELDS.every((key) => file[key] === record.after[key]) && record.realpath === record.afterRealpath : consistent(record ?? {});
  return { path: expected.path, realpathMatches: record?.realpath === expected.path, uid: file?.uid ?? null, gid: file?.gid ?? null, mode: Number.isInteger(file?.mode) ? (file.mode & 0o7777).toString(8) : null, bytes: file?.size ?? null, regular: file?.regular ?? false, symlink: file?.symlink ?? null, stableSnapshot: Boolean(stable), contentsRead: kind !== "keyring" && Buffer.isBuffer(record?.bytes), sha256: kind !== "keyring" && Buffer.isBuffer(record?.bytes) ? sha256(record.bytes) : null, inputError: record?.error ? "fixed-input-unavailable-untrusted-or-changing" : null };
}
export function nativeAptInputFacts(inputs) {
  const result = Object.fromEntries(Object.keys(NATIVE_APT_INPUTS).map((kind) => [kind, snapshotFacts(inputs?.[kind], kind)]));
  try {
    result.source.stanzas = parseSources(inputs.source.bytes).stanzas.map((fields) => ({
      fieldNames: Object.keys(fields).filter((key) => FIELDS.includes(key)), unreviewedFieldCount: Object.keys(fields).filter((key) => !FIELDS.includes(key)).length,
      types: fields.types?.split(/\s+/).map((value) => ["deb", "deb-src"].includes(value) ? value : "[unreviewed-token]") ?? [],
      suites: fields.suites?.split(/\s+/).map((value) => ["noble", "noble-updates", "noble-security", "noble-backports"].includes(value) ? value : "[unreviewed-token]") ?? [],
      uris: fields.uris?.split(/\s+/).filter(Boolean).map(safeUri) ?? [], signingKeyringMatches: fields["signed-by"] === NATIVE_APT_INPUTS.keyring.path
    }));
  } catch { result.source.malformedOrUnavailable = true; }
  try {
    const lines = text(inputs.mirror.bytes).split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith("#"));
    result.mirror.entries = lines.slice(0, 32).map((line) => {
      const [uri, ...options] = line.trim().split(/[ \t]+/);
      return { uri: safeUri(uri), options: options.map((value) => /^priority:[1-3]$/.test(value) ? value : "[unreviewed-option]") };
    }); result.mirror.truncated = lines.length > 32;
  } catch { result.mirror.malformedOrUnavailable = true; }
  return result;
}
export function planOwnedNativeAptSources(inputs, { root, prefix }) {
  const validation = validateNativeAptInputs(inputs);
  requireInput(typeof prefix === "string" && /^spaceapp-native-apt-[1-9][0-9]{0,19}-[1-9][0-9]{0,3}-$/.test(prefix) && typeof root === "string" && new RegExp(`^/var/tmp/${prefix}[A-Za-z0-9]{6}$`).test(root), "unreviewed-owned-apt-target");
  const mirrorPath = `${root}/apt-mirrors.txt`, sourcePath = `${root}/sources/ubuntu.sources`;
  const keyringPath = `${root}/${NATIVE_APT_KEYRING.keyringName}`;
  const parsed = parseSources(inputs.source.bytes); let source = parsed.value;
  for (const token of parsed.fieldTokens.toReversed()) {
    const replacement = token.field === "uris" && token.value === MIRROR_URI ? `mirror+file:${mirrorPath}` : token.field === "signed-by" && token.value === NATIVE_APT_INPUTS.keyring.path ? keyringPath : token.value;
    source = `${source.slice(0, token.start)}${replacement}${source.slice(token.end)}`;
  }
  const sourceBytes = Buffer.from(source), mirrorBytes = validation.usesMirror ? Buffer.from(inputs.mirror.bytes) : null;
  return { ...validation, sourcePath, sourceBytes, copiedSourceSha256: sha256(sourceBytes), mirrorPath: mirrorBytes ? mirrorPath : null, mirrorBytes, copiedMirrorSha256: mirrorBytes ? sha256(mirrorBytes) : null, keyringPath };
}
