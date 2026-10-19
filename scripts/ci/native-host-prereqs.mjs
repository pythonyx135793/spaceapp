import { createHash } from "node:crypto";

export const NATIVE_APPARMOR_VERSION = "4.0.1really4.0.1-0ubuntu0.24.04.9";
// Canonical applied source835ca4d0785bc87bfc44b46a6124644310a31bfe.
export const NATIVE_EXECUTABLES = Object.freeze({
  podman: Object.freeze({ path: "/usr/bin/podman", policy: "/etc/apparmor.d/podman", name: "podman", package: "podman", sha256: "561be6615630ccda5b92d8e540e051774fab92b0de8598856ec84aca341bbf73", md5: "6fc4a4758bb26d4d40a2762692195885" }),
  runc: Object.freeze({ path: "/usr/sbin/runc", policy: "/etc/apparmor.d/runc", name: "runc", package: "runc", sha256: "e97400404d8b8e85ce3e458558105ec218276efab10b355c7a6086a90ad0b4c6", md5: "3335a9af57ce5e863930b6d03d53ba40" })
});

export function nativeRuntimeConfig() {
  return `[engine]\ncgroup_manager = "systemd"\nruntime = "runc"\nconmon_path = ["/usr/libexec/podman/conmon"]\nhelper_binaries_dir = ["/usr/libexec/podman", "/usr/lib/podman"]\n[engine.runtimes]\nrunc = ["${NATIVE_EXECUTABLES.runc.path}"]\n[network]\nnetwork_backend = "netavark"\n`;
}

function requireFact(value, message) { if (!value) throw new Error(message); }
const sha = (text, algorithm = "sha256") => createHash(algorithm).update(text).digest("hex");
const safePaths = new Set(["/usr/bin/podman", "/usr/bin/runc", "/usr/sbin/runc"]);
const safeNames = new Set(["podman", "runc"]);
const words = (text) => String(text ?? "").trim().split(/\s+/).filter(Boolean);
const positive = (value) => Number.isSafeInteger(value) && value > 0;

export function trustedNativeFile(file, path, owner = 0, max = 256 * 1024) {
  return file?.exists === true && file.type === "regular" && file.canonical === path && file.uid === owner &&
    Number.isSafeInteger(file.mode) && !(file.mode & 0o022) && Number.isSafeInteger(file.bytes) && file.bytes >= 0 && file.bytes <= max;
}

export function analyzeVendorProfile(text, namesText) {
  // Only fixed executable/name fields are exported. Unknown paths/names are hashed.
  // Profile/local include contents never enter the artifact or an error message.
  const clean = String(text).split("\n").map((line) => line.replace(/#.*/, "")).join("\n");
  const declarations = [...clean.matchAll(/^\s*profile\b[^\n]*$/gm)];
  const header = declarations.length === 1 ? declarations[0][0].match(/^\s*profile\s+(\S+)\s+(\S+)\s+flags=\(([^()]*)\)\s*\{\s*$/) : null;
  const body = header ? clean.slice(declarations[0].index + declarations[0][0].length).match(/^\s*\n([\s\S]*?)^\s*}\s*$/m)?.[1] : undefined;
  const names = words(namesText);
  return {
    declarationCount: declarations.length,
    headerValid: Boolean(header),
    profile: header && safeNames.has(header[1]) ? header[1] : null,
    attachment: header && safePaths.has(header[2]) ? header[2] : null,
    unknownHeaderSha256: header && (!safeNames.has(header[1]) || !safePaths.has(header[2])) ? sha(header[0]) : null,
    flags: header && header[3] === "unconfined" ? "unconfined" : null,
    bodyClosed: body !== undefined,
    usernsGrant: body !== undefined && /^\s*(?:allow\s+)?userns\s*,\s*$/m.test(body),
    usernsDeny: body !== undefined && /^\s*deny\s+userns\b/m.test(body),
    parsedNameCount: names.length,
    parsedName: names.length === 1 && safeNames.has(names[0]) ? names[0] : null,
    unknownNamesSha256: names.some((name) => !safeNames.has(name)) ? sha(String(namesText)) : null
  };
}

export function nativePolicyObservation(spec, file, raw, expanded, parsedNames, registeredMd5, loadedMode, local) {
  const readable = trustedNativeFile(file, spec.policy) && typeof raw === "string";
  return {
    path: spec.policy, expectedExecutable: spec.path, file, contentRead: readable,
    sha256: readable ? sha(raw) : null, md5: readable ? sha(raw, "md5") : null,
    registeredMd5: /^[0-9a-f]{32}$/.test(registeredMd5 ?? "") ? registeredMd5 : null,
    expanded: typeof expanded === "string" && typeof parsedNames === "string" ? analyzeVendorProfile(expanded, parsedNames) : null,
    loadedProfile: loadedMode === undefined ? null : spec.name,
    loadedMode: ["enforce", "unconfined", "complain"].includes(loadedMode) ? loadedMode : null,
    localInclude: local
  };
}

export function validateNativePolicies(facts) {
  requireFact(facts?.apparmorEnabled === "Y" && facts?.restrictedUserns === "1", "Native AppArmor/user-namespace restriction state differs");
  requireFact(facts.packageVersion === NATIVE_APPARMOR_VERSION, "Unreviewed native AppArmor package version; safe facts retained");
  for (const [name, spec] of Object.entries(NATIVE_EXECUTABLES)) {
    const observed = facts.profiles?.[name];
    requireFact(observed && observed.path === spec.policy && observed.expectedExecutable === spec.path && trustedNativeFile(observed.file, spec.policy), `Untrusted vendor ${name} policy metadata; safe facts retained`);
    requireFact(observed.contentRead && observed.sha256 === spec.sha256 && observed.md5 === spec.md5 && observed.registeredMd5 === spec.md5, `Vendor ${name} policy/package identity differs; safe facts retained`);
    const local = observed.localInclude;
    requireFact(local?.exists === false || trustedNativeFile(local, `/etc/apparmor.d/local/${name}`) && local.bytes === 0, `Unreviewed local ${name} policy include; metadata retained without contents`);
    const parsed = observed.expanded;
    requireFact(parsed?.declarationCount === 1 && parsed.headerValid && parsed.profile === name && parsed.attachment === spec.path && parsed.flags === "unconfined" && parsed.bodyClosed && parsed.usernsGrant && !parsed.usernsDeny && parsed.parsedNameCount === 1 && parsed.parsedName === name, `Vendor ${name} executable/userns attachment differs; safe facts retained`);
    requireFact(observed.loadedProfile === name && ["enforce", "unconfined"].includes(observed.loadedMode), `Vendor ${name} policy is unloaded or in an unreviewed mode; safe facts retained`);
  }
}

export function analyzeSubordinateRanges(text, uid, username) {
  const records = [], own = [];
  let valid = true;
  for (const line of String(text).split("\n")) {
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const fields = line.split(":"), start = Number(fields[1]), count = Number(fields[2]);
    if (fields.length !== 3 || !fields[0] || !/^\d+$/.test(fields[1] ?? "") || !/^\d+$/.test(fields[2] ?? "") || !positive(start) || !positive(count) || start + count > 2 ** 32 - 1) { valid = false; continue; }
    const record = { start, count }; records.push(record);
    if ([String(uid), username].includes(fields[0])) own.push(record);
  }
  return { valid, recordCount: records.length, ownRanges: own,
    ownTotal: own.reduce((total, row) => total + row.count, 0),
    ownNonoverlapping: own.every((row) => records.filter((other) => row.start < other.start + other.count && other.start < row.start + row.count).length === 1) };
}

export function validateNativeMappings(facts) {
  for (const kind of ["uid", "gid"]) {
    const item = facts?.[kind], ranges = item?.ranges;
    requireFact(trustedNativeFile(item?.source, `/etc/sub${kind}`) && ranges?.valid && ranges.ownNonoverlapping && positive(ranges.ownTotal) && ranges.ownTotal >= 65536, `Native subordinate ${kind} allocation is unreviewed; safe facts retained`);
    requireFact(trustedNativeFile(item.helper, `/usr/bin/new${kind}map`, 0, 1024 * 1024) && (item.helper.mode & 0o111) && (Boolean(item.helper.mode & 0o4000) || item.capabilityEffective === true), `Native ${kind} mapping helper metadata/capability differs; safe facts retained`);
  }
}

export function validateNativeDestinations(facts) {
  for (const [name, spec] of Object.entries(NATIVE_EXECUTABLES)) {
    const item = facts?.[name];
    requireFact(item?.path === spec.path && item.parent?.exists === true && item.parent.canonical === spec.path.slice(0, spec.path.lastIndexOf("/")) && item.parent.type === "directory" && item.parent.uid === 0 && Number.isSafeInteger(item.parent.mode) && !(item.parent.mode & 0o022), `Untrusted native ${name} destination parent; safe facts retained`);
    requireFact(item.file?.exists === false || trustedNativeFile(item.file, spec.path, 0, 128 * 1024 * 1024) && item.file.bytes > 0 && /^[0-9a-f]{64}$/.test(item.file.sha256 ?? "") && item.packageOwner === spec.package, `Unreviewed native ${name} destination preimage/package; safe facts retained`);
  }
}

export function validateNativeSessionAndStorage(facts, uid, required, headroom) {
  requireFact(positive(uid) && facts?.runtimePath === `/run/user/${uid}` && facts.busSocket === true && facts.homeOwned === true && facts.userService === "inactive" && facts.userSocket === "inactive" && facts.userConfigAbsent === true && facts.userUnitsAbsent === true, "Native user session/unit/configuration preflight differs; safe facts retained");
  const delegation = facts.delegation;
  requireFact(positive(delegation?.pid) && delegation.pid > 1 && delegation.ownedPid === true && delegation.identityStable === true && delegation.controlGroup?.startsWith("/") && !delegation.controlGroup.split("/").includes("..") && delegation.delegate === "yes" && Array.isArray(delegation.controllers) && ["cpu", "memory"].every((name) => delegation.controllers.includes(name)), "Native user-manager CPU/memory delegation is unreviewed; safe facts retained");
  const capacity = delegation.capacity;
  requireFact(capacity && (capacity.path === delegation.controlGroup || capacity.path?.startsWith(delegation.controlGroup + "/")) && (capacity.cpuLimit === null || Number.isFinite(capacity.cpuLimit) && capacity.cpuLimit >= required.cpuCount) && (capacity.memoryLimit === null || Number.isSafeInteger(capacity.memoryLimit) && capacity.memoryLimit >= required.memoryBytes + headroom) && (capacity.memoryFree === null || Number.isSafeInteger(capacity.memoryFree) && capacity.memoryFree >= required.memoryBytes + headroom), "Native user-manager resource capacity is insufficient or unknown; safe facts retained");
  const storage = facts.storage;
  requireFact(storage?.fresh === true && [0xef53, 0x58465342].includes(storage.filesystemType) && Number.isSafeInteger(storage.freeBytes) && storage.freeBytes >= required.freshDiskBytes + headroom && Number.isSafeInteger(storage.freeInodes) && storage.freeInodes >= 250000, "Native fresh storage/available capacity differs; safe facts retained");
}
