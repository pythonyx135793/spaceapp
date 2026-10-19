#!/usr/bin/env node
// Native Ubuntu CI provisioning and real small-profile acceptance. No containerized builder.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants, createReadStream, readFileSync, readdirSync } from "node:fs";
import { appendFile, chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, readlink, realpath, statfs, unlink, writeFile } from "node:fs/promises";
import { availableParallelism, release, totalmem, userInfo } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { waitForTimedCommand } from "../../packages/run-spaceapp/src/command-timeout.mjs";
import { composeCommand, composeProjectName, PROFILE_REQUIREMENTS, profileRuntimeSettings } from "../../packages/run-spaceapp/src/index.mjs";
import { NATIVE_APT_KEYRING, nativeAptInputFacts, planOwnedNativeAptSources, readNativeAptInputs, validateNativeAptInputs } from "./native-apt-source.mjs";
import { analyzeSubordinateRanges, NATIVE_EXECUTABLES, nativePolicyObservation, nativeRuntimeConfig, trustedNativeFile, validateNativeDestinations, validateNativeMappings, validateNativePolicies, validateNativeSessionAndStorage } from "./native-host-prereqs.mjs";

const MINUTE = 60_000, GIB = 1024 ** 3, HEADROOM = 512 * 1024 ** 2;
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const LAUNCHER = join(ROOT, "packages/run-spaceapp/bin/spaceapp.mjs");
const REQUIRED = PROFILE_REQUIREMENTS.small;
const SOURCES = [
  ["libpathrs", "https://github.com/cyphar/libpathrs", "941f5488a93811bc6c00f6aa4f8c29095252f33b", "v0.2.6"],
  ["conmon", "https://github.com/containers/conmon", "c8cc2c4db27531bd4e084ce7857f73cd21ee639d", "v2.2.1"],
  ["passt", "https://passt.top/passt", "cba357068dc586e7540971eb40bb56c5e62c4de1", "2026_10_02.cba3570"],
  ["netavark", "https://github.com/containers/netavark", "8e91ad1d947ed325327b638f0cb906bea1f7d0ab", "v2.1.0"],
  ["aardvark-dns", "https://github.com/containers/aardvark-dns", "cd7417681229219059939bdd9f0b3bd9ac9abb08", "v2.1.0"],
  ["podman", "https://github.com/podman-container-tools/podman", "464c15fec06f0074c916f9eff87c4806869c2833", "v6.1.4"]
];
const ASSETS = [
  ["runc", "https://github.com/opencontainers/runc/releases/download/v1.5.2/runc.amd64", 10866512, "599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488"],
  ["docker-compose", "https://github.com/docker/compose/releases/download/v2.40.0/docker-compose-linux-x86_64", 76294653, "bd5835ccbbf06a42dcb5294c65e34a4634b34447afb9ed6fc7adf18a000e0f99"]
];
const NATIVE_DEPS = ["apparmor", "apparmor-utils", "uidmap", "catatonit", "libcap2-bin", "btrfs-progs", "libassuan-dev", "libbtrfs-dev", "libc6-dev", "libdevmapper-dev", "libglib2.0-dev", "libgpgme-dev", "libgpg-error-dev", "libprotobuf-dev", "libprotobuf-c-dev", "protobuf-compiler", "libseccomp-dev", "libselinux1-dev", "libsystemd-dev", "libapparmor-dev", "libssl-dev", "iptables", "nftables"];
const PROBE_NAME = /\bspaceapp-engine-probe-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b/g;
const state = { started: Date.now(), phase: "bootstrap", exitCode: 0, active: null, unconfirmed: [], probes: new Set(), secrets: new Set(), createdUserFiles: new Map(), nativeReady: false, appAttempted: false, purged: false, unitsCreated: false, cleanupConfirmed: false };

class Failure extends Error {
  constructor(message, exitCode = 1) { super(message); this.exitCode = exitCode; }
}
function requireThat(condition, message) { if (!condition) throw new Failure(message); }
function within(parent, path) {
  const rel = relative(parent, path);
  return rel !== "" && !rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel);
}
async function absent(path) {
  try { await lstat(path); return false; } catch (error) { if (error.code === "ENOENT") return true; throw error; }
}
async function regular(path, { max = Infinity, owner } = {}) {
  const value = await lstat(path);
  requireThat(value.isFile() && !value.isSymbolicLink() && value.size <= max && (owner === undefined || value.uid === owner), `Unexpected regular file: ${path}`);
  return value;
}
async function jsonFile(path, max = 1024 * 1024) { await regular(path, { max }); return JSON.parse(await readFile(path, "utf8")); }
async function hashFile(path, algorithm = "sha256") {
  await regular(path);
  const digest = createHash(algorithm), input = createReadStream(path);
  const timer = setTimeout(() => input.destroy(new Failure("File hashing deadline exceeded", 124)), 30_000);
  try { for await (const chunk of input) digest.update(chunk); return digest.digest("hex"); } finally { clearTimeout(timer); input.destroy(); }
}
function discoverSecrets() {
  if (!state.home) return;
  const add = (value) => {
    if (value.length < 12) return;
    for (const variant of [value, encodeURIComponent(value), Buffer.from(value).toString("base64")]) state.secrets.add(variant);
    try { state.secrets.add(decodeURIComponent(value)); } catch { /* A generated secret need not be URL encoded. */ }
  };
  try {
    const env = readFileSync(join(state.home, ".env"), "utf8");
    for (const line of env.split(/\r?\n/)) {
      const match = line.match(/^([A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|DATABASE_URL|API_KEY)[A-Z0-9_]*)=(.*)$/);
      if (match) add(match[2].replace(/^['"]|['"]$/g, ""));
    }
  } catch { /* Files may not exist yet, or may already have been purged. */ }
  try {
    for (const entry of readdirSync(join(state.home, "secrets"), { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const value = readFileSync(join(state.home, "secrets", entry.name), "utf8");
      if (value.length <= 32 * 1024) add(value.trim());
    }
  } catch { /* Final retained values still redact logs after purge. */ }
}
function redact(value) {
  discoverSecrets();
  let text = String(value).replace(/((?:New one-time|One-time) setup token:)[^\r\n]*/gi, "$1 [redacted]")
    .replace(/((?:postgresql?|https?):\/\/[^\s/:@]+:)[^@\s/]+@/gi, "$1[redacted]@");
  for (const secret of [...state.secrets].sort((a, b) => b.length - a.length)) text = text.split(secret).join("[redacted]");
  return text;
}
async function artifact(name, value) {
  requireThat(/^[a-z0-9][a-z0-9_.-]*$/.test(name), "Invalid evidence filename");
  const text = redact(typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`);
  await writeFile(join(state.logs, name), text, { mode: 0o600 });
}
async function event(kind, value) {
  if (state.logs) await appendFile(join(state.logs, "events.jsonl"), redact(`${JSON.stringify({ at: new Date().toISOString(), kind, ...value })}\n`), { mode: 0o600 });
}
function phaseDeadline() {
  return state.phase === "cleanup" ? state.cleanupDeadline : state.started + (state.phase === "bootstrap" ? 30 : 53) * MINUTE;
}
async function command(executable, args, { cwd = ROOT, timeout = 30_000, capture = false, allowFailure = false, env = {}, label = basename(executable) } = {}) {
  if (state.abort && state.phase !== "cleanup") throw state.abort;
  const remaining = phaseDeadline() - Date.now();
  if (remaining <= 0) throw new Failure(`${state.phase} budget exceeded`, 124);
  const child = spawn(executable, args, { cwd, shell: false, detached: true, env: { ...state.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
  state.active = child;
  let output = "", errorOutput = "", overflow = false, loggingError, writeChain = Promise.resolve();
  const pending = { stdout: "", stderr: "" };
  const emit = (line) => {
    if (label === "spaceapp install") for (const match of line.matchAll(PROBE_NAME)) state.probes.add(match[0]);
    if (label.startsWith("spaceapp ") && /(?:did not close after termination|cleanup could not be confirmed|remaining descendants.*unconfirmed)/i.test(line)) state.unconfirmed.push({ label: "launcher reported unconfirmed cleanup", launcherPid: child.pid });
    const safe = `${redact(line)}\n`;
    process.stdout.write(safe);
    writeChain = writeChain.then(() => appendFile(join(state.logs, "commands.log"), safe, { mode: 0o600 })).catch((error) => { loggingError ??= error; });
  };
  const receive = (chunk, stream) => {
    const text = chunk.toString("utf8");
    if (Buffer.byteLength(output) + Buffer.byteLength(errorOutput) + chunk.length > 8 * 1024 * 1024) { overflow = true; return; }
    if (stream === "stdout") output += text; else errorOutput += text;
    if (capture && stream === "stdout") return;
    pending[stream] += text;
    const lines = pending[stream].split("\n"); pending[stream] = lines.pop();
    for (const line of lines) emit(line);
    if (pending[stream].length > 1024 * 1024) { overflow = true; pending[stream] = ""; }
  };
  child.stdout.on("data", (chunk) => receive(chunk, "stdout")); child.stderr.on("data", (chunk) => receive(chunk, "stderr"));
  const supervised = waitForTimedCommand(child, {
    timeoutMs: Math.min(timeout, remaining), graceMs: 1000, ownedGroup: true,
    onTimeout: () => process.stderr.write(`Deadline exceeded: ${label}; terminating only its owned process group.\n`),
    onUnconfirmedExit: () => { state.unconfirmed.push({ label, pid: child.pid }); process.stderr.write(`Command exit/descendant cleanup is unconfirmed: ${label}.\n`); }
  });
  const recordedStart = event("command-start", { label, executable, args, pid: child.pid ?? null, timeoutMs: Math.min(timeout, remaining) }).catch((error) => { loggingError ??= error; });
  const code = await supervised;
  for (const text of Object.values(pending)) if (text) emit(text);
  await recordedStart; await writeChain;
  state.active = null;
  const result = overflow && code === 0 ? 1 : code;
  await event("command-exit", { label, pid: child.pid ?? null, code: result, outputOverflow: overflow }).catch((error) => { loggingError ??= error; });
  if (state.abort && state.phase !== "cleanup") throw state.abort;
  if (result !== 0 && !allowFailure) throw new Failure(`${label} failed with exit ${result}${overflow ? " (output limit)" : ""}`, result);
  if (loggingError) throw new Failure(`${label} evidence could not be saved after command settlement`);
  return { code: result, output: output.trim(), stderr: redact(errorOutput.trim()) };
}
async function output(executable, args, options = {}) { return (await command(executable, args, { ...options, capture: true })).output; }
async function podman(args, options = {}) { return command("/usr/bin/podman", args, { ...options, capture: true }); }
async function podmanJson(args) { return JSON.parse((await podman(args)).output); }
async function launcher(args, timeout = 120_000, label = args[0]) { return command(process.execPath, [LAUNCHER, ...args], { timeout, label: `spaceapp ${label}` }); }
function onSignal(signal) {
  state.abort ??= new Failure(`Received ${signal}`, signal === "SIGINT" ? 130 : 143);
  if (state.exitCode === 0) state.exitCode = state.abort.exitCode;
  const child = state.active;
  if (child?.pid && child.exitCode === null && child.signalCode === null) {
    try { process.kill(-child.pid, "SIGTERM"); } catch { /* A child can exit between the checks. */ }
  }
}
process.on("SIGTERM", () => onSignal("SIGTERM"));
process.on("SIGINT", () => onSignal("SIGINT"));

function parseRanges(text) {
  return text.trim().split(/\n/).map((line) => {
    const fields = line.trim().split(/\s+/).map(Number);
    requireThat(fields.length === 3 && fields.every(Number.isSafeInteger) && fields[0] >= 0 && fields[1] >= 0 && fields[2] > 0, "Malformed namespace map");
    return fields;
  });
}
function parseCpuList(text) {
  const cpus = new Set();
  requireThat(/^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/.test(text.trim()), "Invalid CPU affinity list");
  for (const field of text.trim().split(",")) {
    const [first, last = first] = field.split("-").map(Number);
    requireThat(last >= first && last - first <= 65536, "Invalid CPU affinity range");
    for (let n = first; n <= last; n++) cpus.add(n);
  }
  return cpus.size;
}
function statusFields(text) { return Object.fromEntries(text.trim().split("\n").map((line) => { const i = line.indexOf(":"); return [line.slice(0, i), line.slice(i + 1).trim()]; })); }
async function cgroupCapacity(pid = "self") {
  const text = await readFile(`/proc/${pid}/cgroup`, "utf8");
  const path = text.split("\n").find((line) => line.startsWith("0::"))?.slice(3);
  requireThat(path?.startsWith("/") && !path.split("/").includes(".."), "Missing native cgroupv2 process membership");
  const root = "/sys/fs/cgroup", selected = resolve(root, `.${path}`);
  requireThat(selected === root || within(root, selected), "Cgroup path escapes native hierarchy");
  let cpuLimit = Infinity, memoryLimit = Infinity, memoryFree = Infinity;
  for (let current = selected; ; current = dirname(current)) {
    for (const filename of ["cpu.max", "memory.max"]) {
      if (await absent(join(current, filename))) continue;
      const value = (await readFile(join(current, filename), "utf8")).trim();
      if (filename === "cpu.max") {
        const [q, p] = value.split(/\s+/);
        requireThat(/^\d+$/.test(p) && Number.isSafeInteger(Number(p)) && Number(p) > 0 && (q === "max" || /^\d+$/.test(q) && Number.isSafeInteger(Number(q)) && Number(q) > 0), "Malformed cgroup CPU capacity");
        if (q !== "max") cpuLimit = Math.min(cpuLimit, Number(q) / Number(p));
      } else if (value !== "max") {
        requireThat(/^\d+$/.test(value) && Number.isSafeInteger(Number(value)) && Number(value) > 0, "Malformed cgroup memory capacity");
        const used = Number((await readFile(join(current, "memory.current"), "utf8")).trim());
        requireThat(Number.isSafeInteger(used) && used >= 0, "Malformed current cgroup memory usage");
        memoryLimit = Math.min(memoryLimit, Number(value)); memoryFree = Math.min(memoryFree, Number(value) - used);
      }
    }
    if (current === root) break;
  }
  return { path, cpuLimit: Number.isFinite(cpuLimit) ? cpuLimit : null, memoryLimit: Number.isFinite(memoryLimit) ? memoryLimit : null, memoryFree: Number.isFinite(memoryFree) ? memoryFree : null };
}
async function resources(name, diskPath, minimumDisk) {
  const status = statusFields(await readFile("/proc/self/status", "utf8"));
  const affinity = parseCpuList(status.Cpus_allowed_list), cpuCount = Math.min(availableParallelism(), affinity);
  const mem = statusFields(await readFile("/proc/meminfo", "utf8"));
  const memTotal = Number(mem.MemTotal?.split(/\s+/)[0]) * 1024, memAvailable = Number(mem.MemAvailable?.split(/\s+/)[0]) * 1024;
  const capacity = await cgroupCapacity();
  const filesystem = await statfs(diskPath), free = Number(filesystem.bavail) * Number(filesystem.bsize);
  const facts = { kernel: release(), cpuCount, affinity, availableParallelism: availableParallelism(), memoryBytes: Math.min(totalmem(), memTotal), memoryAvailableBytes: memAvailable, freeDiskBytes: free, freeInodes: Number(filesystem.ffree), cgroup: capacity };
  await artifact(`${name}.json`, facts);
  requireThat(cpuCount >= REQUIRED.cpuCount && (capacity.cpuLimit === null || capacity.cpuLimit >= REQUIRED.cpuCount), "The real CPU affinity/quota is below small's4CPU requirement");
  requireThat(Number.isFinite(memAvailable) && facts.memoryBytes >= REQUIRED.memoryBytes && memAvailable >= REQUIRED.memoryBytes + HEADROOM, "Insufficient real usable/available memory and headroom");
  requireThat((capacity.memoryLimit === null || capacity.memoryLimit >= REQUIRED.memoryBytes + HEADROOM) && (capacity.memoryFree === null || capacity.memoryFree >= REQUIRED.memoryBytes + HEADROOM), "Cgroup memory capacity/headroom is insufficient");
  requireThat(Number.isSafeInteger(free) && free >= minimumDisk && Number.isSafeInteger(facts.freeInodes) && facts.freeInodes >= 250000, "Insufficient real available disk/inodes for native build or small installation");
}

async function initialize() {
  requireThat(process.platform === "linux" && process.arch === "x64" && process.getuid() !== 0, "This helper requires a native Linux x86_64 nonroot runner");
  process.umask(0o022);
  const osRelease = await readFile("/etc/os-release", "utf8");
  requireThat(/^ID=ubuntu$/m.test(osRelease) && /^VERSION_ID="24\.04"$/m.test(osRelease), "The native bootstrap currently supports ubuntu-latest on Ubuntu24.04 only; review runner drift");
  requireThat(process.env.GITHUB_ACTIONS === "true" && process.env.RUNNER_OS === "Linux" && process.env.RUNNER_ARCH === "X64", "A genuine native GitHub Linux runner is required");
  requireThat(process.env.SPACEAPP_CI_REPOSITORY_VISIBILITY === "public", "Standard private runners cannot satisfy the unchanged small CPU gate");
  for (const name of ["CONTAINER_HOST", "CONTAINER_CONNECTION", "CONTAINERS_CONF", "CONTAINERS_CONF_OVERRIDE", "CONTAINERS_STORAGE_CONF", "PODMAN_CONNECTIONS_CONF"]) requireThat(!Object.hasOwn(process.env, name), `Unexpected inherited engine selector: ${name}`);
  const runId = process.env.GITHUB_RUN_ID, attempt = process.env.GITHUB_RUN_ATTEMPT;
  requireThat(/^\d+$/.test(runId ?? "") && /^\d+$/.test(attempt ?? ""), "Missing genuine run identity");
  state.temp = await realpath(process.env.RUNNER_TEMP ?? "");
  const home = resolve(process.env.SPACEAPP_HOME ?? "");
  requireThat(home === join(state.temp, `spaceapp-podman-${runId}-${attempt}`) && await absent(home), "Installation root must be this run's fresh exact temp path");
  state.home = home;
  const ciRoot = join(state.temp, `spaceapp-native-${runId}-${attempt}`);
  state.aptPrefix = `spaceapp-native-apt-${runId}-${attempt}-`;
  const logs = join(state.temp, "spaceapp-podman-logs");
  requireThat(await absent(ciRoot) && await absent(logs), "CI evidence/build roots must be fresh");
  await mkdir(logs, { mode: 0o700 }); state.logs = logs;
  await mkdir(ciRoot, { mode: 0o755 }); state.ciRoot = ciRoot;
  state.build = join(state.ciRoot, "build"); state.provider = join(state.ciRoot, "provider");
  await mkdir(state.build, { mode: 0o755 }); await mkdir(join(state.build, "src"), { mode: 0o755 }); await mkdir(state.provider, { mode: 0o700 });
  state.project = composeProjectName(state.home);
  state.runtimeDir = process.env.XDG_RUNTIME_DIR;
  const allowed = ["HOME", "USER", "LOGNAME", "PATH", "LANG", "LC_ALL", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "TERM", "RUSTUP_HOME"];
  state.env = Object.fromEntries(allowed.filter((name) => process.env[name] !== undefined).map((name) => [name, process.env[name]]));
  const goBin = join(process.env.RUNNER_TOOL_CACHE ?? "", "go/1.26.9/x64/bin");
  state.env = { ...state.env, PATH: `${state.provider}:${goBin}:${state.env.PATH}`, CI: "true", GOTOOLCHAIN: "local", GOMAXPROCS: "2", GOCACHE: join(state.build, "go-cache"), GOPATH: join(state.build, "go"), GOPROXY: "off", CARGO_HOME: join(state.build, "cargo-home"), CARGO_BUILD_JOBS: "2", RUSTUP_TOOLCHAIN: "stable", RUSTUP_AUTO_INSTALL: "0", CC: "gcc-13", CXX: "g++-13", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "/bin/false", SPACEAPP_HOME: state.home, PODMAN_COMPOSE_PROVIDER: "docker-compose" };
  const initialErrors = [], initialSession = await collectNativeSession(initialErrors);
  await artifact("native-initial-session-prerequisites.json", { session: initialSession, errors: initialErrors });
  if (initialErrors.length) throw new Failure("Initial native session observations are incomplete; safe facts retained", initialErrors[0].exitCode);
  validateNativeSessionAndStorage(initialSession, process.getuid(), REQUIRED, HEADROOM);

  const tools = { go: await output("go", ["version"]) };
  await artifact("existing-toolchain.json", tools);
  requireThat(tools.go.split(/\s+/)[2] === "go1.26.9", "Pinned existing Go1.26.9 is unavailable");
  for (const executable of ["rustc", "cargo"]) {
    tools[executable] = await output(executable, ["--version"]); await artifact("existing-toolchain.json", tools);
    requireThat(tools[executable].split(/\s+/)[1] === "1.99.0", `Pinned existing ${executable}1.99.0 is unavailable`);
  }
  for (const executable of ["gcc-13", "g++-13", "git", "make", "curl", "pkg-config", "python3"]) tools[executable] = await output(executable, ["--version"]);
  await artifact("existing-toolchain.json", tools);
  const container = await command("systemd-detect-virt", ["--container"], { capture: true, allowFailure: true });
  requireThat(container.code === 1 && container.output === "none", "Nested container provisioning cannot replace the native Ubuntu runner");
  requireThat(Number((await statfs("/sys/fs/cgroup")).type) === 0x63677270, "The native cgroup filesystem is not cgroupv2");
  await artifact("source-pins.json", { sources: SOURCES, assets: ASSETS, aptKeyring: NATIVE_APT_KEYRING, nativeDependencies: NATIVE_DEPS, engine: "6.1.4", provider: "2.40.0", runnerImage: process.env.ImageVersion ?? null, runnerOS: osRelease, appArmorLimitation: "Upstream Podman6.1.4 rootless skips default per-container AppArmor and rejects explicit profiles; vendor executable namespace policy remains enabled. No per-container AppArmor confinement is claimed." });
  await resources("before-build", state.build, 10 * GIB);
}

async function installDependencies() {
  const inputs = await readNativeAptInputs();
  // Retain safe observed facts even when policy rejects an input. Never log raw source text.
  await artifact("native-apt-observed-inputs.json", nativeAptInputFacts(inputs));
  validateNativeAptInputs(inputs);
  // _apt must traverse its own download area without making the runner HOME public.
  requireThat(await realpath("/var/tmp") === "/var/tmp" && (await lstat("/var/tmp")).uid === 0, "Unreviewed native apt scratch parent");
  state.aptRoot = await mkdtemp(join("/var/tmp", state.aptPrefix)); await chmod(state.aptRoot, 0o755);
  const owned = await lstat(state.aptRoot);
  requireThat(owned.isDirectory() && !owned.isSymbolicLink() && owned.uid === process.getuid() && !(owned.mode & 0o022) && await realpath(state.aptRoot) === state.aptRoot, "Untrusted owned native apt scratch");
  await mkdir(join(state.aptRoot, "lists"), { mode: 0o755 }); await mkdir(join(state.aptRoot, "archives"), { mode: 0o755 });
  const sourceDir = join(state.aptRoot, "sources"); await mkdir(sourceDir, { mode: 0o755 });
  const plan = planOwnedNativeAptSources(inputs, { root: state.aptRoot, prefix: state.aptPrefix });
  const packagePath = join(state.aptRoot, NATIVE_APT_KEYRING.packageName);
  requireThat(await absent(packagePath) && await absent(plan.keyringPath), "Owned Ubuntu keyring paths already exist");
  await command("curl", ["--fail", "--silent", "--show-error", "--proto", "=https", "--tlsv1.2", "--connect-timeout", "10", "--max-time", "30", "--max-filesize", String(NATIVE_APT_KEYRING.packageBytes), "--output", packagePath, NATIVE_APT_KEYRING.url], { timeout: 35_000, label: "pinned official Ubuntu keyring package" });
  const pkg = await regular(packagePath, { owner: process.getuid(), max: NATIVE_APT_KEYRING.packageBytes });
  requireThat(pkg.size === NATIVE_APT_KEYRING.packageBytes && await hashFile(packagePath) === NATIVE_APT_KEYRING.packageSha256, "Official Ubuntu keyring package integrity failed");
  await chmod(packagePath, 0o444);
  const extraction = await command("python3", ["-I", "-B", join(ROOT, "scripts/ci/native-apt-keyring.py"), packagePath, plan.keyringPath], { timeout: 30_000, capture: true, allowFailure: true, label: "read only the pinned Ubuntu archive keyring" });
  if (extraction.code !== 0) {
    state.unconfirmed.push({ label: "pinned keyring extraction did not confirm owned decoder cleanup" });
    throw new Failure(`Read-only pinned keyring extraction failed with exit ${extraction.code}`, extraction.code);
  }
  const keyringReceipt = JSON.parse(extraction.output);
  const keyring = await regular(plan.keyringPath, { owner: process.getuid(), max: NATIVE_APT_KEYRING.keyringBytes });
  const keyringHash = await hashFile(plan.keyringPath);
  requireThat(keyring.size === NATIVE_APT_KEYRING.keyringBytes && (keyring.mode & 0o7777) === 0o444 && await realpath(plan.keyringPath) === plan.keyringPath && keyringHash === NATIVE_APT_KEYRING.keyringSha256, "Owned Ubuntu archive keyring could not be verified");
  requireThat(keyringReceipt.packageBytes === NATIVE_APT_KEYRING.packageBytes && keyringReceipt.packageSha256 === NATIVE_APT_KEYRING.packageSha256 && keyringReceipt.keyringBytes === keyring.size && keyringReceipt.keyringSha256 === keyringHash && keyringReceipt.path === plan.keyringPath && keyringReceipt.hostKeyringUsed === false && keyringReceipt.packageInstalled === false && keyringReceipt.maintainerScriptsExecuted === false, "Pinned keyring extraction receipt differs from actual verified files");
  const copies = [[plan.sourcePath, plan.sourceBytes, plan.copiedSourceSha256]];
  if (plan.mirrorBytes) copies.push([plan.mirrorPath, plan.mirrorBytes, plan.copiedMirrorSha256]);
  const receipts = [{ path: plan.keyringPath, bytes: keyring.size, sha256: keyringHash, mode: "444" }];
  for (const [path, bytes, expectedSha256] of copies) {
    await writeFile(path, bytes, { mode: 0o644, flag: "wx" });
    const file = await regular(path, { owner: process.getuid(), max: bytes.length });
    const actual = await readFile(path), hash = createHash("sha256").update(actual).digest("hex");
    requireThat(file.size === bytes.length && !(file.mode & 0o022) && await realpath(path) === path && actual.equals(bytes) && hash === expectedSha256, "Owned native apt copy could not be verified");
    receipts.push({ path, bytes: actual.length, sha256: hash });
  }
  for (const { path } of receipts) await command("sudo", ["-n", "-u", "_apt", "--", "/usr/bin/test", "-r", path], { label: "ordinary APT sandbox input traversal" });
  await artifact("native-apt-owned-inputs.json", { sourceSha256: plan.sourceSha256, mirrorSha256: plan.mirrorSha256, keyringSha256: keyringHash, usesMirror: plan.usesMirror, hostKeyringUsed: false, keyringPackage: keyringReceipt, copies: receipts });
  state.apt = ["-o", "Dir::Etc::sourcelist=/dev/null", "-o", `Dir::Etc::sourceparts=${sourceDir}`, "-o", `Dir::State::lists=${join(state.aptRoot, "lists")}`, "-o", `Dir::Cache::archives=${join(state.aptRoot, "archives")}`, "-o", "Acquire::AllowInsecureRepositories=false", "-o", "APT::Get::AllowUnauthenticated=false"];
  const update = await command("sudo", ["-n", "apt-get", ...state.apt, "update"], { timeout: 5 * MINUTE, label: "signed Ubuntu dependency metadata" });
  requireThat(!/unsandboxed as root/i.test(update.stderr), "APT could not use its ordinary download sandbox");
  const simulated = await output("sudo", ["-n", "apt-get", ...state.apt, "--simulate", "--no-remove", "--no-install-recommends", "install", ...NATIVE_DEPS], { timeout: MINUTE });
  requireThat(!/^Remv\s/m.test(simulated), "Native dependencies would remove unrelated packages"); await artifact("apt-plan.txt", simulated);
  const install = await command("sudo", ["-n", "--preserve-env=DEBIAN_FRONTEND", "apt-get", ...state.apt, "--no-remove", "--no-install-recommends", "install", "-y", ...NATIVE_DEPS], { timeout: 8 * MINUTE, env: { DEBIAN_FRONTEND: "noninteractive" }, label: "signed Ubuntu native dependencies" });
  requireThat(!/unsandboxed as root/i.test(install.stderr), "APT could not use its ordinary download sandbox");
  await artifact("native-package-versions.tsv", await output("dpkg-query", ["-W", "-f=${Package}\t${Version}\n", ...NATIVE_DEPS]));
  await artifact("native-package-origins.txt", await output("apt-cache", [...state.apt, "policy", ...NATIVE_DEPS]));
}

async function nativeSnapshot(path, max = 256 * 1024) {
  let file;
  try { file = await lstat(path); } catch (error) { if (error.code === "ENOENT") return { exists: false }; throw error; }
  let canonical = null;
  try { canonical = await realpath(path); } catch { /* Broken links remain observed, never trusted. */ }
  const facts = { exists: true, type: file.isSymbolicLink() ? "symlink" : file.isFile() ? "regular" : file.isDirectory() ? "directory" : file.isSocket() ? "socket" : "other", canonical, uid: file.uid, gid: file.gid, mode: file.mode & 0o7777, bytes: file.size, device: file.dev, inode: file.ino, mtimeMs: file.mtimeMs };
  if (trustedNativeFile(facts, path, 0, max)) facts.sha256 = await hashFile(path);
  return facts;
}

async function observeNative(errors, field, operation) {
  try { return await operation(); } catch (error) {
    const code = /^[A-Z0-9_]{1,40}$/.test(error.code ?? "") ? error.code : Number.isInteger(error.exitCode) ? `EXIT_${error.exitCode}` : "OBSERVATION_FAILED";
    const exitCode = Number.isInteger(error.exitCode) && error.exitCode > 0 ? error.exitCode : 1;
    errors.push({ field, code, exitCode }); return { observationFailed: true, code, exitCode };
  }
}

async function collectVendorPolicies(errors) {
  const observe = (field, operation) => observeNative(errors, field, operation);
  const facts = { profiles: {} };
  facts.apparmorEnabled = await observe("apparmorEnabled", async () => (await readFile("/sys/module/apparmor/parameters/enabled", "utf8")).trim());
  facts.restrictedUserns = await observe("restrictedUserns", async () => (await readFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "utf8")).trim());
  facts.packageVersion = await observe("apparmorPackageVersion", () => output("dpkg-query", ["-W", "-f=${Version}", "apparmor"], { timeout: 10_000 }));
  const registered = await observe("registeredVendorPolicies", () => output("dpkg-query", ["-W", "-f=${Conffiles}", "apparmor"], { timeout: 10_000 }));
  const loaded = await observe("loadedVendorPolicies", async () => JSON.parse(await output("sudo", ["-n", "aa-status", "--json"], { timeout: 10_000 })));
  for (const [name, spec] of Object.entries(NATIVE_EXECUTABLES)) {
      const file = await observe(`policy-${name}-metadata`, () => nativeSnapshot(spec.policy));
      const local = await observe(`policy-${name}-local-include-metadata`, () => nativeSnapshot(`/etc/apparmor.d/local/${name}`));
      const entry = typeof registered === "string" ? registered.split("\n").map((line) => line.trim().split(/\s+/)).find((fields) => fields[0] === spec.policy) : undefined;
      const raw = trustedNativeFile(file, spec.policy) ? await observe(`policy-${name}-source`, () => readFile(spec.policy, "utf8")) : undefined;
      const sourceKnown = file.sha256 === spec.sha256 && entry?.[1] === spec.md5;
      const localKnown = local.exists === false || trustedNativeFile(local, `/etc/apparmor.d/local/${name}`) && local.bytes === 0;
      let expanded, names;
      if (sourceKnown && localKnown) {
        expanded = await observe(`policy-${name}-preprocess`, () => output("sudo", ["-n", "apparmor_parser", "--preprocess", spec.policy], { timeout: 10_000 }));
        names = await observe(`policy-${name}-parsed-names`, () => output("sudo", ["-n", "apparmor_parser", "--names", spec.policy], { timeout: 10_000 }));
      }
      const modes = loaded?.profiles ?? {};
      facts.profiles[name] = nativePolicyObservation(spec, file, raw, expanded, names, entry?.[1], modes[name] ?? modes[spec.path], local);
  }
  return facts;
}

async function nativeDestination(name, errors) {
  const spec = NATIVE_EXECUTABLES[name];
  const file = await observeNative(errors, `destination-${name}-file`, () => nativeSnapshot(spec.path, 128 * 1024 * 1024));
  const parent = await observeNative(errors, `destination-${name}-parent`, () => nativeSnapshot(dirname(spec.path)));
  let packageOwner = null, unreviewedPackageOwnerSha256 = null;
  if (file.exists) {
    const found = await observeNative(errors, `destination-${name}-package`, async () => {
      const value = await command("dpkg-query", ["-S", "--", spec.path], { capture: true, allowFailure: true, timeout: 10_000 });
      if (![0, 1].includes(value.code)) throw new Failure("Native destination package ownership could not be inspected", value.code);
      return value;
    });
    if (found.code === 0) {
      const lines = found.output.split("\n").filter(Boolean);
      const prefix = lines.length === 1 && lines[0].endsWith(`: ${spec.path}`) ? lines[0].slice(0, -spec.path.length - 2).replace(/:amd64$/, "") : "";
      if (["podman", "runc", "containerd.io"].includes(prefix)) packageOwner = prefix;
      else unreviewedPackageOwnerSha256 = createHash("sha256").update(found.output).digest("hex");
    }
  }
  return { path: spec.path, file, parent, packageOwner, unreviewedPackageOwnerSha256 };
}

async function assertNativeDestinationPreimage(name) {
  const errors = [], current = await nativeDestination(name, errors);
  await artifact(`native-${name}-destination-before-replacement.json`, { ...current, errors });
  if (errors.length) throw new Failure("Native destination preimage inspection failed; safe facts retained", errors[0].exitCode);
  validateNativeDestinations({ ...state.destinationPreimages, [name]: current });
  requireThat(JSON.stringify(current.file) === JSON.stringify(state.destinationPreimages[name].file) && current.packageOwner === state.destinationPreimages[name].packageOwner, `Native ${name} destination changed since its reviewed preflight`);
}

async function collectNativeMappings(errors) {
  const facts = {};
  for (const kind of ["uid", "gid"]) {
    const path = `/etc/sub${kind}`;
    const source = await observeNative(errors, `mapping-${kind}-source-metadata`, () => nativeSnapshot(path));
    const helper = await observeNative(errors, `mapping-${kind}-helper-metadata`, () => nativeSnapshot(`/usr/bin/new${kind}map`, 1024 * 1024));
    const text = trustedNativeFile(source, path) ? await observeNative(errors, `mapping-${kind}-source`, () => readFile(path, "utf8")) : undefined;
    const caps = await observeNative(errors, `mapping-${kind}-capability`, () => output("getcap", [`/usr/bin/new${kind}map`], { timeout: 10_000 }));
    facts[kind] = { source, helper, ranges: typeof text === "string" ? analyzeSubordinateRanges(text, process.getuid(), userInfo().username) : null,
      capabilityEffective: typeof caps === "string" && new RegExp(`(?:^|\\s)cap_set${kind}(?:,[a-z_]+)*[+=]ep(?:\\s|$)`).test(caps) };
  }
  return facts;
}

async function collectNativeSession(errors) {
  const facts = {}, observe = (name, operation) => observeNative(errors, name, operation);
  facts.runtimePath = state.runtimeDir;
  facts.busSocket = await observe("userBus", async () => (await lstat(join(state.runtimeDir, "bus"))).isSocket());
  facts.homeOwned = await observe("ownedNormalHome", async () => await realpath(process.env.HOME) === process.env.HOME && (await lstat(process.env.HOME)).uid === process.getuid());
  for (const [key, unit] of [["userService", "podman.service"], ["userSocket", "podman.socket"]]) facts[key] = await observe(key, () => output("systemctl", ["--user", "show", unit, "--property=ActiveState", "--value"], { timeout: 10_000 }));
  facts.userConfigAbsent = await observe("userConfigAbsent", () => absent(join(process.env.HOME, ".config/containers/containers.conf")));
  facts.userUnitsAbsent = await observe("userUnitsAbsent", async () => await absent(join(process.env.HOME, ".config/systemd/user/podman.service")) && await absent(join(process.env.HOME, ".config/systemd/user/podman.socket")));
  facts.delegation = await observe("userManagerDelegation", async () => {
    const unit = `user@${process.getuid()}.service`;
    const pidValue = await observe("userManagerPid", () => output("systemctl", ["show", unit, "--property=MainPID", "--value"], { timeout: 10_000 }));
    const pid = typeof pidValue === "string" && /^\d+$/.test(pidValue) && Number(pidValue) > 1 ? Number(pidValue) : null;
    const controlGroup = await observe("userManagerCgroup", () => output("systemctl", ["show", unit, "--property=ControlGroup", "--value"], { timeout: 10_000 }));
    const delegate = await observe("userManagerDelegate", () => output("systemctl", ["show", unit, "--property=Delegate", "--value"], { timeout: 10_000 }));
    const root = typeof controlGroup === "string" && controlGroup.startsWith("/") && !controlGroup.split("/").includes("..") ? resolve("/sys/fs/cgroup", `.${controlGroup}`) : null;
    const controllers = root && within("/sys/fs/cgroup", root) ? await observe("userManagerControllers", async () => (await readFile(join(root, "cgroup.controllers"), "utf8")).trim().split(/\s+/)) : null;
    const subtreeControllers = root && within("/sys/fs/cgroup", root) ? await observe("userManagerSubtreeControllers", async () => (await readFile(join(root, "cgroup.subtree_control"), "utf8")).trim().split(/\s+/).filter(Boolean)) : null;
    const before = pid ? await observe("userManagerStartBefore", () => readFile(`/proc/${pid}/stat`, "utf8")) : null;
    const identity = pid ? await observe("userManagerOwnership", async () => statusFields(await readFile(`/proc/${pid}/status`, "utf8"))) : null;
    const capacity = pid ? await observe("userManagerCapacity", () => cgroupCapacity(pid)) : null;
    const after = pid ? await observe("userManagerStartAfter", () => readFile(`/proc/${pid}/stat`, "utf8")) : null;
    const currentPidValue = await observe("userManagerPidAfter", () => output("systemctl", ["show", unit, "--property=MainPID", "--value"], { timeout: 10_000 }));
    const currentPid = typeof currentPidValue === "string" ? Number(currentPidValue) : null;
    const start = (text) => typeof text === "string" ? text.slice(text.lastIndexOf(")") + 2).split(/\s+/)[19] : null;
    return { pid, controlGroup, delegate, controllers, subtreeControllers, capacity,
      ownedPid: identity?.Uid?.split(/\s+/).every((id) => Number(id) === process.getuid()) === true,
      identityStable: /^\d+$/.test(start(before)) && start(before) === start(after) && pid === currentPid };
  });
  facts.storage = await observe("nativeStorageParent", async () => {
    const fs = await statfs(process.env.HOME);
    return { fresh: await absent(join(process.env.HOME, ".local/share/containers/storage")), filesystemType: Number(fs.type), freeBytes: Number(fs.bavail) * Number(fs.bsize), freeInodes: Number(fs.ffree) };
  });
  return facts;
}

async function nativeHostPrerequisites() {
  const facts = { schemaVersion: 1, errors: [], note: "Observed availability/delegation is not application limit enforcement; the production probe is unchanged." };
  facts.policies = await collectVendorPolicies(facts.errors);
  facts.destinations = {};
  for (const name of Object.keys(NATIVE_EXECUTABLES)) facts.destinations[name] = await observeNative(facts.errors, `destination-${name}`, () => nativeDestination(name, facts.errors));
  facts.mappings = await collectNativeMappings(facts.errors);
  facts.session = await collectNativeSession(facts.errors);
  await artifact("native-host-prerequisites-before-build.json", facts);
  if (facts.errors.length) throw new Failure("Native prerequisite observations are incomplete; all safe facts were retained before validation", facts.errors[0].exitCode);
  validateNativePolicies(facts.policies); validateNativeDestinations(facts.destinations);
  validateNativeMappings(facts.mappings); validateNativeSessionAndStorage(facts.session, process.getuid(), REQUIRED, HEADROOM);
  state.vendorProfiles = Object.fromEntries(Object.entries(NATIVE_EXECUTABLES).map(([name, spec]) => [name, { profile: spec.name, executable: spec.path, mode: facts.policies.profiles[name].loadedMode }]));
  state.destinationPreimages = facts.destinations;
  state.subids = Object.fromEntries(["uid", "gid"].map((kind) => [kind, facts.mappings[kind].ranges.ownRanges]));
}

async function vendorPolicy(stage) {
  const errors = [], facts = await collectVendorPolicies(errors);
  await artifact(`apparmor-${stage}.json`, { ...facts, errors, perContainerLimitation: "Rootless Podman skips the default per-container AppArmor profile upstream; actual labels are recorded separately." });
  if (errors.length) throw new Failure("Native policy observations are incomplete; safe facts retained", errors[0].exitCode);
  validateNativePolicies(facts);
}

async function sourceMetadata(name, path, stage) {
  const files = {};
  for (const file of ["Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "vendor/modules.txt", "Makefile"]) if (!await absent(join(path, file))) files[file] = { size: (await regular(join(path, file))).size, sha256: await hashFile(join(path, file)) };
  await artifact(`${name}-source-${stage}.json`, { commit: await output("git", ["rev-parse", "HEAD"], { cwd: path }), tree: await output("git", ["rev-parse", "HEAD^{tree}"], { cwd: path }), files });
}
async function buildNative() {
  for (const [name, url, commit, tag] of SOURCES) {
    const path = join(state.build, "src", name); await mkdir(path, { mode: 0o755 });
    await command("git", ["init"], { cwd: path });
    await command("git", ["-c", "protocol.version=2", "fetch", "--no-tags", "--depth=1", url, commit], { cwd: path, timeout: 3 * MINUTE, label: `fetch pinned ${name}` });
    requireThat(await output("git", ["rev-parse", "FETCH_HEAD"], { cwd: path }) === commit, `Wrong ${name} source identity`);
    await command("git", ["checkout", "--detach", "FETCH_HEAD"], { cwd: path });
    await command("git", ["fsck", "--strict", "--no-dangling"], { cwd: path, timeout: MINUTE });
    if (name === "passt") {
      await command("git", ["fetch", "--no-tags", "--depth=1", url, `refs/tags/${tag}:refs/tags/${tag}`], { cwd: path, timeout: MINUTE });
      requireThat(await output("git", ["rev-parse", `refs/tags/${tag}^{commit}`], { cwd: path }) === commit, "Pasta release tag does not match its pinned source");
    }
    await sourceMetadata(name, path, "before");
    if (name === "libpathrs") {
      await regular(join(path, "Cargo.lock")); await command("make", ["EXTRA_CARGO_FLAGS=--locked", "release"], { cwd: path, timeout: 8 * MINUTE, label: "native libpathrs" });
      await command("sudo", ["-n", "bash", "./install.sh", "--prefix=/usr/local", "--libdir=/usr/local/lib", "--disable-static"], { cwd: path, timeout: MINUTE }); await command("sudo", ["-n", "ldconfig"]);
    } else if (name === "conmon") {
      await command("make", ["-j2"], { cwd: path, timeout: 3 * MINUTE }); await command("sudo", ["-n", "install", "-D", "-m0755", "bin/conmon", "/usr/libexec/podman/conmon"], { cwd: path });
    } else if (name === "passt") {
      await command("make", ["-j2"], { cwd: path, timeout: 4 * MINUTE }); await command("sudo", ["-n", "make", "prefix=/usr", "install"], { cwd: path, timeout: MINUTE });
    } else if (name === "netavark" || name === "aardvark-dns") {
      await regular(join(path, "Cargo.lock")); await command("make", ["CARGO=cargo --locked", "build"], { cwd: path, timeout: 10 * MINUTE, label: `native ${name}` });
      await command("sudo", ["-n", "install", "-D", "-m0755", `bin/${name}`, `/usr/libexec/podman/${name}`], { cwd: path });
    } else {
      const epoch = await output("git", ["show", "-s", "--format=%ct", "HEAD"], { cwd: path });
      await command("make", ["CGO_ENABLED=1", "GOFLAGS=-mod=vendor -trimpath -p=2", "PREFIX=/usr", "HELPER_BINARIES_DIR=/usr/libexec/podman", "bin/podman", "bin/rootlessport"], { cwd: path, timeout: 15 * MINUTE, env: { SOURCE_DATE_EPOCH: epoch }, label: "native local Podman" });
      const info = await output("go", ["version", "-m", "bin/podman"], { cwd: path });
      const tags = new Set((info.split("\n").find((line) => line.includes("-tags="))?.split("-tags=")[1] ?? "").trim().replace(/^"|"$/g, "").split(/[,\s]+/));
      requireThat(info.includes("CGO_ENABLED=1") && ["apparmor", "seccomp", "systemd"].every((tagName) => tags.has(tagName)) && !tags.has("remote"), "Native Podman security/build tags are incomplete");
      await artifact("podman-build-info.txt", info);
      for (const [file, destination] of [["bin/podman", NATIVE_EXECUTABLES.podman.path], ["bin/rootlessport", "/usr/libexec/podman/rootlessport"]]) {
        if (file === "bin/podman") await assertNativeDestinationPreimage("podman");
        await command("sudo", ["-n", "install", "-D", "-m0755", file, destination], { cwd: path });
      }
    }
    await sourceMetadata(name, path, "after");
    await command("git", ["diff", "--exit-code", "--"], { cwd: path, capture: true, label: `${name} tracked source/lock integrity` });
  }
  for (const [name, url, bytes, sha256] of ASSETS) {
    const path = join(state.provider, name);
    await command("curl", ["--fail", "--location", "--proto", "=https", "--tlsv1.2", "--connect-timeout", "20", "--max-time", "180", "--output", path, url], { timeout: 185_000, label: `official ${name} asset` });
    requireThat((await regular(path, { owner: process.getuid() })).size === bytes && await hashFile(path) === sha256, `Official ${name} asset integrity failed`);
    await chmod(path, 0o700);
    if (name === "runc") {
      await assertNativeDestinationPreimage("runc");
      await command("sudo", ["-n", "install", "-m0755", path, NATIVE_EXECUTABLES.runc.path]);
    }
  }
}

async function prepareEngine() {
  state.userConfig = join(process.env.HOME, ".config/containers/containers.conf");
  state.userUnits = join(process.env.HOME, ".config/systemd/user");
  for (const path of [state.userConfig, join(state.userUnits, "podman.service"), join(state.userUnits, "podman.socket")]) requireThat(await absent(path), "Refusing existing user Podman configuration/unit");
  await mkdir(dirname(state.userConfig), { recursive: true }); await mkdir(state.userUnits, { recursive: true });
  await writeFile(state.userConfig, nativeRuntimeConfig(), { mode: 0o600, flag: "wx" });
  state.createdUserFiles.set(state.userConfig, await hashFile(state.userConfig));
  const source = join(state.build, "src/podman/contrib/systemd/user");
  await writeFile(join(state.userUnits, "podman.service"), (await readFile(join(source, "podman.service.in"), "utf8")).replaceAll("@@PODMAN@@", NATIVE_EXECUTABLES.podman.path), { mode: 0o600, flag: "wx" });
  state.createdUserFiles.set(join(state.userUnits, "podman.service"), await hashFile(join(state.userUnits, "podman.service")));
  await copyFile(join(source, "podman.socket"), join(state.userUnits, "podman.socket"), constants.COPYFILE_EXCL);
  state.createdUserFiles.set(join(state.userUnits, "podman.socket"), await hashFile(join(state.userUnits, "podman.socket"))); state.unitsCreated = true;
  await command("systemctl", ["--user", "daemon-reload"]); await command("systemctl", ["--user", "start", "podman.socket"]);
  const versions = {};
  for (const [path, expected] of [[NATIVE_EXECUTABLES.podman.path, "6.1.4"], [NATIVE_EXECUTABLES.runc.path, "1.5.2"], [join(state.provider, "docker-compose"), "2.40.0"], ["/usr/libexec/podman/conmon", "2.2.1"], ["/usr/libexec/podman/netavark", "2.1.0"], ["/usr/libexec/podman/aardvark-dns", "2.1.0"], ["/usr/bin/pasta", "2026_10_02.cba3570"]]) {
    const text = await output(path, path.endsWith("docker-compose") ? ["version", "--short"] : ["--version"]);
    requireThat(new RegExp(`(?:^|[^0-9])v?${expected.replaceAll(".", "\\.")}(?:$|[^0-9])`).test(text), `Wrong native component version: ${path}`);
    const installed = await realpath(path);
    requireThat(installed === (path === "/usr/bin/pasta" ? "/usr/bin/passt" : path), "Installed binary path changed");
    await regular(installed, { owner: path.endsWith("docker-compose") ? process.getuid() : 0 });
    versions[path] = { version: text, sha256: await hashFile(installed) };
  }
  requireThat(await output("pkg-config", ["--modversion", "pathrs"]) === "0.2.6", "Native libpathrs ABI version differs");
  const library = await realpath("/usr/local/lib/libpathrs.so"); await regular(library, { owner: 0 });
  requireThat(dirname(library) === "/usr/local/lib" && /^libpathrs\.so\.0\.2\.6$/.test(basename(library)), "Native libpathrs SONAME differs");
  versions[library] = { version: "0.2.6", sha256: await hashFile(library) };
  await artifact("installed-native-versions.json", versions);
  const mappingScript = "const fs=require('fs');console.log(JSON.stringify({uid:process.getuid(),gid:process.getgid(),uidMap:fs.readFileSync('/proc/self/uid_map','utf8'),gidMap:fs.readFileSync('/proc/self/gid_map','utf8'),userns:fs.readlinkSync('/proc/self/ns/user'),label:fs.readFileSync('/proc/self/attr/current','utf8').trim()}))";
  const mapping = JSON.parse((await podman(["unshare", process.execPath, "-e", mappingScript])).output);
  await artifact("actual-rootless-mapping.json", mapping);
  requireThat(mapping.uid === 0 && mapping.gid === 0 && mapping.userns !== await readlink("/proc/self/ns/user"), "Actual rootless user namespace was not established");
  for (const kind of ["uid", "gid"]) {
    const id = kind === "uid" ? process.getuid() : process.getgid(), ranges = parseRanges(mapping[`${kind}Map`]);
    requireThat(ranges.some(([inside, host, count]) => inside === 0 && host === id && count === 1) && ranges.reduce((n, row) => n + row[2], 0) >= 65537, "Mapping helpers did not establish full rootless mappings");
    for (const [, host, count] of ranges.filter(([inside]) => inside !== 0)) requireThat(state.subids[kind].some((range) => host >= range.start && host + count <= range.start + range.count), "Actual subordinate mapping is outside the verified allocation");
  }
  await engineIdentity();
  const compose = await output("/usr/bin/podman", ["compose", "version", "--short"]);
  requireThat(/^v?2\.40\.0$/.test(compose), "Podman selected a different Compose provider");
  requireThat(Array.isArray(JSON.parse(await output("/usr/bin/podman", ["compose", "ls", "--format", "json"]))), "Compose cannot reach the real selected rootless API");
  state.baseline = await inventories();
  requireThat(state.baseline.containers.length === 0 && state.baseline.volumes.length === 0, "Refusing pre-existing rootless resources");
  state.nativeReady = true;
  await artifact("engine-baseline.json", state.baseline);
}

async function engineIdentity() {
  const socket = await lstat(join(state.runtimeDir, "podman/podman.sock"));
  requireThat(socket.isSocket() && !socket.isSymbolicLink() && socket.uid === process.getuid() && socket.gid === process.getgid() && (socket.mode & 0o007) === 0, "API socket is not the private selected rootless user socket");
  const local = await podmanJson(["--remote=false", "info", "--format", "json"]);
  const remote = await podmanJson(["--remote", "--url", `unix://${state.runtimeDir}/podman/podman.sock`, "info", "--format", "json"]);
  const key = (info) => ({ version: info.version?.Version, commit: info.version?.GitCommit, rootless: info.host?.security?.rootless, cgroupVersion: info.host?.cgroupVersion, cgroupManager: info.host?.cgroupManager, graphRoot: info.store?.graphRoot, runRoot: info.store?.runRoot, runtime: info.host?.ociRuntime?.path });
  const expected = key(local);
  await artifact("cli-api-observed.json", { local: expected, api: key(remote), localControllers: local.host?.cgroupControllers, apiControllers: remote.host?.cgroupControllers, localSecurity: local.host?.security, apiSecurity: remote.host?.security });
  requireThat(JSON.stringify(expected) === JSON.stringify(key(remote)) && expected.version === "6.1.4" && expected.commit === SOURCES.at(-1)[2] && expected.rootless === true && expected.runtime === NATIVE_EXECUTABLES.runc.path && expected.cgroupVersion === "v2" && expected.cgroupManager === "systemd", "Native CLI/API version, rootless store or selected OCI runtime differs");
  const controllers = local.host.cgroupControllers;
  requireThat(Array.isArray(controllers) && ["cpu", "memory"].every((name) => controllers.includes(name)), "Actual CPU/memory controllers are not delegated");
  requireThat(local.host.security.seccompEnabled === true && local.host.security.apparmorEnabled === true && local.host.cpus >= REQUIRED.cpuCount && local.host.memTotal >= REQUIRED.memoryBytes, "Actual engine security/resource prerequisites failed");
  const graph = await realpath(expected.graphRoot);
  requireThat(within(process.env.HOME, graph) && (await lstat(graph)).uid === process.getuid() && local.store.graphDriverName === "overlay", "Selected native storage is not this rootless user's overlay store");
  requireThat(["extfs", "xfs"].includes(local.store.graphStatus?.["Backing Filesystem"]) && local.store.graphStatus?.["Native Overlay Diff"] === "true" && local.store.graphStatus?.["Supports d_type"] === "true", "Unreviewed native overlay backing filesystem/features");
  const options = JSON.stringify(local.store.graphOptions ?? {});
  requireThat(!/ignore_chown_errors[^,}\]]*(?:true|[=:]1)/i.test(options) && !/mount_program/i.test(options), "Unreviewed overlay ownership or external mount-program override");
  const pid = Number(await output("systemctl", ["--user", "show", "podman.service", "--property=MainPID", "--value"]));
  requireThat(Number.isSafeInteger(pid) && pid > 1 && await realpath(`/proc/${pid}/exe`) === NATIVE_EXECUTABLES.podman.path, "Rootless API is not the installed native engine process");
  const startTime = (text) => text.slice(text.lastIndexOf(")") + 2).split(/\s+/)[19];
  const before = startTime(await readFile(`/proc/${pid}/stat`, "utf8")), fields = statusFields(await readFile(`/proc/${pid}/status`, "utf8"));
  const label = (await readFile(`/proc/${pid}/attr/current`, "utf8")).trim();
  requireThat(fields.Uid?.split(/\s+/).every((value) => Number(value) === process.getuid()) && parseCpuList(fields.Cpus_allowed_list) >= REQUIRED.cpuCount && label.startsWith(`${state.vendorProfiles.podman.profile} (`), "API ownership, affinity or actual vendor executable attachment differs");
  const capacity = await cgroupCapacity(pid);
  requireThat((capacity.cpuLimit === null || capacity.cpuLimit >= REQUIRED.cpuCount) && (capacity.memoryLimit === null || capacity.memoryLimit >= REQUIRED.memoryBytes + HEADROOM), "API process inherited insufficient resource capacity");
  requireThat(/^\d+$/.test(before) && before === startTime(await readFile(`/proc/${pid}/stat`, "utf8")) && String(pid) === await output("systemctl", ["--user", "show", "podman.service", "--property=MainPID", "--value"]), "API process identity changed during inspection");
  state.graphRoot = graph;
  await artifact("selected-engine.json", { ...expected, apiPid: pid, apiLabel: label, apiCapacity: capacity, controllers, graphStatus: local.store.graphStatus, network: { backend: local.host.networkBackend, info: local.host.networkBackendInfo } });
}

async function removeBuildScratch() {
  requireThat(await realpath(state.build) === join(await realpath(state.ciRoot), "build") && dirname(await realpath(state.ciRoot)) === state.temp && !(await lstat(state.build)).isSymbolicLink(), "Owned build cleanup path changed");
  const code = "import os,shutil,sys; target,owner,temp=sys.argv[1:]; actual=os.path.realpath(target); expected=os.path.join(os.path.realpath(owner),'build'); assert actual==expected and not os.path.islink(target) and os.path.dirname(os.path.realpath(owner))==os.path.realpath(temp) and shutil.rmtree.avoids_symlink_attacks; shutil.rmtree(target)";
  await command("sudo", ["-n", "python3", "-c", code, state.build, state.ciRoot, state.temp], { timeout: MINUTE, label: "remove only owned build scratch" });
  requireThat(await absent(state.build), "Owned build scratch removal is unconfirmed");
}
async function removeAptScratch() {
  requireThat(await realpath(state.aptRoot) === state.aptRoot && dirname(state.aptRoot) === "/var/tmp" && basename(state.aptRoot).startsWith(state.aptPrefix) && !(await lstat(state.aptRoot)).isSymbolicLink(), "Owned apt cleanup path changed");
  const code = "import os,shutil,sys; target,prefix=sys.argv[1:]; assert os.path.realpath(target)==target and os.path.dirname(target)=='/var/tmp' and os.path.basename(target).startswith(prefix) and not os.path.islink(target) and shutil.rmtree.avoids_symlink_attacks; shutil.rmtree(target)";
  await command("sudo", ["-n", "python3", "-c", code, state.aptRoot, state.aptPrefix], { timeout: MINUTE, label: "remove only owned apt scratch" });
  requireThat(await absent(state.aptRoot), "Owned apt scratch removal is unconfirmed");
}
async function inventories() {
  const values = {};
  for (const [kind, args] of [["containers", ["ps", "-aq"]], ["volumes", ["volume", "ls", "-q"]], ["networks", ["network", "ls", "-q"]]]) values[kind] = (await podman(args)).output.split(/\s+/).filter(Boolean).sort();
  return values;
}
async function projectResources(kind) {
  const args = kind === "container" ? ["ps", "-aq"] : [kind, "ls", "-q"];
  const text = (await podman([...args, "--filter", `label=com.docker.compose.project=${state.project}`])).output;
  const values = text.split(/\s+/).filter(Boolean);
  requireThat(values.every((value) => kind === "container" ? /^[a-f0-9]{12,64}$/.test(value) : /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,200}$/.test(value)), "Unexpected resource identifier");
  return values;
}
async function assertNoLeftovers() {
  for (const kind of ["container", "volume", "network"]) requireThat((await projectResources(kind)).length === 0, `Owned ${kind} resources remain after purge`);
  const probes = (await podman(["ps", "-aq", "--filter", "name=^spaceapp-engine-probe-"])).output;
  requireThat(probes === "", "Runtime probe resources remain; enumeration succeeded");
  const current = await inventories();
  requireThat(JSON.stringify(current) === JSON.stringify(state.baseline), "Unlabelled runtime resources differ from the fresh-engine baseline");
  await artifact("no-leftovers.json", { passed: true, project: state.project, baseline: state.baseline, actual: current, namedProbes: [] });
}

async function checkApplication() {
  const config = await jsonFile(join(state.home, "config.json"), 128 * 1024);
  requireThat(config.engine === "podman" && config.profile === "small" && config.accessMode === "isolated" && config.port === 4911 && config.companionsEnabled === false, "Persisted installation differs from explicit Podman/small/isolated selection");
  const spec = composeCommand("status", state.home, config);
  requireThat(spec.command === "podman" && spec.args.at(-1) === "ps" && spec.args.some((arg) => arg.endsWith("compose.podman.yml")), "Lifecycle provider does not use the generated selected-engine override");
  const resolved = JSON.parse(await output("/usr/bin/podman", [...spec.args.slice(0, -1), "config", "--format", "json"]));
  const settings = profileRuntimeSettings("small"), facts = {};
  for (const service of ["spaceapp-core", "spaceapp-cli"]) {
    const configured = resolved.services?.[service];
    requireThat(configured && configured.user === "0:0" && configured.userns_mode === "keep-id:uid=10001,gid=10001" && configured.privileged !== true && configured.network_mode !== "host" && configured.pid !== "host" && !(configured.security_opt ?? []).some((value) => /(?:seccomp|apparmor)[=:]unconfined/.test(value)), "Generated Compose weakens a supported rootless boundary");
    const ids = (await podman(["ps", "-q", "--filter", `label=com.docker.compose.project=${state.project}`, "--filter", `label=com.docker.compose.service=${service}`])).output.split(/\s+/).filter(Boolean);
    requireThat(ids.length === 1 && /^[a-f0-9]{12,64}$/.test(ids[0]), `Expected one actual ${service} container`);
    const [inspection] = await podmanJson(["container", "inspect", ids[0]]);
    requireThat(inspection?.State?.Running === true && inspection.HostConfig?.Privileged !== true && inspection.Config?.Labels?.["com.docker.compose.project"] === state.project && inspection.HostConfig?.PidMode !== "host" && inspection.HostConfig?.NetworkMode !== "host", "Actual container isolation differs from the source profile");
    requireThat((inspection.HostConfig.SecurityOpt ?? []).some((value) => /^no-new-privileges(?:(?::|=)true)?$/.test(value)) && !(inspection.HostConfig.CapAdd ?? []).length, "Actual no-new-privileges/capability boundary differs");
    for (const mount of inspection.Mounts ?? []) if (mount.Type === "bind") {
      requireThat(within(state.home, resolve(mount.Source)) && mount.Source !== "/", "Unexpected host bind outside this installation");
      if (mount.Destination.startsWith("/run/secrets/")) requireThat(mount.RW === false, "Actual file-secret mount is writable");
    }
    const script = "const fs=require('fs');console.log(JSON.stringify({uid:process.getuid(),gid:process.getgid(),status:fs.readFileSync('/proc/self/status','utf8'),uidMap:fs.readFileSync('/proc/self/uid_map','utf8'),gidMap:fs.readFileSync('/proc/self/gid_map','utf8'),userns:fs.readlinkSync('/proc/self/ns/user'),mountns:fs.readlinkSync('/proc/self/ns/mnt'),pidns:fs.readlinkSync('/proc/self/ns/pid'),label:fs.readFileSync('/proc/self/attr/current','utf8').trim(),memory:fs.readFileSync('/sys/fs/cgroup/memory.max','utf8').trim(),cpu:fs.readFileSync('/sys/fs/cgroup/cpu.max','utf8').trim()}))";
    const actual = JSON.parse((await podman(["exec", "--user", "10001:10001", ids[0], "node", "-e", script])).output);
    const fields = statusFields(actual.status), cpu = actual.cpu.split(/\s+/).map(Number), expectedCpu = Number(service === "spaceapp-core" ? settings.coreCpuLimit : settings.cliCpuLimit);
    await artifact(`${service}-observed.json`, { uid: actual.uid, gid: actual.gid, uidMap: actual.uidMap, gidMap: actual.gidMap, noNewPrivileges: fields.NoNewPrivs, seccomp: fields.Seccomp, effectiveCapabilities: fields.CapEff, userns: actual.userns, mountns: actual.mountns, pidns: actual.pidns, inspectUsernsMode: inspection.HostConfig?.UsernsMode ?? null, memory: actual.memory, cpu: actual.cpu, processLabel: actual.label, appArmorProfile: inspection.AppArmorProfile ?? null });
    requireThat(actual.uid === 10001 && actual.gid === 10001 && fields.NoNewPrivs === "1" && fields.Seccomp === "2" && BigInt(`0x${fields.CapEff}`) === 0n, "Actual agent identity/seccomp/capabilities differ");
    requireThat(actual.userns !== await readlink("/proc/self/ns/user") && actual.mountns !== await readlink("/proc/self/ns/mnt") && actual.pidns !== await readlink("/proc/self/ns/pid"), "Actual agent shares a host namespace");
    for (const kind of ["uid", "gid"]) requireThat(parseRanges(actual[`${kind}Map`]).some(([inside, host, count]) => inside === 10001 && host === (kind === "uid" ? process.getuid() : process.getgid()) && count === 1), "Actual agent keep-id mapping is incorrect");
    requireThat(actual.memory === String(2 * GIB) && cpu.length === 2 && cpu.every((value) => Number.isSafeInteger(value) && value > 0) && cpu[0] / cpu[1] === expectedCpu, "Actual application CPU/memory enforcement differs from small profile");
    delete actual.status;
    facts[service] = { container: ids[0], imageId: inspection.Image, imageName: inspection.ImageName ?? inspection.Config?.Image, ...actual, inspectUsernsMode: inspection.HostConfig?.UsernsMode ?? null, appArmorProfile: inspection.AppArmorProfile ?? null, appArmorLimitation: "Upstream rootless Podman does not apply its default container AppArmor profile; no per-container AppArmor confinement claim." };
  }
  await artifact("actual-application-boundaries.json", facts);
}

async function verifyBackup() {
  const directory = join(state.home, "backups"), entries = await readdir(directory, { withFileTypes: true });
  const ids = entries.filter((entry) => entry.isDirectory() && /^spaceapp-backup-\d{8}T\d{9}Z$/.test(entry.name)).map((entry) => entry.name).sort();
  requireThat(ids.length === 1, "Expected one newly created actual portable backup");
  const root = join(directory, ids[0]), info = await lstat(root);
  requireThat(!info.isSymbolicLink() && info.uid === process.getuid() && (info.mode & 0o777) === 0o700 && await realpath(root) === root, "Backup directory ownership/mode differs");
  const manifest = await jsonFile(join(root, "manifest.json"), 128 * 1024), names = ["data.tar.gz", "database.dump", "memory.tar.gz"];
  requireThat(manifest.format === "spaceapp-portable-backup" && manifest.schemaVersion === 1 && JSON.stringify(Object.keys(manifest.files ?? {}).sort()) === JSON.stringify(names), "Unsupported actual portable backup manifest");
  const records = {};
  await artifact("backup-observed.json", { id: ids[0], expectedFiles: manifest.files, actualFiles: records, verified: false });
  for (const name of ["manifest.json", ...names]) {
    const path = join(root, name), file = await regular(path, { owner: process.getuid() });
    requireThat((file.mode & 0o777) === 0o600 && file.size > 0, "Backup file is empty or has incorrect private ownership/mode");
    const sha256 = await hashFile(path);
    records[name] = { size: file.size, sha256 };
    await artifact("backup-observed.json", { id: ids[0], expectedFiles: manifest.files, actualFiles: records, verified: false });
    if (name !== "manifest.json") requireThat(Number.isSafeInteger(manifest.files[name].size) && file.size === manifest.files[name].size && /^[a-f0-9]{64}$/.test(manifest.files[name].sha256) && sha256 === manifest.files[name].sha256, "Actual backup file size/digest mismatch");
  }
  await artifact("backup-verified.json", { id: ids[0], passed: true, files: records });
}

async function acceptance() {
  state.phase = "runtime";
  await resources("before-small-install", state.homeParent, REQUIRED.freshDiskBytes + HEADROOM);
  await resources("native-store-before-install", state.graphRoot, REQUIRED.freshDiskBytes + HEADROOM);
  state.appAttempted = true;
  await launcher(["install", "--engine", "podman", "--profile", "small", "--non-interactive", "--no-open", "--answers", '{"confirm":true,"companions":false,"telemetry":false}'], 25 * MINUTE);
  await checkApplication();
  const response = await fetch("http://127.0.0.1:4911/readyz", { signal: AbortSignal.timeout(5000), redirect: "error" });
  requireThat(response.body, "Readiness response has no body");
  const chunks = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length; requireThat(size <= 64 * 1024, "Oversized readiness response"); chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  const ready = JSON.parse(text); requireThat(response.ok && ready.ok === true, "Actual small installation is not ready"); await artifact("readyz.json", ready);
  await launcher(["doctor"], 2 * MINUTE);
  await launcher(["backup"], 3 * MINUTE); await verifyBackup();
  const support = join(state.logs, "support-bundle.json"); await launcher(["support-bundle", "--out", support]);
  await artifact("support-bundle.json", await jsonFile(support));
  await launcher(["uninstall", "--purge-data", "--non-interactive", "--answers", '{"purgeConfirm":"DELETE"}'], 3 * MINUTE);
  state.purged = true;
  await assertNoLeftovers(); await vendorPolicy("after-acceptance");
}

async function cleanup() {
  state.phase = "cleanup"; state.cleanupDeadline = Math.min(Date.now() + 4 * MINUTE, state.started + 57 * MINUTE);
  let confirmed = state.unconfirmed.length === 0;
  const attempt = async (name, fn) => { try { await fn(); } catch (error) { confirmed = false; await event("cleanup-failure", { action: name, message: redact(error.message), code: error.exitCode ?? 1 }); } };
  if (state.nativeReady && state.appAttempted) {
    let engineSafe = false;
    await attempt("selected-engine identity before cleanup", async () => { await engineIdentity(); engineSafe = true; });
    if (engineSafe) {
      await attempt("launcher purge", async () => {
        if (state.purged) return;
        if (await absent(join(state.home, "config.json"))) return;
        const config = await jsonFile(join(state.home, "config.json")); requireThat(config.engine === "podman", "Refusing cleanup of a conflicting engine");
        await launcher(["uninstall", "--purge-data", "--non-interactive", "--answers", '{"purgeConfirm":"DELETE"}'], MINUTE);
      });
      for (const kind of ["container", "volume", "network"]) await attempt(`exact owned ${kind} cleanup`, async () => {
        const resources = await projectResources(kind);
        if (state.purged && resources.length) { confirmed = false; await event("cleanup-failure", { action: "resources reappeared after successful purge", kind, resources }); }
        for (const id of resources) {
          const inspected = await podmanJson([kind, "inspect", id]);
          const labels = kind === "container" ? inspected[0]?.Config?.Labels : inspected[0]?.Labels ?? inspected[0]?.labels;
          requireThat(labels?.["com.docker.compose.project"] === state.project, "Cleanup resource ownership changed");
          await podman([kind, "rm", ...(kind === "container" ? ["--force"] : []), id]);
        }
      });
      for (const name of state.probes) await attempt("exact source-reported probe cleanup", async () => {
        const exists = await podman(["container", "exists", name], { timeout: 15_000, allowFailure: true });
        if (exists.code === 1) return; requireThat(exists.code === 0, "Probe existence could not be established");
        const [container] = await podmanJson(["container", "inspect", name]);
        requireThat(container.Name?.replace(/^\//, "") === name && /^ghcr\.io\/oll4com\/spaceapp-core:/.test(container.Config?.Image ?? container.ImageName ?? ""), "Refusing an unrelated probe container");
        await podman(["rm", "--force", name], { timeout: 15_000 });
        requireThat((await podman(["container", "exists", name], { timeout: 15_000, allowFailure: true })).code === 1, "Probe cleanup remains unconfirmed");
      });
      await attempt("successful empty exact-owned enumeration", () => assertNoLeftovers());
    }
  }
  if (state.unitsCreated) await attempt("owned user API unit cleanup", async () => {
    for (const name of ["podman.service", "podman.socket"]) requireThat(await hashFile(join(state.userUnits, name)) === state.createdUserFiles.get(join(state.userUnits, name)), "Owned API unit changed; refusing to stop unrelated configuration");
    await command("systemctl", ["--user", "stop", "podman.socket"]);
    await command("systemctl", ["--user", "stop", "podman.service"]);
    for (const unit of ["podman.socket", "podman.service"]) {
      const value = await output("systemctl", ["--user", "show", unit, "--property=ActiveState", "--value"]);
      requireThat(value === "inactive", `Owned ${unit} stop is unconfirmed`);
    }
  });
  for (const [path, expected] of state.createdUserFiles) await attempt("remove exact owned user configuration", async () => {
    requireThat(await hashFile(path) === expected && (await regular(path)).uid === process.getuid(), "Owned user configuration changed; refusing deletion");
    await unlink(path);
  });
  if (state.unitsCreated) await attempt("reload after owned unit removal", () => command("systemctl", ["--user", "daemon-reload"]));
  if (state.build && !await absent(state.build)) await attempt("owned build scratch cleanup", async () => {
    requireThat(state.unconfirmed.length === 0, "Build scratch is retained because an owned command/descendant remains unconfirmed");
    await removeBuildScratch();
  });
  if (state.aptRoot && !await absent(state.aptRoot)) await attempt("owned apt scratch cleanup", async () => {
    requireThat(state.unconfirmed.length === 0, "Apt scratch is retained because an owned command/descendant remains unconfirmed");
    await removeAptScratch();
  });
  state.cleanupConfirmed = confirmed && state.unconfirmed.length === 0;
  if (state.nativeReady) await attempt("unchanged vendor policy after cleanup", () => vendorPolicy("after-cleanup"));
  state.cleanupConfirmed = confirmed && state.unconfirmed.length === 0;
}

async function sanitizeEvidence() {
  discoverSecrets();
  for (const entry of await readdir(state.logs, { withFileTypes: true })) {
    requireThat(entry.isFile() && !entry.isSymbolicLink(), "Unexpected CI evidence entry");
    const path = join(state.logs, entry.name); await regular(path, { max: 64 * 1024 * 1024, owner: process.getuid() });
    const original = await readFile(path, "utf8"), safe = redact(original);
    if (safe !== original) await writeFile(path, safe, { mode: 0o600 });
    requireThat(![...state.secrets].some((secret) => safe.includes(secret)), "Sanitized evidence still contains a generated secret");
  }
}

async function main() {
  const deadline = setTimeout(() => {
    state.abort ??= new Failure("CI wall deadline exceeded; owned cleanup may be unconfirmed", 124);
    if (state.exitCode === 0) state.exitCode = state.abort.exitCode;
    onSignal("SIGTERM");
    state.forceExit = setTimeout(() => {
      process.stderr.write("CI wall deadline: filesystem/descendant cleanup remains unconfirmed.\n");
      process.exit(state.exitCode || 124);
    }, 10_000);
  }, 57 * MINUTE);
  state.deadline = deadline;
  try {
    await initialize(); state.homeParent = dirname(state.home);
    await installDependencies(); await nativeHostPrerequisites();
    await buildNative(); await vendorPolicy("after-build"); await prepareEngine(); await removeBuildScratch(); await removeAptScratch();
    await acceptance();
  } catch (error) {
    if (state.exitCode === 0) state.exitCode = error.exitCode ?? 1;
    process.stderr.write(`${redact(error.message)}\n`);
    if (state.logs) await event("failure", { message: redact(error.message), code: state.exitCode });
  } finally {
    if (state.logs) {
      try { await cleanup(); } catch (error) { state.cleanupConfirmed = false; await event("cleanup-failure", { message: redact(error.message) }); }
      if (state.exitCode === 0 && !state.cleanupConfirmed) state.exitCode = 1;
      let sanitized = false;
      try { await sanitizeEvidence(); sanitized = true; } catch (error) { process.stderr.write("CI evidence sanitization failed; artifacts must not be uploaded.\n"); if (state.exitCode === 0) state.exitCode = 1; }
      await artifact("terminal.json", { exitCode: state.exitCode, passed: state.exitCode === 0, cleanupConfirmed: state.cleanupConfirmed, cleanupScope: "This run's app resources, created user API units/configuration and build scratch; native tools/image cache remain on the disposable runner", sanitized, unconfirmedOwnedCommands: state.unconfirmed, appAcceptanceStarted: state.appAttempted, runtimeScope: "small only; no large/Mac/EnforcingSELinux claim", elapsedSeconds: (Date.now() - state.started) / 1000 });
      if (sanitized) {
        requireThat(process.env.GITHUB_OUTPUT, "Missing artifact-sanitization output channel");
        await regular(process.env.GITHUB_OUTPUT, { owner: process.getuid(), max: 1024 * 1024 });
        await appendFile(process.env.GITHUB_OUTPUT, "sanitized=true\n");
      }
    }
    clearTimeout(deadline); clearTimeout(state.forceExit);
  }
  process.exitCode = state.exitCode;
}

try { await main(); } catch (error) {
  process.stderr.write(`${redact(error.message)}\n`);
  process.exitCode = state.exitCode || error.exitCode || 1;
} finally {
  clearTimeout(state.deadline); clearTimeout(state.forceExit);
}
