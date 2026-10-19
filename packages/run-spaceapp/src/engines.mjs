import { Writable } from "node:stream";
import { randomUUID } from "node:crypto";

export const PODMAN_COMPOSE_ENV = Object.freeze({ PODMAN_COMPOSE_PROVIDER: "docker-compose" });
export const PODMAN_COMPOSE_UNSET_ENV = Object.freeze(["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]);
export const MIN_PODMAN_VERSION = "5.0.0";
export const MIN_PODMAN_COMPOSE_VERSION = "2.24.4";

// Keep legacy configurations byte-compatible: an absent engine has always meant Docker.
export function containerEngine(config = {}) {
  const engine = typeof config === "string" ? config : config?.engine === undefined ? "docker" : config.engine;
  if (engine !== "docker" && engine !== "podman") throw new Error("Engine must be docker or podman.");
  return engine;
}

export function engineDisplayName(config) {
  return containerEngine(config) === "podman" ? "Podman" : "Docker";
}

export function assertEngineSelection(requested, existing) {
  if (requested !== undefined && requested !== "docker" && requested !== "podman") throw new Error("Engine must be docker or podman.");
  const engine = containerEngine(requested === undefined ? existing ?? {} : requested);
  if (existing && containerEngine(existing) !== engine) {
    throw new Error(`Cannot switch this installation from ${containerEngine(existing)} to ${engine}: Docker and Podman volumes are separate. Keep the stored engine and installation root. In-place engine migration is not supported.`);
  }
  return engine;
}

export function assertEngineAccess(config) {
  if (containerEngine(config) === "podman" && config.accessMode === "host-root") {
    throw new Error("Podman does not support --access host-root. Use --access isolated and register individual folders with workspace add.");
  }
}

export function engineCommand(config, args) {
  return containerEngine(config) === "podman"
    ? { command: "podman", args, ...(args[0] === "compose" ? { env: PODMAN_COMPOSE_ENV, unsetEnv: PODMAN_COMPOSE_UNSET_ENV } : {}) }
    : { command: "docker", args };
}

async function probeResult(execute, spec) {
  let output = "";
  const stdout = new Writable({ write(chunk, _encoding, done) {
    if (output.length < 1024 * 1024) output += chunk.toString();
    done();
  } });
  try {
    const code = await execute({ ...spec, timeoutMs: 15000 }, { stdin: null, stdout, stderr: null });
    return { code, output: output.trim() };
  } catch (error) { return { code: error?.code === "ENOENT" ? 127 : null, output: "" }; }
}

async function probe(execute, spec) {
  const result = await probeResult(execute, spec);
  return result.code === 0 ? result.output : null;
}

function version(value) {
  return typeof value === "string" ? value.match(/\b(v?\d+\.\d+\.\d+)(?:\b|[-+])/)?.[1]?.replace(/^v/, "") ?? null : null;
}

function atLeast(actual, minimum) {
  if (!actual) return false;
  const a = actual.split(".").map(Number), b = minimum.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return true;
}

function json(value) {
  try { return JSON.parse(value); } catch { return null; }
}

async function selectedMachine(execute) {
  const connections = json(await probe(execute, { command: "podman", args: ["system", "connection", "list", "--format", "json"] }));
  const selected = Array.isArray(connections) ? connections.filter((item) => item.Default === true) : [];
  // An environment-selected connection may differ from the default. Refuse that
  // ambiguity rather than attributing an unrelated machine's capacity to it.
  if (selected.length !== 1 || process.env.CONTAINER_HOST || process.env.CONTAINER_CONNECTION) return null;
  const list = json(await probe(execute, { command: "podman", args: ["machine", "list", "--format", "json"] }));
  const names = Array.isArray(list) ? list.map((item) => item.Name).filter((name) => typeof name === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(name)) : [];
  if (!names.length) return null;
  const machines = json(await probe(execute, { command: "podman", args: ["machine", "inspect", ...names] }));
  let uri;
  try { uri = new URL(selected[0].URI); } catch { return null; }
  const matches = Array.isArray(machines) ? machines.filter((item) => item.State === "running" && (
    uri.protocol === "ssh:" && ["127.0.0.1", "localhost", "[::1]"].includes(uri.hostname) &&
      Number(uri.port) === Number(item.SSHConfig?.Port) && decodeURIComponent(uri.username) === item.SSHConfig?.RemoteUsername ||
    uri.protocol === "unix:" && decodeURIComponent(uri.pathname) === item.ConnectionInfo?.PodmanSocket?.Path
  )) : [];
  if (matches.length !== 1 || !names.includes(matches[0].Name)) return null;
  const value = matches[0];
  return { name: value.Name, state: value.State, rootful: value.Rootful,
    configuredCpuCount: value.Resources?.CPUs, configuredMemoryRaw: value.Resources?.Memory, configuredDiskSizeRaw: value.Resources?.DiskSize };
}

export async function inspectPodmanStorage({ info, execute, platform = process.platform, machine }) {
  const graphRoot = info?.store?.graphRoot;
  if (typeof graphRoot !== "string" || !/^\/[A-Za-z0-9_./-]+$/.test(graphRoot)) return null;
  const args = platform === "darwin"
    ? machine ? ["machine", "ssh", machine.name, "df", "-Pk", "--", graphRoot] : null
    : ["unshare", "df", "-Pk", "--", graphRoot];
  if (!args) return null;
  const output = await probe(execute, { command: "podman", args });
  const available = output?.split(/\r?\n/).at(-1)?.trim().split(/\s+/)[3];
  return /^\d+$/.test(available ?? "") ? Number(available) * 1024 : null;
}

export function podmanInstallHelp(platform) {
  const install = platform === "darwin"
    ? "Install Podman 5+ and the standalone docker-compose v2 provider. Run podman machine init, then podman machine start. On Intel Macs use Podman 5.8 (Podman 6 no longer supports Intel)."
    : "Install Podman 5+ and the standalone docker-compose v2 provider using your distribution's instructions. Run as a regular user with subordinate UID/GID ranges, cgroup v2 and a systemd user session.";
  return `${install} The launcher never installs Podman. Python podman-compose is not a supported provider.`;
}

export function podmanMachineHelp(profile, requirements) {
  const memory = Math.ceil(requirements.memoryBytes / 1024 ** 2);
  const disk = Math.ceil(requirements.freshDiskBytes / 1024 ** 3) + 10;
  return `Podman machine must have at least ${requirements.cpuCount} CPUs, ${memory} MiB usable RAM and ${Math.ceil(requirements.freshDiskBytes / 1024 ** 3)} GiB free disk for ${profile}. Stop SpaceApp first, then run podman machine stop <name>; podman machine set --cpus ${requirements.cpuCount} --memory ${memory + 1024} --disk-size ${disk} <name>; podman machine start <name>. Keep extra disk headroom for images and backups; disks can only grow. If the machine provider cannot resize these resources, follow Podman's provider instructions and preserve volumes before recreating it.`;
}

// Only allow automatic fallback for a fresh install and a genuinely missing Docker CLI.
// An installed but stopped Docker daemon remains on its existing recovery/install path.
export async function detectInstallEngine({ requested, existing, platform, execute, allowFallback = true }) {
  if (requested !== undefined || existing) return assertEngineSelection(requested, existing);
  if (!allowFallback || platform === "win32") return "docker";
  const docker = await probeResult(execute, { command: "docker", args: ["--version"] });
  if (docker.code !== 127) return "docker";
  return await probe(execute, { command: "podman", args: ["--version"] }) === null ? "docker" : "podman";
}

export async function inspectContainerEngine({ config, execute, platform = process.platform }) {
  const engine = containerEngine(config);
  const info = json(await probe(execute, engineCommand(config, ["info", "--format", "{{json .}}"])));
  if (engine === "docker") {
    const security = info?.SecurityOptions ?? [];
    return { engine, available: Boolean(info), version: info?.ServerVersion ?? null,
      rootless: info ? security.some((item) => /rootless/i.test(item)) : null,
      cgroupVersion: info?.CgroupVersion ?? null,
      cpuLimits: info ? info.CPUCfsQuota !== false : null,
      memoryLimits: info ? info.MemoryLimit !== false : null };
  }
  const cliVersion = version(await probe(execute, engineCommand(config, ["--version"])));
  const composeVersion = version(await probe(execute, engineCommand(config, ["compose", "version", "--short"])));
  const composeReachable = Array.isArray(json(await probe(execute, engineCommand(config, ["compose", "ls", "--format", "json"]))));
  const host = info?.host ?? {};
  const controllers = Array.isArray(host.cgroupControllers) ? host.cgroupControllers : [];
  const machine = platform === "darwin" ? await selectedMachine(execute) : null;
  return { engine, available: Boolean(info), version: version(info?.version?.Version),
    clientVersion: cliVersion, composeProvider: "docker-compose", composeVersion, composeReachable,
    rootless: host.security?.rootless ?? null, cgroupVersion: host.cgroupVersion ?? null,
    cgroupManager: host.cgroupManager ?? null, cpuLimits: controllers.includes("cpu"), memoryLimits: controllers.includes("memory"),
    cpuCount: host.cpus ?? null, memoryBytes: host.memTotal ?? null,
    // Store only capacities, never full engine info (paths, registries and authentication are unnecessary).
    freeDiskBytes: await inspectPodmanStorage({ info, execute, platform, machine }),
    selinuxEnabled: host.security?.selinuxEnabled ?? null, machine };
}

export function podmanChecks(facts, { platform = process.platform, arch = process.arch, profile, requirements } = {}) {
  const checks = [
    { name: "Podman engine", ok: facts.available, detail: facts.available ? `Podman ${facts.version ?? "unknown"}` : "not running or inaccessible" },
    { name: "Podman version", ok: atLeast(facts.version, MIN_PODMAN_VERSION) && atLeast(facts.clientVersion, MIN_PODMAN_VERSION), detail: `server ${facts.version ?? "unknown"}; client ${facts.clientVersion ?? "unknown"}; >= ${MIN_PODMAN_VERSION} required` },
    { name: "Podman Compose", ok: atLeast(facts.composeVersion, MIN_PODMAN_COMPOSE_VERSION) && facts.composeVersion?.startsWith("2."), detail: `docker-compose ${facts.composeVersion ?? "unavailable"}; v2 >= ${MIN_PODMAN_COMPOSE_VERSION} required (PODMAN_COMPOSE_PROVIDER=docker-compose)` },
    { name: "Podman Compose connection", ok: facts.composeReachable === true, detail: facts.composeReachable ? "provider can reach the selected Podman API" : "provider cannot reach Podman; on Linux run systemctl --user enable --now podman.socket in your user session; on macOS start the selected Podman machine" },
    { name: "Podman rootless", ok: facts.rootless === true, detail: facts.rootless === true ? "rootless" : "rootful or unknown; run Podman as a regular user and use a rootless machine connection" },
    { name: "Podman cgroups", ok: facts.cgroupVersion === "v2" || facts.cgroupVersion === "2", detail: `${facts.cgroupVersion ?? "unknown"}; cgroup v2 required` },
    { name: "Podman CPU delegation", ok: facts.cpuLimits === true, detail: facts.cpuLimits ? "cpu controller delegated" : "cpu controller not delegated; use a systemd user session with CPU and memory delegation" },
    { name: "Podman memory delegation", ok: facts.memoryLimits === true, detail: facts.memoryLimits ? "memory controller delegated" : "memory controller not delegated; use a systemd user session with CPU and memory delegation" }
  ];
  if (platform === "win32") checks.push({ name: "Podman platform", ok: false, detail: "Windows Podman is not supported. Use Docker on Windows." });
  if (platform === "darwin" && arch === "x64") checks.push({ name: "Podman Intel Mac version", ok: facts.version?.startsWith("5.8.") && facts.clientVersion?.startsWith("5.8."), detail: "Intel Macs require the supported Podman 5.8 client and machine; Podman 6 removed Intel support" });
  if (requirements) {
    checks.push(
      { name: "Podman CPU", ok: facts.cpuCount >= requirements.cpuCount, detail: `${facts.cpuCount ?? "unknown"} available; ${requirements.cpuCount} required for ${profile}` },
      { name: "Podman memory", ok: facts.memoryBytes >= requirements.memoryBytes, detail: `${facts.memoryBytes === null ? "unknown" : (facts.memoryBytes / 1024 ** 3).toFixed(1)} GiB usable; ${requirements.memoryBytes / 1024 ** 3} required for ${profile}` },
      { name: "Podman storage", ok: facts.freeDiskBytes !== null && facts.freeDiskBytes >= requirements.freshDiskBytes, detail: `${facts.freeDiskBytes === null ? "unknown" : (facts.freeDiskBytes / 1024 ** 3).toFixed(1)} GiB free; ${requirements.freshDiskBytes / 1024 ** 3} required` }
    );
  }
  if (platform === "darwin") checks.push({ name: "Podman machine", ok: facts.machine?.state === "running" && facts.machine?.rootful !== true, detail: facts.machine ? `${facts.machine.name}: ${facts.machine.state}` : "one running rootless Podman machine is required" });
  return checks;
}

export async function ensurePodmanAvailable({ config = { engine: "podman" }, execute, platform, stdout, stderr }) {
  assertEngineAccess(config);
  const facts = await inspectContainerEngine({ config, execute, platform });
  const checks = podmanChecks(facts, { platform });
  for (const check of checks) (check.ok ? stdout : stderr).write(`${check.ok ? "PASS" : "FAIL"} ${check.name}: ${check.detail}\n`);
  const code = checks.every((check) => check.ok) ? 0 : 1;
  if (code) stderr.write(`${podmanInstallHelp(platform)}\n`);
  return { code, reexecuted: false, facts };
}

// Reported controllers are an early prerequisite; a real bounded container must
// also prove that the kernel applies both limits before any application cutover.
export async function verifyPodmanRuntime({ config, execute, stdout, stderr }) {
  if (containerEngine(config) !== "podman") return 0;
  const script = "const fs=require('node:fs');const m=fs.readFileSync('/sys/fs/cgroup/memory.max','utf8').trim();const [quota,period]=fs.readFileSync('/sys/fs/cgroup/cpu.max','utf8').trim().split(/\\s+/);const q=Number(quota),p=Number(period);if(m!=='134217728'||!Number.isSafeInteger(q)||!Number.isSafeInteger(p)||q<=0||p<=0||q/p!==0.5)process.exit(1);console.log('CPU and memory limits enforced')";
  const name = `spaceapp-engine-probe-${randomUUID()}`;
  let code, prepared = false;
  try {
    // Podman's storage layer may physically remap a cold image during create.
    // Keep that bounded preparation distinct from execution of the kernel check.
    stdout.write("Preparing the Podman runtime UID mapping (up to 10 minutes for a cold image). CPU/memory limits have not been verified yet.\n");
    code = await execute({ command: "podman", args: ["create", "--name", name, "--rm", "--pull=never", "--memory=134217728", "--cpus=0.5", "--userns=keep-id:uid=10001,gid=10001", "--user=0:0", "--entrypoint", "node", `ghcr.io/oll4com/spaceapp-core:${config.version}`, "-e", script], timeoutMs: 600000 }, { stdin: null, stdout, stderr });
    if (code === 0) {
      prepared = true;
      stdout.write("Verifying Podman CPU and memory limits (30 second execution deadline)...\n");
      code = await execute({ command: "podman", args: ["start", "--attach", name], timeoutMs: 30000 }, { stdin: null, stdout, stderr });
    }
  } finally {
    // A killed client can leave the container alive. Cleanup targets only this
    // invocation's random, known name, including on timeout or spawn failure.
    const cleanup = await execute({ command: "podman", args: ["rm", "--force", name], timeoutMs: 15000 }, { stdin: null, stdout: null, stderr: null }).catch(() => null);
    const absent = cleanup === 0 || await execute({ command: "podman", args: ["container", "exists", name], timeoutMs: 15000 }, { stdin: null, stdout: null, stderr: null }).catch(() => null) === 1;
    if (!absent) {
      stderr.write(`Probe cleanup could not be confirmed. Preserve existing data and inspect the engine before retrying. Only this probe may be removed with: podman rm --force ${name}\n`);
      if (code === 0) code = 1;
    }
  }
  if (code !== 0) stderr.write(code === 124
    ? `Podman could not ${prepared ? "verify CPU/memory limits within the 30 second execution deadline" : "prepare the runtime UID mapping within the 10 minute preparation deadline; CPU/memory limits remain unverified"}. No application cutover was attempted. Preserve the engine selection and inspect its storage/preparation state before retrying.\n`
    : "Podman runtime/UID mapping and CPU/memory checks did not complete successfully. No application cutover was attempted. Check the original error and engine storage state, then retry with the same engine.\n");
  return typeof code === "number" ? code : 1;
}
