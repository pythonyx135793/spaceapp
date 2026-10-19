import assert from "node:assert/strict";
import test from "node:test";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile, lstat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import { runInNewContext } from "node:vm";
import { run, executeCommand, commandEnvironment } from "../src/cli.mjs";
import {
  addUser, composeCommand, createDefaultConfig, initializeInstallation, loadConfig,
  prepareInstallation, renderPodmanCompose, renderWorkspaceCompose, saveConfig, validateConfig, loadPendingEngine
} from "../src/index.mjs";
import {
  assertEngineSelection, containerEngine, detectInstallEngine, inspectContainerEngine,
  podmanChecks, podmanMachineHelp, PODMAN_COMPOSE_ENV, PODMAN_COMPOSE_UNSET_ENV, verifyPodmanRuntime
} from "../src/engines.mjs";
import { inspectStoragePlan } from "../src/storage.mjs";

const GiB = 1024 ** 3;
const resources = { cpuCount: 8, totalMemoryBytes: 24 * GiB, freeDiskBytes: 40 * GiB };
const info = () => ({ version: { Version: "5.8.3" },
  host: { cpus: 8, memTotal: 24 * GiB, cgroupVersion: "v2", cgroupManager: "systemd",
    cgroupControllers: ["cpu", "memory", "pids"], security: { rootless: true, selinuxEnabled: true } },
  store: { graphRoot: "/home/test/.local/share/containers/storage", graphRootAllocated: 100 * GiB, graphRootUsed: GiB },
  irrelevantPrivateProperty: "NEVER_COPY_ENGINE_INFO"
});

function output() {
  let value = "";
  return { stream: new Writable({ write(chunk, _encoding, done) { value += chunk; done(); } }), text: () => value };
}

async function snapshotTree(root, relative = "") {
  const path = join(root, relative), metadata = await lstat(path, { bigint: true });
  const entry = { path: relative, mode: String(metadata.mode), mtime: String(metadata.mtimeNs), inode: String(metadata.ino) };
  if (metadata.isFile()) entry.sha256 = createHash("sha256").update(await readFile(path)).digest("hex");
  const entries = [entry];
  if (metadata.isDirectory()) for (const name of (await readdir(path)).sort()) entries.push(...await snapshotTree(root, join(relative, name)));
  return entries;
}

// These are unit fixtures, not Linux/SELinux/machine acceptance evidence.
function executor(calls, { engineInfo = info(), provider = "2.40.0", reachable = true, failUp = false, allowDocker = false } = {}) {
  return async (spec, io = {}) => {
    calls.push(structuredClone(spec));
    const a = spec.args;
    if (spec.command !== "podman" && !(allowDocker && spec.command === "docker")) throw new Error(`Unexpected engine ${spec.command}`);
    let result;
    if (a[0] === "info") result = JSON.stringify(engineInfo);
    else if (a[0] === "--version") result = "podman version 5.8.3";
    else if (a[0] === "compose" && a.includes("version")) result = provider;
    else if (a[0] === "compose" && a.includes("ls")) { if (!reachable) return 1; result = "[]"; }
    else if (a.includes("df")) result = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/test 104857600 1048576 41943040 1% /\n";
    else if (a[0] === "image" && a.includes("inspect")) result = `sha256:${"a".repeat(64)}`;
    else if (a.includes("SELECT pg_database_size(current_database())")) result = "10485760";
    else if (a.includes("pg_dump")) result = "-- PostgreSQL database dump\nSELECT 1;\n";
    if (result !== undefined) io.stdout?.write(result);
    return failUp && a[0] === "compose" && a.includes("up") ? 42 : 0;
  };
}

async function fixture(t, { installed = true, ...options } = {}) {
  const root = await mkdtemp(join(tmpdir(), "spaceapp-podman-unit-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  if (installed) await initializeInstallation(root, { version: "1.1.6", profile: "small", engine: "podman" });
  const calls = [], stdout = output(), stderr = output();
  return { root, calls, stdout, stderr, options: {
    env: { SPACEAPP_HOME: root }, platform: "linux", stdin: Readable.from([]), stdout: stdout.stream, stderr: stderr.stream,
    execute: executor(calls, options), inspectResources: async () => resources,
    ensureDocker: async () => { throw new Error("Podman must never ensure/install Docker"); },
    prepareDockerPath: async () => { throw new Error("Podman must not prepare Docker PATH"); },
    request: async (url) => ({ ok: true, status: 200, json: async () => url.endsWith("/api/setup/status") ? { setupRequired: false, expiresAt: null } : { ok: true } }),
    sleep: async () => {}
  } };
}

test("legacy configs retain their shape and Docker command contract; engine input is an enum", () => {
  const config = createDefaultConfig({ version: "1.1.6" });
  assert.equal(Object.hasOwn(config, "engine"), false);
  assert.equal(containerEngine(config), "docker");
  assert.equal(composeCommand("up", tmpdir(), config).command, "docker");
  for (const engine of [null, "", "nerdctl", "podman;echo unsafe", 1]) {
    assert.throws(() => validateConfig({ ...config, engine }), /Engine/);
  }
});

test("every Compose action selects the stored Podman and pinned provider", () => {
  for (const action of ["up", "down", "status", "logs", "pull", "syncCredentials", "syncWorkspaces", "exportCliSettings", "importCliSettings", "cliHostReady", "exportMemory", "importMemory", "installClaude", "backup", "stopForRestore", "resetOwnerPassword", "rotateOwnerSetupToken", "removeBrowser", "removeTemporal", "enableTemporal", "databaseSize", "storageFree", "purge", "repair", "ensureCheckpointDatabase", "checkpointDump", "checkpointRestore", "installProvider", "restore"]) {
    const command = composeCommand(action, tmpdir(), { engine: "podman", profile: "large", provider: "opencode", backupId: "spaceapp-backup-20261019T110000000Z" });
    assert.equal(command.command, "podman", action);
    assert.deepEqual(command.env, PODMAN_COMPOSE_ENV);
    assert.deepEqual(command.unsetEnv, PODMAN_COMPOSE_UNSET_ENV);
    assert.equal(command.args[0], "compose");
    assert.ok(command.args.includes(join(tmpdir(), "compose.podman.yml")));
    assert.ok(command.args.includes("workflows"));
    assert.ok(command.args.includes("standard"));
  }
  assert.ok(composeCommand("ensureCheckpointDatabase", tmpdir(), { engine: "podman" }).args.includes("--wait"));
  assert.ok(composeCommand("installProvider", tmpdir(), { engine: "podman", provider: "opencode" }).args.includes("10001:10001"));
});

test("fallback detects only Podman on fresh installs; installed or explicit Docker never probes Podman", async () => {
  const calls = [];
  const execute = async (spec, io) => { calls.push(spec); if (spec.command === "docker") return 127; io.stdout?.write("podman version 5.8.3"); return 0; };
  assert.equal(await detectInstallEngine({ platform: "linux", execute }), "podman");
  assert.deepEqual(calls.map((x) => x.command), ["docker", "podman"]);
  calls.length = 0;
  for (const options of [{ existing: {} }, { requested: "docker" }, { allowFallback: false }, { platform: "win32" }]) {
    assert.equal(await detectInstallEngine({ platform: "linux", execute, ...options }), "docker");
  }
  assert.equal(calls.length, 0);
  assert.equal(await detectInstallEngine({ platform: "linux", execute: async () => 0 }), "docker");
  for (const failure of [1, 42, new Error("permission denied")]) {
    const probes = [];
    assert.equal(await detectInstallEngine({ platform: "linux", execute: async (spec) => {
      probes.push(spec.command);
      if (failure instanceof Error) throw failure;
      return failure;
    } }), "docker");
    assert.deepEqual(probes, ["docker"], "an installed malfunctioning Docker must keep its repair path");
  }
});

test("an explicit Docker selection can be recorded without changing legacy defaults", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "spaceapp-docker-selection-unit-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await initializeInstallation(root, { version: "1.1.6" });
  assert.equal(Object.hasOwn(await loadConfig(root), "engine"), false);
  const prepared = await prepareInstallation(root, { version: "1.1.6", engine: "docker" });
  assert.equal(prepared.config.engine, "docker");
  await saveConfig(root, prepared.config);
  assert.equal((await loadConfig(root)).engine, "docker");
});

test("engine switching is refused before configuration, secrets or runtime files change", async (t) => {
  const f = await fixture(t);
  const before = await readFile(join(f.root, "config.json"));
  const files = await readdir(f.root);
  await assert.rejects(() => run(["install", "--engine", "docker", "--non-interactive"], f.options), /Cannot switch/);
  await assert.rejects(() => prepareInstallation(f.root, { version: "1.1.7", engine: "docker" }), /Cannot switch/);
  const config = await loadConfig(f.root);
  delete config.engine;
  await assert.rejects(() => saveConfig(f.root, config), /Cannot switch/);
  assert.deepEqual(await readFile(join(f.root, "config.json")), before);
  assert.deepEqual(await readdir(f.root), files);
  assert.equal(f.calls.length, 0);
  assert.throws(() => assertEngineSelection("podman", {}), /Cannot switch/);
});

test("Podman host-root is refused before a new root is created, including answers", async (t) => {
  const f = await fixture(t, { installed: false });
  const before = await readdir(f.root);
  await assert.rejects(() => run(["install", "--engine=podman", "--access=host-root", "--non-interactive"], f.options), /host-root/);
  await assert.rejects(() => run(["install", "--non-interactive", "--answers", '{"engine":"podman","access":"host-root"}'], f.options), /host-root/);
  assert.deepEqual(await readdir(f.root), before);
  await assert.rejects(() => run(["install", "--non-interactive", "--answers", '{"engine":null}'], f.options), /Engine must/);
});

test("Podman preflight checks real reported versions, provider/API, rootless mode and delegation", async () => {
  const calls = [];
  const facts = await inspectContainerEngine({ config: { engine: "podman" }, platform: "linux", execute: executor(calls) });
  assert.equal(podmanChecks(facts, { platform: "linux" }).every((x) => x.ok), true);
  assert.equal(facts.freeDiskBytes, 40 * GiB);
  assert.equal(JSON.stringify(facts).includes("NEVER_COPY_ENGINE_INFO"), false);
  for (const [field, value, name] of [["version", "4.9.5", "version"], ["clientVersion", "4.9.5", "version"], ["composeVersion", "1.3.0", "Compose"], ["composeVersion", "2.20.0", "Compose"], ["composeReachable", false, "connection"], ["rootless", false, "rootless"], ["cgroupVersion", "v1", "cgroups"], ["cpuLimits", false, "CPU delegation"], ["memoryLimits", false, "memory delegation"]]) {
    assert.equal(podmanChecks({ ...facts, [field]: value }).find((x) => x.name.includes(name)).ok, false, field);
  }
  assert.equal(podmanChecks(facts, { platform: "win32" }).at(-1).ok, false);
  assert.ok(calls.filter((x) => x.args[0] === "compose").every((x) => x.env.PODMAN_COMPOSE_PROVIDER === "docker-compose"));
});

test("reported disk allocation is never substituted for actual available blocks", async () => {
  const facts = await inspectContainerEngine({ config: { engine: "podman" }, execute: async (spec, io) => {
    if (spec.args.includes("df")) return 1;
    return executor([])(spec, io);
  } });
  assert.equal(facts.freeDiskBytes, null);
  const checks = podmanChecks(facts, { profile: "large", requirements: { cpuCount: 8, memoryBytes: 15 * GiB, freshDiskBytes: 11 * GiB } });
  assert.equal(checks.find((x) => x.name === "Podman storage").ok, false);
});

test("the selected custom Mac connection determines the machine and remote disk probe", async () => {
  const calls = [], fallback = executor(calls);
  const facts = await inspectContainerEngine({ config: { engine: "podman" }, platform: "darwin", execute: async (spec, io) => {
    const a = spec.args;
    let result;
    if (a[0] === "system") result = [{ Name: "custom", Default: true, URI: "ssh://core@127.0.0.1:55022/run/user/501/podman/podman.sock" }];
    if (a[0] === "machine" && a[1] === "list") result = [{ Name: "podman-machine-default" }, { Name: "my-custom" }];
    if (a[0] === "machine" && a[1] === "inspect") {
      assert.deepEqual(a.slice(2), ["podman-machine-default", "my-custom"]);
      result = [{ Name: "podman-machine-default", State: "stopped", SSHConfig: { Port: 55021, RemoteUsername: "core" } },
        { Name: "my-custom", State: "running", Rootful: false, SSHConfig: { Port: 55022, RemoteUsername: "core" }, Resources: { CPUs: 8, Memory: 24576, DiskSize: 60 } }];
    }
    if (result) { calls.push(spec); io.stdout.write(JSON.stringify(result)); return 0; }
    return fallback(spec, io);
  } });
  assert.equal(facts.machine.name, "my-custom");
  assert.equal(facts.freeDiskBytes, 40 * GiB);
  assert.ok(calls.some((x) => x.args.slice(0, 4).join(" ") === "machine ssh my-custom df"));
  const guidance = podmanMachineHelp("large", { cpuCount: 8, memoryBytes: 15 * GiB, freshDiskBytes: 11 * GiB });
  assert.match(guidance, /machine stop.*machine set --cpus 8 --memory 16384.*machine start/);
});

test("Podman overlays preserve entrypoint root, map runtime UID10001, and use shared labels without chown", () => {
  let config = createDefaultConfig({ version: "1.1.6", engine: "podman" });
  const workspace = { id: "project-1234abcd", name: "project", hostPath: "/home/test/project", containerPath: "/workspaces/project", readOnly: false };
  config.workspaces = [workspace, { ...workspace, id: "read-only-5678abcd", name: "read-only", hostPath: "/home/test/reference", containerPath: "/workspaces/reference", readOnly: true }];
  config = addUser({ ...config, users: [] }, "user:Example");
  const override = renderPodmanCompose(), mounts = renderWorkspaceCompose(config);
  assert.match(override, /user: "0:0"\n    userns_mode: keep-id:uid=10001,gid=10001/);
  assert.match(override, /secrets: !reset \[\]/);
  assert.match(override, /\.\/secrets\/postgres-password:\/run\/secrets\/postgres-password:ro,z/);
  assert.match(override, /spaceapp-cli-socket:\/run\/spaceapp-cli:z/);
  assert.match(mounts, /read_only: true\n        bind:\n          selinux: z/);
  assert.match(mounts, /read_only: false\n        bind:\n          selinux: z/);
  assert.doesNotMatch(override + mounts, /label=disable|:U\b|:Z\b|privileged:|docker\.sock/);
});

test("a failed real-limit probe always cleans up its exact owned container name", async () => {
  const calls = [], stream = output();
  assert.equal(await verifyPodmanRuntime({ config: { engine: "podman", version: "1.1.6" }, stdout: stream.stream, stderr: stream.stream,
    execute: async (spec) => { calls.push(spec); return spec.args[0] === "start" ? 42 : 0; } }), 42);
  const name = calls[0].args[calls[0].args.indexOf("--name") + 1];
  assert.match(name, /^spaceapp-engine-probe-/);
  assert.deepEqual(calls[1].args, ["start", "--attach", name]);
  assert.deepEqual(calls[2].args, ["rm", "--force", name]);
  assert.ok(calls[0].args.includes("--cpus=0.5"));
  assert.ok(calls[0].args.includes("--memory=134217728"));
  assert.match(stream.text(), /No application cutover/);
});

test("cold image preparation and actual limit verification have separate bounds and both must succeed", async () => {
  for (const [createCode, startCode] of [[42, 0], [124, 0], [0, 124], [0, 0], [undefined, 0]]) {
    const calls = [], stream = output();
    const code = await verifyPodmanRuntime({ config: { engine: "podman", version: "1.1.6" }, stdout: stream.stream, stderr: stream.stream,
      execute: async (spec) => { calls.push(spec); return spec.args[0] === "create" ? createCode : spec.args[0] === "start" ? startCode : 0; } });
    assert.equal(code, createCode === 0 ? startCode : createCode ?? 1);
    assert.equal(calls[0].timeoutMs, 600000);
    for (const flag of ["--pull=never", "--rm", "--memory=134217728", "--cpus=0.5", "--userns=keep-id:uid=10001,gid=10001", "--user=0:0"]) assert.ok(calls[0].args.includes(flag), flag);
    assert.equal(calls[0].args.at(-3), "ghcr.io/oll4com/spaceapp-core:1.1.6");
    const start = calls.find((spec) => spec.args[0] === "start");
    assert.equal(Boolean(start), createCode === 0);
    if (start) assert.equal(start.timeoutMs, 30000);
    assert.equal(calls.at(-1).args[0], "rm");
    assert.equal(calls.at(-1).args.at(-1), calls[0].args[2]);
    if (createCode === 124) assert.match(stream.text(), /10 minute preparation deadline; CPU\/memory limits remain unverified/);
    if (createCode === 0 && startCode === 124) assert.match(stream.text(), /30 second execution deadline/);
  }
});

test("the emitted kernel-limit check rejects malformed, nonfinite, absent or incorrectly applied CPU quotas", async () => {
  let script;
  await verifyPodmanRuntime({ config: { engine: "podman", version: "1.1.6" }, stdout: output().stream, stderr: output().stream,
    execute: async (spec) => { if (spec.args[0] === "create") script = spec.args.at(-1); return 0; } });
  const check = (cpu, memory = "134217728") => runInNewContext(script, {
    require: () => ({ readFileSync: (path) => path.endsWith("cpu.max") ? cpu : memory }),
    process: { exit: (code) => { throw new Error(`exit ${code}`); } }, console: { log() {} }
  });
  assert.doesNotThrow(() => check("50000 100000\n"));
  assert.doesNotThrow(() => check("100000 200000\n"));
  for (const cpu of ["", "max 100000", "wat 100000", "Infinity 100000", "50000 0", "0 100000", "-1 100000", "50000", "50000.5 100001", "25000 100000", "100000 100000"]) {
    assert.throws(() => check(cpu), /exit 1/, cpu);
  }
  assert.throws(() => check("50000 100000", "max"), /exit 1/);
});

test("named probe cleanup distinguishes absent, present and failed checks and preserves exit124", async () => {
  for (const [runCode, exists, expected] of [[0, 1, 0], [0, 0, 1], [0, 124, 1], [124, 124, 124]]) {
    const stream = output(), calls = [];
    const code = await verifyPodmanRuntime({ config: { engine: "podman", version: "1.1.6" }, stdout: stream.stream, stderr: stream.stream,
      execute: async (spec) => { calls.push(spec); return spec.args[0] === "create" ? 0 : spec.args[0] === "start" ? runCode : spec.args[0] === "rm" ? 1 : exists; } });
    assert.equal(code, expected);
    assert.deepEqual(calls[3].args.slice(0, 2), ["container", "exists"]);
    assert.equal(calls[3].args[2], calls[2].args[2]);
    if (exists !== 1) assert.match(stream.text(), /cleanup could not be confirmed/);
  }
});

test("install accepts --engine and answers, persists the selection, and stages only Podman", async (t) => {
  for (const args of [["--engine", "podman"], ["--answers", '{"engine":"podman"}']]) {
    const f = await fixture(t, { installed: false });
    assert.equal(await run(["install", ...args, "--profile", "small", "--no-open", "--non-interactive"], f.options), 0, f.stderr.text());
    assert.equal((await loadConfig(f.root)).engine, "podman");
    assert.ok(f.calls.some((x) => x.args.includes("up")));
    assert.ok(f.calls.some((x) => x.args[0] === "create"));
    assert.ok(f.calls.some((x) => x.args[0] === "start"));
    assert.ok(f.calls.filter((x) => x.args[0] === "compose").every((x) => x.env.PODMAN_COMPOSE_PROVIDER === "docker-compose"));
    assert.ok((await readFile(join(f.root, "compose.podman.yml"), "utf8")).includes("keep-id"));
  }
});

test("fresh noninteractive fallback selects installed Podman without invoking Docker installation", async (t) => {
  const f = await fixture(t, { installed: false });
  delete f.options.ensureDocker;
  const podman = f.options.execute;
  f.options.execute = async (spec, io) => {
    if (spec.command === "docker") { f.calls.push(spec); assert.deepEqual(spec.args, ["--version"]); return 127; }
    return podman(spec, io);
  };
  assert.equal(await run(["install", "--profile", "small", "--no-open", "--non-interactive"], f.options), 0, f.stderr.text());
  assert.equal((await loadConfig(f.root)).engine, "podman");
  assert.equal(f.calls.filter((x) => x.command === "docker").length, 1);
});

test("explicit refusal and insufficient engine resources stop before pull or runtime mutation", async (t) => {
  const f = await fixture(t, { installed: false });
  assert.equal(await run(["install", "--engine", "podman", "--non-interactive", "--answers", '{"confirm":false}'], f.options), 0);
  assert.deepEqual(await readdir(f.root), []);
  assert.equal(f.calls.length, 0);
  const engineInfo = info();
  engineInfo.host.cpus = 4;
  engineInfo.host.memTotal = 10 * GiB;
  f.options.execute = executor(f.calls, { engineInfo });
  assert.equal(await run(["install", "--engine", "podman", "--profile", "large", "--no-open", "--non-interactive"], f.options), 1);
  assert.match(f.stderr.text(), /FAIL Podman CPU|FAIL Podman memory/);
  assert.equal(f.calls.some((x) => x.args.includes("pull") || x.args.includes("up")), false);
});

test("failed fresh install diagnostics and cleanup retain the selected Podman", async (t) => {
  const f = await fixture(t, { installed: false, failUp: true });
  assert.equal(await run(["install", "--engine", "podman", "--profile", "small", "--no-open", "--non-interactive"], f.options), 42);
  for (const action of ["ps", "logs", "down"]) assert.ok(f.calls.some((x) => x.args[0] === "compose" && x.args.includes(action)), action);
  assert.equal(f.calls.some((x) => x.command === "docker"), false);
});

test("failed first starts lock BOTH engines before preserved volumes; same-engine retry commits and removes the marker", async (t) => {
  for (const engine of ["docker", "podman"]) {
    const f = await fixture(t, { installed: false });
    f.options.prepareDockerPath = async () => {};
    f.options.ensureDocker = async () => ({ code: 0 });
    const fail = executor(f.calls, { failUp: true, allowDocker: true });
    f.options.execute = async (spec, io) => {
      if (spec.args[0] === "compose" && spec.args.includes("up")) assert.equal(await loadPendingEngine(f.root), engine);
      return fail(spec, io);
    };
    const args = ["install", "--engine", engine, "--profile", "small", "--no-open", "--non-interactive", "--answers", '{"confirm":true}'];
    assert.equal(await run(args, f.options), 42, f.stderr.text());
    assert.equal(await loadPendingEngine(f.root), engine);
    await assert.rejects(() => loadConfig(f.root), { code: "ENOENT" });
    const marker = await readFile(join(f.root, "install-engine.json"));
    const tree = await snapshotTree(f.root);
    const calls = f.calls.length;
    const other = engine === "docker" ? "podman" : "docker";
    await assert.rejects(() => run(["install", "--engine", other, "--non-interactive"], f.options), /Cannot switch/);
    assert.equal(f.calls.length, calls);
    assert.deepEqual(await readFile(join(f.root, "install-engine.json")), marker);
    assert.deepEqual(await snapshotTree(f.root), tree, "switch refusal must leave every file and directory unchanged");
    f.options.execute = executor(f.calls, { allowDocker: true });
    assert.equal(await run(args, f.options), 0, f.stderr.text());
    assert.equal(containerEngine(await loadConfig(f.root)), engine);
    assert.equal(await loadPendingEngine(f.root), null);
  }
});

test("the first Podman runtime probe already has a durable engine claim and its timeout stays124", async (t) => {
  const f = await fixture(t, { installed: false });
  const execute = f.options.execute;
  f.options.execute = async (spec, io) => {
    if (spec.args[0] === "create") {
      assert.equal(await loadPendingEngine(f.root), "podman");
      f.calls.push(spec);
      return 124;
    }
    return execute(spec, io);
  };
  assert.equal(await run(["install", "--engine", "podman", "--profile", "small", "--non-interactive", "--no-open"], f.options), 124);
  assert.equal(await loadPendingEngine(f.root), "podman");
  assert.equal(f.calls.some((x) => x.args.includes("up")), false);
  await assert.rejects(() => run(["install", "--engine", "docker", "--non-interactive"], f.options), /Cannot switch/);
});

test("malformed, oversized or nonregular pending markers fail before any engine probe or write", async (t) => {
  for (const content of ["not json", JSON.stringify({ schemaVersion: 1, engine: "podman", extra: true }), JSON.stringify({ schemaVersion: 2, engine: "podman" }), "x".repeat(257), null]) {
    const f = await fixture(t, { installed: false });
    const path = join(f.root, "install-engine.json");
    if (content === null) await mkdir(path); else await writeFile(path, content);
    await assert.rejects(() => run(["install", "--engine", "podman", "--non-interactive"], f.options), /Invalid pending/);
    assert.equal(f.calls.length, 0);
    if (content !== null) assert.equal(await readFile(path, "utf8"), content);
    assert.deepEqual(await readdir(f.root), ["install-engine.json"]);
  }
});

test("a pending marker conflicting with config is preserved; matching crash recovery removes it on commit", async (t) => {
  const f = await fixture(t);
  const path = join(f.root, "install-engine.json");
  await writeFile(path, JSON.stringify({ schemaVersion: 1, engine: "docker" }));
  const before = await readFile(join(f.root, "config.json"));
  await assert.rejects(() => run(["up"], f.options), /Cannot switch/);
  assert.deepEqual(await readFile(join(f.root, "config.json")), before);
  assert.equal(f.calls.length, 0);
  await writeFile(path, JSON.stringify({ schemaVersion: 1, engine: "podman" }));
  await saveConfig(f.root, await loadConfig(f.root));
  assert.equal(await loadPendingEngine(f.root), null);
});

test("all ordinary lifecycle, provider and owner commands dispatch Podman", async (t) => {
  const f = await fixture(t);
  for (const args of [["up"], ["status"], ["logs"], ["down"], ["credentials", "list"], ["provider", "install", "opencode"], ["owner", "rotate-setup-token"]]) {
    assert.equal(await run([...args, "--non-interactive", "--answers", '{"confirm":true}'], f.options), 0, `${args}: ${f.stderr.text()}`);
  }
  assert.ok(f.calls.some((x) => x.args.includes("/app/deploy/docker/provider-install.mjs")));
  assert.ok(f.calls.some((x) => x.args.includes("scripts/rotate-owner-setup-token.mjs")));
  assert.equal(f.calls.some((x) => x.command === "docker"), false);
});

test("workspace RW and RO updates and per-user recreation retain Podman without Docker ACL advice", async (t) => {
  const f = await fixture(t);
  const workspace = join(f.root, "example");
  await mkdir(workspace);
  assert.equal(await run(["workspace", "add", workspace], f.options), 0);
  assert.equal(await run(["workspace", "remove", workspace], f.options), 0);
  assert.equal(await run(["workspace", "add", workspace, "--read-only"], f.options), 0);
  assert.match(await readFile(join(f.root, "compose.workspaces.yml"), "utf8"), /read_only: true/);
  assert.doesNotMatch(f.stdout.text(), /setfacl|cannot write/);
});

test("user containers, credentials and owner password changes use only the selected Podman", async (t) => {
  const f = await fixture(t);
  assert.equal(await run(["user", "enable"], f.options), 0);
  assert.equal(await run(["user", "add", "user:Example"], f.options), 0);
  f.options.stdin = Readable.from(["unit-fixture-only-not-a-real-key\n"]);
  assert.equal(await run(["credentials", "set", "opencode", "--user", "user:Example"], f.options), 0);
  assert.equal(await run(["credentials", "remove", "opencode", "--user", "user:Example"], f.options), 0);
  f.options.stdin = Readable.from(["unit-fixture-password\n"]);
  assert.equal(await run(["owner", "reset-password"], f.options), 0);
  assert.ok(f.calls.some((x) => x.args.includes("10001:10001") && x.args.includes("scripts/reset-owner-password.mjs")));
  assert.ok(f.calls.some((x) => x.args.includes("cliHostReady") || x.args.some((a) => a.startsWith("spaceapp-cli-example-"))));
  assert.ok(f.calls.every((x) => x.command === "podman"));
});

test("restore, reinstall and factory reset preserve Podman including fresh configuration", async (t) => {
  const f = await fixture(t);
  await mkdir(join(f.root, "backups", "spaceapp-backup-20261019T110000000Z"));
  f.options.stdin = Readable.from(["RESTORE\n"]);
  assert.equal(await run(["restore"], f.options), 0, f.stderr.text());
  assert.ok(f.calls.some((x) => x.args.includes("scripts/portable-restore.mjs")));
  f.options.stdin = Readable.from([]);
  assert.equal(await run(["reinstall", "--non-interactive", "--answers", '{"confirm":true}'], f.options), 0, f.stderr.text());
  f.options.stdin = Readable.from(["FACTORY-RESET\n"]);
  assert.equal(await run(["factory-reset"], f.options), 0, f.stderr.text());
  assert.equal((await loadConfig(f.root)).engine, "podman");
  assert.ok(f.calls.every((x) => x.command === "podman"));
});

test("backup, repair, checkpoint update and rollback preserve the selected engine", async (t) => {
  const f = await fixture(t);
  for (const args of [["backup"], ["doctor", "--fix"], ["update", "1.1.7"], ["rollback"]]) {
    assert.equal(await run([...args, "--non-interactive", "--answers", '{"confirm":true}'], f.options), 0, `${args}: ${f.stderr.text()}`);
    assert.equal((await loadConfig(f.root)).engine, "podman");
  }
  assert.ok(f.calls.some((x) => x.args.includes("pg_dump")));
  assert.ok(f.calls.some((x) => x.args.includes("--wait")));
  assert.ok(f.calls.every((x) => x.command === "podman"));
});

test("a failed Podman update checkpoint and recovery never dispatch Docker", async (t) => {
  const f = await fixture(t);
  const ok = f.options.execute;
  f.options.execute = async (spec, io) => spec.args[0] === "compose" && spec.args.includes("up") && !spec.args.includes("--wait")
    ? (f.calls.push(spec), 42) : ok(spec, io);
  assert.equal(await run(["update", "1.1.7", "--non-interactive", "--answers", '{"confirm":true}'], f.options), 1);
  assert.match(f.stderr.text(), /RECOVERY_REQUIRED/);
  assert.equal((await loadConfig(f.root)).engine, "podman");
  assert.ok(f.calls.every((x) => x.command === "podman"));
});

test("doctor and the support bundle contain the same safe engine facts", async (t) => {
  const f = await fixture(t);
  assert.equal(await run(["doctor"], f.options), 0, f.stderr.text());
  assert.match(f.stdout.text(), /Podman rootless: rootless/);
  assert.match(f.stdout.text(), /cgroup v2|v2; cgroup v2/);
  assert.match(f.stdout.text(), /CPU delegation: cpu controller delegated/);
  const destination = join(f.root, "support.json");
  assert.equal(await run(["support-bundle", "--out", destination], f.options), 0);
  const raw = await readFile(destination, "utf8"), bundle = JSON.parse(raw);
  assert.equal(bundle.engine.engine, "podman");
  assert.equal(bundle.engine.version, "5.8.3");
  assert.equal(bundle.engine.rootless, true);
  assert.equal(bundle.engine.cpuLimits, true);
  assert.equal(bundle.engine.memoryLimits, true);
  assert.doesNotMatch(raw, /NEVER_COPY_ENGINE_INFO|session-secret|postgres-password/);
});

test("uninstall and purge act on Podman volumes and retain the stored selection", async (t) => {
  const f = await fixture(t);
  for (const args of [["uninstall"], ["uninstall", "--purge-data"]]) {
    assert.equal(await run([...args, "--non-interactive", "--answers", '{"confirm":true,"purgeConfirm":"DELETE"}'], f.options), 0);
  }
  assert.ok(f.calls.some((x) => x.args.includes("--volumes")));
  assert.equal((await loadConfig(f.root)).engine, "podman");
});

test("Podman storage probes the selected engine and retains real CPU/memory allocations", async (t) => {
  const f = await fixture(t);
  const plan = await inspectStoragePlan({ root: f.root, config: await loadConfig(f.root), resources, execute: f.options.execute, operation: "fresh" });
  assert.equal(plan.engine, "podman");
  assert.equal(plan.resources.engineCpuCount, 8);
  assert.equal(plan.resources.engineMemoryBytes, 24 * GiB);
  assert.equal(plan.dockerFreeDiskBytes, 40 * GiB);
  assert.ok(f.calls.every((x) => x.command === "podman"));
});

test("static dispatch rejects arbitrary executables and unpinned compose provider overrides", async () => {
  await assert.rejects(() => executeCommand({ command: "podman;echo unsafe", args: [] }), /untrusted command/);
  await assert.rejects(() => executeCommand({ command: "podman", args: ["compose", "version"], env: { PODMAN_COMPOSE_PROVIDER: "python-podman-compose" } }), /untrusted command environment/);
  await assert.rejects(() => executeCommand({ command: "podman", args: ["compose", "version"], env: { DOCKER_CONTEXT: "desktop-linux" } }), /untrusted command environment/);
  await assert.rejects(() => executeCommand({ command: "podman", args: ["compose", "version"], unsetEnv: ["PATH"] }), /untrusted command environment removals/);
});

test("Podman children drop Docker routing/TLS overrides while preserving parent and Podman connection", () => {
  const inherited = { PATH: "unchanged", DOCKER_HOST: "tcp://wrong-engine:2375", DOCKER_CONTEXT: "desktop-linux", DOCKER_TLS: "1",
    DOCKER_TLS_VERIFY: "1", DOCKER_CERT_PATH: "/unit-fixture-only", CONTAINER_CONNECTION: "my-podman-machine" };
  const original = structuredClone(inherited);
  const child = commandEnvironment(composeCommand("up", tmpdir(), { engine: "podman" }), inherited);
  for (const name of PODMAN_COMPOSE_UNSET_ENV) assert.equal(Object.hasOwn(child, name), false, name);
  assert.equal(child.CONTAINER_CONNECTION, inherited.CONTAINER_CONNECTION);
  assert.equal(child.PATH, inherited.PATH);
  assert.equal(child.PODMAN_COMPOSE_PROVIDER, "docker-compose");
  assert.deepEqual(inherited, original);
  assert.deepEqual(commandEnvironment(composeCommand("up", tmpdir()), inherited), inherited);
});
