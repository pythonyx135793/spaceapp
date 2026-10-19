import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { waitForTimedCommand } from "../src/command-timeout.mjs";

const posix = process.platform !== "win32";

test("a bounded command retains its real nonzero exit code", async () => {
  const child = spawn(process.execPath, ["-e", "process.exit(42)"], { detached: posix, stdio: ["ignore", "pipe", "pipe"] });
  assert.equal(await waitForTimedCommand(child, { timeoutMs: 5000, ownedGroup: posix }), 42);
});

async function ready(child) {
  return new Promise((resolve, reject) => {
    let text = "";
    const timer = setTimeout(() => reject(new Error("Deadline fixture did not start")), 5000);
    child.once("error", reject);
    child.stdout.on("data", (chunk) => {
      text += chunk;
      if (text.includes("READY\n")) { clearTimeout(timer); resolve(); }
    });
  });
}

test("an ignored TERM and a same-group child holding inherited pipes cannot defeat a deadline", { skip: !posix, timeout: 10000 }, async (t) => {
  const code = `
    const {spawn}=require('node:child_process');
    process.on('SIGTERM',()=>{});
    const child=spawn(process.execPath,['-e',"process.on('SIGTERM',()=>{});process.send('ready');setInterval(()=>{},1000)"],{stdio:['ignore','inherit','inherit','ipc']});
    child.once('message',()=>{process.stdout.write('READY\\n');setInterval(()=>{},1000)});
  `;
  const child = spawn(process.execPath, ["-e", code], { detached: true, stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) {
      try { process.kill(-child.pid, "SIGKILL"); } catch { /* Already gone. */ }
    }
  });
  await ready(child);
  let timeout = false, unconfirmed = false;
  const start = performance.now();
  assert.equal(await waitForTimedCommand(child, { timeoutMs: 60, graceMs: 60, ownedGroup: true,
    onTimeout: () => { timeout = true; }, onUnconfirmedExit: () => { unconfirmed = true; } }), 124);
  assert.equal(timeout, true);
  assert.equal(unconfirmed, true);
  assert.ok(performance.now() - start < 2000);
});

test("an exited leader with a live inherited pipe returns 124 and reports unconfirmed descendants", { skip: !posix, timeout: 10000 }, async () => {
  const code = `
    const {spawn}=require('node:child_process');
    const child=spawn(process.execPath,['-e',"process.send('ready');setTimeout(()=>process.exit(0),1500)"],{stdio:['ignore','inherit','inherit','ipc']});
    child.once('message',()=>{process.stdout.write('READY\\n');process.exit(0)});
  `;
  const child = spawn(process.execPath, ["-e", code], { detached: true, stdio: ["ignore", "pipe", "pipe"] });
  await ready(child);
  let unconfirmed = false;
  const start = performance.now();
  assert.equal(await waitForTimedCommand(child, { timeoutMs: 60, graceMs: 60, ownedGroup: true,
    onUnconfirmedExit: () => { unconfirmed = true; } }), 124);
  assert.equal(child.exitCode, 0);
  assert.equal(unconfirmed, true);
  assert.ok(performance.now() - start < 2000);
  // Deliberately do not signal a dead leader's old group. The finite fixture
  // closes its own descendant; returning 124 did not claim that it was killed.
  await new Promise((resolve) => setTimeout(resolve, 1600));
});
