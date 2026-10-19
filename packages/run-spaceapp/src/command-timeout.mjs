export const COMMAND_TIMEOUT_GRACE_MS = 1000;

// The caller creates an isolated POSIX group before spawning the trusted command.
// A deadline bounds the awaiter even when an uninterruptible child or inherited
// pipe cannot close. Exit 124 never certifies that side effects/descendants ended.
export function waitForTimedCommand(child, {
  timeoutMs,
  graceMs = COMMAND_TIMEOUT_GRACE_MS,
  ownedGroup = false,
  platform = process.platform,
  onTimeout = () => {},
  onUnconfirmedExit = () => {}
}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !Number.isFinite(graceMs) || graceMs <= 0) {
    throw new Error("A positive command deadline and termination grace are required.");
  }
  return new Promise((resolve, reject) => {
    let finished = false, exited = false, timedOut = false, deadline, escalation;
    const notify = (callback) => { try { callback(); } catch { /* Diagnostics must not break deadline handling. */ } };
    const finish = (code, error) => {
      if (finished) return;
      finished = true;
      clearTimeout(deadline);
      clearTimeout(escalation);
      if (error) reject(error); else resolve(code);
    };
    const signal = (name) => {
      // Once the leader exits its PID/group could be reused. Do not signal that
      // group based solely on an old number, even when inherited pipes survive.
      if (exited || !child.pid) return;
      try {
        if (ownedGroup && platform !== "win32") process.kill(-child.pid, name);
        else child.kill(name);
      } catch { /* ESRCH/races cannot turn a timeout into success. */ }
    };
    child.once("exit", () => { exited = true; });
    child.once("error", (error) => finish(error?.code === "ENOENT" ? 127 : null, error?.code === "ENOENT" ? null : error));
    child.once("close", (code, exitSignal) => finish(timedOut ? 124 : code ?? (exitSignal ? 1 : 0)));
    deadline = setTimeout(() => {
      timedOut = true;
      notify(onTimeout);
      signal("SIGTERM");
      escalation = setTimeout(() => {
        signal("SIGKILL");
        notify(onUnconfirmedExit);
        child.stdin?.destroy();
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.unref();
        finish(124);
      }, graceMs);
    }, timeoutMs);
  });
}
