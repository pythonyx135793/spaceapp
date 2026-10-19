# run-spaceapp

Docker and rootless Podman launcher for SpaceApp.

Run the same command in Linux, macOS, or Windows 11 Command Prompt:

```bash
npx --yes run-spaceapp@latest install
```

To keep a global `spaceapp` command for later operations, install it
separately:

```bash
npm install -g run-spaceapp
```

The smallest profile requires Node.js 20.11 or newer, 4 CPUs, 8 GB-class RAM
(7 GiB usable), and 6.5 GiB free for a fresh installation. Keep `@latest` in the command so npm resolves the current release instead
of matching an existing local launcher. If Docker is missing, the universal
install command automatically installs it from official Docker sources on
Windows, macOS, Ubuntu, Debian, Fedora, RHEL, and CentOS, or with native
`pacman` packages on Arch-family Linux including CachyOS. It starts Docker and
waits for Engine and Compose readiness before pulling images. Windows prefers
Windows Package Manager's hash-pinned Docker Desktop
manifest and retains a signed direct-download fallback. Docker Desktop license
acceptance still requires confirmation. On Linux, the same command explains
the root-equivalent `docker` group and adds the current user automatically.
On Windows, approve any UAC prompt required by WSL2 or Docker
Desktop. Use the **Command Prompt** profile because a restricted PowerShell
policy can block npm's `npx.ps1` before SpaceApp starts. On Docker Desktop's
first launch, select **Skip** in the top-right of the **Welcome to Docker**
window (or sign in), accept any remaining Docker prompt, and keep the terminal
open. SpaceApp waits for up to ten minutes and continues automatically when
Docker is ready. If WSL2 requires one restart, SpaceApp registers a one-time
resume and asks before scheduling it. Sign back in after Windows restarts; the
same install continues automatically in Command Prompt without entering a
second command. Headless Windows sessions (SSH, CI services, session 0) also
work: during image pulls the launcher switches Docker to a temporary
credential-free config so Docker Desktop's graphical credential helper is never
invoked outside an interactive logon.

The launcher selects `small`, `medium`, or `large` automatically using CPU,
RAM and free disk. Docker's CPU and RAM allocation is checked as well.

| Profile | CPU | Usable RAM | Fresh free space | Services |
| --- | --- | --- | --- | --- |
| small | 4 | 7 GiB | 6.5 GiB | SpaceApp, OpenCode, PostgreSQL |
| medium | 4 | 11 GiB | 8 GiB | small + background workflow/integration workers |
| large | 8 | 15 GiB | 11 GiB | medium + managed Chromium, larger limits |

Use `install --profile small|medium|large` to choose explicitly. Existing
`light` and `standard` profiles remain compatible. Upgrades preserve the installed
profile unless you explicitly choose another one. Companions and additional AI
CLIs remain optional and can be installed when needed.

An upgrade checks **additional** space: missing image layers, the database
checkpoint and 0.5 GiB headroom. Cached target images require no extra image space.
Shared layers are excluded when public registry metadata is available; otherwise
a conservative estimate is shown. Space is checked again after pulling and
before pausing writers. Existing data is kept in place; the launcher never deletes
images, backups or volumes to free space. Separate Docker disk capacity is checked
when measurable and its availability is reported.

### Rootless Podman (Linux and macOS)

Docker remains the default. Select Podman on a new installation:

```bash
npx --yes run-spaceapp@latest install --engine podman --profile small
# Fresh unattended install (does not enable telemetry or open a browser):
npx --yes run-spaceapp@latest install --engine podman --profile small --non-interactive --no-open
```

Install **Podman 5+** and the standalone **docker-compose v2 >= 2.24.4**
provider first. The launcher does not install Podman. The executable must be
named `docker-compose` on `PATH`; a `docker compose` plugin alone is insufficient.
Every Podman Compose command pins `PODMAN_COMPOSE_PROVIDER=docker-compose`,
including diagnostics and recovery. Python `podman-compose` is unsupported.
Docker host/context/TLS overrides are removed only from the Podman Compose
child's environment so its wrapper selects the Podman socket; the parent
environment and Podman connection settings are preserved.
This provider supplies profiles, optional health dependencies, `init`, resource
limits, file secrets, shared socket volumes, `--wait`, and UID-specific
`exec`/`run`. The Podman override keeps each file secret at its original
read-only target with a shared SELinux label; it never mounts the whole secret
directory. Docker's template and commands remain unchanged.

On Linux, run as a regular user with subordinate UID/GID ranges, **cgroup v2**,
and CPU and memory controllers delegated to the systemd user session. Start
the rootless API socket before installation:

```bash
systemctl --user enable --now podman.socket
podman info
```

The launcher checks both reported delegation and actual kernel CPU/memory
limits in a bounded container before installation/update cutover. Preparing a
cold image's UID mapping has a separate ten-minute deadline; the actual kernel
check then has a thirty-second execution deadline. Preparation does not count
as a successful limits check. `doctor`
and `support-bundle` report engine/provider versions, rootless status, cgroups,
delegation, and available engine resources. Failed checks explain the missing
prerequisite. No resource guard is disabled for Podman.

On macOS, initialize and start a rootless Podman machine first. Intel Macs
require **Podman 5.8**; Podman 6 removed Intel support. Select the machine's
default connection with `podman system connection default <connection>`.
The launcher matches that connection to its running machine, checks the
daemon's actual CPU/RAM and available storage, and prints stop/set/start resize
instructions on failure. A different default machine's configuration or the
Mac's host resources cannot satisfy the guest checks. Environment overrides
`CONTAINER_HOST`/`CONTAINER_CONNECTION` cannot be matched safely here: unset
them and choose the default connection instead. Machine providers differ in
which resources they can resize; preserve volumes before recreating a machine.
Allocate at least the profile's resources in the table above plus VM headroom.

`workspace add <path>` and `workspace add <path> --read-only` use shared SELinux
labels (`z`) so both application services can access the same project on an
enforcing host. Register project folders you own, not system directories: a
relabel traverses their contents. The published images still start their root
entrypoints and drop to UID 10001; `keep-id:uid=10001,gid=10001` maps that user
to the invoking host user. The launcher does not recursively change workspace
ownership or grant world write access. Read-only mounts stay read-only.

The engine is saved and used by every subsequent command, including backup,
restore, owner/credentials/provider commands, repair, rollback and purge. A
configuration without an engine remains Docker. Changing an existing
installation's engine is refused before mutation because the engines cannot
see each other's volumes; no in-place migration is supported. Podman does not
support `--access host-root` or Windows. If Docker is absent and Podman is
installed, a new interactive installation offers Podman; `--non-interactive`
selects it. `--answers` also accepts `"engine":"podman"`. Fresh unattended
Podman setup approves the displayed plan; set `"confirm":false` to cancel.
Existing-install changes and destructive commands retain their confirmations.

A first runtime start records a small `install-engine.json` recovery marker
before creating engine resources. If startup fails, retries retain that engine
even while `config.json` is not committed. A successful config commit removes
the marker, leaving the config as the final source of truth. Malformed or
conflicting markers stop setup rather than being overwritten. Preserve them
and existing volumes when investigating a failed install. Timed-out probes
return exit 124; a bounded return does not prove a stuck engine child or its
I/O ended. The launcher checks removal of its exact named probe and reports
unconfirmed cleanup explicitly; it never prunes unrelated containers or data.

The rootless integration job runs on `ubuntu-latest`, builds pinned Podman and
network helpers from official sources, and uses pinned upstream Compose and
OCI runtime releases. It verifies rootless mappings, cgroup delegation and
actual CPU, memory and storage capacity before an actual small install,
`/readyz` check, nonempty backup with matching hashes and exact owned-resource
purge. The job fails when a prerequisite or cleanup check cannot be verified.

Primary references: [Podman compose provider](https://docs.podman.io/en/v5.8.3/markdown/podman-compose.1.html),
[Podman user namespaces and volume labels](https://docs.podman.io/en/v5.8.3/markdown/podman-run.1.html),
[Compose merge/reset rules](https://docs.docker.com/reference/compose-file/merge/).

### Telemetry

Telemetry is off unless you turn it on. The install wizard lists what is sent
and asks "Enable anonymous usage telemetry?"; the default answer is No. Only
when you answer Yes (or pass `"telemetry": true` in `--answers`) does a first
install (not an upgrade or re-run) get a random install ID, stored as
`installId` in `config.json` and passed to SpaceApp as `SPACE_INSTALL_ID`, and
send events to `https://spaceapp.dev/install-ping.php`, each with a new random
event ID and that install ID:

- `install_started`: operating system and its version, CPU architecture, CPU
  count, RAM in GiB, profile, access mode, launcher and runtime versions.
- `install_completed` or `install_failed`: the duration and, on failure, the
  step that failed (`resources`, `docker`, `doctor`, `pull`, `storage`, `start`,
  `ready`, `owner_setup`, `cleanup`).
- From SpaceApp: `setup_completed` (the owner account was created), `first_cli`
  (which CLI started first, for example `opencode`), `first_answer` (an agent
  finished its first answer) and at most one `active` event a day when the owner
  opens SpaceApp, with the screen size, pixel ratio, browser family and major
  version, UI language and SpaceApp version.

The site derives the country from the request and never stores the IP address.
No files, prompts, answers, models, credentials, workspace paths or account
details are sent. A failed send from SpaceApp is retried at most every ten
minutes. Installations created by earlier launchers have no install ID and send
only the single install ping and `first_answer` event they were told about.
With telemetry No, nothing is sent.

The environment variable `SPACEAPP_TELEMETRY` overrides the answer: `0`, `false`,
`no` or `off` never send the ping or the `first_answer` event; `1`, `true`,
`yes` or `on` send them, which is how unattended installs opt in.

The legacy `light` profile runs the workflow service without managed Chromium;
`standard` runs both. Resource limits are maximums, not immediate RAM or
disk reservations. The launcher stores only non-secret configuration in the
current user's platform config directory:

- Linux: `$XDG_CONFIG_HOME/spaceapp` or `$HOME/.config/spaceapp`
- macOS: `$HOME/Library/Application Support/SpaceApp`
- Windows: `%APPDATA%\SpaceApp`

Set `SPACEAPP_HOME` to an absolute path to use a dedicated installation root.

On Linux, host-root access mounts the host `/` at `/host` (read/write in the
CLI service), so CLI sessions can read and modify the entire host. Read the
[security model](https://github.com/oll4com/spaceapp/blob/main/docs/security-model.md)
before enabling it:

```bash
npx --yes run-spaceapp@latest install --access host-root
```

Host-root is supported only on Linux. Run
`npx --yes run-spaceapp@latest install --access isolated` to remove the host
mount while keeping SpaceApp data and volumes.

Provider API keys are read from masked standard input and written to
restrictive files outside Git. OAuth and device-code credentials remain in
isolated Docker provider state. Neither credential source is included in
portable SpaceApp backups.

Claude Code is not redistributed in SpaceApp images. Install the reviewed
package as an explicit owner action with:

```bash
npx --yes run-spaceapp@latest provider install claude
```

Run `npx --yes run-spaceapp@latest help` for the complete command list. Full
documentation:

- [Getting started](https://github.com/oll4com/spaceapp/blob/main/docs/getting-started.md)
- [CLI providers](https://github.com/oll4com/spaceapp/blob/main/docs/cli-providers.md)
- [Operations](https://github.com/oll4com/spaceapp/blob/main/docs/operations.md)
- [Security model](https://github.com/oll4com/spaceapp/blob/main/docs/security-model.md)

After the stack passes readiness checks, the install command prints the fresh
15-minute token to paste into the browser's **One-time setup token** field. If
it expires before the owner is created, run:

```bash
npx --yes run-spaceapp@latest owner rotate-setup-token
```

### Self-Hosted Installation Help & Recovery

- **Forgot your operator password?** Run in your host terminal:
  ```bash
  npx --yes run-spaceapp@latest owner reset-password
  ```
- **Need a clean install from scratch?** Run:
  ```bash
  npx --yes run-spaceapp@latest factory-reset
  ```

### Common Commands

```bash
npx --yes run-spaceapp@latest status         # Check container health and port bindings
npx --yes run-spaceapp@latest logs           # Show recent container log lines
npx --yes run-spaceapp@latest doctor         # Verify system prerequisites and diagnose Docker
npx --yes run-spaceapp@latest up             # Start containers in background
npx --yes run-spaceapp@latest down           # Stop containers cleanly
npx --yes run-spaceapp@latest open           # Open web app in default browser
npx --yes run-spaceapp@latest backup         # Create verified, portable backup archive
npx --yes run-spaceapp@latest restore        # Restore state from a backup archive
npx --yes run-spaceapp@latest update         # Pull latest images and upgrade stack
npx --yes run-spaceapp@latest rollback       # Return to the previously recorded image version
npx --yes run-spaceapp@latest workspace add <path> # Register host folder for AI CLIs
npx --yes run-spaceapp@latest workspace list       # List registered host folders
npx --yes run-spaceapp@latest credentials list     # List provider names accepted by credentials set
npx --yes run-spaceapp@latest credentials set <provider> # Set API key via masked input
npx --yes run-spaceapp@latest user enable      # Turn team accounts on (invite people in Settings -> Users)
npx --yes run-spaceapp@latest user add <user-id> # Give an invited user their own CLI container
npx --yes run-spaceapp@latest user restore <user-id> # Put a user's CLI settings and memory back from a backup
npx --yes run-spaceapp@latest uninstall      # Stop and remove containers (preserves data)
```

Uninstall retains data by default and prints the separate
`npm uninstall -g run-spaceapp` command for removing an optional global
launcher.
