# BaitBox

**Malware scanner and sandbox for untrusted Node.js projects.**

[![CI](https://github.com/Avijit07x/baitbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Avijit07x/baitbox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

BaitBox inspects a project before anyone opens it in an editor or runs it. It works in 4 stages:

1. **Unpack.** It extracts the archive or clones the repository safely.
2. **Read.** It examines every file that can run code by itself.
3. **Check packages.** It checks every npm package against the npm registry and the [OSV](https://osv.dev) malware database.
4. **Run.** It installs and runs the project in an isolated Linux sandbox seeded with decoy credentials, and records every process, file and network call.

The result is a verdict, a report, and the evidence behind every finding.

```console
$ baitbox check project.zip

Verdict: Malware found. Do not open or run this project.
Findings: 5 high, 1 medium
  - [static scan] frontend/package.json:23: known malware | "tw-motion-css": "^2.0.2"
  - [static scan] frontend/tailwind.config.js:103: known malware | require('tw-motion-css')({
  - [packages] tw-motion-css: listed as malware in OSV: MAL-2026-18734
  - [packages] tw-motion-css: npm replaced it with a security placeholder (0.0.1-security); it was malware
  - [packages] tw-motion-css: 1 day old, 507 downloads a week, 2 versions
Report: ~/baitbox-checks/project-20261108-125510/report.md
```

## Why config files matter

Files such as `tailwind.config.js`, `vite.config.ts` and `next.config.js` are code. Editor extensions and dev servers execute them as soon as a folder is opened. Malware hidden in one of them needs no install script.

That is why `npm install --ignore-scripts` and `npm audit` are not enough on their own. BaitBox treats every file that can execute automatically as part of the attack surface.

## Features

- **Safe unpacking:**
  - handles zip, tar, folders, single files and git links (GitHub, GitLab, Bitbucket, Codeberg or any `https`/`ssh` remote);
  - refuses path traversal, external symlinks, device files and zip bombs;
  - turns off git settings that execute commands.
- **Static analysis:** finds files that run code by themselves and the packages each one loads. It also flags:
  - obfuscation, invisible Unicode and bidirectional control characters;
  - code hidden after long runs of whitespace;
  - hard-coded IP addresses, references to credential stores, and disguised binaries.
- **Package checks:** reads lockfiles from npm, pnpm, Yarn (classic and Berry) and Bun, plus `node_modules`. It flags:
  - known malware;
  - packages removed by npm, and versions missing from the registry;
  - throwaway packages: new, rarely downloaded, with few versions;
  - lookalike names, install scripts, and dependencies from outside the registry.
- **Sandboxed execution:** built on bubblewrap. It has:
  - a decoy home directory with bait credentials;
  - no network during the run step;
  - a tamper-proof `strace` recording kept outside the sandbox.
- **Phase-aware analysis:** every action is attributed to the step that caused it: config load, install scripts, or `npm run <script>`.
- **Automation-friendly:** exit codes per verdict, JSON output, and no dependencies beyond Python 3.10+ and Bash.

## Quick start

```bash
git clone https://github.com/Avijit07x/baitbox.git
cd baitbox
bin/baitbox doctor
bin/baitbox selftest
bin/baitbox check path/to/project.zip
```

- `doctor` verifies that the machine can run the sandbox.
- `selftest` runs a harmless simulated attack and confirms that each part of it is detected.
- `check` accepts any of these:
  - an archive, a folder or a single file;
  - a git link, with or without `https://`;
  - a browser link such as `github.com/owner/repo/tree/dev`, which checks the `dev` branch.

> Do not open an untrusted project in an editor before the check is complete. Editor extensions load config files, and config files are code.

## How a check works

| Step | Network | What happens |
| --- | --- | --- |
| 1. Unpack | none (git links: clone only) | Rejects unsafe archive entries. Clones with hooks, symlinks, LFS and submodules off. Turns off `.git/config` settings that execute commands, such as `core.fsmonitor`, `core.sshCommand`, `!` aliases, filters and `include.path`. Turns off hidden bare repositories too, because shell prompts run git as soon as you enter a directory. |
| 2. Static scan | none | Lists every file that executes code by itself, and the packages it loads. Applies pattern, entropy and signature checks. |
| 3. Package check | npm, OSV | Checks every direct, locked and installed package. |
| 4. Install | online, in the sandbox | `npm install --ignore-scripts` (or pnpm). Project `.npmrc` files are off, so embedded tokens and registries are never used. |
| 5. Run | offline, in the sandbox | Runs install scripts, loads every config file the way an editor does, and runs `build`, `dev` and `start`. Then waits for delayed actions. |

## Verdicts

| Verdict | Exit code | Meaning |
| --- | --- | --- |
| `malicious` | 2 | Known malware, or malicious behaviour in the sandbox. |
| `suspicious` | 1 | A high-risk finding, or risky behaviour in the sandbox. |
| `review` | 0 | Nothing harmful ran, but some files need a look. |
| `nothing-seen` | 0 | No findings. This is not proof that the project is safe. |
| `error` | 3 | The check did not complete. Treat the project as unchecked. |

## Detection coverage

| Behaviour | Example finding |
| --- | --- |
| Outbound connection to a hard-coded address | `tried to connect to a hard-coded address 216.126.231.70:1224` |
| Domain lookup during config load or install | `looked up evil.example while loading config or running install scripts` |
| Lookup of tunnelling, paste or exfiltration services | `looked up x.trycloudflare.com, a service often used to leak data or hide servers` |
| Reading credentials | `read a bait secret: ~/.ssh/id_ed25519`, including reads through symlinks |
| Persistence | `wrote to a startup location: ~/.config/autostart/update.desktop` |
| Privilege escalation or second-stage download | `started sudo`, `ran a shell command that downloads or decodes code` |
| Access to host services | `tried to reach a privileged service: /var/run/docker.sock` |
| Tampering with the evidence | not possible: the recording is written outside the sandbox |

Findings are weighted by phase. A config file that opens a network connection is high severity. An application that looks up its own database during `npm run dev` is informational.

## Limitations

- Payloads that wait longer than the run, or wait for a date, a login or user input.
- Malware that detects the sandbox and stays dormant. The sandbox imitates a regular workstation, but it cannot be made undetectable.
- Code paths that need real services, accounts, browsers or network access.
- Windows-only and macOS-only payloads, and projects that are not Node.js. These receive static analysis only.
- Kernel exploits that escape unprivileged sandboxes.

A clean result means nothing harmful was observed. Develop untrusted projects in a VM or a container without personal credentials.

## Installation

### Requirements

- Linux with unprivileged user namespaces
- `bubblewrap` and `strace` 5.9 or newer
- coreutils, findutils and diffutils
- Python 3.10 or newer
- Node.js 18 or newer, and npm
- optional: `git` for git links, and `pnpm` for pnpm projects

```bash
sudo apt install bubblewrap strace
```

`baitbox scan` and `baitbox deps` need only Python, so they also run on macOS and Windows. The sandbox requires Linux.

### Command-line tool

```bash
git clone https://github.com/Avijit07x/baitbox.git ~/.local/share/baitbox
ln -s ~/.local/share/baitbox/bin/baitbox ~/.local/bin/baitbox
baitbox doctor
```

## Usage

| Command | Description |
| --- | --- |
| `baitbox check <source>` | The full check. Options: `--out DIR`, `--name NAME`, `--static-only`, `--offline`, `--install-timeout SECS` (default 900), `--run-timeout SECS` (default 600), `--json`. |
| `baitbox doctor` | Verifies the tools and kernel settings the sandbox needs. |
| `baitbox selftest [--keep]` | Runs a harmless simulated attack and checks detection. |
| `baitbox scan <dir> [--json]` | Static analysis only. Executes nothing. |
| `baitbox deps <dir> [--json] [--offline]` | Package checks only. |
| `baitbox box <net\|nonet> <project> <box> <secs> '<cmd>'` | Runs a single command in the sandbox and records it. |
| `baitbox analyze <box> [--json]` | Summarises sandbox recordings. |

### Output

Each check writes to `~/baitbox-checks/<name>-<timestamp>/`:

| Path | Contents |
| --- | --- |
| `report.md`, `report.json` | Verdict, findings, what ran, notes |
| `scan.txt`, `deps.txt` | Static and package results, plus versions made after the install |
| `sandbox.txt` | Every recorded action, grouped by run and phase |
| `box/logs/` | Raw `strace` recordings, command output and fake-home diffs |
| `src/` | The unpacked copy. Never open it in an editor. |

### CI

The exit code reflects the verdict, so BaitBox can gate a pipeline:

```bash
baitbox check "$REPO_URL" --json > baitbox-report.json
```

## Sandbox design

`box.sh` starts the project with [bubblewrap](https://github.com/containers/bubblewrap) and traces it with `strace` from outside the sandbox.

**Filesystem**
- System directories are read-only. `/tmp`, `/run` and `/dev/shm` are empty.
- There is no D-Bus, X11, Wayland, SSH agent or Docker socket.
- The project copy at `/work` is the only writable directory.

**Decoy home**
- The real home directory is replaced by `/home/alex`, on a host named `alex-thinkpad`.
- It holds decoy credentials:
  - an SSH key;
  - AWS, Docker and Kubernetes credentials;
  - Chrome and Brave password stores, cookies and keys;
  - Discord storage and a Solana wallet;
  - GitHub CLI and git tokens;
  - `.npmrc`, `.env`, shell rc files and GnuPG data.

**Network and privileges**
- The run step has loopback only. Every outbound attempt fails and is recorded.
- `no_new_privs` is set, so `sudo` and setuid binaries cannot gain privileges.
- A time limit applies, and everything still running in the sandbox is killed when it ends.

**Recording**
- `strace -f -y --pidns-translation` records process, file and network calls, and resolves the real path behind every file descriptor.
- Domain lookups are decoded from DNS packets.
- The decoy home is hashed before and after each run.

## Claude Code integration

BaitBox includes an optional [Claude Code](https://claude.com/claude-code) skill in [`skills/baitbox`](skills/baitbox/SKILL.md). The skill runs a check, reads the files that were flagged, and explains the verdict. It treats every project file as untrusted data, and never runs project code outside the sandbox.

```bash
ln -s "$PWD/skills/baitbox" ~/.claude/skills/baitbox
```

## Troubleshooting

**`setting up uid map: Permission denied` on Ubuntu 24.04 or later.** AppArmor restricts unprivileged user namespaces. Allow them for bubblewrap only:

```bash
sudo tee /etc/apparmor.d/bwrap > /dev/null << 'EOF'
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

**`strace can follow the sandbox` fails.** BaitBox needs the standard non-setuid `bwrap` and `kernel.yama.ptrace_scope` set to 0, 1 or 2.

**`ptrace_scope` is 2.** At 2 only root may trace, so each sandbox run asks for your sudo password, sets it to 1 while the run is recorded, and sets it back to 2 when the run ends, even if the run fails or is interrupted. Run BaitBox in a terminal, so sudo can ask. Doctor skips the `strace` check at 2.

**Install fails or times out.** See `box/logs/*-net-*.out`. Private packages are expected to fail, because project `.npmrc` files are off during installation.

## Known indicators

BaitBox includes signatures for a supply-chain attack delivered through a fake Tailwind CSS plugin:

| Type | Indicator |
| --- | --- |
| npm package | `tw-motion-css@2.0.2` (OSV `MAL-2026-18734`, since replaced by npm with `0.0.1-security`) |
| npm package | `@codentra/postcss-kinetix` (private, now removed) |
| C2 servers | `216.126.231.70:1224`, `153.75.88.215:1224` |
| Payload marker | `let sType = 'DEERGS42'` |
| SHA-256, `runtime.js` | `5c0d263e6decfa6d4db3da32eec9ec3f5c83b717d55390f49110cb8d04f55fd6` |
| SHA-256, `config.js` | `cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743` |
| Persistence | `~/.config/gvfs-network/`, user units `gvfs-network-boot.service`, `gvfs-network-activate.service`, `gvfs-network-activate.timer` |

## Contributing

Missed detections, false positives and bug reports are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Never attach live malware; share package names, versions and hashes instead.

## Security

Report vulnerabilities in BaitBox privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
