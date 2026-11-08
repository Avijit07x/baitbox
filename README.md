# BaitBox

**Check a project from a client, a job test or a stranger for malware, before you open it.**

[![CI](https://github.com/Avijit07x/baitbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Avijit07x/baitbox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

BaitBox handles a project in 4 stages:

1. It unpacks the project safely.
2. It reads every file that can run code by itself.
3. It checks every npm package against the npm registry and the [OSV](https://osv.dev) malware database.
4. It installs and runs the project inside a locked Linux sandbox. The sandbox is full of fake secrets, and BaitBox records everything the code tries to do.

You get a verdict, a report, and the evidence behind every finding.

```console
$ baitbox check ~/Downloads/PromptToInvoice.zip

Verdict: Malware found. Do not open or run this project.
Findings: 5 high, 1 medium
  - [static scan] frontend/package.json:23: known malware | "tw-motion-css": "^2.0.2"
  - [static scan] frontend/tailwind.config.js:103: known malware | require('tw-motion-css')({
  - [packages] tw-motion-css: listed as malware in OSV: MAL-2026-18734
  - [packages] tw-motion-css: npm replaced it with a security placeholder (0.0.1-security); it was malware
  - [packages] tw-motion-css: 1 day old, 507 downloads a week, 2 versions
Report: /home/you/baitbox-checks/PromptToInvoice-20261108-125510/report.md
```

BaitBox is a command-line tool written in plain Python and Bash with no dependencies. It also works as a [Claude Code](https://claude.com/claude-code) skill.

Config files such as `tailwind.config.js` or `vite.config.ts` are code. Editors and dev servers run them the moment a folder opens, so malware hidden in one needs no install script. That's why `npm install --ignore-scripts` and `npm audit` are not enough on their own.

## Quick start

```bash
git clone https://github.com/Avijit07x/baitbox.git ~/baitbox
~/baitbox/bin/baitbox doctor
~/baitbox/bin/baitbox selftest
~/baitbox/bin/baitbox check ~/Downloads/client-project.zip
~/baitbox/bin/baitbox check https://github.com/someone/their-repo
~/baitbox/bin/baitbox check github.com/someone/their-repo/tree/dev
```

- `doctor` checks that your machine can run the sandbox.
- `selftest` runs a harmless fake attack and checks that every part of it gets caught.
- `check` takes a `.zip`, a `.tar.*`, a folder, a single file, or a git link.
- Git links can be copied straight from the browser. A `/tree/<branch>` link checks that branch.
- GitHub, GitLab, Bitbucket and Codeberg links work, with or without `https://`, as do `git@host:user/repo.git` links.
- Private repos work once you have signed in: for GitHub, run `gh auth login` and then `gh auth setup-git`.

> **Do not open the project in your editor before the check is done.** Editor extensions load config files, and a config file can run code.

## What a check does

| Step | Network | What happens |
| --- | --- | --- |
| 1. Unpack | none (git links: clone only) | Refuses `../` paths, absolute paths, links that point outside the project, device files, and zip bombs. Git clones run with hooks, symlinks, LFS and submodules off. `.git/config` settings that run commands (`core.fsmonitor`, `core.sshCommand`, `!` aliases, filters, `include.path`) and hidden bare repos are switched off in the copy, because your shell prompt runs git as soon as you enter a folder. |
| 2. Read | none | Lists every file that can run code by itself, and the packages each one loads. Flags scrambled code, invisible Unicode, code hidden after long runs of spaces, raw IPs, secret paths and disguised programs. |
| 3. Packages | npm, OSV | Checks every package (direct, lockfile and `node_modules`). Flags packages that are known malware, removed by npm, new, rarely used, private, or have a lookalike name. Also flags non-registry sources. |
| 4. Install | online, in the sandbox | Runs `npm install --ignore-scripts`, so no package code runs. Your project's `.npmrc` is switched off, so tokens or registries it contains are never used. |
| 5. Run | offline, in the sandbox | Runs install scripts, loads every config file the way an editor would, then runs `build`, `dev` and `start`, and waits for delayed payloads. |

## Verdicts

| Verdict | Exit code | Meaning |
| --- | --- | --- |
| `malicious` | 2 | Known malware, or the code did something malicious in the sandbox. |
| `suspicious` | 1 | A high-risk finding, or risky behaviour in the sandbox. Do not run it until you have read the report. |
| `review` | 0 | Nothing bad happened when it ran, but some files need a look. |
| `nothing-seen` | 0 | Nothing bad was seen. That is not proof that the project is safe. |
| `error` | 3 | The check did not finish. Treat the project as unchecked. |

## What the sandbox catches

| If the code tries to... | the report says |
| --- | --- |
| call a server | `tried to connect to a hard-coded address 216.126.231.70:1224` |
| look up a domain | `looked up evil.example while loading config` |
| read SSH keys, browser passwords, wallets or tokens | `read a bait secret: ~/.ssh/id_ed25519`, including reads through a symlink |
| stay on the machine | `wrote to a startup location: ~/.config/autostart/...` |
| get root or download more code | `started sudo`, `ran a shell command that downloads or decodes code` |
| reach Docker or desktop services | `tried to reach a privileged service: /var/run/docker.sock` |
| tamper with the evidence | nothing it can do; the record is kept outside the sandbox |

Each finding is labelled with the step it happened in:
- **config load**
- **install scripts**
- **npm run dev** (or another script)

A config file that opens a network connection is treated far more seriously than an app that looks up its own database.

## What it does not catch

- Malware that waits longer than the run, or waits for a date, a login or a click.
- Malware that notices the sandbox and stays quiet. BaitBox makes the sandbox look like a normal laptop, but a careful attacker can still tell.
- Code paths that need a real database, account, browser or network.
- Windows-only and Mac-only code, and non-Node projects. These get the static scan and nothing more.
- Sandbox escapes through kernel bugs.

A clean result means "nothing bad was seen". After a project passes, work on it in a VM or a container with no personal logins.

## Install

### Requirements

- Linux with unprivileged user namespaces (Ubuntu, Debian, Mint, Fedora, Arch and others)
- `bubblewrap`, `strace` (5.9 or newer), coreutils, findutils, diffutils
- Python 3.10 or newer
- Node.js 18 or newer, and npm
- `git`, only if you check git URLs
- `pnpm` is used if installed; npm is used otherwise

```bash
sudo apt install bubblewrap strace
```

`baitbox scan` and `baitbox deps` only need Python, so they also run on macOS and Windows. The sandbox needs Linux.

### Command on your PATH

```bash
git clone https://github.com/Avijit07x/baitbox.git ~/baitbox
mkdir -p ~/.local/bin
ln -s ~/baitbox/bin/baitbox ~/.local/bin/baitbox
```

### Claude Code skill

```bash
mkdir -p ~/.claude/skills
ln -s ~/baitbox/skills/baitbox ~/.claude/skills/baitbox
```

Then tell Claude Code to **check this project ~/Downloads/client-project.zip**. Claude runs the check, reads the files that were flagged, and explains the verdict.

Claude treats every file in the project as untrusted data. The steps it follows are in [`skills/baitbox/SKILL.md`](skills/baitbox/SKILL.md).

## Commands

| Command | What it does |
| --- | --- |
| `baitbox check <source>` | The full check. Options: `--out DIR`, `--name NAME`, `--static-only`, `--offline`, `--install-timeout SECS` (default 900), `--run-timeout SECS` (default 600), `--json`. |
| `baitbox doctor` | Checks the tools and kernel settings the sandbox needs. |
| `baitbox selftest` | Runs a harmless fake attack and checks that every part of it is caught. Add `--keep` to keep the logs. |
| `baitbox scan <folder>` | Static scan only. Runs nothing. Add `--json` for JSON output. |
| `baitbox deps <folder>` | Package check only. Add `--json` or `--offline`. |
| `baitbox box <net\|nonet> <project> <box> <secs> '<cmd>'` | Runs one command in the sandbox and records it. |
| `baitbox analyze <box>` | Turns the sandbox recordings into a report. Add `--json` for JSON output. |

Each check gets its own folder, `~/baitbox-checks/<name>-<time>/`, containing:

- `report.md` and `report.json`: the verdict and every finding;
- `scan.txt` and `deps.txt`, plus versions of both made after the install;
- `sandbox.txt`;
- `box/logs/`, with the raw `strace` recording and output of each sandbox run;
- `src/`: the unpacked copy. Never open this folder in your editor.

## How the sandbox works

`box.sh` uses [bubblewrap](https://github.com/containers/bubblewrap), and runs `strace` from outside the sandbox.

**What the sandbox can see**
- System folders are read-only. `/tmp`, `/run` and `/dev/shm` are empty.
- There is no D-Bus, X11, Wayland, SSH agent or Docker socket.
- Your real home folder is not there. `/home/alex` is a fake home on a fake laptop named `alex-thinkpad`.
- The fake home holds bait files: an SSH key, AWS, Docker and Kubernetes credentials, Chrome and Brave passwords, cookies and keys, Discord storage, a Solana wallet, GitHub CLI and git tokens, `.npmrc`, `.env`, shell rc files and GnuPG files.
- The project copy at `/work` is the only folder the code can write to.

**What it cannot do**
- In the offline run, only loopback exists. Every outside call fails and gets recorded.
- It cannot gain new privileges, so `sudo` and setuid programs can't get root.
- It runs under a time limit, and everything in it is killed when the limit is reached.

**How it is recorded**
- `strace` records every process, file and network call, including the real path behind a symlink.
- The recording is written outside the sandbox, so the code cannot see or edit it.
- The fake home is hashed before and after each run, so any new or changed file shows up.

## Troubleshooting

**`setting up uid map: Permission denied` on Ubuntu 24.04 or later.** AppArmor blocks unprivileged user namespaces. Allow them for bubblewrap only:

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

**`strace can follow the sandbox` fails.** Your `bwrap` may be setuid. BaitBox needs the standard non-setuid build. It can also mean `kernel.yama.ptrace_scope` is 2 or 3; BaitBox needs 0 or 1.

**Install fails or times out.** Read `box/logs/*-net-*.out` for the npm error. Private packages are expected to fail, because the project's `.npmrc` is switched off on purpose.

## Built-in malware signatures

BaitBox ships with the signs of a real attack that hid in a fake Tailwind plugin. `baitbox scan` flags all of these:

- **npm packages:**
  - `tw-motion-css@2.0.2`, which npm has since replaced with `0.0.1-security` and OSV lists as `MAL-2026-18734`;
  - `@codentra/postcss-kinetix`, which was private and is now gone.
- **Servers:** `216.126.231.70:1224` and `153.75.88.215:1224`.
- **First line of the payload:** `let sType = 'DEERGS42'`.
- **SHA-256 of the files:**
  - `runtime.js`: `5c0d263e6decfa6d4db3da32eec9ec3f5c83b717d55390f49110cb8d04f55fd6`
  - `config.js`: `cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743`
- **What it left on the machine:** the folder `~/.config/gvfs-network/` and the user services `gvfs-network-boot.service`, `gvfs-network-activate.service` and `gvfs-network-activate.timer`.

## Contributing

- Bug reports, missed detections and false alarms are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
- Never attach live malware to an issue. Share the package name, version and hashes instead.

## Security

To report a weakness in BaitBox itself, such as a sandbox escape, a way to hide from detection, or a way to change the report, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
