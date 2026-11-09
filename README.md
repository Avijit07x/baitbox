# BaitBox

**Check untrusted Node.js projects for malware before you open them.**

[![CI](https://github.com/Avijit07x/baitbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Avijit07x/baitbox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

BaitBox unpacks a project safely, scans its files and packages, then runs it in a Linux sandbox full of fake credentials. It records everything the project does and gives you a verdict.

Run it before you open a project in your editor. Files like `tailwind.config.js` and `vite.config.ts` are code, and editors run them as soon as you open the folder. `npm install --ignore-scripts` and `npm audit` do not catch this.

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

## Install

You need Linux, Python 3.10+, Node.js 18+ with npm, `bubblewrap`, and `strace` 5.9+. `git` and `pnpm` are optional.

```bash
sudo apt install bubblewrap strace
git clone https://github.com/Avijit07x/baitbox.git ~/.local/share/baitbox
ln -s ~/.local/share/baitbox/bin/baitbox ~/.local/bin/baitbox
baitbox doctor
```

`baitbox scan` and `baitbox deps` need only Python, so they also work on macOS and Windows.

## Usage

```bash
baitbox check project.zip
baitbox check https://github.com/owner/repo
baitbox check github.com/owner/repo/tree/dev
```

`check` takes a zip or tar file, a folder, a single file, or a git link.

| Command | What it does |
| --- | --- |
| `baitbox check <source>` | Full check. Add `--static-only` to skip the sandbox, or `--json` for JSON output. |
| `baitbox doctor` | Checks that your machine can run the sandbox. |
| `baitbox selftest` | Runs a harmless fake attack and confirms it is caught. |
| `baitbox scan <dir>` | Static scan only. Runs nothing. |
| `baitbox deps <dir>` | Package check only. |

Run `baitbox --help` or `baitbox check --help` for all options.

Each check saves its report in `~/baitbox-checks/<name>-<time>/`. The `src/` folder there is the unpacked project. Never open it in an editor.

## Verdicts

| Verdict | Exit code | Meaning |
| --- | --- | --- |
| `malicious` | 2 | Known malware, or harmful behaviour in the sandbox. |
| `suspicious` | 1 | A high-risk finding, or risky behaviour in the sandbox. |
| `review` | 0 | Nothing harmful ran, but some files need a look. |
| `nothing-seen` | 0 | No findings. This is not proof the project is safe. |
| `error` | 3 | The check did not finish. Treat the project as unchecked. |

The exit code makes BaitBox easy to use as a CI gate.

## What it catches

- Known malware, packages npm removed, brand-new throwaway packages, and lookalike names.
- Hidden code: obfuscation, invisible Unicode, and code pushed off-screen with whitespace.
- Network calls to hard-coded IPs, tunnels and paste sites.
- Reads of SSH keys, cloud tokens, browser passwords and crypto wallets. All of them are fake.
- Startup persistence, `sudo`, second-stage downloads, and access to the Docker socket.
- Unsafe archives, such as path traversal and zip bombs, and git settings that run commands.

## Limits

A clean result means nothing harmful was seen. It does not prove the project is safe. BaitBox can miss:

- Payloads that wait longer than the run, or wait for a date, a login or user input.
- Malware that detects the sandbox and stays quiet.
- Code that needs real services, accounts or network access.
- Windows-only or macOS-only payloads, and projects that are not Node.js. These get the static scan only.
- Kernel exploits that escape the sandbox.

Work on untrusted projects in a VM or container with no personal credentials.

## Troubleshooting

**`setting up uid map: Permission denied` on Ubuntu 24.04 or later.** AppArmor blocks user namespaces. Allow them for bubblewrap only:

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

**`strace can follow the sandbox` fails.** Use the standard (not setuid) `bwrap`, and set `kernel.yama.ptrace_scope` to 0, 1 or 2.

**`ptrace_scope` is 2.** Each run asks for your sudo password, sets it to 1 while it records, and sets it back to 2 when it ends. Run BaitBox in a terminal so sudo can ask.

**Install fails or times out.** Look at `box/logs/*-net-*.out` in the report folder. Private packages fail on purpose, because the project's `.npmrc` is turned off.

## Claude Code skill

[`skills/baitbox`](skills/baitbox/SKILL.md) lets Claude Code run a check and explain the result. It uses the `baitbox` command, so install that first. It never runs project code outside the sandbox.

```bash
ln -s "$PWD/skills/baitbox" ~/.claude/skills/baitbox
```

## Contributing

Bug reports, missed detections and false alarms are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Never attach live malware.

Report security issues privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
