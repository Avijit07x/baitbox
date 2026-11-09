# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org).

## Unreleased

- The code moved out of the skill folder into a Python package, `src/baitbox/`, with one folder per check step. Commands, reports and exit codes are unchanged. The skill now calls the `baitbox` command, so install the command before you link the skill.
- Help and error messages from `baitbox scan`, `deps` and `analyze` now show the command name instead of `scan.py`, `deps.py` or `analyze.py`.
- Works with `kernel.yama.ptrace_scope=2`. Each sandbox run asks for the sudo password, sets it to 1 while the run is recorded, and sets it back to 2 when the run ends. Before, every run failed, and doctor blamed a setuid `bwrap`. Doctor now reports 2 as usable and names 3 as the value that turns ptrace off.

## 0.1.0 - 2026-11-08

First public release.

### Commands

`baitbox check` runs the full check:
- safe unpack;
- static scan;
- npm and OSV package check;
- online install with scripts off;
- offline run;
- report.

The tool also ships:
- `baitbox doctor` and `baitbox selftest`;
- `baitbox scan`, `deps`, `box` and `analyze` for running single steps by hand;
- a Claude Code skill in `skills/baitbox`.

### Safe unpacking

- Handles zip, tar, folders, single files and git URLs.
- Blocks unsafe paths, links that point outside the project, device files and zip bombs.
- Clones git repos with hooks, symlinks, LFS and submodules switched off.
- Accepts git links copied straight from the browser: GitHub, GitLab, Bitbucket and Codeberg, with or without `https://`. A `/tree/<branch>` link checks that branch.
- Switches off `.git/config` settings that run commands (such as `core.fsmonitor` or `!` aliases), hidden bare repos, and `.git` files that point outside the project.

### Static scan

- **Files that run code by themselves:**
  - config files, together with the packages each one loads;
  - `.npmrc`, `.yarnrc` and `.yarnrc.yml` (`yarnPath`);
  - `bunfig.toml` preload;
  - VS Code tasks that run when a folder opens, and risky editor settings;
  - devcontainer `initializeCommand`;
  - git and husky hooks;
  - Claude Code hooks and MCP server settings.
- **Hidden or scrambled code:** obfuscation, invisible Unicode and bidi controls, code hidden after long runs of spaces, and disguised programs.
- **Built-in signatures of a real attack that hid in a fake Tailwind plugin.**

### Package check

- Reads lockfiles from npm (v1 to v3), pnpm (v5 to v9), Yarn (v1 and Berry) and Bun, plus `node_modules`.
- **Flags:**
  - known malware (OSV `MAL-` entries);
  - packages npm removed and replaced with a security placeholder;
  - versions missing from npm;
  - throwaway packages: new, rarely downloaded, with few versions;
  - lookalike names;
  - install scripts;
  - sources outside the npm registry;
  - `exec:` dependencies.

### Sandbox

- **Isolation:** bubblewrap with a fake home full of bait secrets, and no network in the run step.
- **Recording:**
  - `strace` runs from outside the sandbox, so the record can't be tampered with;
  - it shows the real path behind symlinks;
  - it decodes domain lookups;
  - it labels each action with its step (config load, install scripts, `npm run`).
- **During install:** the project's own `.npmrc` files are switched off, so their tokens and registries are never used.
