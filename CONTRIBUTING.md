# Contributing

Thanks for helping. The most useful contributions are:

- **missed detections**;
- **false alarms**;
- **sandbox weaknesses**. Report these privately; see [SECURITY.md](SECURITY.md).

## Reporting a missed detection or a false alarm

Open an issue with the matching template and include:

- the package name and version, or the file pattern;
- what BaitBox reported, and what it should have reported;
- the relevant lines from `report.md` or `sandbox.txt`.

Never attach live malware or a project that contains it. Share names, versions, hashes and the lines that matter.

## Development setup

```bash
git clone https://github.com/Avijit07x/baitbox.git
cd baitbox
python3 -m venv .venv
.venv/bin/pip install pytest ruff shellcheck-py
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/shellcheck src/baitbox/sandbox/box.sh bin/baitbox
bin/baitbox selftest
```

The sandbox tests need `bubblewrap`, `strace` and Node.js, and are skipped when the sandbox can't start. CI runs them on Ubuntu with Python 3.10 to 3.13.

## Code rules

- **Standard library only.** BaitBox must run with a plain `python3` and `bash`, with nothing to install.
- **No code comments.** Use clear names and small functions. Put the reasoning in the commit message or the pull request.
- **Every new detection needs a test**: one that shows it fires, and one that shows a normal project does not trigger it.
- **Keep findings plain.** A finding says what the code did, in words a busy developer can read in one second.
- **Report only what was observed.** If something is a guess, label it as a risk, not as a finding.
- **Severity:**
  - `high` means "this is what malware does";
  - `medium` means "a person should look at this";
  - `info` is context.

## Project layout

```
bin/baitbox                command-line entry point
skills/baitbox/SKILL.md    Claude Code skill
src/baitbox/
  cli.py                   reads the command line and runs a command
  commands/                one file per command: check, doctor, selftest, scan, deps, analyze, box
  unpack/                  step 1: safe unpacking and cloning
  scan/                    step 2: static scan
  deps/                    step 3: npm registry and OSV checks
  sandbox/                 steps 4 and 5: install and run plans, and box.sh (bubblewrap + strace)
  analyze/                 reads sandbox recordings
  report/                  findings, verdict and report.md
tests/                     one test file per folder in src/baitbox
```

Each folder in `src/baitbox` is one part of the check:

- `rules.py` holds its patterns and lists, and `output.py` turns its results into text;
- `__init__.py` lists what other parts may use. Code in other folders imports from there, not from the files inside;
- a new command is a new file in `commands/`, plus one line in `cli.py`.

## Pull requests

- Keep each pull request to one change.
- Run the tests, `ruff` and `shellcheck` before you push.
- Add a line to `CHANGELOG.md` under "Unreleased".
