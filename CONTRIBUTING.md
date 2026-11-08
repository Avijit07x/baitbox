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
.venv/bin/shellcheck skills/baitbox/scripts/box.sh bin/baitbox
bin/baitbox selftest
```

The sandbox tests need `bubblewrap`, `strace` and Node.js, and are skipped when the sandbox can't start. CI runs them on Ubuntu with Python 3.10 to 3.13.

## Code rules

- **Standard library only.** The scripts must run with a plain `python3` and `bash`, with nothing to install.
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
bin/baitbox                      command-line entry point
skills/baitbox/SKILL.md          Claude Code skill
skills/baitbox/scripts/
  baitbox.py                     check, doctor, selftest
  extract.py                     safe unpacking and cloning
  scan.py                        static scan
  deps.py                        npm registry and OSV checks
  box.sh                         bubblewrap + strace sandbox
  analyze.py                     reads sandbox recordings
tests/                           pytest suite
```

## Pull requests

- Keep each pull request to one change.
- Run the tests, `ruff` and `shellcheck` before you push.
- Add a line to `CHANGELOG.md` under "Unreleased".
