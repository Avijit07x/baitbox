# Security policy

BaitBox runs untrusted code on your machine. Weaknesses in it matter, so please report them privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue.

Please include:

- the BaitBox version (`baitbox --version`), your distribution, kernel, `bwrap --version` and `strace -V`;
- the smallest project or command that shows the problem;
- what you expected and what happened.

You will get a reply within 7 days. Fixes for confirmed issues are released as soon as they are ready, and you are credited unless you ask not to be.

## In scope

- Code inside the sandbox reaching your real home folder, your real network in an offline run, host services, or anything outside `/work` and the fake home.
- Code inside the sandbox changing, hiding or deleting its own recording or the report.
- Unpacking an archive or cloning a repo writing outside the check folder, or running code.
- A way for project files to make BaitBox itself, or the Claude Code skill, run project code outside the sandbox.
- A detection bypass for something BaitBox claims to catch, as listed in the README.

## Out of scope

- Malware that waits longer than the run, needs a real login or network, or detects the sandbox and stays quiet. The README lists these as known limits.
- Kernel exploits that escape every unprivileged sandbox.
- False alarms. Please report these as normal issues.

## Threat model in short

BaitBox reduces the risk of looking at untrusted code. It does not remove it. For projects you have real doubts about, run BaitBox inside a VM.
