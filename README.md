```
   ____        ____        _____      __      __     _________       _____      __     __
  / ___)      / __ \      (  __ \     ) \    / (    (_   _____)     (_   _)    (_ \   / _)
 / /         / /  \ \      ) )_) )     \ \  / /       ) (___          | |        \ \_/ /
( (         ( ()  () )    (  ___/       \ \/ /       (   ___)         | |         \   /
( (         ( ()  () )     ) )           \  /         ) (             | |         / _ \
 \ \___      \ \__/ /     ( (             )(         (   )           _| |__     _/ / \ \_
  \____)      \____/      /__\           /__\         \_/           /_____(    (__/   \__)
```

**Detects page-cache tampering of executables, the footprint of the Linux "Copy Fail" kernel vulnerability (CVE-2026-31431).**

![Tests](https://github.com/Stlwtrs/CopyFix/actions/workflows/tests.yml/badge.svg)
![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Table of Contents

1. [The Problem](#the-problem)
2. [How CopyFix Works](#how-copyfix-works)
3. [What Changed in Version 2](#what-changed-in-version-2)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Running It Automatically](#running-it-automatically)
7. [If Tampering Is Detected](#if-tampering-is-detected)
8. [Limitations](#limitations)
9. [Testing](#testing)
10. [Project Structure](#project-structure)
11. [Contributing and Security](#contributing-and-security)
12. [How This Was Built](#how-this-was-built)
13. [License and Disclaimer](#license-and-disclaimer)

---

## The Problem

**Copy Fail (CVE-2026-31431)** is a Linux kernel flaw in the `algif_aead` crypto interface, present in kernels from 4.17 until patched. It lets an **unprivileged local user** make a controlled 4-byte write into the kernel's **page cache** for any file they can read.

The page cache is the kernel's in-memory copy of file contents. The corrupted page is never marked dirty, so:

- **The file on disk never changes.** Package-manager checks and many integrity tools that look at disk state see nothing wrong.
- **Every normal read and every execution of the file gets the corrupted copy** for as long as the page stays cached.

The published attack corrupts the cached copy of a **setuid-root binary** (such as `su`) and then runs it to gain root.

This creates a detection trap. A tool that compares a "disk" hash with a "memory" hash using ordinary file reads sees the same corrupted bytes twice, because both reads are served from the same page cache.

---

## How CopyFix Works

CopyFix reads every byte of each target file **two independent ways** and compares them:

| View | How it is read | What it returns |
|---|---|---|
| **Cached** | Normal `read()` | The page cache, which is what the kernel executes |
| **On-disk** | `read()` with `O_DIRECT` | The storage device directly, bypassing the page cache |

```text
                 ┌──────────────┐
  normal read ──►│  page cache  │──► cached bytes ───┐
                 └──────┬───────┘                    ├──► compare every byte
                        │ (bypassed)                 │
  O_DIRECT read ───────►│ disk ────► on-disk bytes ──┘
```

Before comparing, CopyFix calls `fsync()` on the file. That flushes **legitimate** unwritten changes, such as a package upgrade in progress, so they can't cause false alarms. Copy Fail's pages are not marked dirty, so they survive the flush and show up as a difference.

If the two views differ, CopyFix reports the file as **TAMPERED**, with the offset of the first changed byte, how many bytes differ, and the SHA-256 of both versions.

Other safeguards:

- **Whole-file comparison.** The exploit can write anywhere, so every byte is checked.
- **Targets what attackers target.** With no arguments, CopyFix finds every setuid and setgid binary under `/usr/bin`, `/usr/sbin`, `/usr/lib` and `/usr/libexec`.
- **Change detection.** If a file's inode, size or modification time changes during the check, the result is reported as `changed-during-scan` instead of guessing.
- **Honest about filesystems.** On `tmpfs`, `overlay`, `squashfs` and other filesystems without an independent disk copy (for example a live ISO), a comparison proves nothing, so CopyFix reports `unsupported` instead of a false "clean".
- **No dependencies.** Python 3.12+ standard library only.

---

## What Changed in Version 2

Version 1 compared a hash of the file read normally with a hash of `/proc/<PID>/exe`. Reviewing it against the CVE showed that approach could not detect Copy Fail:

| Version 1 | Problem | Version 2 |
|---|---|---|
| Both reads went through the page cache | During a real attack both return the same corrupted bytes, so hashes match | Compares a cached read with an `O_DIRECT` disk read |
| Hashed only the first 100 bytes | The exploit's 4-byte write can land anywhere in the file | Compares every byte |
| Required the binary to be running | Most setuid binaries, like `su`, run only briefly | Checks files directly, running or not |
| Fixed list of three binaries | Missed other setuid targets | Discovers all setuid/setgid binaries |

Version 1's "tampered" demonstration showed a different, real event: the file on disk changed after a process had started, so the process still ran the old copy. That check lives on in version 2 as the informational `--processes` report, described below.

Finding and fixing this in my own tool was the most useful part of the project. The full history is in [CHANGELOG.md](CHANGELOG.md).

---

## Installation

CopyFix is a single Python script. Python 3.12 or newer is preinstalled on most Linux distributions; check with `python3 --version`.

```bash
git clone https://github.com/Stlwtrs/CopyFix.git
cd CopyFix
sudo install -Dm755 copyfix.py /usr/local/bin/copyfix
```

You can also run it in place with `sudo ./copyfix.py`.

---

## Usage

```text
copyfix [-h] [--json] [-v] [--processes] [--version] [PATH ...]
```

| Command | What it does |
|---|---|
| `sudo copyfix` | Check every setuid/setgid binary |
| `sudo copyfix /usr/bin/su /usr/bin/sudo` | Check specific files |
| `sudo copyfix -v` | Also list clean files |
| `sudo copyfix --processes` | Also list processes whose executable was replaced on disk or runs from memory |
| `sudo copyfix --json` | Machine-readable output for scripts and log pipelines |

Root is recommended. Some setuid binaries are not readable by normal users, and CopyFix warns when run without root.

**Example: a clean system**

```text
$ sudo copyfix -v /usr/bin/su /usr/bin/passwd
CopyFix 2.0.0: page-cache integrity check
[*] Checking 2 file(s)
[+] /usr/bin/su: clean (55680 bytes, sha256 48dcbeb0258d7520...)
[+] /usr/bin/passwd: clean (64152 bytes, sha256 ca3fc307dda8259f...)

Summary: 2 clean, 0 tampered, 0 unsupported, 0 changed during scan, 0 error(s)
```

**Example: what a detection looks like.** This output comes from simulated tampering (4 bytes changed in the cached view at offset `0x1b4c`), not from a live exploit:

```text
[!] /usr/bin/su: TAMPERED
    first difference at offset 0x1b4c, 4 byte(s) differ
    cached  sha256 008a329d3e3af5ad200f0f509e87d2d5661a6991be45bbfb1ce399cf92672406
    on-disk sha256 48dcbeb0258d75204360988dc573e6e750e601b7420883c992817959995c7532
```

**Example: process report** (illustrative)

```text
[*] Processes whose executable is not a file on disk:
    pid 812 (sshd) [replaced]: /usr/bin/sshd (deleted)
```

- `replaced`: the program's file was replaced after it started. This is normal after a package upgrade until the program restarts.
- `memfd`: the program runs from an anonymous in-memory file. Some legitimate software does this, but it is also a common fileless-malware technique.

Neither is a Copy Fail indicator. They are context for an investigation.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every checked file is clean |
| `1` | Tampering detected |
| `2` | Usage error, such as a path that doesn't exist |
| `3` | No tampering found, but some files could not be checked |

---

## Running It Automatically

The `contrib/` folder has an example systemd service and timer that run CopyFix hourly and log results to the journal. The service is sandboxed: no network, read-only system, and minimal capabilities.

```bash
sudo install -Dm644 contrib/copyfix.service /etc/systemd/system/copyfix.service
sudo install -Dm644 contrib/copyfix.timer /etc/systemd/system/copyfix.timer
sudo systemctl daemon-reload
sudo systemctl enable --now copyfix.timer
journalctl -u copyfix.service
```

A detection makes the service exit with code `1`, so it shows up in `systemctl --failed`.

---

## If Tampering Is Detected

A TAMPERED result means someone with local access exploited the kernel. Treat the machine as compromised.

1. **Don't run the affected binary.** Executing a corrupted setuid binary is how the exploit gains root.
2. **Preserve evidence first.** Copying the file captures the corrupted cached version for analysis: `sudo cp /usr/bin/su /root/su.cached`. Save the CopyFix JSON output as well.
3. **Evict the corrupted pages.** The pages are not dirty, so dropping clean caches discards them: `echo 1 | sudo tee /proc/sys/vm/drop_caches`. Pages a running process is using may stay cached until it exits. Re-run CopyFix to confirm.
4. **Patch the kernel** and reboot.
5. **Investigate** who had local access and what else they did. The attacker may already have had root.

### Prevention

CopyFix detects the attack; it doesn't prevent it. To prevent it:

- **Update your kernel** to a version with the upstream fix. Check your distribution's advisories.
- **If you can't patch yet,** and nothing on the system uses the kernel's `AF_ALG` AEAD interface, block the vulnerable module:
  ```bash
  echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif-aead.conf
  ```

---

## Limitations

- **Detection is time-limited.** The corruption only exists while the page is cached. If the kernel evicts it before a scan, there is nothing left to find. Scheduled scans narrow the gap but cannot close it.
- **Filesystem support.** Detection needs `O_DIRECT` reads from a real disk (ext4, btrfs, XFS and others). Files on `tmpfs`, `overlay` or `squashfs` are reported as `unsupported`.
- **A root attacker can blind it.** Someone with root can stop, modify or fake CopyFix. It detects an exploit in progress; it is not a defense against a fully compromised system.
- **Not validated against the live exploit yet.** Detection logic is tested with simulated tampering (see [Testing](#testing)). Validation against the public proof of concept, in an isolated VM running an unpatched kernel, is planned.
- **Linux only.**

---

## Testing

```bash
python3 -m unittest discover -s tests -v
```

19 tests cover the byte comparison (including a 4-byte write deep inside a file, past byte 100), real `O_DIRECT` reads on files that aren't block-aligned, empty files, unsupported filesystems, files changing mid-scan, setuid discovery, process reporting, JSON output and exit codes.

A real page-cache write can't be produced from user space on a patched kernel, so tests simulate tampering by substituting the cached reader. Everything else runs against real files. Tests also run on every push through GitHub Actions on Python 3.9, 3.12 and 3.13.

---

## Project Structure

```text
CopyFix/
├── copyfix.py              # The tool (standard library only)
├── tests/
│   └── test_copyfix.py     # Unit and integration tests
├── contrib/
│   ├── copyfix.service     # Sandboxed systemd service
│   └── copyfix.timer       # Hourly schedule
├── .github/                # CI workflow, issue and PR templates
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
└── LICENSE                 # MIT
```

---

## Contributing and Security

Bug reports and improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Found a way to bypass CopyFix?** Please report it privately, following [SECURITY.md](SECURITY.md).

---

## How This Was Built

I built version 1 myself. Version 2 was redesigned with assistance from Claude (Anthropic's AI assistant) after reviewing version 1 against the CVE details. I reviewed the changes and verified them with the test suite and on my own system before release.

---

## License and Disclaimer

Released under the [MIT License](LICENSE).

CopyFix is intended for defensive monitoring of systems you own or are authorized to monitor. It is an educational project and has not been independently audited.

### References

- [CERT/CC VU#260001: Copy Fail](https://kb.cert.org/vuls/id/260001)
- [Openwall oss-security disclosure](https://openwall.com/lists/oss-security/2026/04/29/23)
- [Sophos: proof-of-concept exploit available for Copy Fail](https://www.sophos.com/en-us/blog/proof-of-concept-exploit-available-for-linux-copy-fail-cve-2026-31431)
