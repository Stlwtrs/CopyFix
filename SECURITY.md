# Security Policy

CopyFix is a security tool, so a flaw in it can give users false confidence. Reports are taken seriously and handled privately.

## Supported Versions

| Version | Supported |
|---|:--:|
| 2.x (`main`) | ✅ |
| 1.x | ❌ Does not detect Copy Fail. Please upgrade. |

## Scope

**In scope:**

- Ways to make CopyFix report `clean` for a file whose cached contents differ from disk (detection bypasses)
- Ways a non-root user can make CopyFix crash, hang or report false results
- False positives on common, supported filesystems
- Bugs in the example systemd units that weaken the service's sandboxing

**Out of scope:**

- An attacker who already has root stopping, modifying or faking CopyFix. This is a documented limitation.
- Vulnerabilities in the Linux kernel itself, including CVE-2026-31431. Report those upstream.
- Files on filesystems CopyFix reports as `unsupported`.

## Reporting a Vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and select **Report a vulnerability**. If that isn't possible, email **stlwtrs@proton.me**.

Please include:

- The CopyFix version (`copyfix --version`), kernel version and filesystem type
- Steps to reproduce, or proof-of-concept code
- The impact: what an attacker gains or what CopyFix gets wrong

## What to Expect

CopyFix is maintained by one person, so responses are best effort:

- **Acknowledgement** within 7 days
- **A fix or documented mitigation** as soon as practical
- **Credit** in the changelog, unless you prefer to stay anonymous

Please allow reasonable time for a fix before public disclosure.
