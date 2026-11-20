# Changelog

All notable changes to CopyFix are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-20

Version 2 is a redesign. Version 1 could not detect Copy Fail (see *Fixed*).

### Fixed
- **Detection method.** Version 1 compared a normal read of the file with a read of `/proc/<PID>/exe`. Both reads are served from the same page cache, so during a real Copy Fail attack they return the same corrupted bytes and the hashes match. Version 2 compares a normal (cached) read with an `O_DIRECT` read that bypasses the page cache.
- **Partial hashing.** Version 1 hashed only the first 100 bytes, but the exploit can write anywhere. Version 2 compares every byte.
- **Running-process requirement.** Version 1 could only check binaries that were currently running. Version 2 checks files directly.
- **Install instructions** pointed to an old repository URL.

### Added
- Automatic discovery of all setuid and setgid binaries under `/usr/bin`, `/usr/sbin`, `/usr/lib` and `/usr/libexec`
- `fsync()` before comparison so legitimate unwritten changes don't cause false alarms
- Exact offset and count of differing bytes, plus SHA-256 of both views
- Detection of files that change during a scan
- `unsupported` status for filesystems without an independent disk copy (`tmpfs`, `overlay`, `squashfs` and others)
- `--processes` report of processes whose executable was replaced on disk or runs from memory (`memfd`)
- `--json` output and documented exit codes for automation
- Sandboxed systemd service and hourly timer in `contrib/`
- Test suite (19 tests) and GitHub Actions CI on Python 3.9, 3.12 and 3.13

## [1.0.0] - 2026-11-13

### Added
- Initial release: compared hashes of a binary's first 100 bytes, read from the file and from `/proc/<PID>/exe`, for `su`, `sudo` and `ssh`
