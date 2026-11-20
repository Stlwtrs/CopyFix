#!/usr/bin/env python3
"""
CopyFix: detect page-cache tampering of executables.

CVE-2026-31431 ("Copy Fail") lets an unprivileged user write into the kernel's
page cache for a file without marking the page dirty. The file on disk is never
changed, but every normal read() and every execve() of that file is served the
corrupted cached copy until the page is evicted.

Because normal reads go through the page cache, comparing a "disk" hash against
a "memory" hash with ordinary open()/read() calls cannot see this attack: both
reads return the same corrupted bytes. CopyFix instead compares, for every byte
of the file:

  1. the cached view   (a normal read, served from the page cache), and
  2. the on-disk view  (an O_DIRECT read, which bypasses the page cache).

Legitimate unwritten changes are flushed with fsync() first. A page-cache-only
modification like Copy Fail is never marked dirty, so it survives the fsync and
shows up as a difference between the two views.
"""

import argparse
import errno
import hashlib
import json
import mmap
import os
import stat
import sys

__version__ = "2.0.0"

CHUNK_SIZE = 1 << 20  # 1 MiB; a multiple of every common block size

DEFAULT_SEARCH_DIRS = ("/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec")

# Filesystems where an O_DIRECT read is not an independent view of a disk:
# memory-backed filesystems have no disk at all, and overlay/squashfs (for
# example a live ISO) may be backed by one. A comparison there proves nothing.
NO_INDEPENDENT_DISK_FS = {"tmpfs", "ramfs", "devtmpfs", "overlay", "squashfs", "proc", "sysfs"}

CLEAN = "clean"
TAMPERED = "tampered"
UNSUPPORTED = "unsupported"
CHANGED = "changed-during-scan"
ERROR = "error"

EXIT_CLEAN = 0
EXIT_TAMPERED = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3


# --------------------------------------------------------------------------
# Readers
# --------------------------------------------------------------------------

def read_cached(path):
    """Yield the file in CHUNK_SIZE pieces through the page cache."""
    with open(path, "rb", buffering=0) as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                return
            yield chunk


def read_direct(path):
    """Yield the file in CHUNK_SIZE pieces straight from disk with O_DIRECT.

    O_DIRECT requires a block-aligned buffer, offset and length. An anonymous
    mmap is page-aligned, CHUNK_SIZE is a multiple of the block size, and the
    offset only advances by full chunks, so every request is aligned. The final
    read may return fewer bytes than requested, which O_DIRECT allows at EOF.
    """
    fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
    buf = mmap.mmap(-1, CHUNK_SIZE)
    try:
        offset = 0
        while True:
            n = os.preadv(fd, [buf], offset)
            if n <= 0:
                return
            yield bytes(buf[:n])
            if n < CHUNK_SIZE:
                return
            offset += n
    finally:
        buf.close()
        os.close(fd)


def flush_dirty_pages(path):
    """Write any legitimately dirty cached pages to disk.

    Without this, a file that was just written (for example during a package
    upgrade) could differ between cache and disk for an innocent reason. Copy
    Fail's pages are not marked dirty, so fsync() leaves them in place.
    """
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _unescape_mount(field):
    """Decode the octal escapes (such as \\040 for a space) used in mountinfo."""
    return field.encode().decode("unicode_escape")


def filesystem_type(path, mountinfo="/proc/self/mountinfo"):
    """Return the filesystem type holding path, or None if it cannot be found."""
    path = os.path.realpath(path)
    best_point, best_type = "", None
    try:
        with open(mountinfo) as f:
            for line in f:
                left, _, right = line.partition(" - ")
                fields = left.split()
                if len(fields) < 5 or not right:
                    continue
                point = _unescape_mount(fields[4])
                if (path == point or path.startswith(point.rstrip("/") + "/")) \
                        and len(point) >= len(best_point):
                    best_point, best_type = point, right.split()[0]
    except OSError:
        return None
    return best_type


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def compare_streams(cached_chunks, direct_chunks):
    """Compare two chunked byte streams.

    Returns a dict with the size and SHA-256 of each stream, the offset of the
    first differing byte (or None) and the number of differing bytes.
    """
    h_cached = hashlib.sha256()
    h_direct = hashlib.sha256()
    size_cached = size_direct = 0
    first_diff = None
    diff_bytes = 0

    cached_iter = iter(cached_chunks)
    direct_iter = iter(direct_chunks)
    while True:
        c = next(cached_iter, b"")
        d = next(direct_iter, b"")
        if not c and not d:
            break
        h_cached.update(c)
        h_direct.update(d)
        if c != d:
            common = min(len(c), len(d))
            for i in range(common):
                if c[i] != d[i]:
                    diff_bytes += 1
                    if first_diff is None:
                        first_diff = size_cached + i
            if len(c) != len(d):
                diff_bytes += abs(len(c) - len(d))
                if first_diff is None:
                    first_diff = size_cached + common
        size_cached += len(c)
        size_direct += len(d)

    return {
        "size_cached": size_cached,
        "size_direct": size_direct,
        "sha256_cached": h_cached.hexdigest(),
        "sha256_direct": h_direct.hexdigest(),
        "first_diff_offset": first_diff,
        "diff_bytes": diff_bytes,
    }


def _snapshot(path):
    st = os.stat(path)
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def check_file(path, cached_reader=read_cached, direct_reader=read_direct,
               fs_type_of=filesystem_type):
    """Check one file and return a result dict with a "status" key."""
    result = {"path": path}
    fs_type = fs_type_of(path)
    result["filesystem"] = fs_type
    if fs_type in NO_INDEPENDENT_DISK_FS:
        result["status"] = UNSUPPORTED
        result["detail"] = f"{fs_type} has no disk copy that can be read independently of the cache"
        return result
    try:
        before = _snapshot(path)
        flush_dirty_pages(path)
        comparison = compare_streams(cached_reader(path), direct_reader(path))
        after = _snapshot(path)
    except OSError as e:
        if e.errno in (errno.EINVAL, errno.EOPNOTSUPP):
            result["status"] = UNSUPPORTED
            result["detail"] = "filesystem does not support O_DIRECT reads"
        else:
            result["status"] = ERROR
            result["detail"] = e.strerror or str(e)
        return result

    result.update(comparison)
    if before != after:
        result["status"] = CHANGED
        result["detail"] = "file was modified while it was being checked; re-run"
    elif comparison["first_diff_offset"] is None:
        result["status"] = CLEAN
    else:
        result["status"] = TAMPERED
        result["detail"] = (
            "cached contents differ from the on-disk contents; "
            "consistent with page-cache tampering such as CVE-2026-31431"
        )
    return result


# --------------------------------------------------------------------------
# Target discovery
# --------------------------------------------------------------------------

def find_privileged_binaries(search_dirs=DEFAULT_SEARCH_DIRS):
    """Return sorted paths of regular setuid or setgid files.

    These are the primary Copy Fail targets: corrupting the cached copy of a
    setuid-root binary and then executing it is the published route to root.
    Symlinks are not followed, so each file is reported once.
    """
    found = set()
    for top in search_dirs:
        if not os.path.isdir(top):
            continue
        for root, dirs, files in os.walk(top, followlinks=False):
            for name in files:
                path = os.path.join(root, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    found.add(os.path.realpath(path))
    return sorted(found)


def find_replaced_executables(proc_root="/proc"):
    """List processes whose executable no longer exists as a file on disk.

    Two kinds are reported. This is informational, not a Copy Fail indicator:

    - "replaced": the program's file was deleted or replaced after it started.
      Normal for a while after a package upgrade, until the program restarts.
    - "memfd": the program runs from an anonymous in-memory file
      (memfd_create). Some legitimate software does this, but it is also a
      common fileless-malware technique, so unexpected entries deserve a look.
    """
    entries = []
    try:
        pids = [p for p in os.listdir(proc_root) if p.isdigit()]
    except OSError:
        return entries
    for pid in sorted(pids, key=int):
        try:
            target = os.readlink(os.path.join(proc_root, pid, "exe"))
        except OSError:
            continue
        if target.endswith(" (deleted)"):
            try:
                with open(os.path.join(proc_root, pid, "comm")) as f:
                    comm = f.read().strip()
            except OSError:
                comm = "?"
            kind = "memfd" if target.startswith("/memfd:") else "replaced"
            entries.append({"pid": int(pid), "comm": comm, "exe": target, "kind": kind})
    return entries


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _print_result(r, verbose):
    status = r["status"]
    path = r["path"]
    if status == CLEAN:
        if verbose:
            print(f"[+] {path}: clean ({r['size_cached']} bytes, sha256 {r['sha256_cached'][:16]}...)")
    elif status == TAMPERED:
        print(f"[!] {path}: TAMPERED")
        print(f"    first difference at offset {r['first_diff_offset']:#x}, {r['diff_bytes']} byte(s) differ")
        print(f"    cached  sha256 {r['sha256_cached']}")
        print(f"    on-disk sha256 {r['sha256_direct']}")
    else:
        print(f"[-] {path}: {status} ({r.get('detail', '')})")


def summarize(results):
    counts = {s: 0 for s in (CLEAN, TAMPERED, UNSUPPORTED, CHANGED, ERROR)}
    for r in results:
        counts[r["status"]] += 1
    return counts


def exit_code_for(counts):
    if counts[TAMPERED]:
        return EXIT_TAMPERED
    if counts[UNSUPPORTED] or counts[CHANGED] or counts[ERROR]:
        return EXIT_INCOMPLETE
    return EXIT_CLEAN


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="copyfix",
        description=(
            "Detect page-cache tampering of executables (CVE-2026-31431, "
            "\"Copy Fail\") by comparing each file's cached contents with its "
            "on-disk contents."
        ),
        epilog=(
            "Exit codes: 0 all checked files clean, 1 tampering detected, "
            "2 usage error, 3 some files could not be checked."
        ),
    )
    p.add_argument("paths", nargs="*", metavar="PATH",
                   help="files to check (default: every setuid/setgid binary under "
                        + ", ".join(DEFAULT_SEARCH_DIRS) + ")")
    p.add_argument("--json", action="store_true", help="print results as JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="also list clean files")
    p.add_argument("--processes", action="store_true",
                   help="also list running processes whose executable was replaced on disk "
                        "or runs from memory (memfd)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.paths:
        targets = []
        for path in args.paths:
            if not os.path.isfile(path):
                print(f"copyfix: {path}: not a regular file", file=sys.stderr)
                return EXIT_USAGE
            targets.append(os.path.realpath(path))
    else:
        targets = find_privileged_binaries()

    if not args.json:
        print(f"CopyFix {__version__}: page-cache integrity check")
        if os.geteuid() != 0:
            print("[-] Not running as root: some binaries may be unreadable.")
        print(f"[*] Checking {len(targets)} file(s)")

    results = [check_file(t) for t in targets]
    counts = summarize(results)
    processes = find_replaced_executables() if args.processes else None

    if args.json:
        out = {"version": __version__, "summary": counts, "results": results}
        if processes is not None:
            out["replaced_executables"] = processes
        print(json.dumps(out, indent=2))
    else:
        for r in results:
            _print_result(r, args.verbose)
        if processes is not None:
            print("\n[*] Processes whose executable is not a file on disk:")
            if processes:
                for p in processes:
                    print(f"    pid {p['pid']} ({p['comm']}) [{p['kind']}]: {p['exe']}")
            else:
                print("    none")
        print(
            f"\nSummary: {counts[CLEAN]} clean, {counts[TAMPERED]} tampered, "
            f"{counts[UNSUPPORTED]} unsupported, {counts[CHANGED]} changed during scan, "
            f"{counts[ERROR]} error(s)"
        )
        if counts[TAMPERED]:
            print("[!] Tampering detected. Do not run the affected binaries; see the README's response steps.")

    return exit_code_for(counts)


if __name__ == "__main__":
    sys.exit(main())
