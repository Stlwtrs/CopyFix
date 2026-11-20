"""Tests for CopyFix.

A real Copy Fail page-cache write cannot be produced from user space on a
patched kernel, so tampering is simulated by substituting the cached reader.
Everything else (O_DIRECT reads, fsync, comparison, discovery, exit codes)
runs against real files.
"""

import errno
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import copyfix  # noqa: E402


# Real-file tests need a disk-backed directory. /tmp is tmpfs on many distros
# (including Arch), so use the directory these tests live in instead.
DISK_DIR = os.path.dirname(os.path.abspath(__file__))
DISK_FS = copyfix.filesystem_type(DISK_DIR)
needs_disk = unittest.skipIf(
    DISK_FS in copyfix.NO_INDEPENDENT_DISK_FS,
    f"tests directory is on {DISK_FS}, which has no independent disk copy",
)


def _write(path, data):
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


class CompareStreamsTests(unittest.TestCase):
    def test_identical_streams(self):
        r = copyfix.compare_streams([b"abc", b"def"], [b"abc", b"def"])
        self.assertIsNone(r["first_diff_offset"])
        self.assertEqual(r["diff_bytes"], 0)
        self.assertEqual(r["sha256_cached"], r["sha256_direct"])

    def test_four_byte_write_reports_exact_offset(self):
        original = bytes(range(256)) * 10
        corrupted = bytearray(original)
        corrupted[1000:1004] = b"\xde\xad\xbe\xef"
        r = copyfix.compare_streams([bytes(corrupted)], [original])
        self.assertEqual(r["first_diff_offset"], 1000)
        self.assertEqual(r["diff_bytes"], 4)

    def test_offset_counts_across_chunks(self):
        r = copyfix.compare_streams([b"aaaa", b"bXbb"], [b"aaaa", b"bbbb"])
        self.assertEqual(r["first_diff_offset"], 5)

    def test_length_mismatch_is_a_difference(self):
        r = copyfix.compare_streams([b"abcd"], [b"ab"])
        self.assertEqual(r["first_diff_offset"], 2)
        self.assertEqual(r["diff_bytes"], 2)


@needs_disk
class CheckFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=DISK_DIR)
        self.path = os.path.join(self.tmp.name, "target")
        # Larger than one chunk and not block-aligned, to exercise O_DIRECT edges.
        self.data = os.urandom(copyfix.CHUNK_SIZE + 12345)
        _write(self.path, self.data)

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_file_is_clean(self):
        r = copyfix.check_file(self.path)
        self.assertEqual(r["status"], copyfix.CLEAN, r)
        self.assertEqual(r["size_direct"], len(self.data))

    def test_direct_read_matches_file_contents(self):
        self.assertEqual(b"".join(copyfix.read_direct(self.path)), self.data)

    def test_empty_file_is_clean(self):
        empty = os.path.join(self.tmp.name, "empty")
        _write(empty, b"")
        self.assertEqual(copyfix.check_file(empty)["status"], copyfix.CLEAN)

    def test_simulated_page_cache_tampering_is_detected(self):
        offset = copyfix.CHUNK_SIZE + 500  # past the first chunk and far past byte 100

        def corrupted_cache(path):
            data = bytearray(b"".join(copyfix.read_cached(path)))
            data[offset:offset + 4] = b"\x90\x90\x90\x90"
            size = copyfix.CHUNK_SIZE
            for i in range(0, len(data), size):
                yield bytes(data[i:i + size])

        r = copyfix.check_file(self.path, cached_reader=corrupted_cache)
        self.assertEqual(r["status"], copyfix.TAMPERED)
        self.assertEqual(r["first_diff_offset"], offset)
        self.assertNotEqual(r["sha256_cached"], r["sha256_direct"])

    def test_unsupported_filesystem(self):
        def no_direct(path):
            raise OSError(errno.EINVAL, "Invalid argument")
            yield  # pragma: no cover

        r = copyfix.check_file(self.path, direct_reader=no_direct)
        self.assertEqual(r["status"], copyfix.UNSUPPORTED)

    def test_memory_backed_filesystem_is_unsupported(self):
        r = copyfix.check_file(self.path, fs_type_of=lambda p: "tmpfs")
        self.assertEqual(r["status"], copyfix.UNSUPPORTED)
        self.assertIn("tmpfs", r["detail"])

    def test_unreadable_file_is_an_error(self):
        r = copyfix.check_file(os.path.join(self.tmp.name, "missing"))
        self.assertEqual(r["status"], copyfix.ERROR)

    def test_file_changed_during_scan(self):
        snapshots = iter([(1, 1, 1), (1, 2, 2)])
        with mock.patch.object(copyfix, "_snapshot", lambda p: next(snapshots)):
            r = copyfix.check_file(self.path)
        self.assertEqual(r["status"], copyfix.CHANGED)


class FilesystemTypeTests(unittest.TestCase):
    def test_longest_mount_point_wins(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n")
            f.write("30 22 0:5 / /dev/shm rw - tmpfs tmpfs rw\n")
            f.write("31 22 0:6 / /mnt/my\\040disk rw - btrfs /dev/sdb1 rw\n")
            name = f.name
        try:
            with mock.patch("os.path.realpath", side_effect=lambda p: p):
                self.assertEqual(copyfix.filesystem_type("/usr/bin/su", name), "ext4")
                self.assertEqual(copyfix.filesystem_type("/dev/shm/x", name), "tmpfs")
                self.assertEqual(copyfix.filesystem_type("/dev/shmx", name), "ext4")
                self.assertEqual(copyfix.filesystem_type("/mnt/my disk/f", name), "btrfs")
        finally:
            os.unlink(name)


class DiscoveryTests(unittest.TestCase):
    def test_finds_only_setuid_and_setgid_regular_files(self):
        with tempfile.TemporaryDirectory() as d:
            suid = os.path.join(d, "suid")
            sgid = os.path.join(d, "sub", "sgid")
            plain = os.path.join(d, "plain")
            os.makedirs(os.path.dirname(sgid))
            for p in (suid, sgid, plain):
                _write(p, b"x")
            os.chmod(suid, 0o4755)
            os.chmod(sgid, 0o2755)
            os.chmod(plain, 0o755)
            os.symlink(suid, os.path.join(d, "link-to-suid"))

            found = copyfix.find_privileged_binaries([d])
            self.assertEqual(found, sorted([os.path.realpath(suid), os.path.realpath(sgid)]))


class ProcessTests(unittest.TestCase):
    def test_reports_deleted_executables(self):
        with tempfile.TemporaryDirectory() as d:
            for pid, exe in (("100", "/usr/bin/foo (deleted)"), ("200", "/usr/bin/bar"),
                             ("300", "/memfd:payload (deleted)")):
                os.makedirs(os.path.join(d, pid))
                os.symlink(exe, os.path.join(d, pid, "exe"))
                with open(os.path.join(d, pid, "comm"), "w") as f:
                    f.write("proc" + pid + "\n")
            os.makedirs(os.path.join(d, "self"))

            entries = copyfix.find_replaced_executables(d)
            self.assertEqual(entries, [
                {"pid": 100, "comm": "proc100", "exe": "/usr/bin/foo (deleted)", "kind": "replaced"},
                {"pid": 300, "comm": "proc300", "exe": "/memfd:payload (deleted)", "kind": "memfd"},
            ])


@needs_disk
class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=DISK_DIR)
        self.path = os.path.join(self.tmp.name, "bin")
        _write(self.path, os.urandom(4096))

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = copyfix.main(argv)
        return code, buf.getvalue()

    def test_clean_exit_code_and_json(self):
        code, out = self.run_main(["--json", self.path])
        self.assertEqual(code, copyfix.EXIT_CLEAN)
        data = json.loads(out)
        self.assertEqual(data["summary"]["clean"], 1)
        self.assertEqual(data["results"][0]["status"], "clean")

    def test_tampered_exit_code(self):
        tampered = {"path": self.path, "status": copyfix.TAMPERED, "first_diff_offset": 8,
                    "diff_bytes": 4, "sha256_cached": "a" * 64, "sha256_direct": "b" * 64}
        with mock.patch.object(copyfix, "check_file", return_value=tampered):
            code, out = self.run_main([self.path])
        self.assertEqual(code, copyfix.EXIT_TAMPERED)
        self.assertIn("TAMPERED", out)

    def test_incomplete_exit_code(self):
        with mock.patch.object(copyfix, "check_file",
                               return_value={"path": self.path, "status": copyfix.UNSUPPORTED, "detail": "x"}):
            code, _ = self.run_main([self.path])
        self.assertEqual(code, copyfix.EXIT_INCOMPLETE)

    def test_missing_path_is_usage_error(self):
        with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            code = copyfix.main([os.path.join(self.tmp.name, "nope")])
        self.assertEqual(code, copyfix.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
