# Contributing to CopyFix

Thanks for your interest in CopyFix. Bug reports, test results from different kernels and filesystems, and code improvements are all welcome.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Reporting Bugs

Use the **Bug report** form in the Issues tab. Include:

- The exact command you ran, and its full output (`--json` output is ideal)
- Your distribution, kernel version (`uname -r`) and Python version (`python3 --version`)
- The filesystem of the files you checked (`findmnt -T /usr/bin/su`)

## Suggesting Improvements

Use the **Feature request** form, and explain how the change improves detection or reduces false results.

## Pull Requests

1. Fork the repository and create a branch from `main`.
2. Keep CopyFix dependency-free: Python 3.9+ standard library only.
3. Add or update tests in `tests/` for any change in behavior.
4. Run the test suite and make sure it passes:

   ```bash
   python3 -m unittest discover -s tests -v
   ```

5. Run CopyFix against real binaries on your system and include the output in the pull request.
6. Update `README.md` and `CHANGELOG.md` if behavior or usage changes.

## Code Style

- Follow PEP 8, with 4-space indentation.
- Keep functions small and focused.
- Comment anything involving `/proc`, `O_DIRECT` or the page cache, and explain *why*, not just *what*.
- Never weaken a check to avoid a false positive without documenting the trade-off.
