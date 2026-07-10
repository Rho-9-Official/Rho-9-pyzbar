# Rho-9 pyzbar (hardened fork)

Note: Claude didn't realize it fixed the RCE,LMFAO, eh whatever, I'm no longer able to trigger commands via the exploit images I crafted like...what 2 years ago or so? I forget, but what matters is the problem seems to be fixed.

A hardened fork of [`pyzbar`](https://github.com/NaturalHistoryMuseum/pyzbar) 0.1.9,
a Python `ctypes` binding for the `libzbar` barcode/QR decoding library.

`pyzbar` itself does not decode anything - it hands image bytes across a
`ctypes` boundary into the compiled `libzbar` C/C++ library and reads the
results back out. That boundary is where this fork adds hardening, aimed
specifically at the case where the image being decoded comes from an
untrusted source (user upload, chat attachment, downloaded file, etc.).

## What's different from upstream

- **Input validation** (`pyzbar.py`) - sanity-checks values read back from
  `libzbar`'s internal state (buffer lengths, symbol counts, linked-list
  traversal) before trusting them, raising `PyZbarValidationError` instead
  of using values outside expected bounds.
- **Process-isolated decoding** (`safe.py`) - `decode_isolated()` runs the
  decode in a disposable worker process with a hard timeout, so a crash or
  hang inside `libzbar` itself (which Python-level validation cannot catch)
  takes down a throwaway worker instead of the caller's process.
- **Library load hardening** (`zbar_library.py`) - logs the resolved
  `libzbar` path and version on load, refuses to load from a relative/CWD
  path on POSIX, and warns if `LD_LIBRARY_PATH` is set.
- **Distinct exception type** (`pyzbar_error.py`) - `PyZbarValidationError`
  lets callers distinguish "rejected in pure Python before reaching zbar"
  from "zbar itself raised a decode error."

Full technical writeup, including what these fixes can and cannot cover
and the adversarial testing performed, is in
[`pyzbar/SECURITY_NOTES.md`](pyzbar/SECURITY_NOTES.md).

## Install

```bash
pip install .
```

For the CLI script or running tests:

```bash
pip install .[scripts]   # adds Pillow, for read_zbar CLI
pip install .[test]      # adds Pillow + numpy, for the test suite
```

## Usage

Basic decode (same API as upstream `pyzbar`):

```python
from pyzbar.pyzbar import decode
from PIL import Image

results = decode(Image.open('code.png'))
```

Process-isolated decode, for untrusted/attacker-supplied images:

```python
from pyzbar.safe import decode_isolated
from pyzbar.pyzbar_error import PyZbarError

try:
    results = decode_isolated(image, timeout=5)
except TimeoutError:
    # decode hung past the timeout - treat as a rejected/hostile input
    ...
except PyZbarError:
    # zbar raised, or pre-flight validation rejected the input
    ...
```

## Testing

```bash
pip install .[test]
python -m pytest pyzbar/tests/
```

`pyzbar/tests/test_rho9_hardening.py` covers the fork-specific hardening
(validation limits, isolated-worker crash/timeout behavior, library-load
checks) on top of the original upstream test suite.

## License

Same license terms as upstream `pyzbar`. This fork adds hardening on top
of the original project; see upstream for attribution.
