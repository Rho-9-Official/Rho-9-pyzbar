# Rho-9 hardened pyzbar - security notes

Base: upstream `pyzbar` 0.1.9 (https://github.com/NaturalHistoryMuseum/pyzbar)
Fork version: `0.1.9-rho9.1`

## Why this exists

`pyzbar.pyzbar.decode()` is often called on fully attacker-controlled
image bytes - e.g. any barcode/QR image uploaded by a user, received as
an attachment, or pulled from an untrusted URL. A common pattern in
security-conscious pipelines is to isolate the *PIL* decode step
(libpng/libjpeg/libwebp/libtiff) into a worker process with a timeout,
since PIL's underlying image codecs are themselves attack surface. This
package applies the equivalent hardening to the *zbar* decode step, which
sits immediately downstream of PIL in that same code path and has the
same trust boundary: an untrusted uploaded image is not more trusted than
a downloaded file.

## What `pyzbar` actually is

`pyzbar` (the Python package) is **not** a barcode decoder. It is a thin
`ctypes` binding around the compiled `libzbar` shared library, which does
all the actual decoding in C/C++. This matters a lot for what "patching
pyzbar" can and cannot mean:

- Bugs in the C/C++ decoders themselves (buffer overflows, use-after-free,
  OOB reads in a specific symbology parser, etc.) live in `libzbar`, a
  separate compiled artifact this package does not build or ship. They
  cannot be fixed by editing Python.
- What *can* be done in Python is controlling what's allowed to cross the
  boundary in either direction, and containing the blast radius if
  something on the other side of that boundary misbehaves anyway.

## What changed vs. upstream

**`pyzbar.py`** - the only file with functional changes:
- Every value about to cross into a ctypes call (width, height, pixel
  buffer length) is validated against sanity caps (`MAX_DIMENSION`,
  `MAX_PIXELS`, `MAX_RAW_PIXEL_BYTES`) before `zbar_image_set_size` /
  `zbar_image_set_data` are ever called.
- Fixed a real gap in the upstream buffer-length check: it only verified
  `len(pixels) % (width * height) == 0`, which accepts any integer
  multiple of the expected size (e.g. 300 bytes for a 10x10 image) as
  "fine" and then computes a `bpp` that happens to still equal 8. This
  fork requires an *exact* match, since only 8bpp is actually supported
  and a buffer bigger than expected has no valid interpretation here.
- Every value read *back out* of zbar's C structures is treated as
  untrusted and capped before use: `zbar_symbol_get_data_length()` before
  the `string_at()` call that uses it as a read length
  (`MAX_SYMBOL_DATA_LENGTH`), `zbar_symbol_get_loc_size()` before
  iterating that many location points (`MAX_LOC_POINTS`), and the
  `zbar_symbol_next()` linked-list walk itself is bounded
  (`MAX_SYMBOLS_PER_IMAGE`) so a corrupted/cyclic list can't hang forever.
  Exceeding any of these raises `PyZbarValidationError` (a new, distinct
  subclass of `PyZbarError`) rather than silently truncating - an
  out-of-range value here means zbar's internal state already shouldn't be
  trusted further, so failing loud is the correct response.

**`zbar_library.py`** - loader hardening:
- Logs the resolved `libzbar` path and reported version on load, so "which
  libzbar is this actually running" is always visible in application logs.
- On POSIX, refuses to load from a relative/CWD path (confirmed by testing
  - see the adversarial testing section below); does *not* protect against
  an `LD_LIBRARY_PATH`-based redirect (also confirmed by testing), and now
  warns if that env var is set.

**`safe.py`** - new module, not present upstream:
- `decode_isolated()` runs `decode()` in a disposable single-use worker
  process (`multiprocessing.Process`, not `ProcessPoolExecutor` - see
  below) with a hard timeout. This is the actual fix for the risk that
  Python-level validation *cannot* close: a bug that trips *inside*
  `zbar_scan_image` itself, before control returns to Python, can still
  segfault or hang - no `try/except` in this file or any caller can catch
  that. Process isolation is the only real mitigation, identical in
  spirit to the `ProcessPoolExecutor` pattern commonly applied to the PIL
  decode step in similar pipelines.
  - Uses `multiprocessing.Process` directly, not
    `concurrent.futures.ProcessPoolExecutor`, because the latter's `with`
    block blocks on exit waiting for a hung worker to finish on its own -
    which defeats the entire point of the timeout. This was caught by
    testing the actual hang path, not assumed.
  - The worker entrypoint lives in its own leaf module
    (`pyzbar/_isolated_worker.py`) with zero `multiprocessing` imports.
    This was also found by testing, and is worth recording since it's
    non-obvious: if the worker entrypoint function had lived directly in
    `safe.py`, the spawned child process resolving that function
    reference would import `safe.py`, which at module level calls
    `multiprocessing.get_context('spawn')` to build the context the
    *parent* uses. Calling `get_context('spawn')` a second time, from
    inside a process that was itself already spawned, was observed in
    testing to intermittently (roughly 15-25% of runs, reproduced with a
    100-iteration stress test) segfault the very next ctypes call into
    libzbar - plain `import multiprocessing` in the child is harmless; it
    is specifically constructing another context object in the
    already-spawned child that triggers it. Root cause not fully pinned
    down (likely some fork/signal/fd side effect of context construction
    interacting badly with libzbar's internal state on this platform),
    but the fix is straightforward: never let the child re-construct a
    context, by keeping the worker entrypoint import-clean of
    `multiprocessing`. Confirmed fixed with a 100-iteration stress test
    (0 failures) after the change; see `pyzbar/tests/test_safe.py`.

**`wrapper.py`, `locations.py`, `pyzbar_error.py` (base `PyZbarError`),
`__init__.py`** - unchanged in behaviour; `pyzbar_error.py` adds the new
`PyZbarValidationError` subclass, `__init__.py` bumps the version string.

## What this does *not* claim to fix

- No CVE database is consulted or maintained here. `zbar_library.py` logs
  the loaded libzbar's version for visibility; it does not block known-bad
  versions, because no such curated mapping is included in this fork.
- This does not patch `libzbar`'s C/C++ source and cannot fix a
  vulnerability that lives entirely inside a single `zbar_scan_image` call
  before it returns. Use `decode_isolated()` on any untrusted input path;
  that's the actual containment for that class of bug, not a Python-level
  workaround for it.

## Adversarial testing pass (post-hardening validation)

After the hardening above, the fork was pentested directly: crafted
malicious QR codes (command injection, path traversal, format-string,
XSS/SQLi payloads, binary garbage, structured-append, multiple
symbologies/modes), large-scale structural fuzzing (~35,000 cases across
dimensions/buffer sizes/types against `decode()`), targeted numpy/PIL
fuzzing, a real command-injection canary check, a CLI argument-injection
check, and a library-path-hijack check. This found and fixed four real
bugs, and confirmed one real, out-of-scope limitation:

1. **Orientation type mismatch (uncaught `ValueError`)**. Crafted
   structured-append QR symbols reliably made zbar report "unknown
   orientation" (native value `-1`). `zbar_symbol_get_orientation` was
   declared with ctypes `restype=c_uint` (upstream bug, inherited
   unmodified), so `-1` came back as `4294967295`, which doesn't match
   any `ZBarOrientation` member - raising an uncaught `ValueError` that
   bypassed `PyZbarError` entirely. **Not exploitable for RCE/memory
   corruption** - it's an input-validation/exception-hygiene bug, but a
   real one, reliably attacker-triggerable, and a caller catching only
   `PyZbarError` would have an unhandled exception reach it. Fixed: the
   ctypes restype corrected to `c_int` in `wrapper.py`, plus an
   independent second layer in `pyzbar.py` that treats *any* unrecognised
   orientation value as a soft "unrecognised" case (matching the existing
   pattern for unrecognised symbol types) rather than raising.
   Regression test: `test_rho9_hardening.TestOrientationRegression`.

2. **Validation-order gap allowing a pre-cap memory exhaustion (numpy)**.
   Fuzzing with `numpy.lib.stride_tricks.as_strided` (a huge *declared*
   shape backed by a tiny actual buffer - a classic "lie about the size"
   trick) triggered a `MemoryError` inside `.tobytes()`. Root cause: the
   `MAX_DIMENSION`/`MAX_PIXELS` checks existed, but ran *after* the
   numpy/PIL branches had already called their expensive/dangerous native
   extraction methods (`.tobytes()`, `.convert()`, `.astype()`) to
   determine what to validate. The caps were real but checked too late to
   prevent the exact resource-exhaustion pattern they existed to stop.
   Fixed: `_pixel_data()` restructured (see `_validate_dimensions()`) so
   `width`/`height` are read via the cheap `O(1)` `.size`/`.shape`
   attributes and validated *before* any expensive native call runs, for
   every input type (PIL, numpy, tuple). Confirmed by testing: the same
   `as_strided` attack now rejects instantly (`0.0000s`) with a clean
   `PyZbarValidationError`, no allocation attempted.

3. **Uncaught `ValueError` on 1-D numpy arrays**. `height, width =
   image.shape[:2]` raises "not enough values to unpack" for a 1-D (or
   0-D) array, again bypassing `PyZbarError`. Fixed: explicit
   `len(image.shape) >= 2` check before unpacking.

4. **Uncaught Pillow `ValueError` on unconvertible PIL modes**. Some PIL
   modes (e.g. `'LAB'`) raise their own `ValueError` on `.convert('L')`
   rather than failing in a way `pyzbar` could catch cleanly. Fixed:
   the PIL and numpy extraction branches each wrap their native
   conversion calls in `try/except`, normalising any native-library
   failure to `PyZbarValidationError` with the original exception chained
   via `raise ... from exc`.

None of the above were exploitable for command execution, arbitrary file
write, or memory corruption - the adversarial QR content battery (~30
crafted images: shell metacharacters, `$()`/backtick/pipe injection
patterns, path traversal, format-string payloads, Python
format/f-string-injection patterns, XSS/SQLi strings, raw binary,
embedded nulls, invalid UTF-8, near-max-capacity payloads, multiple
symbologies/ECI/Kanji/micro-QR/structured-append) all round-tripped as
inert `bytes` with zero side effects, verified with a canary-file check
(no file was ever created by a payload, proving no command injection
occurred anywhere in the decode path). The bugs above were pure
input-validation/exception-hygiene gaps, which is exactly the class of
bug this kind of adversarial testing is for - they wouldn't have been
found by code review alone.

**Confirmed, but explicitly out of scope**: `LD_LIBRARY_PATH` *can*
redirect which `libzbar` gets loaded (tested with a fake `libzbar.so.0`
containing a malicious native constructor - it loaded and ran). This is
a different, higher-privilege threat model than the CWD-hijack case
(which testing confirmed *is* blocked): it requires control over the
process's execution environment, at which point simpler code-execution
paths already exist (`LD_PRELOAD`, `PYTHONPATH`). Not something this
module can close; `zbar_library.py` now logs a warning if
`LD_LIBRARY_PATH` is set, for visibility rather than prevention. See that
module's docstring for the full writeup.

**Confirmed safe**: the CLI script (`read_zbar.py`) was tested with
filenames containing shell metacharacters (`` `id` ``, `$(whoami)`, etc.)
- they're treated as literal filesystem paths (no `shell=True`/
`subprocess`/`os.system` anywhere in this package, confirmed by a
grep-based static audit as well), so no injection is possible regardless
of filename content.



## Recommended integration in a consuming application

Replace a direct `pyzbar.pyzbar.decode(img)` call with
`pyzbar.safe.decode_isolated(img, timeout=...)`, and catch
`TimeoutError` / `PyZbarError` there the same way an existing PIL-decode
isolation path (if one exists in your pipeline) is already handled -
treating a timeout or worker crash as a signal to reject the input, not
a silently-swallowed "clean" result.
