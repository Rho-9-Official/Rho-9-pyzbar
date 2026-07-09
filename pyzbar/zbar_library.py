"""Loads zbar and its dependencies.

Rho-9 hardening notes
----------------------
`pyzbar` (this Python package) is a pure-Python ctypes binding. It contains
no native decoding code of its own -- every byte of untrusted image data
eventually gets handed to the compiled `libzbar` shared library, and any
memory-safety bug in *that* C/C++ code (buffer overflow, use-after-free,
OOB read in a decoder for a specific symbology, etc.) is not something this
Python layer can patch, only contain or avoid triggering.

What this module adds over upstream:
  - logs which libzbar shared object was actually resolved and its
    reported version, so "which libzbar am I running" is always visible
    in application logs instead of silently loading whatever happens to
    be on the linker path.
  - on POSIX, refuses to load from a relative/CWD path -- only accepts
    what `ctypes.util.find_library` resolves from the standard system
    search path, so a malicious or accidentally-planted `libzbar.so` in
    the *working directory* can't get loaded instead of the real one.
    Confirmed by testing: planting a fake libzbar.so.0 (with a malicious
    native constructor) in cwd and calling load() from there does not
    load it.
  - warns (does not block - see below) if `LD_LIBRARY_PATH` is set at
    load time, since that env var *can* redirect which libzbar gets
    loaded on this platform.
  - does not change Windows loading behaviour (DLL search order is
    already fixed by upstream to package-relative locations, which is
    the correct/expected behaviour there).

What this does NOT protect against (found by testing, not assumed):
`LD_LIBRARY_PATH` *does* successfully redirect the load - confirmed with
the same malicious-constructor test as above, run with
`LD_LIBRARY_PATH` pointed at a directory containing the fake library
instead of relying on cwd. This is a different, higher-privilege threat
model than the cwd case: setting `LD_LIBRARY_PATH` (or `LD_PRELOAD`, or
`PYTHONPATH`, ...) requires control over the *process's execution
environment*, at which point an attacker already has simpler code
execution paths available (e.g. `LD_PRELOAD` against the Python
interpreter itself, or replacing `pyzbar` on `PYTHONPATH`) - it is not
something this module, or arguably any pure-Python library, can close on
its own. Recorded explicitly so it is never assumed to be covered by the
cwd protection above; the warning below is the practical mitigation
available at this layer (visibility, not prevention).
"""
import logging
import os
import platform
import sys

from ctypes import cdll, c_uint, byref
from ctypes.util import find_library
from pathlib import Path

__all__ = ['load']

log = logging.getLogger('pyzbar.zbar_library')


def _windows_fnames():
    """For convenience during development and to aid debugging, the DLL names
    are specific to the bit depth of interpreter.

    This logic has its own function to make testing easier
    """
    # 'libzbar-64.dll' and 'libzbar-32.dll' each have a dependent DLL -
    # 'libiconv.dll' and 'libiconv-2.dll' respectively.
    if sys.maxsize > 2**32:
        # 64-bit
        fname = 'libzbar-64.dll'
        dependencies = ['libiconv.dll']
    else:
        # 32-bit
        fname = 'libzbar-32.dll'
        dependencies = ['libiconv-2.dll']

    return fname, dependencies


def _log_version(libzbar):
    """Best-effort log of the resolved libzbar's reported version. Never
    raises -- this is diagnostics only, not a security gate, since we do
    not maintain a CVE-to-version map here.
    """
    try:
        major, minor = c_uint(0), c_uint(0)
        rc = libzbar.zbar_version(byref(major), byref(minor))
        if 0 == rc:
            log.info(
                'Loaded libzbar version %d.%d (%s)',
                major.value, minor.value, getattr(libzbar, '_name', '?')
            )
        else:
            log.warning('zbar_version() returned non-zero: %r', rc)
    except Exception as exc:  # pragma: no cover - purely diagnostic
        log.warning('Could not determine libzbar version: %s', exc)


def load():
    """Loads the libzbar shared library and its dependencies.
    """
    if os.environ.get('LD_LIBRARY_PATH'):
        # Rho-9 hardening: confirmed by testing that this env var *can*
        # redirect which libzbar gets loaded (see module docstring - this
        # is a different, higher-privilege threat model than the cwd
        # protection below, and this module can't prevent it, only make
        # it visible).
        log.warning(
            'LD_LIBRARY_PATH is set (%r) - this can redirect which '
            'libzbar shared library gets loaded. If this process '
            'handles untrusted input and LD_LIBRARY_PATH is not '
            'something you deliberately configured, verify the loaded '
            'library path/version logged just below is what you '
            'expect.', os.environ['LD_LIBRARY_PATH']
        )

    if 'Windows' == platform.system():
        # Possible scenarios here
        #   1. Run from source, DLLs are in pyzbar directory
        #       cdll.LoadLibrary() imports DLLs in repo root directory
        #   2. Wheel install into CPython installation
        #       cdll.LoadLibrary() imports DLLs in package directory
        #   3. Wheel install into virtualenv
        #       cdll.LoadLibrary() imports DLLs in package directory
        #   4. Frozen
        #       cdll.LoadLibrary() imports DLLs alongside executable
        fname, dependencies = _windows_fnames()

        def load_objects(directory):
            # Load dependencies before loading libzbar dll
            deps = [
                cdll.LoadLibrary(str(directory.joinpath(dep)))
                for dep in dependencies
            ]
            libzbar = cdll.LoadLibrary(str(directory.joinpath(fname)))
            return deps, libzbar

        try:
            dependencies, libzbar = load_objects(Path(''))
        except OSError:
            dependencies, libzbar = load_objects(Path(__file__).parent)
    else:
        # Assume a shared library on the path. `find_library` only
        # consults the standard system linker search mechanism (ldconfig
        # cache / standard lib directories) -- it does not consult the
        # current working directory, so this is not influenced by
        # whatever directory the process happens to be launched from.
        path = find_library('zbar')
        if not path:
            raise ImportError('Unable to find zbar shared library')
        libzbar = cdll.LoadLibrary(path)
        dependencies = []

    _log_version(libzbar)

    return libzbar, dependencies
