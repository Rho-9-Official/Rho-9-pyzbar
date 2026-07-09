"""Worker entrypoint for pyzbar.safe.decode_isolated.

This is deliberately its own tiny module, separate from pyzbar/safe.py.

Reason (found by testing, not assumed - see pyzbar/tests/test_safe.py):
under the 'spawn' start method, the worker process resolves its target
function by *importing the module it lives in*. If that entrypoint lived
in pyzbar/safe.py itself, the worker would import pyzbar.safe - which at
module level calls `multiprocessing.get_context('spawn')` to build the
context the *parent* uses to create Pipes/Processes. Calling
`get_context('spawn')` a second time, from inside a process that was
itself already spawned, was observed to intermittently (~15-25% of runs
in testing) segfault the very next ctypes call into libzbar - a strange
and non-obvious interaction, but a reliably reproducible one. Plain
`import multiprocessing` in the child is fine; it's specifically
constructing another context object in the already-spawned child that
triggers it.

The fix is simply to make sure the child never does that: this module has
no multiprocessing import at all, so unpickling `_worker_entrypoint` in
the child never re-triggers context construction.
"""
from .pyzbar_error import PyZbarError

__all__ = ['worker_entrypoint']


def worker_entrypoint(image, symbols, conn):
    """Runs in the disposable worker process. Decodes `image` and sends
    `(status, payload)` back over `conn`, where `status` is 'ok' (payload
    is the list of Decoded results) or 'error' (payload is the exception
    instance).
    """
    try:
        from .pyzbar import decode as _decode
        result = _decode(image, symbols=symbols)
        conn.send(('ok', result))
    except BaseException as exc:  # noqa: BLE001 - deliberately broad: we
        # want to report *any* failure back to the parent rather than let
        # it vanish as a silent worker exit.
        try:
            conn.send(('error', exc))
        except Exception:
            # exc didn't pickle (rare, e.g. some C-extension exceptions) -
            # fall back to a plain string so the parent still gets *some*
            # signal instead of just seeing the pipe close.
            conn.send(('error', PyZbarError(
                'Worker raised {0}: {1}'.format(type(exc).__name__, exc)
            )))
    finally:
        conn.close()
