__all__ = ["PyZbarError", "PyZbarValidationError"]


class PyZbarError(Exception):
    pass


class PyZbarValidationError(PyZbarError):
    """Raised when input fails a Rho-9 hardening sanity check before it
    would otherwise be handed across the ctypes boundary into libzbar.

    This is intentionally a distinct, catchable exception type so callers
    (and the Elysium security dashboard) can tell "we rejected obviously
    hostile/malformed input in pure Python" apart from "zbar itself raised
    a decode error", without needing to string-match exception messages.
    """
    pass
