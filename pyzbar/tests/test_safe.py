"""Tests for pyzbar.safe.decode_isolated.

These use real subprocesses (via the 'spawn' start method), so they're
slower than the rest of the suite but they're testing exactly the thing
that matters: does a hung or crashed worker actually get contained, not
just "does the code look right".
"""
import os
import time
import unittest

from PIL import Image

from pyzbar.safe import decode_isolated
from pyzbar.pyzbar_error import PyZbarError

_HERE = os.path.dirname(__file__)


class TestDecodeIsolatedSuccess(unittest.TestCase):
    def test_real_qrcode_decodes(self):
        img = Image.open(os.path.join(_HERE, 'qrcode.png'))
        results = decode_isolated(img, timeout=5)
        self.assertEqual(1, len(results))
        self.assertEqual('QRCODE', results[0].type)

    def test_blank_tuple_image_returns_empty_list(self):
        results = decode_isolated((b'\x00' * 256, 16, 16), timeout=5)
        self.assertEqual([], results)


class TestDecodeIsolatedValidationPropagates(unittest.TestCase):
    def test_validation_error_from_worker_propagates(self):
        # Oversized dimension - should be rejected inside the worker by
        # the same PyZbarValidationError as an in-process decode() call,
        # and that exception should survive the trip across the pipe.
        with self.assertRaises(PyZbarError):
            decode_isolated((b'\x00', 999999, 999999), timeout=5)


class TestDecodeIsolatedTimeout(unittest.TestCase):
    def test_hung_worker_is_killed_within_timeout(self):
        """Uses a module-level target (see _hang_forever below) so it's
        picklable under the 'spawn' start method, and monkeypatches
        pyzbar.safe.worker_entrypoint for the duration of this test only.
        """
        import pyzbar.safe as safe_mod

        original = safe_mod.worker_entrypoint
        safe_mod.worker_entrypoint = _hang_forever
        try:
            t0 = time.time()
            with self.assertRaises(TimeoutError):
                decode_isolated((b'\x00' * 100, 10, 10), timeout=2)
            elapsed = time.time() - t0
            # Must return promptly (bounded by timeout + kill overhead),
            # not block for anywhere near how long the worker would have
            # slept if left to run to completion.
            self.assertLess(
                elapsed, 10,
                'decode_isolated took {0:.1f}s to return after a 2s '
                'timeout against a hung worker - the worker was not '
                'actually killed, only "waited out".'.format(elapsed)
            )
        finally:
            safe_mod.worker_entrypoint = original

    def test_crashed_worker_raises_pyzbar_error(self):
        import pyzbar.safe as safe_mod

        original = safe_mod.worker_entrypoint
        safe_mod.worker_entrypoint = _crash_immediately
        try:
            with self.assertRaises(PyZbarError):
                decode_isolated((b'\x00' * 100, 10, 10), timeout=5)
        finally:
            safe_mod.worker_entrypoint = original


def _hang_forever(image, symbols, conn):
    """Module-level (picklable under 'spawn') stand-in worker that never
    responds, simulating libzbar hanging inside a native call.
    """
    time.sleep(120)


def _crash_immediately(image, symbols, conn):
    """Module-level (picklable under 'spawn') stand-in worker that exits
    hard without going through the normal try/except/send path, simulating
    a native segfault inside libzbar.
    """
    os._exit(1)


if __name__ == '__main__':
    unittest.main()
