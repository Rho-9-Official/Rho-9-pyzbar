"""Tests for the Rho-9 hardening additions on top of upstream pyzbar.

These deliberately exercise the validation paths added in pyzbar.py -
they do not require a real barcode image, just crafted (pixels, width,
height) tuples designed to trip each sanity cap.
"""
import unittest

from pyzbar.pyzbar import decode, MAX_DIMENSION, MAX_PIXELS
from pyzbar.pyzbar_error import PyZbarError, PyZbarValidationError


class TestDimensionValidation(unittest.TestCase):
    def test_zero_width_rejected(self):
        with self.assertRaises(PyZbarValidationError):
            decode((b'', 0, 10))

    def test_zero_height_rejected(self):
        with self.assertRaises(PyZbarValidationError):
            decode((b'', 10, 0))

    def test_negative_width_rejected(self):
        with self.assertRaises(PyZbarValidationError):
            decode((b'\x00' * 100, -10, 10))

    def test_oversized_dimension_rejected(self):
        w = MAX_DIMENSION + 1
        with self.assertRaises(PyZbarValidationError):
            decode((b'\x00' * w, w, 1))

    def test_oversized_pixel_count_rejected(self):
        # Both dimensions individually legal, product exceeds MAX_PIXELS
        w = h = int(MAX_PIXELS ** 0.5) + 100
        self.assertLessEqual(w, MAX_DIMENSION + 1)  # sanity check on test itself
        with self.assertRaises(PyZbarValidationError):
            decode((b'\x00' * (w * h), w, h))

    def test_empty_pixel_buffer_rejected(self):
        with self.assertRaises((PyZbarValidationError, ZeroDivisionError, PyZbarError)):
            decode((b'', 10, 10))

    def test_mismatched_buffer_length_rejected(self):
        # 10x10 = 100 bytes expected at 8bpp; supply 300 (a clean multiple,
        # which the upstream modulo-only check would have accepted).
        with self.assertRaises(PyZbarValidationError):
            decode((b'\x00' * 300, 10, 10))

    def test_non_int_dimensions_rejected(self):
        with self.assertRaises(PyZbarValidationError):
            decode((b'\x00' * 100, 10.0, 10))


class TestValidSmallImage(unittest.TestCase):
    def test_blank_image_decodes_without_error(self):
        # A legitimate, small, blank 8bpp image should pass all sanity
        # checks and simply return no symbols (not raise).
        w = h = 16
        result = decode((b'\x00' * (w * h), w, h))
        self.assertEqual(result, [])


class TestOrientationRegression(unittest.TestCase):
    """Regression test for a real bug found via adversarial testing
    (crafted structured-append QR symbols): zbar_symbol_get_orientation
    was declared with ctypes restype c_uint upstream, but zbar's actual C
    signature is signed (ZBAR_ORIENT_UNKNOWN == -1). Under c_uint, that -1
    came back as 4294967295, which doesn't match any ZBarOrientation
    member and raised an uncaught ValueError - reachable by any
    attacker-supplied image that makes zbar report unknown orientation,
    bypassing PyZbarError entirely. Fixed in wrapper.py (c_int) with a
    second, independent hardening layer in pyzbar.py's _decode_symbols
    (never let an unrecognised enum value raise past this point,
    regardless of cause).
    """

    def test_structured_append_symbol_does_not_raise_valueerror(self):
        # Structured-append QR segments reliably report unknown
        # orientation in this zbar build - a real, reproducible trigger
        # for the bug, not a synthetic one.
        try:
            import segno
        except ImportError:
            self.skipTest(
                'segno not installed - only needed to craft this '
                'specific regression test case, not a pyzbar runtime '
                'dependency'
            )
        from PIL import Image

        seq = segno.make_sequence(b'REGRESSION_TEST_PAYLOAD' * 20,
                                   symbol_count=4, error='h')
        for i, part in enumerate(seq):
            path = '/tmp/_orientation_regression_{0}.png'.format(i)
            part.save(path, scale=4, border=3)
            # Must not raise ValueError (or anything other than the
            # documented PyZbarError/PyZbarValidationError hierarchy).
            results = decode(Image.open(path))
            for r in results:
                self.assertIsInstance(r.orientation, str)


if __name__ == '__main__':
    unittest.main()
