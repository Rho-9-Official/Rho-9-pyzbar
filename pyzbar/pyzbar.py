"""Rho-9 hardened fork of pyzbar.pyzbar (upstream 0.1.9).

Threat model
------------
`decode()` is reachable from fully attacker-controlled bytes (e.g. any
image attached to a chat message). Everything below the `_image_scanner`/
`_image` context managers is a ctypes call into the compiled `libzbar`
shared library - a C/C++ codebase this Python layer does not control and
cannot patch. A memory-safety bug in libzbar's decoders is not something
`except Exception` can catch: it can segfault the interpreter outright, or
corrupt memory and continue running with a poisoned heap.

What this module can and does do:
  1. Validate every value *before* it crosses into C, so obviously
     malformed/hostile input (absurd dimensions, mismatched buffer sizes,
     zero-size images) never reaches zbar_image_set_size /
     zbar_image_set_data at all.
  2. Treat every value *coming back out* of zbar's C structures as
     untrusted too. `zbar_symbol_get_data_length`, `zbar_symbol_get_loc_size`,
     and the `zbar_symbol_next` linked list are all reads from the C
     library's internal state; if that state is ever corrupted (by a bug
     triggered on a hostile input), trusting those values blindly is how a
     "one decoder had a bug" turns into "we called string_at() with a
     multi-gigabyte length and OOM'd" or "we followed a corrupted/cyclic
     linked list forever". Every one of those reads is now capped, and
     values outside the cap raise `PyZbarValidationError` instead of being
     used.
  3. What it explicitly *cannot* do: catch a segfault or a hang caused by
     a bug that trips *before* zbar returns control to Python at all (e.g.
     inside `zbar_scan_image` itself). For that, use
     `pyzbar.safe.decode_isolated()`, which runs decode() in a disposable
     worker process with a hard timeout - the same pattern already applied
     to Pillow decoding in Elysium's `scan_qr_code()`.

All caps below are conservative defaults sized for chat-message-attached
images, not scientific/GIS imagery. Override via the module-level
constants if a legitimate use case needs larger images.
"""
from collections import namedtuple
from contextlib import contextmanager
from ctypes import cast, c_void_p, string_at

from .locations import bounding_box, convex_hull, Point, Rect
from .pyzbar_error import PyZbarError, PyZbarValidationError
from .wrapper import (
    zbar_image_scanner_set_config,
    zbar_image_scanner_create, zbar_image_scanner_destroy,
    zbar_image_create, zbar_image_destroy, zbar_image_set_format,
    zbar_image_set_size, zbar_image_set_data, zbar_scan_image,
    zbar_image_first_symbol, zbar_symbol_get_data_length,
    zbar_symbol_get_data, zbar_symbol_get_orientation,
    zbar_symbol_get_loc_size, zbar_symbol_get_loc_x, zbar_symbol_get_loc_y,
    zbar_symbol_get_quality, zbar_symbol_next, ZBarConfig, ZBarOrientation,
    ZBarSymbol, EXTERNAL_DEPENDENCIES,
)

__all__ = [
    'decode', 'Point', 'Rect', 'Decoded', 'ZBarSymbol', 'EXTERNAL_DEPENDENCIES',
    'ORIENTATION_AVAILABLE',
]


ORIENTATION_AVAILABLE = zbar_symbol_get_orientation is not None

Decoded = namedtuple('Decoded', 'data type rect polygon quality orientation')

# ZBar's magic 'fourcc' numbers that represent image formats
_FOURCC = {
    'L800': 808466521,
    'GRAY': 1497715271
}

_RANGEFN = getattr(globals(), 'xrange', range)


# --------------------------------------------------------------------------
# Rho-9 hardening: sanity caps.
#
# These bound the attack surface of the ctypes boundary in both directions.
# They are deliberately generous for ordinary photos/screenshots/QR crops
# and deliberately restrictive against pathological inputs designed to
# force huge allocations, huge loops, or out-of-bounds reads.
# --------------------------------------------------------------------------

# Upper bound on width or height (pixels) handed to zbar_image_set_size.
# zbar_image_set_size takes c_uint; without a cap, a caller (or a decoder
# upstream of pyzbar, e.g. a PIL image opened from attacker bytes) could
# hand across dimensions large enough to force a multi-gigabyte internal
# allocation inside libzbar purely as a memory-exhaustion DoS.
MAX_DIMENSION = 8192

# Upper bound on total pixel count (width * height), independent of the
# per-dimension cap above, so e.g. a 8192 x 8192 image (67M pixels) is
# still rejected even though neither dimension alone exceeds MAX_DIMENSION.
MAX_PIXELS = 16_000_000  # ~16 megapixels

# Upper bound on the raw pixel buffer size in bytes handed to
# zbar_image_set_data. At 8bpp this tracks MAX_PIXELS, but is enforced
# independently as a second, cheap check before any cast() happens.
MAX_RAW_PIXEL_BYTES = MAX_PIXELS

# Upper bound on a single decoded symbol's payload length. This value
# comes from zbar_symbol_get_data_length() - i.e. it is read back out of
# zbar's C struct, not supplied by us. If that value is ever corrupted
# (heap corruption, decoder bug) and unbounded, the following
# string_at(ptr, length) call would read `length` bytes starting at
# whatever pointer zbar handed back, which is an OOB-read primitive.
# Capping this means the worst case is "we refuse to read a suspiciously
# huge symbol", not "we read arbitrary process memory".
MAX_SYMBOL_DATA_LENGTH = 1_048_576  # 1 MiB - generous for any real barcode

# Upper bound on the number of (x, y) location points read per symbol via
# zbar_symbol_get_loc_size(). Real symbologies report a handful of corner
# points; anything in the thousands is not a legitimate barcode shape.
MAX_LOC_POINTS = 1_024

# Upper bound on the number of symbols iterated per image via
# zbar_symbol_next(). This list is a C linked list; if it were ever
# corrupted into a cycle (again: only reachable via a libzbar bug), naive
# iteration would hang forever. Capping the iteration count turns a
# potential infinite loop into a bounded one that raises instead.
MAX_SYMBOLS_PER_IMAGE = 4_096


@contextmanager
def _image():
    """A context manager for `zbar_image`, created and destoyed by
    `zbar_image_create` and `zbar_image_destroy`.

    Yields:
        POINTER(zbar_image): The created image

    Raises:
        PyZbarError: If the image could not be created.
    """
    image = zbar_image_create()
    if not image:
        raise PyZbarError('Could not create zbar image')
    else:
        try:
            yield image
        finally:
            zbar_image_destroy(image)


@contextmanager
def _image_scanner():
    """A context manager for `zbar_image_scanner`, created and destroyed by
    `zbar_image_scanner_create` and `zbar_image_scanner_destroy`.

    Yields:
        POINTER(zbar_image_scanner): The created scanner

    Raises:
        PyZbarError: If the decoder could not be created.
    """
    scanner = zbar_image_scanner_create()
    if not scanner:
        raise PyZbarError('Could not create image scanner')
    else:
        try:
            yield scanner
        finally:
            zbar_image_scanner_destroy(scanner)


def _symbols_for_image(image):
    """Generator of symbols.

    Args:
        image: `zbar_image`

    Yields:
        POINTER(zbar_symbol): Symbol

    Raises:
        PyZbarValidationError: If more than MAX_SYMBOLS_PER_IMAGE symbols
            are encountered. zbar_symbol_next() walks a C linked list; a
            corrupted (e.g. cyclic) list would otherwise iterate forever.
            This is a hardening backstop, not an expected code path -
            hitting it means something upstream is already wrong.
    """
    count = 0
    symbol = zbar_image_first_symbol(image)
    while symbol:
        count += 1
        if count > MAX_SYMBOLS_PER_IMAGE:
            raise PyZbarValidationError(
                'Exceeded MAX_SYMBOLS_PER_IMAGE ({0}) while walking zbar '
                'symbol list - possible corrupted/cyclic list, refusing '
                'to continue.'.format(MAX_SYMBOLS_PER_IMAGE)
            )
        yield symbol
        symbol = zbar_symbol_next(symbol)


def _decode_symbols(symbols):
    """Generator of decoded symbol information.

    Args:
        symbols: iterable of instances of `POINTER(zbar_symbol)`

    Yields:
        Decoded: decoded symbol

    Raises:
        PyZbarValidationError: If a symbol reports a data length or
            location-point count beyond the sanity caps above. Both
            values are read back out of zbar's internal C state rather
            than supplied by pyzbar, so an out-of-range value here means
            that state should not be trusted further.
    """
    for symbol in symbols:
        data_length = zbar_symbol_get_data_length(symbol)
        if data_length > MAX_SYMBOL_DATA_LENGTH:
            raise PyZbarValidationError(
                'Symbol data length {0} exceeds MAX_SYMBOL_DATA_LENGTH '
                '({1}) - refusing to read, possible corrupted zbar '
                'state.'.format(data_length, MAX_SYMBOL_DATA_LENGTH)
            )
        data = string_at(
            zbar_symbol_get_data(symbol),
            data_length
        )
        # The 'type' int should be a value in the ZBarSymbol enumeration
        try:
            symbol_type = ZBarSymbol(symbol.contents.type)
        except ValueError:
            # This release of zbar supports a type that pyzbar does not know about
            symbol_type = "Unrecognised type [{0}]".format(symbol.contents.type)
        else:
            symbol_type = symbol_type.name

        quality = zbar_symbol_get_quality(symbol)

        loc_size = zbar_symbol_get_loc_size(symbol)
        if loc_size > MAX_LOC_POINTS:
            raise PyZbarValidationError(
                'Symbol location point count {0} exceeds MAX_LOC_POINTS '
                '({1}) - refusing to read, possible corrupted zbar '
                'state.'.format(loc_size, MAX_LOC_POINTS)
            )
        polygon = convex_hull(
            (
                zbar_symbol_get_loc_x(symbol, index),
                zbar_symbol_get_loc_y(symbol, index)
            )
            for index in _RANGEFN(loc_size)
        )

        if zbar_symbol_get_orientation:
            raw_orientation = zbar_symbol_get_orientation(symbol)
            try:
                orientation = ZBarOrientation(raw_orientation).name
            except ValueError:
                # Rho-9 hardening: found via adversarial testing that a
                # ctypes restype mismatch (see wrapper.py) let zbar's
                # "unknown orientation" value reach here as a value
                # outside the enum, raising an uncaught ValueError that
                # bypassed our entire PyZbarError taxonomy - reachable by
                # attacker-supplied input (a crafted/structured-append QR
                # symbol reliably triggers "unknown orientation"). That
                # root cause is now fixed in wrapper.py, but this is kept
                # as a second, independent layer: *no* value read back
                # from zbar - now or in some future zbar version/symbology
                # this fork hasn't been tested against - should be able to
                # crash decode() with an unhandled exception just because
                # it doesn't match a known enum member. Matches the same
                # "unrecognised type" handling already used for symbol
                # type, just above.
                orientation = "Unrecognised orientation [{0}]".format(
                    raw_orientation
                )
        else:
            orientation = None

        yield Decoded(
            data=data,
            type=symbol_type,
            rect=bounding_box(polygon),
            polygon=polygon,
            orientation=orientation,
            quality=quality,
        )


def _validate_dimensions(width, height, context):
    """Rho-9 hardening: validates width/height *before* any expensive or
    dangerous operation is allowed to run on their basis (native
    `.tobytes()` / `.convert()` / `.astype()` calls, or a ctypes call).

    This has to be a cheap, standalone, callable-early step rather than a
    single validation block at the end of `_pixel_data()` - fuzzing found
    that when it ran only at the end, a numpy array with a "lied" shape
    (e.g. via `numpy.lib.stride_tricks.as_strided`: a huge declared shape
    backed by a tiny actual buffer) could force a multi-gigabyte
    allocation inside `.tobytes()` *before* our own MAX_DIMENSION /
    MAX_PIXELS caps ever got checked - the caps existed but were being
    checked too late to prevent the expensive operation they were meant
    to gate. Calling this immediately after cheaply reading `.size` /
    `.shape` (both O(1), unlike `.tobytes()`) closes that gap.

    Args:
        context: short string identifying the caller, used only in error
            messages (e.g. 'PIL image', 'numpy array', 'tuple input').

    Raises:
        PyZbarValidationError: if width/height fail any sanity check.
    """
    if not isinstance(width, int) or not isinstance(height, int):
        raise PyZbarValidationError(
            '{0}: width/height must be int, got {1!r}/{2!r}'.format(
                context, type(width), type(height)
            )
        )
    if width <= 0 or height <= 0:
        raise PyZbarValidationError(
            '{0}: invalid dimensions width={1}, height={2} (must be '
            'positive)'.format(context, width, height)
        )
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise PyZbarValidationError(
            '{0}: dimensions {1}x{2} exceed MAX_DIMENSION ({3}) per '
            'side'.format(context, width, height, MAX_DIMENSION)
        )
    if width * height > MAX_PIXELS:
        raise PyZbarValidationError(
            '{0}: pixel count {1} exceeds MAX_PIXELS ({2})'.format(
                context, width * height, MAX_PIXELS
            )
        )


def _pixel_data(image):
    """Returns (pixels, width, height)

    Returns:
        :obj: `tuple` (pixels, width, height)

    Raises:
        PyZbarValidationError: If dimensions or buffer size fail the
            Rho-9 sanity caps (MAX_DIMENSION / MAX_PIXELS /
            MAX_RAW_PIXEL_BYTES), the buffer size doesn't exactly match
            width * height at the only supported bit depth (8bpp), or a
            native conversion (`.convert()` / `.astype()` / `.tobytes()`)
            failed for a reason outside our control (unsupported PIL
            mode, malformed array, etc. - found by fuzzing that Pillow
            and numpy can both raise their own uncaught exceptions here
            for legitimate-looking-but-unusual inputs; those are now
            caught and normalised to this one exception type).
        PyZbarError: For unsupported bit depths (matches upstream
            behaviour for non-8bpp buffers supplied via the tuple form).
    """
    # Test for PIL.Image, numpy.ndarray, and imageio.core.util without
    # requiring that cv2, PIL, or imageio are installed.

    image_type = str(type(image))
    if 'PIL.' in image_type:
        # Cheap (O(1)) - read dimensions and validate BEFORE the
        # potentially expensive .convert() / .tobytes() calls below.
        width, height = image.size
        _validate_dimensions(width, height, 'PIL image')
        try:
            if 'L' != image.mode:
                image = image.convert('L')
            pixels = image.tobytes()
        except PyZbarError:
            raise
        except Exception as exc:
            # Found by fuzzing: some PIL modes (e.g. 'LAB') raise their
            # own ValueError on .convert('L') rather than pyzbar ever
            # getting a chance to reject them cleanly. Normalise any such
            # native-library failure to our own exception type instead of
            # letting it escape as an arbitrary, uncatalogued exception.
            raise PyZbarValidationError(
                'PIL image: failed to convert mode {0!r} to L / extract '
                'pixel bytes: {1}: {2}'.format(
                    getattr(image, 'mode', '?'), type(exc).__name__, exc
                )
            ) from exc
    elif 'numpy.ndarray' in image_type or 'imageio.core.util' in image_type:
        # Different versions of imageio use a subclass of numpy.ndarray
        # called either imageio.core.util.Image or imageio.core.util.Array.
        #
        # Found by fuzzing: a 1-D (or 0-D) array makes
        # `height, width = image.shape[:2]` raise an uncaught ValueError
        # ("not enough values to unpack") rather than a clean
        # PyZbarValidationError. Require at least 2 dimensions up front.
        if not hasattr(image, 'shape') or len(image.shape) < 2:
            raise PyZbarValidationError(
                'numpy array: expected at least 2 dimensions, got '
                'shape={0!r}'.format(getattr(image, 'shape', None))
            )
        # Cheap (O(1)) - read dimensions and validate BEFORE the
        # potentially expensive .astype() / .tobytes() calls below. This
        # is the fix for the as_strided "lied shape, tiny backing buffer"
        # case found by fuzzing: without validating here first,
        # .tobytes() below would materialise the full (attacker-declared)
        # shape and could OOM before MAX_PIXELS was ever checked.
        height, width = image.shape[:2]
        _validate_dimensions(width, height, 'numpy array')
        try:
            if 3 == len(image.shape):
                # Take just the first channel
                image = image[:, :, 0]
            if 'uint8' != str(image.dtype):
                image = image.astype('uint8')
            try:
                pixels = image.tobytes()
            except AttributeError:
                # `numpy.ndarray.tobytes()` introduced in `numpy` 1.9.0 -
                # use the older `tostring` method.
                pixels = image.tostring()
        except PyZbarError:
            raise
        except Exception as exc:
            raise PyZbarValidationError(
                'numpy array: failed to extract pixel bytes (dtype={0!r} '
                'shape={1!r}): {2}: {3}'.format(
                    getattr(image, 'dtype', '?'),
                    getattr(image, 'shape', '?'),
                    type(exc).__name__, exc
                )
            ) from exc
    else:
        # image should be a tuple (pixels, width, height)
        pixels, width, height = image
        # NOTE: upstream had a dimension-consistency check here
        # (`len(pixels) % (width * height)`). It's been removed in favour
        # of the stricter, uniformly-applied checks below - the modulo
        # form (a) divides by zero on a zero width/height instead of
        # raising a clean validation error, and (b) accepts any integer
        # multiple of width*height as "fine", which the exact-match check
        # below closes.
        _validate_dimensions(width, height, 'tuple input')

    # --- Rho-9 hardening: buffer-level checks (width/height dimension
    # checks already ran above, before any expensive extraction) ---
    if len(pixels) == 0:
        raise PyZbarValidationError('Empty pixel buffer')
    if len(pixels) > MAX_RAW_PIXEL_BYTES:
        raise PyZbarValidationError(
            'Pixel buffer of {0} bytes exceeds MAX_RAW_PIXEL_BYTES '
            '({1})'.format(len(pixels), MAX_RAW_PIXEL_BYTES)
        )

    # Only 8bpp is supported (matches upstream). Rather than deriving a
    # bpp value from len(pixels) // (width * height) - which, as above,
    # silently accepts any integer multiple of the expected size - this
    # requires an *exact* match. Any other bit depth or any mismatched
    # buffer size is rejected here, uniformly, as a validation error.
    if len(pixels) != width * height:
        raise PyZbarValidationError(
            'Pixel buffer length {0} does not exactly match width x '
            'height ({1}) at the only supported bit depth (8bpp)'.format(
                len(pixels), width * height
            )
        )

    return pixels, width, height


def decode(image, symbols=None):
    """Decodes datamatrix barcodes in `image`.

    Args:
        image: `numpy.ndarray`, `PIL.Image` or tuple (pixels, width, height)
        symbols: iter(ZBarSymbol) the symbol types to decode; if `None`, uses
            `zbar`'s default behaviour, which is to decode all symbol types.

    Returns:
        :obj:`list` of :obj:`Decoded`: The values decoded from barcodes.

    Raises:
        PyZbarValidationError: If input fails Rho-9 sanity checks (see
            module docstring) before it would otherwise cross into
            libzbar, or if values read back out of libzbar during
            decoding fail those same sanity checks.
        PyZbarError: For zbar-reported decode errors (matches upstream
            behaviour).

    Note:
        This function still executes libzbar's native decode in-process.
        A memory-safety bug inside libzbar itself (not in this Python
        layer) could still crash the interpreter or hang indefinitely
        before returning control here - no amount of Python-level
        validation can fully close that off. Callers on an untrusted
        input path (e.g. images from chat messages) should prefer
        `pyzbar.safe.decode_isolated()`, which runs this function in a
        disposable worker process with a hard timeout.
    """
    pixels, width, height = _pixel_data(image)

    results = []
    with _image_scanner() as scanner:
        if symbols:
            # Disable all but the symbols of interest
            disable = set(ZBarSymbol).difference(symbols)
            for symbol in disable:
                zbar_image_scanner_set_config(
                    scanner, symbol, ZBarConfig.CFG_ENABLE, 0
                )
            # I think it likely that zbar will detect all symbol types by
            # default, in which case enabling the types of interest is
            # redundant but it seems sensible to be over-cautious and enable
            # them.
            for symbol in symbols:
                zbar_image_scanner_set_config(
                    scanner, symbol, ZBarConfig.CFG_ENABLE, 1
                )
        with _image() as img:
            zbar_image_set_format(img, _FOURCC['L800'])
            zbar_image_set_size(img, width, height)
            zbar_image_set_data(img, cast(pixels, c_void_p), len(pixels), None)
            decoded = zbar_scan_image(scanner, img)
            if decoded < 0:
                raise PyZbarError('Unsupported image format')
            else:
                results.extend(_decode_symbols(_symbols_for_image(img)))

    return results
