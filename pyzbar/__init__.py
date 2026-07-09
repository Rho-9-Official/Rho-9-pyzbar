"""Read one-dimensional barcodes and QR codes from Python 2 and 3.

Rho-9 hardened fork.
Based on upstream pyzbar 0.1.9 (https://github.com/NaturalHistoryMuseum/pyzbar).

This fork adds defense-in-depth around the ctypes boundary into libzbar:
  - input validation / sanity caps before any value crosses into C
    (dimensions, pixel buffer size, per-symbol data length, polygon
    point count, total symbol count)
  - a process-isolated decode_isolated() in pyzbar.safe for callers who
    cannot tolerate an in-process crash or hang, since a memory-safety
    bug inside libzbar itself cannot be caught by any amount of Python
    try/except -- only process isolation can contain it.

See pyzbar/SECURITY_NOTES.md for the full rationale and threat model.
"""

__version__ = '0.1.9-rho9.1'
