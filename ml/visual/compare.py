"""Perceptual hash (pHash) of a screenshot, and the closest official reference.

A pHash keeps the coarse look of a page (where the big light and dark areas
are) and drops small details, so two screenshots of the same page give nearly
the same 64 bits even when a date, a banner or the image compression differ.
Phishing kits copy the official page, so a cloned login page lands within a
few bits of the original, while an unrelated page differs in about half of
them (around 32).

How the hash is made (the classic DCT pHash):

1. Greyscale, shrunk to 32 x 32 pixels.
2. 2-D discrete cosine transform (DCT); the top-left 8 x 8 block holds the
   lowest frequencies, which describe the overall layout.
3. One bit per coefficient: above the block's median or not.

Two hashes are compared by Hamming distance: the number of differing bits.

Each screenshot gets two hashes: one of the whole page, and one of its top
strip (logo and menu, ``header_hash``). Home pages carry a rotating banner
that changes the whole-page hash by as much as an unrelated page would, while
the header stays put and phishing kits copy it. A screenshot matches a
reference when either hash is close.
"""

from __future__ import annotations

import io
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from PIL import Image

HASH_BITS = 64
_HASH_SIDE = 8  # 8 x 8 low frequencies = 64 bits
_SAMPLE_SIDE = 32  # the image is shrunk to this before the DCT
HEADER_HEIGHT = 160  # pixels of the top strip that make the header hash


@dataclass(frozen=True)
class Reference:
    """The hash of one screenshot of an official site."""

    brand: str  # as in data/lists/brands.txt, e.g. "alrajhi"
    source: str  # the official page or the file it came from
    hash: int
    header: int | None = None  # hash of the top strip; None if it was blank


@dataclass(frozen=True)
class Match:
    """The closest reference to a screenshot and how far it is."""

    brand: str
    source: str
    distance: int  # differing bits, 0 to 64
    part: str = "page"  # which hash was closer: "page" or "header"


@lru_cache(maxsize=1)
def _dct_matrix(size: int = _SAMPLE_SIDE) -> np.ndarray:
    """Orthonormal DCT-II matrix: ``M @ x @ M.T`` is the 2-D DCT of ``x``."""
    k = np.arange(size)[:, None]
    n = np.arange(size)[None, :]
    matrix = np.cos(np.pi * (2 * n + 1) * k / (2 * size)) * np.sqrt(2 / size)
    matrix[0, :] /= np.sqrt(2)
    return matrix


def phash(image: bytes | Image.Image) -> int:
    """64-bit perceptual hash of a PNG/JPEG (bytes) or an opened image."""
    if isinstance(image, bytes):
        image = Image.open(io.BytesIO(image))
    small = image.convert("L").resize((_SAMPLE_SIDE, _SAMPLE_SIDE), Image.Resampling.LANCZOS)
    pixels = np.asarray(small, dtype=np.float64)
    matrix = _dct_matrix()
    low = (matrix @ pixels @ matrix.T)[:_HASH_SIDE, :_HASH_SIDE]
    bits = (low > np.median(low)).flatten()
    value = 0
    for bit in bits:
        value = (value << 1) | int(bit)
    return value


EMPTY_SHARE = 0.95  # error and bot-check pages measure 0.99; real pages, even dark ones, stay under 0.8


def empty_share(image: bytes | Image.Image) -> float:
    """The share of pixels within 8 grey levels of the most common one (0 to 1).

    A page that is nearly all one colour is not a page to compare: it is a
    blank page, an error ("The requested URL was rejected"), or a bot check
    (a captcha). Two such pages hash almost the same whatever site they came
    from, so they must never be a reference and never count as a match.
    """
    if isinstance(image, bytes):
        image = Image.open(io.BytesIO(image))
    grey = np.asarray(image.convert("L"))
    counts = np.bincount(grey.ravel(), minlength=256)
    peak = int(counts.argmax())
    return float(counts[max(0, peak - 8) : peak + 9].sum() / grey.size)


def is_nearly_empty(image: bytes | Image.Image) -> bool:
    return empty_share(image) >= EMPTY_SHARE


def header_hash(image: bytes | Image.Image) -> int | None:
    """Hash of the top ``HEADER_HEIGHT`` pixels, or None if that strip is blank.

    A blank strip says nothing about the site (every blank strip hashes the
    same), so it is never compared.
    """
    if isinstance(image, bytes):
        image = Image.open(io.BytesIO(image))
    strip = image.crop((0, 0, image.width, min(HEADER_HEIGHT, image.height)))
    return None if is_nearly_empty(strip) else phash(strip)


def to_hex(value: int) -> str:
    return f"{value:016x}"


def from_hex(text: str) -> int:
    value = int(text, 16)
    if not 0 <= value < 1 << HASH_BITS:
        raise ValueError(f"not a 64-bit hash: {text!r}")
    return value


def distance(a: int, b: int) -> int:
    """Hamming distance: how many of the 64 bits differ."""
    return (a ^ b).bit_count()


def closest(value: int, references: Iterable[Reference], header: int | None = None) -> Match | None:
    """The reference nearest to ``value`` (or, if given, to its ``header`` hash), or None if there are none."""
    best: Match | None = None
    for reference in references:
        d, part = distance(value, reference.hash), "page"
        if header is not None and reference.header is not None:
            d_header = distance(header, reference.header)
            if d_header < d:
                d, part = d_header, "header"
        if best is None or d < best.distance:
            best = Match(reference.brand, reference.source, d, part)
    return best


def looks_like(value: int, references: Iterable[Reference], max_distance: int, header: int | None = None) -> Match | None:
    """The closest reference if it is within ``max_distance`` bits, else None."""
    match = closest(value, references, header)
    return match if match is not None and match.distance <= max_distance else None
