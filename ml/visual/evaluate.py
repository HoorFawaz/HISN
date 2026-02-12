"""Precision and recall of the visual match on its own (Phase 11).

Positives are pages that copy an official site; negatives are other sites.
Each screenshot is hashed and counted as a match when its closest official
reference is within the distance limit (``HISN_VISUAL_MAX_DISTANCE``).

- **Negatives** (required): screenshots of ordinary sites, for example from
  ``python -m ml.visual.capture --out data/visual_eval/negatives <names>``.
  Never include the official sites themselves.
- **Positives**: real screenshots of impersonation pages in ``--positives``.
  Without them, synthetic clones are made from each reference screenshot
  (re-compressed, shifted, resized, a cookie banner, a changed corner,
  darker, zoomed), which is the best case: a kit that copies the page as it
  is. Real kits change more, so read synthetic recall as an upper bound.

Run from the project root::

    python -m ml.visual.evaluate --negatives data/visual_eval/negatives
"""

from __future__ import annotations

import argparse
import io
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageEnhance

from ml.visual.compare import Reference, closest, header_hash, phash
from ml.visual.reference_hashes import load_references

DISTANCES = tuple(range(0, 25, 2))


@dataclass(frozen=True)
class Sample:
    name: str
    hash: int
    positive: bool
    brand: str | None = None  # expected brand for synthetic clones
    header: int | None = None  # hash of the top strip


@dataclass(frozen=True)
class Scores:
    max_distance: int
    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int
    wrong_brand: int  # positives matched, but to another brand

    @property
    def precision(self) -> float:
        flagged = self.true_positives + self.false_positives
        return self.true_positives / flagged if flagged else 0.0

    @property
    def recall(self) -> float:
        positives = self.true_positives + self.false_negatives
        return self.true_positives / positives if positives else 0.0


def _pad_to(image: Image.Image, size: tuple[int, int], offset: tuple[int, int]) -> Image.Image:
    canvas = Image.new("RGB", size, image.getpixel((0, 0)))
    canvas.paste(image, offset)
    return canvas


def _jpeg(image: Image.Image) -> Image.Image:
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", quality=60)
    return Image.open(io.BytesIO(buffer.getvalue())).convert("RGB")


def _shift(image: Image.Image) -> Image.Image:
    return _pad_to(image.crop((0, 0, image.width, image.height - 24)), image.size, (0, 24))


def _resize(image: Image.Image) -> Image.Image:
    small = image.resize((int(image.width * 0.94), int(image.height * 0.94)))
    return _pad_to(small, image.size, ((image.width - small.width) // 2, 0))


def _banner(image: Image.Image) -> Image.Image:
    copy = image.copy()
    ImageDraw.Draw(copy).rectangle((0, copy.height - 70, copy.width, copy.height), fill=(32, 32, 32))
    return copy


def _corner(image: Image.Image) -> Image.Image:
    copy = image.copy()
    ImageDraw.Draw(copy).rectangle((copy.width - 320, copy.height - 220, copy.width - 40, copy.height - 60), fill=(230, 230, 230))
    return copy


def _darker(image: Image.Image) -> Image.Image:
    return ImageEnhance.Brightness(image).enhance(0.85)


def _zoom(image: Image.Image) -> Image.Image:
    return image.crop((0, 0, int(image.width * 0.92), int(image.height * 0.92))).resize(image.size)


CLONES: dict[str, Callable[[Image.Image], Image.Image]] = {
    "jpeg": _jpeg,
    "shift": _shift,
    "resize": _resize,
    "banner": _banner,
    "corner": _corner,
    "darker": _darker,
    "zoom": _zoom,
}


def synthetic_clones(reference_dir: Path, references: Sequence[Reference]) -> list[Sample]:
    samples: list[Sample] = []
    for reference in references:
        path = reference_dir / reference.source
        if not path.exists():
            continue
        image = Image.open(path).convert("RGB")
        for name, clone in CLONES.items():
            cloned = clone(image)
            samples.append(Sample(f"{reference.source}:{name}", phash(cloned), True, reference.brand, header_hash(cloned)))
    return samples


def from_folder(folder: Path, positive: bool) -> list[Sample]:
    return [
        Sample(path.name, phash(data), positive, None, header_hash(data))
        for path in sorted(folder.glob("*.png"))
        for data in [path.read_bytes()]
    ]


def score(samples: Iterable[Sample], references: Sequence[Reference], max_distance: int) -> Scores:
    tp = fn = fp = tn = wrong = 0
    for sample in samples:
        match = closest(sample.hash, references, sample.header)
        flagged = match is not None and match.distance <= max_distance
        if sample.positive:
            tp += flagged
            fn += not flagged
            wrong += bool(flagged and sample.brand and match is not None and match.brand != sample.brand)
        else:
            fp += flagged
            tn += not flagged
    return Scores(max_distance, tp, fn, fp, tn, wrong)


def main(argv: Sequence[str] | None = None) -> int:
    from config import settings

    parser = argparse.ArgumentParser(prog="python -m ml.visual.evaluate", description=__doc__.split("\n")[0])
    parser.add_argument("--negatives", type=Path, required=True, help="folder of screenshots of other sites")
    parser.add_argument("--positives", type=Path, help="folder of real impersonation screenshots")
    args = parser.parse_args(argv)

    references = load_references(settings.references_dir)
    if not references:
        print("No references. Build them first: python -m ml.visual.reference_hashes", file=sys.stderr)
        return 1
    negatives = from_folder(args.negatives, positive=False)
    if args.positives:
        positives, kind = from_folder(args.positives, positive=True), "real"
    else:
        positives, kind = synthetic_clones(settings.references_dir, references), "synthetic clones (upper bound)"
    if not negatives or not positives:
        print("Need at least one positive and one negative screenshot.", file=sys.stderr)
        return 1

    samples = positives + negatives
    print(f"References: {len(references)} ({', '.join(sorted({r.brand for r in references}))})")
    print(f"Positives: {len(positives)} {kind}; negatives: {len(negatives)}")
    chosen = score(samples, references, settings.visual_max_distance)
    print()
    print(f"At HISN_VISUAL_MAX_DISTANCE={chosen.max_distance}:")
    print(f"  precision {chosen.precision:.3f}, recall {chosen.recall:.3f}")
    print(f"  matched clones {chosen.true_positives}, missed clones {chosen.false_negatives}")
    print(f"  ordinary sites flagged {chosen.false_positives} of {chosen.false_positives + chosen.true_negatives}")
    if chosen.wrong_brand:
        print(f"  clones matched to the wrong brand: {chosen.wrong_brand}")
    print()
    print("distance  precision  recall  sites flagged")
    for limit in DISTANCES:
        s = score(samples, references, limit)
        print(f"{limit:>8}  {s.precision:>9.3f}  {s.recall:>6.3f}  {s.false_positives:>4} of {s.false_positives + s.true_negatives}")
    print()
    print("Distances are bits out of 64; unrelated pages are usually around 32 apart.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
