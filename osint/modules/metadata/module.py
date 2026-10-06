import asyncio
import hashlib
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import exifread
from PIL import Image

from osint.core.logger import logger
from osint.core.models import ModuleResult
from osint.modules.base import BaseOSINTModule

EXCLUDED_TAGS = frozenset(
    {"JPEGThumbnail", "TIFFThumbnail", "Filename", "EXIF MakerNote"}
)
MINUTES_PER_DEGREE = 60.0
SECONDS_PER_DEGREE = 3600.0
COORDINATE_DECIMALS = 7
HASH_CHUNK_BYTES = 1 << 20
FILE_TIMES_NOTE = (
    "Filesystem times describe this copy of the file, not when the photo was taken; "
    "see EXIF DateTimeOriginal for capture time."
)

# exifread logs "no EXIF data" warnings straight to stderr; they are not errors here.
logging.getLogger("exifread").setLevel(logging.ERROR)


def _ratio_to_float(value: Any) -> float | None:
    num, den = getattr(value, "num", None), getattr(value, "den", None)
    if num is not None and den is not None:
        return None if den == 0 else float(num) / float(den)
    try:
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _dms_to_degrees(tag: Any) -> float | None:
    values = list(getattr(tag, "values", None) or [])
    if len(values) != 3:
        return None
    parts = [_ratio_to_float(value) for value in values]
    if any(part is None for part in parts):
        return None
    degrees, minutes, seconds = parts
    return degrees + minutes / MINUTES_PER_DEGREE + seconds / SECONDS_PER_DEGREE


def _hemisphere(tags: Mapping[str, Any], key: str, default: str) -> str:
    tag = tags.get(key)
    ref = getattr(tag, "values", default) if tag is not None else default
    return (str(ref).strip().upper() or default)[0]


def extract_gps(tags: Mapping[str, Any]) -> dict[str, Any] | None:
    """Decimal coordinates from exifread GPS tags, or None if absent or corrupt."""
    lat = _dms_to_degrees(tags.get("GPS GPSLatitude"))
    lon = _dms_to_degrees(tags.get("GPS GPSLongitude"))
    if lat is None or lon is None:
        return None
    lat = round(
        -lat if _hemisphere(tags, "GPS GPSLatitudeRef", "N") == "S" else lat,
        COORDINATE_DECIMALS,
    )
    lon = round(
        -lon if _hemisphere(tags, "GPS GPSLongitudeRef", "E") == "W" else lon,
        COORDINATE_DECIMALS,
    )
    return {
        "latitude": lat,
        "longitude": lon,
        "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
        "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
    }


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_info(path: Path) -> dict[str, Any]:
    stat = path.stat()
    birth_time = getattr(stat, "st_birthtime", None)
    return {
        "name": path.name,
        "size_bytes": stat.st_size,
        "sha256": _sha256(path),
        "created": _iso(birth_time) if birth_time else None,
        "modified": _iso(stat.st_mtime),
        "note": FILE_TIMES_NOTE,
    }


def _image_info(path: Path) -> dict[str, Any]:
    try:
        with Image.open(path) as image:
            return {
                "format": image.format,
                "mode": image.mode,
                "size": list(image.size),
            }
    except (OSError, ValueError) as exc:
        return {"error": str(exc)}


def _extract_metadata(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        tags = exifread.process_file(handle, details=False)
    data = {
        "file_info": _file_info(path),
        "image_info": _image_info(path),
        "exif": {
            tag: str(value) for tag, value in tags.items() if tag not in EXCLUDED_TAGS
        },
    }
    gps = extract_gps(tags)
    return {**data, "gps": gps} if gps else data


class MetadataModule(BaseOSINTModule):
    name = "metadata"
    description = "Image EXIF, GPS and file fingerprint extraction"

    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        path = Path(target).expanduser()
        if not path.is_file():
            return self._error(
                target, f"File not found or not a regular file: {target}"
            )
        try:
            data = await asyncio.to_thread(_extract_metadata, path)
        except (
            Exception
        ) as exc:  # noqa: BLE001 - exifread raises many types on corrupt files
            logger.debug("Metadata extraction failed for %s: %r", path, exc)
            return self._error(
                target, f"Could not read metadata: {type(exc).__name__}: {exc}"
            )
        return ModuleResult(module_name=self.name, target=target, data=data)

    def _error(self, target: str, message: str) -> ModuleResult:
        return ModuleResult(
            module_name=self.name, target=target, status="error", errors=[message]
        )
