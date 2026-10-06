"""Investigator pivots for a phone number: spellings, search links and hashes.

Nothing here contacts the network. Messaging links are for manual checks only:
wa.me and t.me answer identically for registered and unregistered numbers, so an
automated probe cannot tell them apart.
"""

import hashlib
from urllib.parse import urlencode

import phonenumbers
from phonenumbers import PhoneNumberFormat

from osint.core.models import ConfidenceTier

NANP_COUNTRY_CODE = 1
NANP_NATIONAL_LENGTH = 10
SEARCH_ENGINES = {
    "google": "https://www.google.com/search",
    "bing": "https://www.bing.com/search",
    "duckduckgo": "https://duckduckgo.com/",
}
MANUAL_CHECK_NOTE = (
    "Open manually. These links resolve the same way for unregistered numbers, "
    "so registration cannot be confirmed automatically."
)


def _nanp_variants(country_code: int, digits: str) -> list[str]:
    if country_code != NANP_COUNTRY_CODE or len(digits) != NANP_NATIONAL_LENGTH:
        return []
    area, exchange, line = digits[:3], digits[3:6], digits[6:]
    return [
        f"{area}-{exchange}-{line}",
        f"{area}.{exchange}.{line}",
        f"({area}) {exchange}-{line}",
    ]


def number_formats(e164: str) -> list[str]:
    """Spellings the number is likely to appear under on the web, most specific first."""
    parsed = phonenumbers.parse(e164)
    digits = phonenumbers.national_significant_number(parsed)
    candidates = [
        e164,
        e164.lstrip("+"),
        phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL),
        phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL),
        digits,
        *_nanp_variants(parsed.country_code, digits),
    ]
    return list(dict.fromkeys(candidates))


def search_dorks(formats: list[str]) -> dict[str, str]:
    query = " OR ".join(f'"{fmt}"' for fmt in formats)
    return {
        name: f"{base}?{urlencode({'q': query})}"
        for name, base in SEARCH_ENGINES.items()
    }


def messaging_links(e164: str) -> dict[str, dict[str, str]]:
    digits = e164.lstrip("+")
    links = {
        "whatsapp": f"https://wa.me/{digits}",
        "telegram": f"https://t.me/+{digits}",
    }
    return {
        app: {
            "url": url,
            "status": "manual_check",
            "tier": ConfidenceTier.UNVERIFIED,
            "note": MANUAL_CHECK_NOTE,
        }
        for app, url in links.items()
    }


def number_hashes(e164: str) -> dict[str, dict[str, str]]:
    """Hashes of common spellings, for searching breach and leak datasets."""

    def _digests(value: str) -> dict[str, str]:
        raw = value.encode()
        return {
            "md5": hashlib.md5(raw).hexdigest(),
            "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    return {variant: _digests(variant) for variant in (e164, e164.lstrip("+"))}
