import asyncio
import secrets
import string
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from osint.core.exceptions import NetworkError
from osint.core.http import http_client
from osint.core.logger import logger
from osint.core.models import Evidence
from osint.modules.username.profile import extract_profile
from osint.modules.username.sites import Site

# Fixed desktop-browser headers: WhatsMyName markers are tuned against desktop pages,
# a random (possibly mobile) UA can change the page, and requests without Accept
# headers are refused by more sites.
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
CANARY_LENGTH = 14
UNRELIABLE_DETAIL = "Site also reports a random username as existing; result ignored."
CANARY_INCONCLUSIVE_DETAIL = "Control check with a random username was inconclusive."


class SiteStatus(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    UNRELIABLE = "unreliable"


@dataclass(frozen=True)
class SiteResult:
    site: str
    category: str
    url: str
    status: SiteStatus
    http_status: int | None
    detail: str | None
    verified: bool = False
    evidence: Evidence | None = None
    profile: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "category": self.category,
            "url": self.url,
            "status": self.status.value,
            "http_status": self.http_status,
            "detail": self.detail,
            "evidence_sha256": self.evidence.sha256 if self.evidence else None,
            "profile": self.profile,
        }


def classify(site: Site, status_code: int, body: str) -> SiteStatus:
    """Apply WhatsMyName rules: both the status code and the page marker must agree."""
    exists = status_code == site.e_code and site.e_string in body
    missing = status_code == site.m_code and site.m_string in body
    if exists and not missing:
        return SiteStatus.FOUND
    if missing and not exists:
        return SiteStatus.NOT_FOUND
    return SiteStatus.INCONCLUSIVE


def make_canary() -> str:
    """A random handle that almost certainly has no account anywhere."""
    alphabet = string.ascii_lowercase + string.digits
    tail = "".join(secrets.choice(alphabet) for _ in range(CANARY_LENGTH - 1))
    return secrets.choice(string.ascii_lowercase) + tail


def _inconclusive_detail(site: Site, status_code: int) -> str:
    detail = f"HTTP {status_code}; page matched neither the profile nor the not-found marker."
    if site.protection:
        detail += f" Site uses bot protection ({', '.join(site.protection)})."
    return detail


async def check_site(
    site: Site, username: str, capture_evidence: bool = False
) -> SiteResult:
    body = site.request_body(username)
    url = site.profile_url(username)
    check_url = site.check_url(username)
    try:
        response = await http_client.request(
            "POST" if body is not None else "GET",
            check_url,
            headers={**BROWSER_HEADERS, **site.headers},
            content=body,
            follow_redirects=False,
        )
    except NetworkError as exc:
        return SiteResult(
            site.name, site.category, url, SiteStatus.ERROR, None, str(exc)
        )

    status = classify(site, response.status_code, response.text)
    if status is not SiteStatus.FOUND:
        detail = (
            _inconclusive_detail(site, response.status_code)
            if status is SiteStatus.INCONCLUSIVE
            else None
        )
        return SiteResult(
            site.name, site.category, url, status, response.status_code, detail
        )

    content_type = response.headers.get("content-type")
    # Keep the exact page behind every hit: profiles get edited or deleted later.
    evidence = (
        Evidence.capture(
            check_url, response.status_code, content_type, response.content
        )
        if capture_evidence
        else None
    )
    return SiteResult(
        site.name,
        site.category,
        url,
        status,
        response.status_code,
        None,
        evidence=evidence,
        profile=_read_profile(response.text, content_type, check_url, username),
    )


def _read_profile(
    text: str, content_type: str | None, page_url: str, username: str
) -> dict[str, Any] | None:
    try:
        return extract_profile(text, content_type, page_url, username)
    except Exception as exc:  # noqa: BLE001 - a parsing problem must not lose the hit
        logger.debug("Profile extraction failed for %s: %r", page_url, exc)
        return None


async def _safe_check(
    site: Site, username: str, capture_evidence: bool = False
) -> SiteResult:
    """Never let one broken site definition abort the whole scan."""
    try:
        return await check_site(site, username, capture_evidence)
    except Exception as exc:  # noqa: BLE001 - reported per site, not swallowed
        logger.warning("Unexpected error checking %s: %r", site.name, exc)
        return SiteResult(
            site.name,
            site.category,
            site.profile_url(username),
            SiteStatus.ERROR,
            None,
            f"{type(exc).__name__}: {exc}",
        )


def _apply_canary(hit: SiteResult, canary: SiteResult) -> SiteResult:
    if canary.status is SiteStatus.FOUND:
        return replace(hit, status=SiteStatus.UNRELIABLE, detail=UNRELIABLE_DETAIL)
    if canary.status is SiteStatus.NOT_FOUND:
        return replace(hit, verified=True)
    return replace(hit, detail=CANARY_INCONCLUSIVE_DETAIL)


async def _verify_hits(
    results: list[SiteResult], sites: Sequence[Site]
) -> list[SiteResult]:
    """Re-check every hit with a random username; drop sites that say yes to anything."""
    canary = make_canary()
    hit_indexes = [
        i for i, result in enumerate(results) if result.status is SiteStatus.FOUND
    ]
    canary_results = await asyncio.gather(
        *(_safe_check(sites[i], canary) for i in hit_indexes)
    )
    canary_by_index = dict(zip(hit_indexes, canary_results))
    return [
        _apply_canary(result, canary_by_index[i]) if i in canary_by_index else result
        for i, result in enumerate(results)
    ]


async def scan_username(
    username: str,
    sites: Sequence[Site],
    verify: bool = True,
    on_progress: Callable[[], None] | None = None,
    capture_evidence: bool = False,
) -> list[SiteResult]:
    async def _check_and_report(site: Site) -> SiteResult:
        try:
            return await _safe_check(site, username, capture_evidence)
        finally:
            if on_progress is not None:
                on_progress()

    results = list(await asyncio.gather(*(_check_and_report(site) for site in sites)))
    return await _verify_hits(results, sites) if verify else results
