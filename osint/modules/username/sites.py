"""WhatsMyName site definitions.

Data: https://github.com/WebBreacher/WhatsMyName (CC BY-SA 4.0, Micah Hoffman et al.).
A snapshot ships in ``data/wmn-data.json``; ``osint sites update`` refreshes a copy
in the user cache, which takes precedence when present and valid.
"""

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError

from osint.core.exceptions import ValidationError
from osint.core.http import http_client
from osint.core.logger import logger

WMN_DATA_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
)
BUNDLED_SITES_PATH = Path(__file__).parent / "data" / "wmn-data.json.gz"
CACHE_DIR_NAME = "osint-toolkit"
CACHE_FILENAME = "wmn-data.json"
NSFW_CATEGORY = "xx NSFW xx"
ACCOUNT_PLACEHOLDER = "{account}"
HTTP_OK = 200
UPDATE_TIMEOUT_SECONDS = 30.0


class Site(BaseModel):
    """One site definition: how to probe it and what found/missing pages look like."""

    model_config = ConfigDict(frozen=True)

    name: str
    uri_check: str
    uri_pretty: str | None = None
    e_code: int
    e_string: str
    m_code: int
    m_string: str
    category: str = Field(alias="cat")
    known: tuple[str, ...] = ()
    post_body: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    strip_bad_char: str = ""
    valid: bool = True
    protection: tuple[str, ...] = ()

    def account_name(self, username: str) -> str:
        return "".join(ch for ch in username if ch not in self.strip_bad_char)

    def _fill(self, template: str, username: str) -> str:
        return template.replace(
            ACCOUNT_PLACEHOLDER, quote(self.account_name(username), safe="")
        )

    def check_url(self, username: str) -> str:
        return self._fill(self.uri_check, username)

    def profile_url(self, username: str) -> str:
        return self._fill(self.uri_pretty or self.uri_check, username)

    def request_body(self, username: str) -> str | None:
        if self.post_body is None:
            return None
        return self.post_body.replace(ACCOUNT_PLACEHOLDER, self.account_name(username))


def _parse_site(entry: Any) -> Site | None:
    try:
        return Site.model_validate(entry)
    except PydanticValidationError as exc:
        name = entry.get("name") if isinstance(entry, dict) else entry
        logger.debug("Skipping malformed site entry %r: %s", name, exc)
        return None


def parse_sites(document: Any) -> list[Site]:
    """Validate a WhatsMyName document, dropping malformed or retired entries."""
    if not isinstance(document, dict) or not isinstance(document.get("sites"), list):
        raise ValidationError(
            "Site list must be a WhatsMyName document with a 'sites' array."
        )
    parsed = (_parse_site(entry) for entry in document["sites"])
    return [site for site in parsed if site is not None and site.valid]


def user_sites_path() -> Path:
    cache_home = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(cache_home) / CACHE_DIR_NAME / CACHE_FILENAME


def _read_document(path: Path) -> Any:
    try:
        if path.suffix == ".gz":
            import gzip
            content = gzip.decompress(path.read_bytes()).decode("utf-8")
        else:
            content = path.read_text(encoding="utf-8")
        return json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"Cannot read site list {path}: {exc}") from exc


def _load_default_sites() -> list[Site]:
    cached = user_sites_path()
    if cached.is_file():
        try:
            return parse_sites(_read_document(cached))
        except ValidationError as exc:
            logger.warning("Ignoring unreadable site cache %s: %s", cached, exc)
    return parse_sites(_read_document(BUNDLED_SITES_PATH))


def load_sites(path: Path | None = None, include_nsfw: bool = False) -> list[Site]:
    sites = parse_sites(_read_document(path)) if path else _load_default_sites()
    return [site for site in sites if include_nsfw or site.category != NSFW_CATEGORY]


async def update_sites(dest: Path | None = None) -> int:
    """Download the latest WhatsMyName list, validate it, and save it atomically."""
    target = dest or user_sites_path()
    response = await http_client.get(WMN_DATA_URL, timeout=UPDATE_TIMEOUT_SECONDS)
    if response.status_code != HTTP_OK:
        raise ValidationError(
            f"Site list download failed with HTTP {response.status_code}."
        )
    try:
        document = response.json()
    except ValueError as exc:
        raise ValidationError("Downloaded site list is not valid JSON.") from exc

    sites = parse_sites(document)
    if not sites:
        raise ValidationError("Downloaded site list contains no usable sites.")

    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.with_suffix(".tmp")
    staging.write_text(json.dumps(document), encoding="utf-8")
    staging.replace(target)
    return len(sites)
