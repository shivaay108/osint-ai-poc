import asyncio
from dataclasses import dataclass
from typing import Any

import httpx
from fake_useragent import UserAgent

from osint.config import Config, settings
from osint.core.exceptions import NetworkError, RateLimitError, ResponseTooLargeError
from osint.core.logger import logger

FALLBACK_USER_AGENT = "OSINT-Toolkit/0.2"
MAX_KEEPALIVE_CONNECTIONS = 20
MAX_CONNECTIONS = 100
HTTP_TOO_MANY_REQUESTS = 429


def _client_kwargs(timeout: float, proxy: str | None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "timeout": timeout,
        "limits": httpx.Limits(
            max_keepalive_connections=MAX_KEEPALIVE_CONNECTIONS,
            max_connections=MAX_CONNECTIONS,
        ),
        # HTTP/1.1 only: in testing, HTTP/2 caused protocol errors on several sites.
        "follow_redirects": True,
    }
    if proxy:
        kwargs["proxy"] = proxy
    return kwargs


@dataclass(frozen=True)
class BoundedResponse:
    """A response read with a size cap (see HttpClient.get_bounded)."""

    status_code: int
    headers: httpx.Headers
    content: bytes
    url: str


async def _read_capped(
    client: httpx.AsyncClient, url: str, max_bytes: int, kwargs: dict[str, Any]
) -> BoundedResponse:
    async with client.stream("GET", url, **kwargs) as response:
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > max_bytes:
            raise ResponseTooLargeError(
                f"{url} declares {declared} bytes (> {max_bytes})"
            )
        chunks: list[bytes] = []
        size = 0
        # Counted after decompression, so gzip bombs are caught too.
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise ResponseTooLargeError(f"{url} sent more than {max_bytes} bytes")
            chunks.append(chunk)
        return BoundedResponse(
            response.status_code, response.headers, b"".join(chunks), str(response.url)
        )


class HttpClient:
    """Async HTTP client with a concurrency cap, UA rotation and typed errors."""

    def __init__(self, config: Config = settings) -> None:
        self._max_concurrency = config.max_concurrency
        self._user_agents = UserAgent() if config.user_agent_rotation else None
        self._client: httpx.AsyncClient | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._defaults = config
        self.client_kwargs = _client_kwargs(config.timeout, config.proxy)

    @property
    def proxy(self) -> str | None:
        return self.client_kwargs.get("proxy")

    def configure(self, timeout: float | None = None, proxy: str | None = None) -> None:
        """Set this run's timeout/proxy; omitted values fall back to the defaults.

        Takes effect for the next client that is created.
        """
        self.client_kwargs = _client_kwargs(
            timeout if timeout is not None else self._defaults.timeout,
            proxy if proxy is not None else self._defaults.proxy,
        )
        self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        # httpx clients and semaphores are bound to one event loop; each CLI command
        # runs its own loop, so rebuild them whenever the loop changes.
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            self._client = httpx.AsyncClient(**self.client_kwargs)
            self._semaphore = asyncio.Semaphore(self._max_concurrency)
            self._loop = loop
        return self._client

    def get_headers(
        self, custom_headers: dict[str, str] | None = None
    ) -> dict[str, str]:
        user_agent = (
            self._user_agents.random if self._user_agents else FALLBACK_USER_AGENT
        )
        return {"User-Agent": user_agent, **(custom_headers or {})}

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        headers = self.get_headers(kwargs.pop("headers", None))
        client = self.client
        async with self._semaphore:
            try:
                logger.debug("HTTP %s %s", method, url)
                response = await client.request(method, url, headers=headers, **kwargs)
            except (httpx.RequestError, httpx.InvalidURL) as exc:
                logger.debug("HTTP %s %s failed: %s", method, url, exc)
                raise NetworkError(f"Request failed for {url}: {exc}") from exc

        if response.status_code == HTTP_TOO_MANY_REQUESTS:
            logger.warning("Rate limited by %s", url)
            raise RateLimitError(f"Rate limited by {url} (429)")
        return response

    async def get_bounded(
        self, url: str, max_bytes: int, deadline: float, **kwargs: Any
    ) -> BoundedResponse:
        """GET that never buffers more than ``max_bytes`` or runs past ``deadline`` s.

        For untrusted URLs (e.g. avatars named by a remote page).
        """
        headers = self.get_headers(kwargs.pop("headers", None))
        client = self.client
        async with self._semaphore:
            try:
                return await asyncio.wait_for(
                    _read_capped(
                        client, url, max_bytes, {"headers": headers, **kwargs}
                    ),
                    timeout=deadline,
                )
            except asyncio.TimeoutError as exc:
                raise NetworkError(
                    f"Download from {url} took longer than {deadline}s"
                ) from exc
            except (httpx.RequestError, httpx.InvalidURL) as exc:
                raise NetworkError(f"Request failed for {url}: {exc}") from exc

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None


# Shared client used by all modules.
http_client = HttpClient()
