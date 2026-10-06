from collections.abc import Iterable
from typing import Any

from osint.core.exceptions import NetworkError
from osint.core.http import http_client

CRT_SH_URL = "https://crt.sh/"
CT_TIMEOUT_SECONDS = 30.0
HTTP_OK = 200


def extract_subdomains(entries: Iterable[dict[str, Any]], domain: str) -> list[str]:
    """Unique, sorted subdomains of ``domain`` from crt.sh certificate entries."""
    suffix = "." + domain.lower()
    names = (
        name.strip().lower().removeprefix("*.")
        for entry in entries
        for name in str(entry.get("name_value") or "").splitlines()
    )
    return sorted({name for name in names if name.endswith(suffix) and "@" not in name})


async def scan_ct_logs(domain: str) -> dict[str, Any]:
    """Find subdomains in Certificate Transparency logs via crt.sh."""
    try:
        response = await http_client.get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=CT_TIMEOUT_SECONDS,
        )
    except NetworkError as exc:
        return {"subdomains": [], "error": str(exc)}

    if response.status_code != HTTP_OK:
        return {
            "subdomains": [],
            "error": f"crt.sh returned HTTP {response.status_code}",
        }
    try:
        entries = response.json()
    except ValueError:
        return {"subdomains": [], "error": "crt.sh returned invalid JSON"}
    if not isinstance(entries, list):
        return {"subdomains": [], "error": "crt.sh returned an unexpected response"}

    records = (entry for entry in entries if isinstance(entry, dict))
    return {"subdomains": extract_subdomains(records, domain), "error": None}
