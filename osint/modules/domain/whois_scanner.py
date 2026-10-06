import asyncio
import ipaddress
from datetime import date, datetime
from typing import Any

import asyncwhois
from ipwhois import IPWhois

from osint.core.logger import logger

WHOIS_TIMEOUT_SECONDS = 10
RDAP_DEPTH = 1

# output key -> asyncwhois parser key
DOMAIN_FIELDS = {
    "registrar": "registrar",
    "creation_date": "created",
    "expiration_date": "expires",
    "updated_date": "updated",
    "name_servers": "name_servers",
    "status": "status",
    "dnssec": "dnssec",
    "registrant_organization": "registrant_organization",
    "registrant_country": "registrant_country",
    "registrar_abuse_email": "registrar_abuse_email",
}


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _jsonable(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _failure(kind: str, exc: Exception) -> dict[str, Any]:
    return {"type": kind, "data": None, "error": f"{type(exc).__name__}: {exc}"}


def _lookup_ip_rdap(ip: str) -> dict[str, Any]:
    response = IPWhois(ip).lookup_rdap(depth=RDAP_DEPTH)
    network = response.get("network") or {}
    return {
        "asn": response.get("asn"),
        "asn_description": response.get("asn_description"),
        "asn_country_code": response.get("asn_country_code"),
        "asn_cidr": response.get("asn_cidr"),
        "network_name": network.get("name"),
        "network_cidr": network.get("cidr"),
    }


async def _whois_ip(ip: str) -> dict[str, Any]:
    try:
        # ipwhois is blocking; keep the event loop free for other lookups.
        data = await asyncio.to_thread(_lookup_ip_rdap, ip)
    except Exception as exc:  # noqa: BLE001 - ipwhois raises many unrelated types
        logger.debug("RDAP lookup failed for %s: %r", ip, exc)
        return _failure("ip", exc)
    return {"type": "ip", "data": data, "error": None}


async def _whois_domain(domain: str) -> dict[str, Any]:
    try:
        _, parsed = await asyncwhois.aio_whois(domain, timeout=WHOIS_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - asyncwhois raises many unrelated types
        logger.debug("WHOIS lookup failed for %s: %r", domain, exc)
        return _failure("domain", exc)
    data = {key: _jsonable(parsed.get(source)) for key, source in DOMAIN_FIELDS.items()}
    return {"type": "domain", "data": data, "error": None}


async def scan_whois(target: str) -> dict[str, Any]:
    """WHOIS for a domain, or RDAP (ASN/network) for an IP address."""
    if is_ip_address(target):
        return await _whois_ip(target)
    return await _whois_domain(target)
