import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from osint.core.exceptions import NetworkError
from osint.core.logger import logger

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA")
DEFAULT_DNS_TIMEOUT = 5.0
TIMEOUT_ERROR = "timeout"


def _make_resolver(timeout: float) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _rdata_to_text(rdata: Any) -> str:
    # TXT records arrive as several byte chunks; join them instead of keeping quotes.
    if hasattr(rdata, "strings"):
        return b"".join(rdata.strings).decode("utf-8", errors="replace")
    return str(rdata).rstrip(".")


async def _resolve_type(
    resolver: dns.asyncresolver.Resolver, name: str, rtype: str
) -> tuple[list[str], str | None]:
    """Resolve one record type. Returns (values, error) and never raises."""
    try:
        logger.debug("DNS resolve %s [%s]", name, rtype)
        answers = await resolver.resolve(name, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], None
    except dns.exception.Timeout:
        logger.debug("DNS timeout for %s [%s]", name, rtype)
        return [], TIMEOUT_ERROR
    except dns.exception.DNSException as exc:
        logger.debug("DNS error for %s [%s]: %s", name, rtype, exc)
        return [], str(exc) or type(exc).__name__

    if rtype == "MX":
        ordered = sorted(answers, key=lambda record: record.preference)
        return [str(record.exchange).rstrip(".") for record in ordered], None
    return [_rdata_to_text(record) for record in answers], None


def _first_with_prefix(values: list[str], prefix: str) -> str | None:
    return next((value for value in values if value.lower().startswith(prefix)), None)


async def query_all_dns_records(
    domain: str, timeout: float = DEFAULT_DNS_TIMEOUT
) -> dict[str, Any]:
    resolver = _make_resolver(timeout)
    outcomes = await asyncio.gather(
        *(_resolve_type(resolver, domain, rtype) for rtype in RECORD_TYPES)
    )
    records = {rtype: values for rtype, (values, _) in zip(RECORD_TYPES, outcomes)}
    errors = {
        rtype: error for rtype, (_, error) in zip(RECORD_TYPES, outcomes) if error
    }

    dmarc_values, _ = await _resolve_type(resolver, f"_dmarc.{domain}", "TXT")
    security = {
        "spf": _first_with_prefix(records["TXT"], "v=spf1"),
        "dmarc": _first_with_prefix(dmarc_values, "v=dmarc1"),
    }
    return {**records, "errors": errors, "security": security}


async def resolve_mx(domain: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> list[str]:
    values, error = await _resolve_type(_make_resolver(timeout), domain, "MX")
    if error == TIMEOUT_ERROR:
        raise NetworkError(f"DNS MX Timeout for {domain}")
    return values


async def reverse_lookup(ip: str, timeout: float = DEFAULT_DNS_TIMEOUT) -> list[str]:
    try:
        answers = await _make_resolver(timeout).resolve_address(ip)
    except dns.exception.DNSException as exc:
        logger.debug("Reverse DNS failed for %s: %s", ip, exc)
        return []
    return [str(record).rstrip(".") for record in answers]
