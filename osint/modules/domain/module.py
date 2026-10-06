import asyncio
import re
from typing import Any
from urllib.parse import urlparse

from osint.core.dns import query_all_dns_records, reverse_lookup
from osint.core.models import ModuleResult
from osint.modules.base import BaseOSINTModule
from osint.modules.domain.ct_logs import scan_ct_logs
from osint.modules.domain.whois_scanner import is_ip_address, scan_whois

DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
INVALID_TARGET_MESSAGE = "Target is not a valid domain name, URL or IP address."


def normalize_domain(raw: str) -> str | None:
    """Lower-cased ASCII hostname from a domain or URL, or None if it isn't one."""
    candidate = raw.strip()
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or ""
    candidate = candidate.rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return candidate if DOMAIN_PATTERN.fullmatch(candidate) else None


def _section(outcome: Any) -> Any:
    if isinstance(outcome, BaseException):
        return {"error": str(outcome) or type(outcome).__name__}
    return outcome


def _section_error(name: str, section: Any) -> str | None:
    if isinstance(section, dict) and section.get("error"):
        return f"{name}: {section['error']}"
    return None


def _collect(outcomes: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Turn gather() outcomes into data sections plus a list of per-section errors."""
    sections = {name: _section(outcome) for name, outcome in outcomes.items()}
    errors = [
        message
        for name, section in sections.items()
        if (message := _section_error(name, section)) is not None
    ]
    return sections, errors


class DomainModule(BaseOSINTModule):
    name = "domain"
    description = "Domain and IP address reconnaissance"

    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        candidate = target.strip()
        if is_ip_address(candidate):
            return await self._investigate_ip(target, candidate)
        domain = normalize_domain(candidate)
        if domain is None:
            return ModuleResult(
                module_name=self.name,
                target=target,
                status="error",
                errors=[INVALID_TARGET_MESSAGE],
            )
        return await self._investigate_domain(target, domain)

    async def _investigate_ip(self, target: str, ip: str) -> ModuleResult:
        outcomes = await asyncio.gather(
            reverse_lookup(ip), scan_whois(ip), return_exceptions=True
        )
        sections, errors = _collect(dict(zip(("reverse_dns", "whois"), outcomes)))
        return self._result(target, {"target_type": "ip", "ip": ip, **sections}, errors)

    async def _investigate_domain(self, target: str, domain: str) -> ModuleResult:
        outcomes = await asyncio.gather(
            query_all_dns_records(domain),
            scan_whois(domain),
            scan_ct_logs(domain),
            return_exceptions=True,
        )
        sections, errors = _collect(dict(zip(("dns", "whois", "ct_logs"), outcomes)))
        return self._result(
            target, {"target_type": "domain", "domain": domain, **sections}, errors
        )

    def _result(
        self, target: str, data: dict[str, Any], errors: list[str]
    ) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            target=target,
            status="warning" if errors else "success",
            data=data,
            errors=errors,
        )
