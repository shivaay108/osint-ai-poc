import hashlib
import secrets
import string
from typing import Any
from urllib.parse import quote

import aiosmtplib
from email_validator import EmailNotValidError, ValidatedEmail, validate_email

from osint.core.dns import resolve_mx
from osint.core.exceptions import NetworkError
from osint.core.logger import logger
from osint.core.models import ModuleResult
from osint.modules.base import BaseOSINTModule

SMTP_PORT = 25
SMTP_TIMEOUT_SECONDS = 10
SMTP_ACCEPTED_CODES = (250, 251)
SMTP_PERMANENT_FAILURE_CLASS = 5
# Sent in EHLO instead of the default socket.getfqdn(), which reveals the machine name.
SMTP_HELO_HOSTNAME = "localhost"
CONTROL_LOCAL_PART_LENGTH = 20
HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/account/{}"
GRAVATAR_PROFILE_URL = "https://gravatar.com/{}"
NO_MX_MESSAGE = "No MX records found; the domain cannot receive email."
CATCH_ALL_DETAIL = (
    "Server accepts any address (catch-all); mailbox existence is unknown."
)
TEMPORARY_DETAIL = (
    "Server deferred the check with a temporary (4xx) reply, often greylisting; "
    "try again later."
)


def email_pivots(info: ValidatedEmail) -> dict[str, str]:
    gravatar_hash = hashlib.md5(info.normalized.lower().encode()).hexdigest()
    return {
        "username_candidate": info.local_part,
        "domain": info.domain,
        "breach_search": HIBP_ACCOUNT_URL.format(quote(info.normalized, safe="")),
        "gravatar_profile": GRAVATAR_PROFILE_URL.format(gravatar_hash),
    }


def _random_local_part() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(CONTROL_LOCAL_PART_LENGTH))


async def _recipient_status(client: aiosmtplib.SMTP, address: str) -> bool | None:
    """True if accepted, False if permanently refused (5xx), None if deferred (4xx)."""
    try:
        code, _ = await client.rcpt(address)
    except aiosmtplib.SMTPRecipientRefused as exc:
        return False if exc.code // 100 == SMTP_PERMANENT_FAILURE_CLASS else None
    return code in SMTP_ACCEPTED_CODES


def _interpret_probe(
    target: bool | None, control: bool | None
) -> tuple[bool | None, bool | None, str]:
    """(deliverable, catch_all, detail) from the target and control RCPT outcomes."""
    catch_all = False if control is False else None
    if control is True:
        return None, True, CATCH_ALL_DETAIL
    if target is False:
        return False, catch_all, "Mailbox rejected by server."
    if target is None or control is None:
        return None, catch_all, TEMPORARY_DETAIL
    return True, False, "Mailbox accepted by server."


async def _quit_quietly(client: aiosmtplib.SMTP) -> None:
    try:
        await client.quit()
    except (aiosmtplib.SMTPException, OSError) as exc:
        logger.debug("SMTP QUIT failed: %s", exc)


async def probe_mailbox(address: str, mx_host: str) -> dict[str, Any]:
    """Ask the MX whether it accepts ``address``, with a random address as a control.

    This contacts the target's mail server (an active check) and needs outbound
    port 25, which many ISPs block.
    """
    control = f"{_random_local_part()}@{address.rsplit('@', 1)[1]}"
    client = aiosmtplib.SMTP(
        hostname=mx_host,
        port=SMTP_PORT,
        timeout=SMTP_TIMEOUT_SECONDS,
        local_hostname=SMTP_HELO_HOSTNAME,
    )
    try:
        await client.connect()
        await client.ehlo()
        await client.mail("")
        target = await _recipient_status(client, address)
        control_status = await _recipient_status(client, control)
    except (aiosmtplib.SMTPException, OSError) as exc:
        client.close()
        return {
            "mx_host": mx_host,
            "deliverable": None,
            "catch_all": None,
            "detail": str(exc),
        }
    await _quit_quietly(client)

    deliverable, catch_all, detail = _interpret_probe(target, control_status)
    return {
        "mx_host": mx_host,
        "deliverable": deliverable,
        "catch_all": catch_all,
        "detail": detail,
    }


class EmailModule(BaseOSINTModule):
    name = "email"
    description = "Email validation, mail routing and pivots"

    async def run(
        self, target: str, *, smtp: bool = False, **kwargs: Any
    ) -> ModuleResult:
        try:
            info = validate_email(target.strip(), check_deliverability=False)
        except EmailNotValidError as exc:
            return ModuleResult(
                module_name=self.name,
                target=target,
                status="error",
                data={"syntax_valid": False},
                errors=[str(exc)],
            )

        base = {
            "syntax_valid": True,
            "normalized": info.normalized,
            "local_part": info.local_part,
            "domain": info.domain,
            "pivots": email_pivots(info),
            "smtp_check": None,
        }
        try:
            mx_records = await resolve_mx(info.domain)
        except NetworkError as exc:
            return self._warning(target, {**base, "mx_records": []}, str(exc))
        if not mx_records:
            return self._warning(target, {**base, "mx_records": []}, NO_MX_MESSAGE)

        smtp_check = (
            await probe_mailbox(info.normalized, mx_records[0]) if smtp else None
        )
        data = {**base, "mx_records": mx_records, "smtp_check": smtp_check}
        return ModuleResult(module_name=self.name, target=target, data=data)

    def _warning(self, target: str, data: dict[str, Any], message: str) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            target=target,
            status="warning",
            data=data,
            errors=[message],
        )
