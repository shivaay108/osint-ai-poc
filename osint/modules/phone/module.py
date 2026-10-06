from typing import Any

from osint.core.exceptions import ValidationError
from osint.core.models import ConfidenceTier, ModuleResult
from osint.modules.base import BaseOSINTModule
from osint.modules.phone.phone_osint import analyze_phone_core
from osint.modules.phone.pivots import (
    messaging_links,
    number_formats,
    number_hashes,
    search_dorks,
)

DEFAULT_REGION = "US"
CARRIER_NOTE = (
    "Carrier is the network the number range was originally allocated to; "
    "the number may since have been ported."
)


class PhoneModule(BaseOSINTModule):
    name = "phone"
    description = "Phone number analysis and investigator pivots"

    async def run(
        self, target: str, *, region: str = DEFAULT_REGION, **kwargs: Any
    ) -> ModuleResult:
        try:
            core = analyze_phone_core(target, default_region=region.upper())
        except ValidationError as exc:
            return ModuleResult(
                module_name=self.name, target=target, status="error", errors=[str(exc)]
            )

        e164 = core["e164"]
        formats = number_formats(e164)
        data = {
            "core": {
                **core,
                "tier": ConfidenceTier.VERIFIED,
                "carrier_note": CARRIER_NOTE,
            },
            "pivots": {
                "formats": formats,
                "search": search_dorks(formats),
                "messaging": messaging_links(e164),
            },
            "hashes": number_hashes(e164),
        }
        return ModuleResult(module_name=self.name, target=target, data=data)
