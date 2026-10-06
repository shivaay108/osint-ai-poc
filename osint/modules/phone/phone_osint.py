from typing import Any, Dict

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone

from osint.core.exceptions import ValidationError
from osint.core.logger import logger


def analyze_phone_core(raw_number: str, default_region: str = "US") -> Dict[str, Any]:
    """
    Phase 1: Core Number Analysis using phonenumbers library.
    Guaranteed accurate (✅ VERIFIED tier)
    """
    try:
        logger.debug(f"Parsing phone number: {raw_number}")
        parsed = phonenumbers.parse(raw_number, default_region)
    except phonenumbers.NumberParseException as e:
        logger.warning(f"Phone parse error for {raw_number}: {e}")
        raise ValidationError(f"Invalid phone number format: {str(e)}") from e

    is_valid = phonenumbers.is_valid_number(parsed)
    if not is_valid:
        logger.warning(f"Phone number parsed but invalid: {raw_number}")
        raise ValidationError(f"Phone number is parsed but invalid or unassigned.")

    # Line Type Mapping
    type_code = phonenumbers.number_type(parsed)
    type_labels = {
        PhoneNumberType.FIXED_LINE: "Fixed Line (Landline)",
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        PhoneNumberType.TOLL_FREE: "Toll-Free",
        PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        PhoneNumberType.SHARED_COST: "Shared Cost",
        PhoneNumberType.VOIP: "VoIP (Virtual Number)",
        PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "Universal Access Number (UAN)",
        PhoneNumberType.UNKNOWN: "Unknown",
    }

    return {
        "valid": True,
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "national": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        "rfc3966": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.RFC3966
        ),
        "country_code": f"+{parsed.country_code}",
        "region_code": phonenumbers.region_code_for_number(parsed),
        "number_type": type_labels.get(type_code, "Unknown"),
        "carrier": carrier.name_for_number(parsed, "en") or "Not Available / Ported",
        "geographic_location": geocoder.description_for_number(parsed, "en")
        or "Not Available",
        "timezones": list(timezone.time_zones_for_number(parsed)),
    }
