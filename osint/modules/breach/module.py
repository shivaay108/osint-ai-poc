from typing import Any
import httpx
from urllib.parse import quote

from osint.modules.base import BaseOSINTModule
from osint.core.models import ModuleResult
from osint.core.http import http_client
from osint.config import settings

class BreachModule(BaseOSINTModule):
    name = "breach"
    
    async def run(self, target: str, **options: Any) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)
        
        if not settings.hibp_api_key:
            result.errors.append("HIBP_API_KEY environment variable is not set. Get an API key from https://haveibeenpwned.com/API/Key")
            result.data["status"] = "missing_api_key"
            return result
            
        # HIBP requires a specific User-Agent format
        headers = {
            "hibp-api-key": settings.hibp_api_key,
            "User-Agent": "OSINT-Toolkit-Cli"
        }
        
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target)}?truncateResponse=false"
        
        try:
            response = await http_client.get(url, headers=headers)
            if response.status_code == 404:
                result.data["breaches"] = []
                result.data["status"] = "clean"
            elif response.status_code == 200:
                result.data["breaches"] = response.json()
                result.data["status"] = "pwned"
            elif response.status_code == 401:
                result.errors.append("HIBP API key is invalid or unauthorized.")
                result.data["status"] = "auth_error"
            elif response.status_code == 429:
                result.errors.append("HIBP rate limit exceeded.")
                result.data["status"] = "rate_limited"
            else:
                result.errors.append(f"Unexpected HIBP response: {response.status_code}")
                result.data["status"] = "error"
        except Exception as e:
            result.errors.append(f"HIBP connection failed: {e}")
            result.data["status"] = "error"
            
        return result
