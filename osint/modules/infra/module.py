import socket
from typing import Any
from urllib.parse import quote

from osint.modules.base import BaseOSINTModule
from osint.core.models import ModuleResult
from osint.core.http import http_client
from osint.config import settings

class InfraModule(BaseOSINTModule):
    name = "infra"
    
    async def run(self, target: str, **options: Any) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)
        
        if not settings.shodan_api_key:
            result.errors.append("SHODAN_API_KEY environment variable is not set. Get an API key from https://account.shodan.io/")
            result.data["status"] = "missing_api_key"
            return result
            
        # Resolve domain to IP if necessary
        ip = target
        try:
            # Basic validation: if it's not an IP, try resolving
            socket.inet_aton(target)
        except socket.error:
            try:
                ip = socket.gethostbyname(target)
                result.data["resolved_ip"] = ip
            except socket.gaierror:
                result.errors.append(f"Failed to resolve domain: {target}")
                result.data["status"] = "resolution_failed"
                return result

        url = f"https://api.shodan.io/shodan/host/{quote(ip)}?key={settings.shodan_api_key}"
        
        try:
            response = await http_client.get(url)
            if response.status_code == 404:
                result.data["host_info"] = None
                result.data["status"] = "not_found_on_shodan"
            elif response.status_code == 200:
                data = response.json()
                result.data["host_info"] = {
                    "ip": data.get("ip_str"),
                    "organization": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "vulns": data.get("vulns", [])
                }
                result.data["status"] = "found"
            elif response.status_code == 401:
                result.errors.append("Shodan API key is invalid or unauthorized.")
                result.data["status"] = "auth_error"
            else:
                result.errors.append(f"Unexpected Shodan response: {response.status_code}")
                result.data["status"] = "error"
        except Exception as e:
            result.errors.append(f"Shodan connection failed: {e}")
            result.data["status"] = "error"
            
        return result
