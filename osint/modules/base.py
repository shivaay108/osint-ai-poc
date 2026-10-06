from abc import ABC, abstractmethod
from typing import Any, Dict

from osint.core.models import ModuleResult


class BaseOSINTModule(ABC):
    name: str = "base"
    description: str = "Base OSINT Module"

    @abstractmethod
    async def run(self, target: str, **kwargs) -> ModuleResult:
        """
        Execute passive OSINT investigation asynchronously.

        Args:
            target: The primary target (username, domain, email, phone, file path)
            **kwargs: Additional module-specific options

        Returns:
            ModuleResult containing the findings
        """
        pass
