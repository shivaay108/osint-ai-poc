import re

from rich.console import Console
from rich.markup import escape
from rich.text import Text
from rich.theme import Theme

from osint import __version__
from osint.core.models import ConfidenceTier

THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "dim": "dim white",
    }
)

# Results go to stdout; banner, progress and status messages go to stderr so that
# `osint ... --json - | jq` stays clean.
console = Console(theme=THEME)
err_console = Console(theme=THEME, stderr=True)

TIER_LABELS = {
    ConfidenceTier.VERIFIED: "✅ VERIFIED",
    ConfidenceTier.CONFIRMED: "🔵 CONFIRMED",
    ConfidenceTier.LIKELY: "🟡 LIKELY",
    ConfidenceTier.UNVERIFIED: "⚠️  UNVERIFIED",
}

# C0/C1 control characters except tab and newline. Remote data (DNS TXT, WHOIS,
# EXIF, SMTP replies) can carry escape sequences that would drive the terminal.
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

BANNER = r"""
  ___  ___ _____ _   _ _____
 / _ \/ __|_   _| \ | |_   _|
| | | \__ \ | | |  \| | | |
| |_| |___/ | | | . ` | | |
 \___/|___/ |_| |_|\_| |_|
"""


def safe_text(value: object) -> str:
    """Make untrusted text safe to print: strip control characters, escape Rich markup."""
    return escape(CONTROL_CHARACTERS.sub("", str(value)))


def tier_label(tier: str) -> str:
    try:
        return TIER_LABELS[ConfidenceTier(tier)]
    except ValueError:
        return str(tier)


def print_banner() -> None:
    err_console.print(Text(BANNER, style="bold cyan"))
    err_console.print(f"[dim]OSINT Toolkit v{__version__}[/dim]\n")


def log_success(message: str) -> None:
    err_console.print(f"[success]✅ {safe_text(message)}[/success]", soft_wrap=True)


def log_error(message: str) -> None:
    err_console.print(f"[error]❌ {safe_text(message)}[/error]", soft_wrap=True)


def log_info(message: str) -> None:
    err_console.print(f"[info]ℹ️  {safe_text(message)}[/info]", soft_wrap=True)


def log_warning(message: str) -> None:
    err_console.print(f"[warning]⚠️  {safe_text(message)}[/warning]", soft_wrap=True)
