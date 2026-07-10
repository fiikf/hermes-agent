"""Local web extract plugin — self-hosted, no API key required.

Uses trafilatura + requests for direct HTML extraction.
For Cloudflare-blocked sites, use browser_navigate + browser_snapshot directly.
"""

from plugins.web.local_extract.provider import LocalExtractWebSearchProvider


def register(ctx) -> None:
    """Register the local extract provider with the plugin context."""
    ctx.register_web_search_provider(LocalExtractWebSearchProvider())
