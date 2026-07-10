"""LocalExtractWebSearchProvider — extract-only, no search, no API key.

Uses trafilatura + requests for direct HTML extraction. No browser fallback.
For Cloudflare-blocked sites, use browser_navigate + browser_snapshot directly.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from agent.web_search_provider import WebSearchProvider


class LocalExtractWebSearchProvider(WebSearchProvider):
    """Self-hosted web page extractor. Extract-only (no search)."""

    @property
    def name(self) -> str:
        return "local-extract"

    @property
    def display_name(self) -> str:
        return "Local Extract (trafilatura)"

    def is_available(self) -> bool:
        """Always available — trafilatura installed as bundled dependency."""
        try:
            import trafilatura  # noqa: F401
            return True
        except ImportError:
            return False

    def supports_search(self) -> bool:
        return False

    def supports_extract(self) -> bool:
        return True

    def extract(self, urls: List[str], **kwargs: Any) -> List[Dict[str, Any]]:
        """Extract content from URLs. Accepts format and max_chars in kwargs."""
        results = []
        for url in urls:
            result = self._extract_single(url)
            results.append(result)
        return results

    def _extract_single(self, url: str) -> Dict[str, Any]:
        """Extract a single URL directly via requests + trafilatura. No browser fallback."""
        return self._extract_direct(url)

    def _extract_direct(self, url: str, timeout: int = 15) -> Dict[str, Any]:
        """Extract using requests + trafilatura. Lightweight, no browser."""
        import requests
        import trafilatura

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        try:
            resp = requests.get(
                url, headers=headers, timeout=timeout, allow_redirects=True
            )
            resp.raise_for_status()

            # Detect Cloudflare challenge
            if "html" in resp.headers.get("Content-Type", ""):
                if (
                    "Just a moment" in resp.text[:500]
                    and "challenge" in resp.text[:2000].lower()
                ):
                    return {
                        "url": url,
                        "success": False,
                        "error": "Cloudflare challenge",
                    }

            # trafilatura extraction
            extracted = trafilatura.extract(
                resp.text,
                url=url,
                include_comments=False,
                include_tables=True,
                include_images=False,
                include_links=False,
                output_format="markdown",
                favor_precision=True,
            )

            if extracted:
                bare = trafilatura.bare_extraction(
                    resp.text, url=url, include_comments=False
                )
                title = bare.title if bare and hasattr(bare, "title") else ""
                content = extracted.strip()
                if len(content) >= 50 or title:
                    return {
                        "url": url,
                        "title": title,
                        "content": content,
                        "raw_content": content,
                        "metadata": {"method": "direct"},
                        "success": True,
                    }

            # Fallback: BeautifulSoup
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "html.parser")
            title = (
                soup.title.string.strip()
                if soup.title and soup.title.string
                else ""
            )
            for tag in soup(["script", "style", "nav", "header", "footer", "aside"]):
                tag.decompose()
            body = soup.find("body") or soup
            text = body.get_text(separator="\n", strip=True)
            text = re.sub(r"\n{3,}", "\n\n", text)
            return {
                "url": url,
                "title": title,
                "content": text[:50000],
                "raw_content": text[:50000],
                "metadata": {"method": "bs4_fallback"},
                "success": bool(text),
            }

        except requests.Timeout:
            return {"url": url, "success": False, "error": "Timeout"}
        except requests.RequestException as e:
            return {"url": url, "success": False, "error": str(e)}

    def get_setup_schema(self) -> Dict[str, Any]:
        return {
            "name": "Local Extract (trafilatura)",
            "badge": "self-hosted",
            "tag": "No API key needed — uses trafilatura for direct extraction.",
            "env_vars": [],
        }
