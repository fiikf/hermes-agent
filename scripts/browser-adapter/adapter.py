#!/usr/bin/env python3
"""
Hermes Browser Adapter — InvisiblePlaywright Firefox 150 backend with on-demand VNC.
Exposes Camofox-compatible REST API on port 9377.

Uses Playwright async API with a dedicated event loop thread so Flask's
threaded mode doesn't break Playwright's thread-affinity requirement.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import dotenv

import flask
from flask import Flask, jsonify, request, make_response

log = logging.getLogger("browser-adapter")
app = Flask(__name__)

# ---------------------------------------------------------------------------
# Idle page auto-cleanup
# ---------------------------------------------------------------------------
_IDLE_TIMEOUT = 7200  # 2h — was 300s (5min), too aggressive for manual VNC browsing


@app.before_request
def _track_last_active():
    global _page_last_active
    if request.path != "/health":
        _page_last_active = time.time()


def _idle_cleanup_loop():
    while True:
        time.sleep(3)
        try:
            idle = time.time() - _page_last_active
            if idle > _IDLE_TIMEOUT:
                try:
                    cur = _pw_call(lambda: _pw_get_url(), timeout=3)
                except Exception:
                    cur = None
                if cur and cur != "about:blank" and "about:blank" not in cur:
                    log.info("Page idle for %.0fs, auto-blanking from %s", idle, cur)
                    _pw_call(lambda: _pw_goto("about:blank"), timeout=5)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ADAPTER_PORT = int(os.environ.get("ADAPTER_PORT", "9377"))
HERMES_HOME = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
ADAPTER_DIR = HERMES_HOME / "browser-adapter"
NOVNC_DIR = ADAPTER_DIR / "novnc"
DISPLAY_NUM = 99
DISPLAY = f":{DISPLAY_NUM}"
VNC_BASE_PORT = 5901
VNC_WS_PORT = 6000


def _get_host() -> str:
    """Return the hostname from the current request context, or localhost."""
    try:
        return request.host.split(":")[0]
    except RuntimeError:
        return "localhost"

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_pw_loop: Optional[asyncio.AbstractEventLoop] = None
_pw_ready = threading.Event()

_vnc_proc: Optional[subprocess.Popen] = None
_websockify_proc: Optional[subprocess.Popen] = None
_vnc_port: int = 0
_pw_console_messages: list = []
_nav_history: list[str] = []
_nav_index: int = -1
_ref_map: dict = {}
_page_last_active: float = 0.0
_tab_registry: dict[str, dict] = {}  # userId → {tabId, sessionKey, url, title}
_pages: dict[str, Any] = {}  # tab_id → Page object (actual Playwright page)
_page_consoles: dict[str, list] = {}  # tab_id → console message list
_page_nav: dict[str, dict] = {}  # tab_id → {"history": [...], "index": int}
_page_last_access: dict[str, float] = {}  # tab_id → time.monotonic() last touch
_MAX_TABS = 20

def _page_for(tab_id: str):
    """Get Page for a tab_id, falling back to _page for backward compat.
    Stale pages (from dead browser contexts) are ignored to avoid hangs."""
    page = _pages.get(tab_id)
    if page is not None:
        _page_last_access[tab_id] = time.monotonic()
        # Fast dead-page check: try lightweight operation, skip if zombie
        try:
            # page.url is property that raises TargetClosedError on dead pages
            _ = page.url
        except Exception:
            log.warning("Page for tab %s is dead, removing from registry", tab_id)
            _pages.pop(tab_id, None)
            _page_consoles.pop(tab_id, None)
            _page_nav.pop(tab_id, None)
            _page_last_access.pop(tab_id, None)
            return globals().get('_page')
        return page
    return globals().get('_page')


import time as _time

def _touch_tab(tab_id: str) -> None:
    """Record that a tab was accessed (called by _page_for automatically)."""
    _page_last_access[tab_id] = _time.monotonic()

def _evict_lru_tabs() -> None:
    """Close least-recently-used tabs when _MAX_TABS is exceeded."""
    while len(_pages) > _MAX_TABS:
        if not _pages:
            break
        # Find oldest (minimum monotonic time)
        oldest_id = min(_pages, key=lambda tid: _page_last_access.get(tid, 0))
        page = _pages.get(oldest_id)
        if page and page != globals().get('_page'):
            try:
                asyncio.run_coroutine_threadsafe(page.close(), _pw_loop).result(timeout=10)
            except Exception:
                pass
        _pages.pop(oldest_id, None)
        _page_consoles.pop(oldest_id, None)
        _page_nav.pop(oldest_id, None)
        _page_last_access.pop(oldest_id, None)
        log.info("LRU evicted tab %s (%d tabs remain)", oldest_id, len(_pages))

# Playwright / IPW globals
_browser = None   # BrowserContext (returned by launch_persistent_context)
_page = None      # Page
_pw = None        # Playwright instance (for lifecycle / cleanup)
_ipw = None       # invisible_playwright module ref (unused, kept for compat)

_LAST_URL_FILE = ADAPTER_DIR / "last_url.json"


def _save_last_url(url: str) -> None:
    if not url or url == "about:blank":
        return
    try:
        with open(_LAST_URL_FILE, "w") as f:
            json.dump({"url": url, "timestamp": time.time()}, f)
    except Exception as e:
        log.warning("Failed to save last URL: %s", e)


def _load_last_url() -> str:
    try:
        if _LAST_URL_FILE.exists():
            with open(_LAST_URL_FILE) as f:
                data = json.load(f)
            return data.get("url", "")
    except Exception:
        pass
    return ""


def _clear_last_url() -> None:
    try:
        if _LAST_URL_FILE.exists():
            _LAST_URL_FILE.unlink()
    except Exception:
        pass


async def _strip_csp_headers(route):
    """Strip Content-Security-Policy headers from responses at the network level.

    Firefox's ``security.csp.enable = False`` disables most CSP enforcement but
    does NOT disable the ``sandbox`` CSP directive (used by e.g.
    raw.githubusercontent.com).  Removing CSP headers at the network level
    before the browser processes them is the most reliable approach.

    We only intercept document loads to minimise overhead — sub-resources
    (images, scripts, styles) pass through unchanged via route.continue_().
    """
    if route.request.resource_type != "document":
        await route.continue_()
        return
    try:
        response = await route.fetch()
        headers = dict(response.headers)
        csp_keys = [k for k in headers if k.lower().startswith("content-security-policy")]
        if not csp_keys:
            await route.continue_()
            return
        for k in csp_keys:
            del headers[k]
        await route.fulfill(
            status=response.status,
            headers=headers,
            body=await response.body(),
        )
    except Exception:
        # If route interception fails for any reason, let the request through
        await route.continue_()


# ---------------------------------------------------------------------------
# Async Playwright operations (run in event loop thread)
# ---------------------------------------------------------------------------

async def _pw_init():
    """Initialize InvisiblePlaywright (patched Firefox 150) with persistent profile."""
    global _browser, _page, _pw, _ipw

    # Import IPW internals directly — the InvisiblePlaywright class at this
    # pinned commit (143aff4b) supports profile_dir on the async variant. We
    # use the module-level helpers and launch Firefox manually for control
    # over launch_persistent_context kwargs (firefox-4 binary doesn't expose
    # the C++ IDL methods for locale/timezone_id, so we pass them via
    # firefox_user_prefs + env TZ instead).
    #
    # **2026-06-05 upstream restored**: feder-cr/invisible_playwright
    # 143aff4b (0.2.0) is active (1187 stars, 6 binary revs). The 2026-06-04
    # 404 was a temporary account-state glitch (now resolved). We pull from
    # git source again, pinning rev in pyproject.toml.
    #
    # Patched Firefox 150.0.1 binary: defer to upstream's current default
    # (firefox-7 as of IPW 0.2.0, 112MB). ensure_binary() downloads on first
    # call if not cached; subsequent calls hit the cache. The previous
    # firefox-4 binary (cached at ~/.hermes/home/.cache/invisible-playwright/
    # firefox-4/ — 705KB extracted, BuildID 20260519190058) is intentionally
    # **left in place** as a known-good fallback. If the firefox-7 network
    # path ever fails (404 / timeout / GitHub rate limit), the firefox-4
    # cache is still available; an admin can flip back via
    # `ensure_binary(version="firefox-4")` and `git checkout` an earlier
    # commit. firefox-7 release notes say its headless fix targets Windows
    # only and the Linux-relevant change (timezone IDL method) is already
    # sidestepped via env TZ + firefox_user_prefs, so the upgrade carries
    # minimal regression risk for our HK2 stack.

    import sys as _sys_for_vd
    from invisible_playwright._fpforge import generate_profile
    from invisible_playwright.prefs import translate_profile_to_prefs
    from invisible_playwright.download import ensure_binary
    from playwright.async_api import async_playwright

    _ensure_display_sync()
    _start_wm()

    profile_dir = ADAPTER_DIR / "profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    # Clean stale Firefox locks — prevents launch-after-crash failure
    profile_dir.joinpath(".parentlock").unlink(missing_ok=True)
    profile_dir.joinpath("lock").unlink(missing_ok=True)

    # Note: uBlock Origin is intentionally NOT auto-installed. The browser
    # profile is persistent and the user installs uBlock manually via the
    # VNC UI. The adapter stays profile-agnostic — it never reads or writes
    # anything under profile_dir/extensions/.

    log.info("Starting InvisiblePlaywright (patched Firefox 150) — persistent profile at %s", profile_dir)

    # Generate stealth fingerprint profile with seed 42 for consistency
    stealth_profile = generate_profile(42)
    prefs = translate_profile_to_prefs(
        stealth_profile,
        locale="zh-CN",
        timezone="Asia/Shanghai",
        extra_prefs=None,
        virtual_display=False,
    )
    # Enable humanize (Bezier mouse curves)
    prefs["invisible_playwright.humanize"] = True
    prefs["invisible_playwright.humanize.maxTime"] = "1.5"

    # Disable CSP at the browser engine level.
    # Playwright's ``bypass_csp=True`` is Chromium-only — silently ignored on
    # Firefox.  Without ``security.csp.enable`` = ``False`` every
    # ``page.evaluate()`` call gets blocked by CSP headers, breaking snapshots,
    # click-fallback, and console evaluation on CSP-hardened sites.
    prefs["security.csp.enable"] = False

    # CSP sandbox directive (used by e.g. raw.githubusercontent.com) is NOT
    # disabled by security.csp.enable in Firefox — it's implemented separately
    # from other CSP directives.  We strip CSP headers at the network level
    # below via page.route() to handle this edge case.

    # Ensure Firefox binary is available. Defer to upstream 0.2.0 default
    # (firefox-7, 112MB) — first call downloads to the cache, subsequent
    # calls hit it. firefox-4 cache retained as a fallback (see comment above).
    binary_path = ensure_binary()

    # Launch via Playwright async API with persistent profile dir.
    # Using profile_dir ensures cookies, extensions and history survive restarts.
    # CRITICAL: Do NOT pass locale/timezone_id to launch_persistent_context — the
    # firefox-4 binary doesn't expose the C++ IDL methods these params require,
    # causing the call to hang for 180s. The locale and timezone are already set
    # via firefox_user_prefs (from translate_profile_to_prefs) and we pass TZ
    # via the env dict for the libc-level timezone override.
    _pw = await async_playwright().start()
    _browser = await _pw.firefox.launch_persistent_context(
        user_data_dir=str(profile_dir),
        executable_path=str(binary_path),
        headless=False,
        args=["--start-maximized"],
        firefox_user_prefs=prefs,
        bypass_csp=True,
        no_viewport=True,
        env={**os.environ, "TZ": "Asia/Shanghai"},
    )
    _page = _browser.pages[0] if _browser.pages else await _browser.new_page()
    _page.set_default_timeout(15000)

    # Capture browser console/log messages
    global _pw_console_messages
    _pw_console_messages.clear()
    _page.on("console", lambda msg: _pw_console_messages.append({
        "type": msg.type, "text": msg.text, "location": str(msg.location),
    }))
    _page.on("pageerror", lambda err: _pw_console_messages.append({
        "type": "error", "text": str(err), "location": "",
    }))

    log.info("InvisiblePlaywright ready — persistent profile at %s", profile_dir)


async def _pw_goto(url: str, page=None) -> dict:
    """Navigate and return {url, title, snapshot, refsCount, turnstile_detected}."""
    p = page or globals().get('_page')
    if not p:
        return {"error": "Browser not initialized"}
    try:
        await p.goto(url, wait_until="domcontentloaded", timeout=20000)
        await asyncio.sleep(2)
        try:
            await p.wait_for_function("document.readyState === 'complete'", timeout=5000)
        except:
            pass
    except Exception as e:
        log.warning("Navigation timed out: %s", e)
        await asyncio.sleep(1)

    _track_nav(p.url if p else url)
    _save_last_url(p.url if p else url)

    try:
        snapshot_data = await _pw_snapshot_internal(p)
        blocker = await _pw_detect_blocker(p)
        return {
            "url": p.url,
            "title": await p.title(),
            "snapshot": snapshot_data["snapshot"],
            "refsCount": snapshot_data["refsCount"],
            "turnstile_detected": blocker["detected"],
            "blocker": blocker,
        }
    except Exception as e2:
        log.error("post-navigate failed: %s", e2)
        return {"error": str(e2)}


async def _pw_snapshot_internal(p=None) -> dict:
    p = p or globals().get('_page')
    if not p:
        return {"snapshot": "", "refsCount": 0}
    try:
        result = await p.evaluate("""() => {
            document.querySelectorAll('[data-hermes-ref]').forEach(e => e.removeAttribute('data-hermes-ref'));
            let refCounter = 0;
            const lines = [];
            function name(el) {
                return el.getAttribute('aria-label') || el.title || el.alt || (el.textContent || '').trim().slice(0, 120) || '';
            }
            function walk(root, depth) {
                if (depth > 25 || !root || root.nodeType !== 1) return;
                const t = root.tagName.toLowerCase();
                if (['script','style','noscript','meta','link','head'].includes(t)) return;
                const indent = '  '.repeat(depth);
                const isInt = ['a','button','input','textarea','select','iframe'].includes(t)
                    || root.hasAttribute('tabindex') || root.hasAttribute('role')
                    || root.hasAttribute('onclick')
                    || (t === 'input' && ['submit','button','checkbox','radio'].includes(root.type));
                if (isInt) {
                    refCounter++;
                    const ref = 'e' + refCounter;
                    root.setAttribute('data-hermes-ref', ref);
                    const n = name(root);
                    let role = root.getAttribute('role') || t;
                    if (t === 'a') role = 'link';
                    const extra = t === 'a' ? ' /url: ' + (root.href || '') :
                                  t === 'iframe' ? ' /url: ' + (root.src || '') : '';
                    lines.push(indent + '- ' + role + ' "' + n + '" [' + ref + ']' + extra);
                } else if (t === 'img') {
                    refCounter++;
                    const ref = 'e' + refCounter;
                    root.setAttribute('data-hermes-ref', ref);
                    lines.push(indent + '- img "' + (root.alt || '') + '" [' + ref + '] /url: ' + (root.src || ''));
                } else if (['h1','h2','h3','h4','h5','h6'].includes(t)) {
                    const txt = name(root) || (root.textContent || '').trim().slice(0, 100);
                    if (txt) lines.push(indent + '- heading "' + txt + '"');
                }
                for (let i = 0; i < root.children.length; i++) walk(root.children[i], depth + 1);
            }
            walk(document.body || document.documentElement, 0);
            return {snapshot: lines.join('\\n'), refsCount: refCounter};
        }""")
        return {"snapshot": result.get("snapshot", ""), "refsCount": result.get("refsCount", 0)}
    except Exception as e:
        err_str = str(e)
        if "blocked by CSP" in err_str:
            log.warning(
                "Snapshot JS blocked by CSP on %s. "
                "security.csp.enable=False handles regular CSP but does NOT"
                " disable the CSP sandbox directive (used by e.g."
                " raw.githubusercontent.com). Falling back to page.content().",
                p.url,
            )
        else:
            log.warning("Snapshot JS failed: %s", e)
        try:
            html = await p.content()
            return _parse_html_snapshot(html)
        except Exception as e2:
            log.warning("Snapshot content fallback also failed: %s", e2)
            return {"snapshot": "", "refsCount": 0}


def _parse_html_snapshot(html: str) -> dict:
    from html.parser import HTMLParser
    lines = []
    ref_counter = [0]
    depth = [0]

    class SnapshotParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self._stack = []
            self._skip = 0
            self._text_buf = ""

        def handle_starttag(self, tag, attrs):
            if self._skip:
                return
            if tag in ('script', 'style', 'noscript'):
                self._skip = 1
                return
            if tag in ('link', 'meta', 'head'):
                return
            attrs_dict = dict(attrs)
            is_int = tag in ('a', 'button', 'input', 'textarea', 'select', 'iframe') \
                     or 'tabindex' in attrs_dict or 'role' in attrs_dict
            role = attrs_dict.get('role', tag)
            if tag == 'a':
                role = 'link'
            indent = '  ' * depth[0]
            txt = (attrs_dict.get('aria-label') or attrs_dict.get('title')
                   or attrs_dict.get('alt', '')).strip()[:120]
            if is_int:
                ref_counter[0] += 1
                ref = f'e{ref_counter[0]}'
                extra = ''
                if tag == 'a':
                    extra = f' /url: {attrs_dict.get("href", "")}'
                elif tag == 'iframe':
                    extra = f' /url: {attrs_dict.get("src", "")}'
                lines.append(f'{indent}- {role} "{txt}" [{ref}]{extra}')
            elif tag == 'img':
                ref_counter[0] += 1
                ref = f'e{ref_counter[0]}'
                lines.append(f'{indent}- img "{attrs_dict.get("alt", "")}" [{ref}] /url: {attrs_dict.get("src", "")}')
            self._stack.append((tag, attrs_dict))
            if tag not in ('br', 'hr', 'img', 'input', 'meta', 'link'):
                depth[0] += 1

        def handle_endtag(self, tag):
            if self._skip:
                if tag in ('script', 'style', 'noscript'):
                    self._skip = 0
                return
            if self._stack:
                prev_tag, _ = self._stack.pop()
                if prev_tag == tag:
                    depth[0] = max(0, depth[0] - 1)
                if tag in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
                    txt = self._text_buf.strip()[:100]
                    if txt:
                        indent = '  ' * depth[0]
                        lines.append(f'{indent}- heading "{txt}"')
                self._text_buf = ""

        def handle_data(self, data):
            if not self._skip:
                self._text_buf += data

    parser = SnapshotParser()
    parser.feed(html)
    return {"snapshot": "\n".join(lines), "refsCount": ref_counter[0]}


async def _pw_detect_blocker(p=None) -> dict:
    p = p or globals().get('_page')
    if not p:
        return {"detected": False, "type": "none", "vnc_reason": ""}
    try:
        return await p.evaluate("""() => {
            const text = document.body?.innerText || '';
            const html = document.body?.innerHTML || '';
            const url = window.location.href;

            if (document.querySelector('[data-turnstile], .cf-turnstile, #cf-turnstile'))
                return {detected: true, type: 'turnstile', vnc_reason: 'Cloudflare Turnstile'};
            for (const f of document.querySelectorAll('iframe')) {
                const src = f.src || '';
                if (src.includes('challenge-platform') || src.includes('turnstile'))
                    return {detected: true, type: 'turnstile', vnc_reason: 'Cloudflare Turnstile iframe'};
            }
            if (url.includes('__cf_chl_') || url.includes('cdn-cgi/challenge'))
                return {detected: true, type: 'turnstile', vnc_reason: 'Cloudflare challenge page'};
            if ((text.includes('Checking your browser') && text.includes('Just a moment'))
                || text.includes('Performing security verification')
                || text.includes('security service to protect'))
                return {detected: true, type: 'turnstile', vnc_reason: 'Cloudflare JS challenge'};
            if (text.includes('Ray ID:') && text.includes('Cloudflare'))
                return {detected: true, type: 'turnstile', vnc_reason: 'Cloudflare Ray ID'};

            if (html.includes('g-recaptcha') || html.includes('recaptcha/api'))
                return {detected: true, type: 'recaptcha', vnc_reason: 'reCAPTCHA detected'};
            if (document.querySelector('.g-recaptcha, div[class*="recaptcha"], iframe[src*="recaptcha"]'))
                return {detected: true, type: 'recaptcha', vnc_reason: 'reCAPTCHA element'};

            if (html.includes('h-captcha') || html.includes('hcaptcha.com'))
                return {detected: true, type: 'hcaptcha', vnc_reason: 'hCaptcha detected'};
            if (document.querySelector('.h-captcha, div[class*="hcaptcha"], iframe[src*="hcaptcha"]'))
                return {detected: true, type: 'hcaptcha', vnc_reason: 'hCaptcha element'};

            const humanKeywords = ['verify you are human', 'verify your identity',
                'security check', 'are you a robot', 'prove you are human',
                'complete the security check', 'enter the code below',
                'type the characters', 'enter the captcha', 'captcha verification',
                'press and hold', 'click and hold', 'solve the puzzle'];
            for (const kw of humanKeywords) {
                if (text.toLowerCase().includes(kw))
                    return {detected: true, type: 'human-verify', vnc_reason: `"${kw}" in page text`};
            }

            if (typeof turnstile !== 'undefined')
                return {detected: true, type: 'turnstile', vnc_reason: 'turnstile JS global'};

            return {detected: false, type: 'none', vnc_reason: ''};
        }""")
    except:
        return {"detected": False, "type": "none", "vnc_reason": ""}


def _track_nav(url: str) -> None:
    global _nav_history, _nav_index
    if not url or url == "about:blank":
        return
    if not _nav_history or url != _nav_history[_nav_index]:
        if _nav_index < len(_nav_history) - 1:
            _nav_history[:] = _nav_history[:_nav_index + 1]
        _nav_history.append(url)
        _nav_index = len(_nav_history) - 1


async def _pw_click(ref: str, page=None) -> dict:
    p = page or globals().get('_page')
    if not p:
        return {"error": "No page"}
    try:
        await p.locator(f'[data-hermes-ref="{ref}"]').click(timeout=5000)
        await asyncio.sleep(2)
        _track_nav(p.url)
        _save_last_url(p.url)
        return {"url": p.url}
    except Exception as e:
        log.debug("locator click failed for %s: %s", ref, e)
    try:
        await p.evaluate(f"""() => {{
            const el = document.querySelector('[data-hermes-ref="{ref}"]');
            if (el) el.click();
        }}""")
        await asyncio.sleep(2)
        _track_nav(p.url)
        _save_last_url(p.url)
        return {"url": p.url}
    except Exception as e:
        log.debug("evaluate click failed for %s: %s", ref, e)
    info = _ref_map.get(ref)
    if not info:
        return {"error": f"Click failed: no element info for ref {ref}"}
    try:
        tag, role, name, href = info["tag"], info["role"], info["name"], info["href"]
        locator = None
        if tag == "a" and href:
            locator = p.locator(f'a[href="{href}"]').first
        elif name:
            locator = p.get_by_role(role, name=name).first
        else:
            locator = p.locator(tag).first
        if locator:
            await locator.click(timeout=5000)
            await asyncio.sleep(2)
            _track_nav(p.url)
            _save_last_url(p.url)
            return {"url": p.url}
    except Exception as e2:
        log.warning("ref_map click failed for %s: %s", ref, e2)
    return {"error": f"All click strategies failed for {ref}"}


async def _pw_type(ref: str, text: str, page=None) -> dict:
    p = page or globals().get('_page')
    if not p:
        return {"error": "No page"}
    clicked = False
    try:
        await p.locator(f'[data-hermes-ref="{ref}"]').click(timeout=3000)
        clicked = True
    except Exception:
        pass
    if not clicked:
        try:
            await p.evaluate(f"""() => {{
                const el = document.querySelector('[data-hermes-ref="{ref}"]');
                if (el) el.focus();
            }}""")
            clicked = True
        except Exception:
            pass
    if not clicked:
        info = _ref_map.get(ref)
        if info:
            try:
                tag, name, href = info["tag"], info["name"], info["href"]
                if tag == "a" and href:
                    await p.locator(f'a[href="{href}"]').first.focus(timeout=3000)
                elif name:
                    await p.get_by_role(info["role"], name=name).first.focus(timeout=3000)
                else:
                    await p.locator(tag).first.focus(timeout=3000)
                clicked = True
            except Exception:
                pass
    await asyncio.sleep(0.3)
    try:
        await p.keyboard.press("Control+A")
        await asyncio.sleep(0.1)
        await p.keyboard.type(text)
    except Exception as e:
        log.warning("keyboard type failed: %s", e)
    return {"ok": True}


async def _pw_scroll(direction: str, page=None) -> dict:
    p = page or globals().get('_page')
    if not p:
        return {"error": "No page"}
    amount = 300 if direction == "down" else -300
    try:
        await p.mouse.wheel(0, amount)
        await asyncio.sleep(0.3)
        return {"ok": True}
    except Exception as e:
        log.warning("mouse.wheel failed: %s", e)
    try:
        await p.evaluate(f"window.scrollBy({{top: {amount}, behavior: 'instant'}})")
        await asyncio.sleep(0.3)
        return {"ok": True}
    except Exception as e:
        log.warning("evaluate scrollBy failed: %s", e)
    try:
        key = "PageDown" if direction == "down" else "PageUp"
        await p.keyboard.press(key)
        await asyncio.sleep(0.3)
        return {"ok": True}
    except Exception as e:
        log.warning("keyboard scroll failed: %s", e)
        return {"error": f"all scroll strategies failed: {e}"}


async def _pw_back(page=None) -> dict:
    global _nav_index, _nav_history
    p = page or globals().get('_page')
    if not p:
        return {"error": "No page"}
    if _nav_index <= 0 or len(_nav_history) < 2:
        return {"url": p.url, "warning": "no history"}
    _nav_index -= 1
    prev_url = _nav_history[_nav_index]
    try:
        await p.goto(prev_url, wait_until="domcontentloaded", timeout=15000)
    except Exception as e:
        log.warning("goto back failed: %s", e)
    await asyncio.sleep(1)
    try:
        _save_last_url(p.url)
        return {"url": p.url}
    except Exception:
        return {"url": ""}


async def _pw_press(key: str, page=None) -> dict:
    p = page or globals().get('_page')
    if not p:
        return {"error": "No page"}
    try:
        await p.keyboard.press(key)
    except Exception as e:
        log.warning("keyboard.press failed, trying evaluate fallback: %s", e)
        await p.evaluate(f"""() => {{
            const el = document.activeElement || document.body;
            el.dispatchEvent(new KeyboardEvent('keydown', {{key: '{key}', bubbles: true}}));
            el.dispatchEvent(new KeyboardEvent('keyup', {{key: '{key}', bubbles: true}}));
            if ('{key}' === 'Enter') {{
                const form = el.closest('form');
                if (form) form.dispatchEvent(new Event('submit', {{bubbles: true}}));
            }}
        }}""")
    await asyncio.sleep(1)
    return {"url": p.url, "pressed": key}


async def _pw_screenshot(page=None) -> bytes:
    p = page or globals().get('_page')
    if not p:
        return b""
    return await p.screenshot(type="png")


async def _pw_execute(code: str, page=None) -> Any:
    p = page or globals().get('_page')
    if not p:
        return ""
    try:
        return await p.evaluate(code)
    except Exception as e:
        err_str = str(e)
        if "blocked by CSP" in err_str:
            log.warning("Execute JS blocked by CSP (sandboxed page: %s)", p.url)
        raise


async def _pw_get_url(page=None) -> str:
    p = page or globals().get('_page')
    if not p:
        return ""
    try:
        return p.url
    except Exception:
        return ""


async def _pw_wait_for_page(page=None, timeout: int = 60) -> dict:
    p = page or globals().get('_page')
    if not p:
        return {"passed": False, "reason": "no page"}
    import time as _time
    start = _time.time()
    deadline = start + timeout
    while _time.time() < deadline:
        try:
            result = await p.evaluate("""() => {
                const text = document.body?.innerText || '';
                const hasCF = (
                    document.querySelector('[data-turnstile], .cf-turnstile, #cf-turnstile') !== null ||
                    document.querySelector('iframe[src*="challenge-platform"], iframe[src*="turnstile"]') !== null ||
                    window.location.href.includes('__cf_chl_') ||
                    window.location.href.includes('cdn-cgi/challenge') ||
                    (text.includes('Checking your browser') && text.includes('Just a moment'))
                );
                return !hasCF && document.readyState === 'complete' && text.length > 50 ? 'LOADED' : 'BLOCKED';
            }""")
            if result == 'LOADED':
                return {"passed": True, "reason": "page_loaded", "elapsed": _time.time() - start}
        except Exception:
            pass
        await asyncio.sleep(1)
    return {"passed": False, "reason": "timeout", "elapsed": timeout}


async def _pw_close(page=None):
    global _page
    try:
        p = page or globals().get('_page')
        if p:
            await p.goto("about:blank", timeout=5000)
            _clear_last_url()
    except:
        pass


async def _create_page():
    global _page
    b = globals().get('_browser')
    if b:
        _page = await b.new_page()
        _page.set_default_timeout(15000)
        log.info("New page created")
    else:
        log.error("No browser to create page in")
        raise RuntimeError("Browser was closed — need re-init")


async def _new_page(tab_id: str = ""):
    """Create a new browser page, register console listener, return the page."""
    b = globals().get('_browser')
    if not b:
        log.error("No browser to create page in")
        raise RuntimeError("Browser was closed — need re-init")
    try:
        page = await asyncio.wait_for(b.new_page(), timeout=10)
    except asyncio.TimeoutError:
        log.error("new_page() timed out (10s) — browser deadlock, scheduling reinit")
        asyncio.create_task(_reinit_browser_async())
        raise RuntimeError("Timed out creating new page (browser deadlock)")
    page.set_default_timeout(15000)
    # Register per-page console capture
    msgs: list = []
    page.on("console", lambda msg: msgs.append({
        "type": msg.type, "text": msg.text, "location": str(msg.location),
    }))
    page.on("pageerror", lambda err: msgs.append({
        "type": "error", "text": str(err), "location": "",
    }))
    if tab_id:
        _page_consoles[tab_id] = msgs
        _page_nav[tab_id] = {"history": [], "index": -1}
    log.info("New page created%s", f" for tab {tab_id}" if tab_id else "")
    return page


def _pw_call(coro_factory, timeout=60):
    global _pw_loop
    if not _pw_loop:
        raise RuntimeError("Playwright not initialized")
    from playwright._impl._errors import TargetClosedError as _pw_target_closed
    try:
        future = asyncio.run_coroutine_threadsafe(coro_factory(), _pw_loop)
        return future.result(timeout=timeout)
    except _pw_target_closed as _pw_err:
        log.warning("Browser context closed (%s) — reinitializing and retrying...", _pw_err)
        _reinit_browser()
        future = asyncio.run_coroutine_threadsafe(coro_factory(), _pw_loop)
        return future.result(timeout=timeout)


def _ensure_pw():
    global _pw_loop
    if not (_pw_loop and _pw_ready.is_set()):
        def _run_loop():
            global _pw_loop
            _pw_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(_pw_loop)
            try:
                _pw_loop.run_until_complete(_pw_init())
            except Exception as e:
                log.error("Playwright init failed: %s", e, exc_info=True)
                _pw_ready.set()
                return
            _pw_ready.set()
            _pw_loop.run_forever()

        t = threading.Thread(target=_run_loop, daemon=True, name="pw-loop")
        t.start()
        if not _pw_ready.wait(timeout=120):
            raise RuntimeError("Playwright initialization timed out (120s)")

    if globals().get('_page') is None:
        log.info("Creating new page")
        try:
            future = asyncio.run_coroutine_threadsafe(
                _create_page(), _pw_loop)
            future.result(timeout=20)
        except Exception as e:
            log.warning("Page creation failed (%s), re-launching browser", e)
            _reinit_browser()


def _reinit_browser():
    global _pw_loop, _pw_ready, _browser, _page, _pw, _ipw
    # Clear ALL stale tab state before reinit — old Page objects become
    # zombie references that cause navigate 30s hangs if not removed.
    _pages.clear()
    _page_consoles.clear()
    _page_nav.clear()
    _page_last_access.clear()
    _tab_registry.clear()
    log.info("Cleared %d stale tab pages before reinit", len(_pages))
    if _pw_loop and _pw_loop.is_running():
        try:
            if _browser:
                future = asyncio.run_coroutine_threadsafe(
                    _browser.close(), _pw_loop)
                future.result(timeout=10)
        except:
            pass
        try:
            if _pw:
                future = asyncio.run_coroutine_threadsafe(
                    _pw.stop(), _pw_loop)
                future.result(timeout=5)
        except:
            pass
        _pw_loop.call_soon_threadsafe(_pw_loop.stop)
    _pw_loop = None
    _pw_ready.clear()
    _browser = None
    _page = None
    _pw = None
    _ipw = None

    # Graceful cascade: WebSocket→SIGTERM→SIGKILL
    # (browser.close + pw.stop already done above, now kill orphans)
    profile_dir = ADAPTER_DIR / "profile"
    # Step 3: SIGTERM — allow clean shutdown
    subprocess.run(
        ["pkill", "-15", "-f", rf"firefox.*{profile_dir}"],
        capture_output=True, timeout=5
    )
    time.sleep(2)
    # Step 4: SIGKILL if still alive
    still_alive = subprocess.run(
        ["pgrep", "-f", rf"firefox.*{profile_dir}"],
        capture_output=True, timeout=5
    )
    if still_alive.returncode == 0:
        log.warning("Firefox didn't exit on SIGTERM — sending SIGKILL")
        subprocess.run(
            ["pkill", "-9", "-f", rf"firefox.*{profile_dir}"],
            capture_output=True, timeout=5
        )
    profile_dir.joinpath(".parentlock").unlink(missing_ok=True)
    profile_dir.joinpath("lock").unlink(missing_ok=True)

    _ensure_pw()
    # If browser still dead after reinit, exit non-zero for systemd auto-restart
    if globals().get('_browser') is None:
        log.error("Browser reinit failed — exiting for systemd auto-restart")
        _cleanup()
        logging.shutdown()
        _os._exit(1)


async def _reinit_browser_async():
    """Reinit browser from inside the event loop (e.g. after new_page timeout)."""
    _reinit_browser()


# ---------------------------------------------------------------------------
# Xvfb
# ---------------------------------------------------------------------------

def _ensure_display_sync():
    lockfile = Path(f"/tmp/.X{DISPLAY_NUM}-lock")
    if lockfile.exists():
        lockfile.unlink()
    sock = Path(f"/tmp/.X11-unix/X{DISPLAY_NUM}")
    if sock.exists():
        try:
            sock.unlink()
        except OSError:
            pass

    r = subprocess.run(["xdpyinfo", "-display", DISPLAY],
                       capture_output=True, timeout=5)
    if r.returncode == 0:
        os.environ.setdefault("DISPLAY", DISPLAY)
        return

    log.info("Starting Xvfb on display %s", DISPLAY)
    proc = subprocess.Popen(
        ["Xvfb", DISPLAY, "-screen", "0", "1920x1080x24", "-ac"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    if proc.poll() is not None:
        raise RuntimeError(f"Xvfb failed on {DISPLAY} (exit {proc.returncode})")
    os.environ["DISPLAY"] = DISPLAY


def _start_wm():
    env = {**os.environ, "DISPLAY": DISPLAY}
    existing = subprocess.run(["pgrep", "-f", "fluxbox"], capture_output=True,
                              timeout=5).returncode == 0
    if existing:
        return
    log.info("Starting fluxbox window manager on %s", DISPLAY)
    proc = subprocess.Popen(
        ["fluxbox", "-display", DISPLAY],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env,
    )
    time.sleep(1)
    if proc.poll() is not None:
        log.warning("fluxbox failed (exit %d), trying openbox", proc.returncode)
        proc = subprocess.Popen(
            ["openbox", "--display", DISPLAY],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env,
        )
        time.sleep(1)
        if proc.poll() is not None:
            log.warning("openbox also failed, continuing without WM")


# ---------------------------------------------------------------------------
# VNC Management
# ---------------------------------------------------------------------------

def _find_free_port(start=5900):
    for p in range(start, start + 100):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.bind(("", p))
            s.close()
            return p
        except OSError:
            continue
    return start


def _start_vnc():
    global _vnc_proc, _websockify_proc, _vnc_port
    if _vnc_proc and _vnc_proc.poll() is None:
        return _vnc_port

    port = _find_free_port(VNC_BASE_PORT)

    log.info("Starting x11vnc on display %s port %d", DISPLAY, port)
    _vnc_proc = subprocess.Popen(
        ["x11vnc", "-display", DISPLAY, "-rfbport", str(port),
         "-localhost", "-shared", "-forever", "-noxdamage",
         "-nopw",
         "-o", str(ADAPTER_DIR / f"x11vnc-{port}.log")],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    log.info("Starting websockify %d -> localhost:%d", VNC_WS_PORT, port)
    subprocess.run(["pkill", "-f", f"websockify.*:{VNC_WS_PORT}"],
                   capture_output=True, timeout=5)
    time.sleep(0.5)
    _websockify_proc = subprocess.Popen(
        ["websockify", "--web=" + str(NOVNC_DIR), "127.0.0.1:" + str(VNC_WS_PORT), f"localhost:{port}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    _vnc_port = port
    log.info("VNC ready: raw=%d  web=http://localhost:%d/vnc.html", port, VNC_WS_PORT)
    return port


def _stop_vnc():
    global _vnc_proc, _websockify_proc, _vnc_port
    if _websockify_proc:
        _websockify_proc.terminate()
        try:
            _websockify_proc.wait(timeout=5)
        except:
            _websockify_proc.kill()
        _websockify_proc = None
    if _vnc_proc:
        _vnc_proc.terminate()
        try:
            _vnc_proc.wait(timeout=5)
        except:
            _vnc_proc.kill()
        _vnc_proc = None
    subprocess.run(["pkill", "-f", rf"x11vnc.*{DISPLAY}"],
                   capture_output=True, timeout=5)
    _vnc_port = 0


# ---------------------------------------------------------------------------
# noVNC
# ---------------------------------------------------------------------------

def _install_novnc():
    if NOVNC_DIR.exists() and (NOVNC_DIR / "vnc.html").exists():
        return
    log.info("Downloading noVNC...")
    NOVNC_DIR.mkdir(parents=True, exist_ok=True)
    import requests as req
    import tarfile, io
    url = "https://github.com/novnc/noVNC/archive/refs/tags/v1.5.0.tar.gz"
    try:
        r = req.get(url, timeout=30)
        t = tarfile.open(fileobj=io.BytesIO(r.content))
        prefix = None
        for member in t.getmembers():
            if prefix is None:
                prefix = member.name.split("/", 1)[0] + "/"
            rel = member.name[len(prefix):] if member.name.startswith(prefix) else member.name
            if not rel:
                continue
            target = NOVNC_DIR / rel
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                f = t.extractfile(member)
                if f:
                    target.write_bytes(f.read())
        log.info("noVNC installed")
    except Exception as e:
        log.warning("noVNC download failed: %s", e)
        (NOVNC_DIR / "vnc.html").write_text(
            "<html><body><h2>VNC: connect with vncviewer</h2></body></html>")


# ---------------------------------------------------------------------------
# Flask REST API
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "vncPort": _vnc_port,
        "vncUrl": f"https://{_get_host()}/vnc/",
        "version": "hermes-pw-async-1.0",
    })


@app.route("/tabs/open", methods=["POST"])
def open_tab():
    data = request.get_json() or {}
    url = data.get("url", "about:blank")
    _ensure_pw()
    tab_id = str(uuid.uuid4())[:8]
    _evict_lru_tabs()  # keep within limit before creating
    # Create new page
    try:
        page = _pw_call(lambda: _new_page(tab_id), timeout=60)
    except Exception as e:
        log.warning("open_tab: _new_page failed (%s), reinit already scheduled", e)
        return jsonify({"error": f"Browser deadlock, reinit in progress: {e}"}), 503
    _pages[tab_id] = page
    _touch_tab(tab_id)
    # Register in tab_registry for session cleanup
    user_id = data.get("userId", "")
    if user_id:
        if user_id not in _tab_registry:
            _tab_registry[user_id] = {
                "tabIds": [],
                "sessionKey": data.get("sessionKey", ""),
            }
        _tab_registry[user_id]["tabIds"].append(tab_id)
    try:
        result = _pw_call(lambda: _pw_goto(url, page=page), timeout=30)
    except Exception as e:
        log.warning("open_tab: _pw_goto failed (%s), cleaning up tab", e)
        _pages.pop(tab_id, None)
        # Clean up registry if we added to it
        if user_id and user_id in _tab_registry:
            _tab_registry[user_id]["tabIds"] = [t for t in _tab_registry[user_id]["tabIds"] if t != tab_id]
            if not _tab_registry[user_id]["tabIds"]:
                _tab_registry.pop(user_id, None)
        return jsonify({"error": f"Navigation failed after reinit: {e}"}), 503
    if "error" in result:
        return jsonify(result), 500
    return jsonify({
        "ok": True,
        "targetId": tab_id,
        "tabId": tab_id,
        "url": result.get("url", url),
    })


@app.route("/tabs/<tab_id>", methods=["DELETE"])
def close_tab(tab_id):
    _ensure_pw()
    page = _page_for(tab_id)
    if page and page != globals().get('_page'):
        # Close only if it's a dedicated multi-tab page
        _pw_call(lambda: _pw_close(page=page), timeout=10)
        # Also close the actual page in Playwright
        try:
            asyncio.run_coroutine_threadsafe(page.close(), _pw_loop).result(timeout=10)
        except Exception:
            pass
        _pages.pop(tab_id, None)
        _page_consoles.pop(tab_id, None)
        _page_nav.pop(tab_id, None)
    else:
        _pw_call(lambda: _pw_goto("about:blank", page=page), timeout=10)
        _clear_last_url()
    # Remove from tab_registry if present
    for _cu_user_id, _cu_entry in list(_tab_registry.items()):
        _cu_tab_ids = _cu_entry.get("tabIds", [])
        if tab_id in _cu_tab_ids:
            _cu_tab_ids.remove(tab_id)
            if not _cu_tab_ids:
                _tab_registry.pop(_cu_user_id, None)
            break
    return jsonify({"ok": True})


@app.route("/tabs/<tab_id>/wait-for-page", methods=["POST"])
def wait_for_page(tab_id):
    body = request.get_json() or {}
    timeout = int(body.get("timeout", 60))
    _ensure_pw()
    page = _page_for(tab_id)
    result = _pw_call(lambda: _pw_wait_for_page(page=page, timeout=timeout), timeout=timeout + 5)
    return jsonify(result)


@app.route("/tabs", methods=["POST"])
def create_tab():
    data = request.get_json() or {}
    url = data.get("url", "about:blank")
    _ensure_pw()
    tab_id = str(uuid.uuid4())[:8]
    _evict_lru_tabs()  # keep within limit before creating
    # Create new page for this tab
    try:
        page = _pw_call(lambda: _new_page(tab_id), timeout=60)
    except Exception as e:
        log.warning("create_tab: _new_page failed (%s), reinit already scheduled", e)
        return jsonify({"error": f"Browser deadlock, reinit in progress: {e}"}), 503
    _pages[tab_id] = page
    _touch_tab(tab_id)
    try:
        result = _pw_call(lambda: _pw_goto(url, page=page), timeout=30)
    except Exception as e:
        log.warning("create_tab: _pw_goto failed (%s), cleaning up tab", e)
        _pages.pop(tab_id, None)
        return jsonify({"error": f"Navigation failed after reinit: {e}"}), 503
    result["tabId"] = tab_id
    turnstile = result.get("turnstile_detected", False)
    if turnstile:
        _start_vnc()
        result["vnc_url"] = f"https://{_get_host()}/vnc/"
        blocker = result.get("blocker", {})
        reason = blocker.get("vnc_reason", "CAPTCHA/verification challenge")
        result["vnc_hint"] = f"[{reason}] VNC ready for manual solving. Type '好了' when done."
    user_id = data.get("userId", "")
    if user_id:
        if user_id not in _tab_registry:
            _tab_registry[user_id] = {
                "tabIds": [],
                "sessionKey": data.get("sessionKey", ""),
                "url": url,
                "title": result.get("title", ""),
            }
        _tab_registry[user_id]["tabIds"].append(tab_id)
    return jsonify(result)


@app.route("/tabs", methods=["GET"])
def list_tabs():
    user_id = request.args.get("userId", "")
    items = []
    if user_id:
        entry = _tab_registry.get(user_id)
        if entry:
            items.append(entry)
    else:
        items = list(_tab_registry.values())
    return jsonify({"tabs": items})


@app.route("/tabs/<tab_id>/navigate", methods=["POST"])
def navigate_tab(tab_id):
    data = request.get_json() or {}
    url = data.get("url", "about:blank")
    _ensure_pw()
    page = _page_for(tab_id)
    if page is None:
        return jsonify({"error": "Tab not found (browser was reinitialized)"}), 404
    try:
        result = _pw_call(lambda: _pw_goto(url, page=page), timeout=30)
    except Exception as e:
        log.warning("navigate_tab(%s): _pw_goto failed (%s)", tab_id, e)
        # Page is dead — remove from registry so next call gets 404
        _pages.pop(tab_id, None)
        _page_consoles.pop(tab_id, None)
        _page_nav.pop(tab_id, None)
        return jsonify({"error": f"Page navigation failed, tab invalidated: {e}"}), 503
    if "error" in result:
        return jsonify(result), 500
    turnstile = result.get("turnstile_detected", False)
    if turnstile:
        _start_vnc()
        result["vnc_url"] = f"https://{_get_host()}/vnc/"
        blocker = result.get("blocker", {})
        reason = blocker.get("vnc_reason", "CAPTCHA/verification challenge")
        result["vnc_hint"] = f"[{reason}] VNC ready for manual solving. Type '好了' when done."
    return jsonify(result)


@app.route("/tabs/<tab_id>/snapshot", methods=["GET"])
def get_snapshot(tab_id):
    _ensure_pw()
    page = _page_for(tab_id)
    snap = _pw_call(lambda: _pw_snapshot_internal(p=page), timeout=15)
    blocker = _pw_call(lambda: _pw_detect_blocker(p=page), timeout=10)
    return jsonify({**snap, "turnstile_detected": blocker["detected"], "blocker": blocker})


@app.route("/tabs/<tab_id>/click", methods=["POST"])
def click_element(tab_id):
    ref = request.get_json().get("ref", "").lstrip("@")
    _ensure_pw()
    page = _page_for(tab_id)
    result = _pw_call(lambda: _pw_click(ref, page=page), timeout=15)
    return jsonify(result)


@app.route("/tabs/<tab_id>/type", methods=["POST"])
def type_text(tab_id):
    data = request.get_json() or {}
    _ensure_pw()
    page = _page_for(tab_id)
    result = _pw_call(lambda: _pw_type(data.get("ref", "").lstrip("@"), data.get("text", ""), page=page), timeout=15)
    return jsonify(result)


@app.route("/tabs/<tab_id>/scroll", methods=["POST"])
def scroll_page(tab_id):
    direction = request.get_json().get("direction", "down")
    _ensure_pw()
    page = _page_for(tab_id)
    result = _pw_call(lambda: _pw_scroll(direction, page=page), timeout=10)
    return jsonify(result)


@app.route("/tabs/<tab_id>/back", methods=["POST"])
def go_back(tab_id):
    _ensure_pw()
    page = _page_for(tab_id)
    result = _pw_call(lambda: _pw_back(page=page), timeout=15)
    return jsonify(result)


@app.route("/tabs/<tab_id>/press", methods=["POST"])
def press_key(tab_id):
    key = request.get_json().get("key", "")
    _ensure_pw()
    page = _page_for(tab_id)
    result = _pw_call(lambda: _pw_press(key, page=page), timeout=15)
    return jsonify(result)


@app.route("/tabs/<tab_id>/screenshot", methods=["GET"])
def screenshot(tab_id):
    _ensure_pw()
    page = _page_for(tab_id)
    img_data = _pw_call(lambda: _pw_screenshot(page=page), timeout=15)
    resp = make_response(img_data)
    resp.headers["Content-Type"] = "image/png"
    return resp


@app.route("/tabs/<tab_id>/execute", methods=["POST"])
@app.route("/tabs/<tab_id>/evaluate", methods=["POST"])
def execute_js(tab_id):
    body = request.get_json() or {}
    code = body.get("code") or body.get("expression", "")
    _ensure_pw()
    page = _page_for(tab_id)
    result = _pw_call(lambda: _pw_execute(code, page=page), timeout=15)
    return jsonify({"result": result})


@app.route("/tabs/<tab_id>/console", methods=["GET"])
def get_console(tab_id):
    clear = request.args.get("clear", "false").lower() == "true"
    msgs = _page_consoles.get(tab_id, _pw_console_messages.copy())
    if clear:
        _page_consoles.pop(tab_id, None)
        if tab_id not in _page_consoles:
            _pw_console_messages.clear()
    errors = [m for m in msgs if m["type"] == "error"]
    return jsonify({
        "messages": msgs,
        "total": len(msgs),
        "errors": len(errors),
    })


@app.route("/sessions/<user_id>", methods=["DELETE"])
def close_session(user_id):
    # Close ALL pages for this user
    entry = _tab_registry.get(user_id)
    if entry:
        tab_ids = list(entry.get("tabIds", []))
        for tid in tab_ids:
            if tid and tid in _pages:
                page = _pages.pop(tid, None)
                if page:
                    try:
                        asyncio.run_coroutine_threadsafe(page.close(), _pw_loop).result(timeout=10)
                    except Exception:
                        pass
                _page_consoles.pop(tid, None)
                _page_nav.pop(tid, None)
        _tab_registry.pop(user_id, None)
    # Also blank the main page
    _pw_call(lambda: _pw_close(), timeout=10)
    return jsonify({"ok": True})


@app.route("/vnc", methods=["POST"])
def vnc_start():
    port = _start_vnc()
    return jsonify({"vnc_url": f"https://{_get_host()}/vnc/", "port": port})


@app.route("/vnc", methods=["DELETE"])
def vnc_stop():
    _stop_vnc()
    return jsonify({"ok": True})


@app.route("/vnc", methods=["GET"])
def vnc_status():
    running = subprocess.run(["pgrep", "-f", rf"x11vnc.*{DISPLAY}"],
                             capture_output=True, timeout=5).returncode == 0
    return jsonify({
        "running": running,
        "vnc_url": f"https://{_get_host()}/vnc/" if running else "",
    })


@app.route("/vnc.html")
def serve_vnc_html():
    return flask.send_file(str(NOVNC_DIR / "vnc.html"))


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

import atexit, signal, os as _os


@atexit.register
def _cleanup():
    log.info("Shutting down...")
    _stop_vnc()
    if _pw_loop:
        try:
            if _browser:
                future = asyncio.run_coroutine_threadsafe(
                    _browser.close(), _pw_loop)
                future.result(timeout=10)
        except:
            pass
        try:
            if _pw:
                future = asyncio.run_coroutine_threadsafe(
                    _pw.stop(), _pw_loop)
                future.result(timeout=5)
        except:
            pass
        _pw_loop.call_soon_threadsafe(_pw_loop.stop)


def _sigterm_handler(signum, frame):
    _cleanup()
    logging.shutdown()
    _os._exit(0)


signal.signal(signal.SIGTERM, _sigterm_handler)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    ADAPTER_DIR.mkdir(parents=True, exist_ok=True)
    load_dotenv = dotenv.load_dotenv
    load_dotenv(ADAPTER_DIR / ".env")
    # Re-read env after .env load
    ADAPTER_PORT = int(os.environ.get("ADAPTER_PORT", str(ADAPTER_PORT)))
    _install_novnc()
    _ensure_display_sync()
    _start_vnc()
    t = threading.Thread(target=_idle_cleanup_loop, daemon=True, name="idle-cleanup")
    t.start()
    log.info("Pre-warming browser…")
    try:
        _ensure_pw()
        log.info("Browser pre-warm complete")
    except Exception as e:
        log.warning("Browser pre-warm failed (%s), will start on first request", e)
    log.info("Starting Hermes Browser Adapter (InvisiblePlaywright Firefox 150) on port %d", ADAPTER_PORT)
    log.info("Set CAMOFOX_URL=http://localhost:%d in .env", ADAPTER_PORT)
    app.run(host="127.0.0.1", port=ADAPTER_PORT, debug=False, use_reloader=False, threaded=True)
