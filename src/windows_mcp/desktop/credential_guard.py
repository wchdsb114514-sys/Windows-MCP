"""Refuse to inject text into password fields or credential windows.

The desktop ownership gate answers one question: is the human idle? It says
nothing about *what* gets typed or *where*. An agent that passes that gate can
just as easily type into a bank's login form or a system credential prompt as
into a scratchpad. This module is the second gate, and it is deliberately not
about ownership:

* text injection is refused for any element the last snapshot marked
  ``IsPassword`` — the OS says which fields hide their input, so we do not have
  to guess;
* text injection is refused for windows whose title reads like a credential
  prompt (best-effort, localized strings included);
* *any* input — click, scroll, move, drag, shortcut — is refused against a
  window owned by a logon / credential-broker / password-manager process.

Process ownership is the reliable axis: exe names are locale-independent while
titles are not, so the title rules only ever add to the process rules.

Every lookup goes through Win32 (``WindowFromPoint`` + PID resolution), never
UI Automation: deciding whether to *avoid* touching a window must not require
entering that window's accessibility provider.
"""

from __future__ import annotations

import ctypes
import fnmatch
import logging
import os
import re
from contextlib import contextmanager
from ctypes import wintypes
from typing import Any, Callable, Iterable, Iterator

logger = logging.getLogger(__name__)

# Top-level window for a point, ignoring child controls.
_GA_ROOT = 3

# comtypes marshals POINT by identity, not layout: passing a look-alike ctypes
# structure raises "expected POINT instance instead of _POINT", which is why
# the probe must use the very type comtypes declares in its signature.
_POINT = wintypes.POINT

# DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, as an opaque value.
_PER_MONITOR_AWARE_V2 = -4


# Browsers are exempt from the *title* heuristic: a page titled "登录" is the
# normal shape of the web, and their password fields already carry IsPassword,
# which is the reliable signal. Blocking on title there would refuse ordinary
# form-filling while adding nothing that IsPassword does not already catch.
BROWSER_PROCESSES: frozenset[str] = frozenset(
    {
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave-browser.exe",
        "brave.exe",
        "vivaldi.exe",
        "opera.exe",
    }
)

# Windows' own credential surfaces. These are the ones that can hand an agent a
# route to the account rather than to a document.
DEFAULT_DENY_PROCESSES: frozenset[str] = frozenset(
    {
        "logonui.exe",
        "credentialui.exe",
        "credentialuibroker.exe",
        "authhost.exe",
        "cchost.exe",
    }
)

# Common password vaults. Named by their shipping exe so the rule survives
# localization and window-title churn.
PASSWORD_MANAGER_PROCESSES: frozenset[str] = frozenset(
    {
        "keepass.exe",
        "keepassxc.exe",
        "bitwarden.exe",
        "1password.exe",
        "lastpass.exe",
        "dashlane.exe",
        "nordpass.exe",
        "roboform.exe",
    }
)

_ALL_DENY = DEFAULT_DENY_PROCESSES | PASSWORD_MANAGER_PROCESSES

# Only ever consulted for text injection. Deliberately narrow: a window titled
# "密码管理" is not enough on its own to block a click, but it is enough to block
# typing into it.
CREDENTIAL_TITLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(sign[- ]?in|log[- ]?on|log[- ]?in|password|passphrase|credential)s?\b", re.I),
    re.compile(r"(密码|口令|凭据|凭证|登录|登陆|验证码|二次验证)"),
    re.compile(r"\b(2fa|two[- ]factor|otp|uac)\b", re.I),
    re.compile(r"\buser account control\b", re.I),
)

_TRUTHY_OFF = {"0", "false", "off", "no", "disable", "disabled"}
_TRUTHY_ON = {"1", "true", "yes", "on", "allow"}


class CredentialBlocked(RuntimeError):
    """Input was refused by the credential gate.

    The message names the rule that fired and the environment variable that
    turns it off, so an agent cannot mistake this for a generic failure and
    retry until it lands somewhere unintended.
    """


def _set_thread_dpi_context(value: int | None) -> Any:
    """Switch this thread's DPI context and hand back the previous one.

    Tool coordinates are physical (UIA reports them that way), but a Python
    process that never claimed DPI awareness sees a *virtualized* desktop: on a
    1920x1200 panel at 125%, ``SM_CXSCREEN`` answers 1536, so a point like
    (1700,300) is off-screen as far as ``WindowFromPoint`` is concerned and the
    gate would fail open on the right third of the display. Claiming
    per-monitor-v2 for the duration of one hit-test — thread-local, restored on
    the way out — makes geometry agree without touching the process-wide
    awareness the input path runs under.
    """
    user32 = ctypes.windll.user32  # type: ignore[attr-defined]
    user32.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
    user32.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    return user32.SetThreadDpiAwarenessContext(
        None if value is None else ctypes.c_void_p(value)
    )


@contextmanager
def _physical_pixels() -> Iterator[None]:
    previous: Any = None
    try:
        previous = _set_thread_dpi_context(_PER_MONITOR_AWARE_V2)
    except Exception:  # pragma: no cover - pre-Win10: geometry stays as-is
        previous = None
    try:
        yield
    finally:
        if previous:
            try:
                ctypes.windll.user32.SetThreadDpiAwarenessContext(previous)  # type: ignore[attr-defined]
            except Exception:  # pragma: no cover
                logger.debug("restoring DPI context failed", exc_info=True)


def _fallback_window_at(x: int, y: int) -> int:
    """Topmost visible top-level window whose rectangle contains the point.

    ``WindowFromPoint`` answers 0 for points it cannot see (see
    ``_physical_pixels`` for the DPI case), and a credential gate that fails
    open whenever the Win32 helper shrugs is a gate in name only.
    ``EnumWindows`` walks the z-order top-down, so the first hit is the right
    one; invisible and zero-sized shells are skipped so a maximized helper
    cannot swallow the whole screen.
    """
    try:
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - non-Windows
        return 0

    found = ctypes.c_void_p(0)
    proto = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def probe(hwnd, _lparam):  # pragma: no cover - runs on the Win32 callback stack
        if found.value or not user32.IsWindowVisible(hwnd):
            return True
        rect = wintypes.RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return True
        if rect.right - rect.left <= 0 or rect.bottom - rect.top <= 0:
            return True
        if rect.left <= x < rect.right and rect.top <= y < rect.bottom:
            found.value = hwnd
            return False
        return True

    try:
        with _physical_pixels():
            user32.EnumWindows(proto(probe), 0)
    except Exception:
        logger.debug("EnumWindows fallback failed", exc_info=True)
        return 0
    return int(found.value or 0)


def _window_at_point(x: int, y: int) -> int:
    """Root HWND under a virtual-desktop point, or 0."""
    try:
        with _physical_pixels():
            user32 = ctypes.windll.user32  # type: ignore[attr-defined]
            hwnd = user32.WindowFromPoint(_POINT(x, y))
            if hwnd:
                return int(user32.GetAncestor(hwnd, _GA_ROOT)) or int(hwnd)
    except Exception:  # pragma: no cover - defensive
        logger.debug("WindowFromPoint failed", exc_info=True)
    # WindowFromPoint returned nothing usable: fall back to a rectangle scan
    # rather than treating the point as "no window, nothing to protect".
    return _fallback_window_at(x, y)


def _process_name_for_window(hwnd: int) -> str | None:
    """Executable basename owning `hwnd`, or None when it cannot be resolved."""
    if not hwnd:
        return None
    try:
        import psutil  # local import: keeps the module importable off-Windows
        import win32process

        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        if not pid:
            return None
        return psutil.Process(pid).name()
    except Exception:
        logger.debug("process lookup failed for hwnd %s", hwnd, exc_info=True)
        return None


def _title_for_window(hwnd: int) -> str:
    if not hwnd:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(512)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, 512)  # type: ignore[attr-defined]
        return buf.value or ""
    except Exception:  # pragma: no cover
        return ""


def _foreground_window() -> int:
    try:
        return int(ctypes.windll.user32.GetForegroundWindow())  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover
        return 0


def _node_boxes(state: Any) -> Iterable[tuple[Any, Any]]:
    tree = getattr(state, "tree_state", None) if state is not None else None
    if tree is None:
        return ()
    return [
        (node, node.bounding_box)
        for node in list(tree.interactive_nodes) + list(tree.scrollable_nodes)
        if getattr(node, "bounding_box", None) is not None
    ]


def _focused_element_is_password() -> bool | None:
    """IsPassword on whatever holds focus now — same three-state contract."""
    try:
        from windows_mcp.uia.core import _AutomationClient
        from windows_mcp.uia.enums import PropertyId

        element = _AutomationClient.instance().IUIAutomation.GetFocusedElement()
        if element is None:
            return None
        return bool(element.GetCurrentPropertyValue(PropertyId.IsPasswordProperty))
    except Exception:
        logger.debug("UIA focused-element probe failed", exc_info=True)
        return None


def _password_element_at(x: int, y: int) -> bool | None:
    """Ask UIA directly whether the element under this point hides its input.

    Returns None when the question could not be answered, which is different
    from False: the caller then falls back to the snapshot's node list.

    Measured reason this is the primary rule: a WinForms password box passes
    every one of windows-mcp's interactive filters (EditControl is in the type
    table, role TEXT is interactive, it is keyboard-focusable, and
    IsPassword=True on the element) yet never reaches ``interactive_nodes``
    when the 500-element capture budget is already spent by whatever else is
    on screen. A gate that reads only the tree is a gate whose coverage depends
    on what else the user happens to have open.
    """
    try:
        from windows_mcp.uia.core import _AutomationClient
        from windows_mcp.uia.enums import PropertyId

        element = _AutomationClient.instance().IUIAutomation.ElementFromPoint(_POINT(x, y))
        if element is None:
            return None
        return bool(element.GetCurrentPropertyValue(PropertyId.IsPasswordProperty))
    except Exception:
        logger.debug("UIA IsPassword probe failed", exc_info=True)
        return None


class CredentialGuard:
    """Coordinate- and node-level refusal rules for injected input."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        block_password_fields: bool = True,
        block_credential_titles: bool = True,
        deny_processes: Iterable[str] = _ALL_DENY,
        window_at: Callable[[int, int], int] | None = None,
        process_name: Callable[[int], str | None] | None = None,
        window_title: Callable[[int], str] | None = None,
        foreground_window: Callable[[], int] | None = None,
        password_at: Callable[[int, int], bool | None] | None = None,
        focused_password: Callable[[], bool | None] | None = None,
    ) -> None:
        self.enabled = enabled
        self.block_password_fields = block_password_fields
        self.block_credential_titles = block_credential_titles
        self.deny_processes = frozenset(name.lower() for name in deny_processes)
        self._window_at = window_at or _window_at_point
        self._process_name = process_name or _process_name_for_window
        self._window_title = window_title or _title_for_window
        self._foreground = foreground_window or _foreground_window
        self._password_at = password_at or _password_element_at
        self._focused_password = focused_password or _focused_element_is_password

    # -- environment -------------------------------------------------------

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "CredentialGuard":
        source = os.environ if environ is None else environ
        off = (source.get("WINDOWS_MCP_CREDENTIAL_GUARD") or "").strip().lower() in _TRUTHY_OFF
        allow_passwords = (
            source.get("WINDOWS_MCP_ALLOW_PASSWORD_FIELDS") or ""
        ).strip().lower() in _TRUTHY_ON
        extra = [
            entry.strip().lower()
            for entry in (source.get("WINDOWS_MCP_CREDENTIAL_DENY") or "").split(",")
            if entry.strip()
        ]
        return cls(
            enabled=not off,
            block_password_fields=not allow_passwords,
            deny_processes=_ALL_DENY | frozenset(extra),
        )

    # -- rules -------------------------------------------------------------

    def _owner(self, x: int, y: int) -> tuple[int, str | None, str]:
        hwnd = self._window_at(x, y)
        if not hwnd:
            return 0, None, ""
        return hwnd, self._process_name(hwnd), self._window_title(hwnd)

    def check_input(self, x: int, y: int, *, tool: str, state: Any = None) -> None:
        """Raise if input at this point is refused.

        ``state`` is the last snapshot (``desktop.desktop_state``) and is only
        consulted for the password-field rule; the window rules work blind, so
        an agent cannot bypass them by skipping Snapshot.
        """
        if not self.enabled:
            return
        # Claude Desktop serializes coordinates as strings, so normalize before
        # any comparison — a str x,y would raise TypeError inside the rules.
        x, y = int(x), int(y)
        _, process, title = self._owner(x, y)
        if process and self._is_denied_process(process):
            raise CredentialBlocked(
                f"{tool} refused: the window at ({x},{y}) belongs to {process}, which is on the "
                "credential denylist. Set WINDOWS_MCP_CREDENTIAL_DENY or "
                "WINDOWS_MCP_CREDENTIAL_GUARD=off only if you mean it."
            )
        if tool in ("Type", "MultiEdit") and self.block_credential_titles:
            if title and (process or "").lower() not in BROWSER_PROCESSES:
                if any(pattern.search(title) for pattern in CREDENTIAL_TITLE_PATTERNS):
                    raise CredentialBlocked(
                        f"{tool} refused: window {title!r} reads like a credential prompt. "
                        "Password and credential entry is left to the person at the keyboard."
                    )
        if tool in ("Type", "MultiEdit") and self.block_password_fields:
            answer = self._password_at(x, y)
            if answer is True:
                raise CredentialBlocked(
                    f"{tool} refused: UIA reports the element at ({x},{y}) as IsPassword. "
                    "This agent does not read or type passwords; set "
                    "WINDOWS_MCP_ALLOW_PASSWORD_FIELDS=1 to change that."
                )
            if answer is None:
                # UIA could not answer; the last snapshot is the weaker witness.
                field = self._password_field_at(state, x, y)
                if field is not None:
                    label = field.name or field.control_type or "field"
                    raise CredentialBlocked(
                        f"{tool} refused: the target at ({x},{y}) is marked IsPassword "
                        f"({label!r}). This agent does not read or type passwords; set "
                        "WINDOWS_MCP_ALLOW_PASSWORD_FIELDS=1 to change that."
                    )

    def check_foreground(self, *, tool: str, state: Any = None) -> None:
        """Guard keyboard shortcuts, which have no coordinates to inspect.

        A focused password field matters here: with the caret already in the box,
        ``ctrl+v`` pastes a secret just as well as ``Type`` would have typed it.
        """
        if not self.enabled:
            return
        hwnd = self._foreground()
        if hwnd:
            process = self._process_name(hwnd)
            if process and self._is_denied_process(process):
                raise CredentialBlocked(
                    f"{tool} refused: the focused window belongs to {process}, which is on the "
                    "credential denylist."
                )
        if self.block_password_fields:
            answer = self._focused_password()
            blocked = answer is True or (
                answer is None and bool(self._focused_password_field(state))
            )
            if blocked:
                raise CredentialBlocked(
                    f"{tool} refused: the focused element is marked IsPassword. Paste and "
                    "keystrokes reach that field too, so keyboard shortcuts are held back as "
                    "well as typing; set WINDOWS_MCP_ALLOW_PASSWORD_FIELDS=1 to change that."
                )

    @staticmethod
    def _focused_password_field(state: Any) -> Any:
        for node, _box in _node_boxes(state):
            if node.metadata.get("is_password") and node.metadata.get("has_focused"):
                return node
        return None

    def _is_denied_process(self, name: str) -> bool:
        lowered = name.lower()
        for pattern in self.deny_processes:
            if pattern == lowered:
                return True
            # Entries with glob characters are opt-in breadth for user-supplied
            # deny lists; built-in names are matched exactly so a stray prefix
            # can never block an unrelated program.
            if ("*" in pattern or "?" in pattern) and fnmatch.fnmatch(lowered, pattern):
                return True
        return False

    @staticmethod
    def _password_field_at(state: Any, x: int, y: int) -> Any:
        for node, box in _node_boxes(state):
            if not node.metadata.get("is_password"):
                continue
            left, top = box.left, box.top
            right = box.right or (left + box.width)
            bottom = box.bottom or (top + box.height)
            if left <= x <= right and top <= y <= bottom:
                return node
        return None


_guard: CredentialGuard | None = None


def get_guard() -> CredentialGuard:
    """The process-wide guard, configured from the environment on first use."""
    global _guard
    if _guard is None:
        _guard = CredentialGuard.from_env()
    return _guard
