"""Act, then prove the action landed — and refuse to credit evidence that predates it.

Every input tool used to answer "Single left clicked at (x,y)." and nothing else.
Whether the click did anything was the caller's problem, which is how an agent
comes to report a task complete on the strength of a keystroke that landed
nowhere. Pass `expect` and the tool re-checks the live UI after acting.

Three outcomes, deliberately not reducible to one boolean:

* verified      — the condition became true after the action and was not true
                  before it;
* UNPROVEN      — the action ran and the condition holds, but it already held
                  *before* the action, so it evidences nothing. Returned as a
                  message no reader can mistake for success, not an error,
                  because the action may well have worked;
* ActionUnverified — the action ran and the condition never held. Raised, since
                  the agent must not have to parse prose to learn the click did
                  not take effect.

The predicate is windows-mcp's own WaitFor matcher (`_matches_wait_condition`),
so an expectation is spelled exactly the way `WaitFor` spells it and the two
cannot drift apart.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

# The WaitFor matcher is imported inside the functions below. `tools.input`
# imports this module to wrap its own tools, so a module-level import here would
# close the cycle and make whichever module loads first fail at import time.

DEFAULT_EXPECT_TIMEOUT = 3.0
DEFAULT_EXPECT_INTERVAL = 0.25
UNPROVEN_PREFIX = "UNPROVEN"


class ActionUnverified(RuntimeError):
    """The action was performed and the expected UI change did not appear.

    Carries the word "performed" on purpose: the tool cannot know the action had
    *no* effect, only that it failed to produce the effect that was asked about.
    Retrying the action blindly can double it (a second submit, a second delete),
    so the caller has to look before acting again.
    """


@dataclass(frozen=True)
class Expectation:
    condition: str
    text: str | None
    window_name: str | None
    use_dom: bool
    timeout: float
    interval: float

    def describe(self) -> str:
        parts = [self.condition]
        if self.text:
            parts.append(f"text={self.text!r}")
        if self.window_name:
            parts.append(f"window={self.window_name!r}")
        return " ".join(parts)


def parse_expect(expect: Any) -> Expectation | None:
    """Normalise the `expect` argument into an Expectation, or None for absent.

    Accepts a mapping or a JSON string: some MCP clients serialize objects as
    strings, and the existing tools already tolerate that for coordinates.
    """
    if expect is None:
        return None
    if isinstance(expect, str):
        stripped = expect.strip()
        if not stripped:
            return None
        try:
            expect = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"expect must be a JSON object, e.g. '{{\"condition\": \"text_exists\", \"text\": \"Saved\"}}': {exc}") from exc
    if not isinstance(expect, dict):
        raise ValueError("expect must be an object with a 'condition' key, or null to skip verification")

    condition = expect.get("condition")
    if not condition or not isinstance(condition, str):
        raise ValueError("expect requires a 'condition' (text_exists, active_window, element_exists, element_enabled, focused_element)")

    timeout = expect.get("timeout", DEFAULT_EXPECT_TIMEOUT)
    interval = expect.get("interval", DEFAULT_EXPECT_INTERVAL)
    from windows_mcp.tools.input import _validate_wait_for_args

    normalized = _validate_wait_for_args(
        condition=condition,
        text=expect.get("text"),
        window_name=expect.get("window_name"),
        timeout=float(timeout),
        interval=float(interval),
    )
    use_dom = expect.get("use_dom", False)
    if isinstance(use_dom, str):
        use_dom = use_dom.strip().lower() in {"1", "true", "yes", "on"}
    return Expectation(
        condition=normalized,
        text=expect.get("text"),
        window_name=expect.get("window_name"),
        use_dom=bool(use_dom),
        timeout=float(timeout),
        interval=float(interval),
    )


def _scoped_state(window_name: str):
    """Build a tree-like state from one window's UIA subtree.

    `get_state` re-captures the *whole desktop*: measured at 9.6-16.1 seconds on a
    normal workstation with a text-heavy app open, which is longer than any
    sensible settle budget, so a polling verifier degenerates into a single
    check and the UI can change in the blind interval. It also inherits the
    500-element capture cap, so an expectation can be judged "absent" merely
    because a neighbouring window consumed the budget.

    Naming the window in the expectation scopes the search to that window and
    costs milliseconds. The nodes produced carry the same fields the WaitFor
    matcher reads, so `element_exists` means exactly the same thing here as it
    does in `WaitFor` — only faster and without the budget.
    """
    import ctypes

    from windows_mcp.tree.views import BoundingBox, Center, TreeElementNode, TreeState
    from windows_mcp.uia.core import _AutomationClient

    user32 = ctypes.windll.user32
    titles = []
    proto = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def collect(hwnd, _l):
        length = user32.GetWindowTextLengthW(hwnd)
        if length:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            titles.append((hwnd, buf.value))
        return True

    user32.EnumWindows(proto(collect), 0)
    wanted = window_name.casefold()
    handles = [h for h, title in titles if wanted in title.casefold()]
    if not handles:
        return None

    nodes = []
    iua = _AutomationClient.instance().IUIAutomation
    from windows_mcp.uia.enums import ControlTypeNames

    for hwnd in handles:
        title = next((t for h, t in titles if h == hwnd), window_name)
        root = iua.ElementFromHandle(hwnd)
        if root is None:
            continue
        try:
            found = root.FindAll(4, iua.CreateTrueCondition())
        except Exception:
            continue
        for i in range(min(found.Length, 2000)):
            try:
                element = found.GetElement(i)
            except Exception:
                continue

            def read(attribute: str, default: Any = None) -> Any:
                """One property at a time.

                Reading them in a single try-block meant that the very common
                "this control type has no Value" COMError discarded the whole
                element — which silently emptied the node list and sent the
                verifier back to a 15-second full-desktop capture.
                """
                try:
                    value = getattr(element, attribute)
                except Exception:
                    return default
                return default if value is None else default

            rect = read("CurrentBoundingRectangle")
            if rect is None:
                continue
            width = max(rect.right - rect.left, 0)
            height = max(rect.bottom - rect.top, 0)
            nodes.append(
                TreeElementNode(
                    bounding_box=BoundingBox(
                        left=rect.left,
                        top=rect.top,
                        right=rect.right,
                        bottom=rect.bottom,
                        width=width,
                        height=height,
                    ),
                    center=Center(x=rect.left + width // 2, y=rect.top + height // 2),
                    name=read("CurrentName", ""),
                    # Same spelling the tree builder uses, so an expectation
                    # written for WaitFor (control_type "ButtonControl")
                    # matches here too.
                    control_type=ControlTypeNames.get(read("CurrentControlType"), ""),
                    window_name=title,
                    metadata={
                        "has_focused": bool(read("CurrentHasKeyboardFocus", False)),
                        "value": read("CurrentValue", "") or "",
                        "enabled": bool(read("CurrentIsEnabled", True)),
                    },
                )
            )
    if not nodes:
        return None
    # active_window must stay the truth: filling it with the scoped window would
    # make an `active_window` expectation hold no matter which window is focused.
    try:
        fg = user32.GetForegroundWindow()
        length = user32.GetWindowTextLengthW(fg)
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(fg, buffer, length + 1)
        foreground = buffer.value
    except Exception:
        foreground = ""
    return SimpleNamespace(
        tree_state=TreeState(interactive_nodes=nodes),
        active_window=SimpleNamespace(name=foreground),
        windows=[SimpleNamespace(name=title) for _hwnd, title in titles],
    )


def _sample(desktop: Any, expectation: Expectation) -> tuple[bool, str]:
    from windows_mcp.tools.input import _matches_wait_condition

    if expectation.window_name:
        scoped = _scoped_state(expectation.window_name)
        if scoped is not None:
            return _matches_wait_condition(
                desktop_state=scoped,
                condition=expectation.condition,
                text=expectation.text,
                window_name=expectation.window_name,
            )

    state = desktop.get_state(
        use_vision=False,
        use_dom=expectation.use_dom,
        use_ui_tree=True,
        use_annotation=False,
    )
    return _matches_wait_condition(
        desktop_state=state,
        condition=expectation.condition,
        text=expectation.text,
        window_name=expectation.window_name,
    )


def act_and_verify(action: Callable[[], str], expectation: Expectation | None, *, desktop: Any, tool: str) -> str:
    """Sample, run `action`, then prove the expected change is a *consequence* of it.

    With no expectation this is a bare passthrough, so tools that are not asked
    to verify cost nothing they did not cost before.
    """
    if expectation is None:
        return action()

    already, already_detail = _sample(desktop, expectation)
    result = action()

    started_at = time.monotonic()
    deadline = started_at + expectation.timeout
    attempts = 0
    matched, detail = False, "condition was not re-checked"
    while True:
        attempts += 1
        matched, detail = _sample(desktop, expectation)
        if matched:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(expectation.interval, remaining))

    elapsed = time.monotonic() - started_at
    if not matched:
        raise ActionUnverified(
            f"{tool} was performed but its effect was not observed: expected {expectation.describe()}, "
            f"and after {elapsed:.2f}s over {attempts} check(s) the UI reported: {detail}. "
            f"The action itself did run ({result}) — do not simply repeat it, since a second "
            "submit or delete may take effect twice. Inspect the state before deciding."
        )
    if already:
        return (
            f"{UNPROVEN_PREFIX}: {result}. The expectation ({expectation.describe()}) already "
            f"held before this action — {already_detail} — so it proves nothing about this action."
        )
    return f"{result} Verified in {elapsed:.2f}s over {attempts} check(s): {detail}."
