"""`expect`: act, then prove the UI actually changed — or say it cannot be proven.

Without this, every input tool answered "Single left clicked at (x,y)." whether or
not anything happened, so an agent could mark a task complete on the strength of a
click that landed nowhere. The interesting cases are the two that are not a simple
pass/fail: a condition that was *already* true before the action (proves nothing,
must not read as success), and an action that ran while its effect never appeared
(must raise, and must not invite a blind retry that would take effect twice).
"""

import pytest

from windows_mcp.tools import verification
from windows_mcp.tools.verification import (
    ActionUnverified,
    act_and_verify,
    parse_expect,
)
from windows_mcp.tree.views import BoundingBox, Center, TreeElementNode, TreeState

TEXT = "已保存 4C1D"


def _state_with(*names: str) -> object:
    nodes = []
    for i, name in enumerate(names):
        nodes.append(
            TreeElementNode(
                bounding_box=BoundingBox(0, 0, 10, 10, 10, 10),
                center=Center(x=5, y=5),
                name=name,
                control_type="text",
                window_name="靶窗",
                metadata={},
            )
        )
    return type(
        "State",
        (),
        {
            "tree_state": TreeState(interactive_nodes=nodes),
            "active_window": None,
            "windows": [],
        },
    )()


class FakeDesktop:
    """Serves a scripted sequence of states and counts what it was asked for."""

    def __init__(self, *states) -> None:
        self.script = list(states)
        self.get_state_calls = 0
        self.click_calls = 0

    def get_state(self, **kwargs) -> object:
        self.get_state_calls += 1
        if len(self.script) > 1:
            return self.script.pop(0)
        return self.script[0] if self.script else _state_with()

    def click(self, **kwargs) -> None:
        self.click_calls += 1


EXPECT = {"condition": "text_exists", "text": TEXT}


@pytest.fixture(autouse=True)
def instant_clock(monkeypatch: pytest.MonkeyPatch) -> list:
    """Replace the poll clock so a timeout costs no real seconds."""
    now = [0.0]
    monkeypatch.setattr(verification.time, "monotonic", lambda: now[0])

    def fake_sleep(seconds):
        now[0] += seconds

    monkeypatch.setattr(verification.time, "sleep", fake_sleep)
    return now


# -- parsing ----------------------------------------------------------------


def test_absent_expectation_is_a_passthrough():
    assert parse_expect(None) is None
    assert parse_expect("") is None
    assert parse_expect("   ") is None


def test_json_string_is_accepted_because_clients_serialize_objects():
    parsed = parse_expect('{"condition": "text_exists", "text": "已保存"}')
    assert parsed.condition == "text_exists" and parsed.text == "已保存"


def test_waitfor_aliases_are_honoured():
    assert parse_expect({"condition": "window", "text": "靶窗"}).condition == "active_window"


def test_missing_and_unknown_arguments_are_rejected():
    with pytest.raises(ValueError, match="text is required"):
        parse_expect({"condition": "text_exists"})
    with pytest.raises(ValueError, match="condition must be one of"):
        parse_expect({"condition": "vibes"})
    with pytest.raises(ValueError, match="condition"):
        parse_expect({"text": "x"})
    with pytest.raises(ValueError, match="JSON object"):
        parse_expect("not json")
    with pytest.raises(ValueError, match="must be an object"):
        parse_expect(7)


def test_timeout_bounds_come_from_waitfor_validation():
    with pytest.raises(ValueError, match="timeout"):
        parse_expect({"condition": "text_exists", "text": TEXT, "timeout": 0})


# -- the three outcomes -----------------------------------------------------


def test_no_expectation_never_touches_the_state_reader():
    desktop = FakeDesktop(_state_with())
    result = act_and_verify(
        lambda: "Single left clicked at (1,2).", None, desktop=desktop, tool="Click"
    )
    assert result == "Single left clicked at (1,2)."
    assert desktop.get_state_calls == 0


# -- where the evidence comes from ------------------------------------------
#
# `get_state` re-captures the whole desktop (measured 9.6-16.1 s on this box), so
# a 3 s settle budget degenerates into a single check and the poll cannot follow
# a slow app at all. Naming a window scopes the search instead (~44 ms measured).
# These tests pin the routing rule; the scoping function itself only speaks to
# the live desktop and is covered by the live demo, not by a fake.


def test_a_named_window_uses_the_scoped_sample(monkeypatch: pytest.MonkeyPatch):
    calls = []
    # The before-sample must say absent and the after-sample present; a fake that
    # always says "present" correctly yields UNPROVEN, never Verified.
    def scoped(name: str):
        calls.append(name)
        return _state_with() if len(calls) == 1 else _state_with(TEXT)

    monkeypatch.setattr(verification, "_scoped_state", scoped)
    desktop = FakeDesktop(_state_with())
    result = act_and_verify(
        lambda: "Clicked.",
        parse_expect({"condition": "text_exists", "text": TEXT, "window_name": "靶窗"}),
        desktop=desktop,
        tool="Click",
    )
    assert calls == ["靶窗", "靶窗"] and "Verified" in result
    # The expensive full-desktop capture must not have been used at all.
    assert desktop.get_state_calls == 0


def test_an_unnamed_expectation_falls_back_to_the_full_capture(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(verification, "_scoped_state", lambda name: None)
    desktop = FakeDesktop(_state_with(), _state_with(TEXT))
    result = act_and_verify(
        lambda: "Clicked.", parse_expect(EXPECT), desktop=desktop, tool="Click"
    )
    assert "Verified" in result and desktop.get_state_calls >= 1


def test_verified_reports_the_evidence_and_when_it_appeared():
    desktop = FakeDesktop(_state_with(), _state_with(TEXT))
    result = act_and_verify(
        lambda: "Single left clicked at (1,2).",
        parse_expect(EXPECT),
        desktop=desktop,
        tool="Click",
    )
    assert result.startswith("Single left clicked at (1,2). Verified")
    assert "appeared" in result


def test_a_condition_that_preceded_the_action_is_reported_as_unproven():
    # This is the case a naive "check after acting" turns into a false success:
    # the text was already on screen, so it says nothing about the click.
    desktop = FakeDesktop(_state_with(TEXT))
    result = act_and_verify(
        lambda: "Pressed ctrl+s.", parse_expect(EXPECT), desktop=desktop, tool="Shortcut"
    )
    assert result.startswith(verification.UNPROVEN_PREFIX)
    assert "proves nothing" in result


def test_an_effect_that_never_shows_up_raises_instead_of_returning_praise():
    desktop = FakeDesktop(_state_with())
    with pytest.raises(ActionUnverified) as excinfo:
        act_and_verify(
            lambda: "Single left clicked at (1,2).",
            parse_expect(EXPECT),
            desktop=desktop,
            tool="Click",
        )
    message = str(excinfo.value)
    assert "was performed" in message and "not observed" in message
    # The agent must not conclude "retry the click": a second submit can land twice.
    assert "do not simply repeat it" in message


def test_a_slow_ui_is_polled_not_given_up_on():
    # Slot 1 is the before-sample (absent), slot 2 is the first poll (still
    # absent), slot 3 is the second poll where the app finally caught up.
    desktop = FakeDesktop(_state_with(), _state_with(), _state_with(TEXT))
    result = act_and_verify(
        lambda: "Typed.",
        parse_expect({"condition": "text_exists", "text": TEXT, "timeout": 5, "interval": 0.5}),
        desktop=desktop,
        tool="Type",
    )
    assert "over 2 check(s)" in result and "0.50s" in result
    assert desktop.get_state_calls == 3


def test_the_action_running_is_not_reversed_by_a_failed_expectation():
    desktop = FakeDesktop(_state_with())

    def perform() -> str:
        desktop.click(loc=[1, 2])
        return "clicked"

    with pytest.raises(ActionUnverified):
        act_and_verify(perform, parse_expect(EXPECT), desktop=desktop, tool="Click")
    assert desktop.click_calls == 1


def test_an_action_that_raises_propagates_without_reporting_unverified():
    desktop = FakeDesktop(_state_with())

    def explode() -> str:
        raise ValueError("input unavailable")

    with pytest.raises(ValueError, match="input unavailable"):
        act_and_verify(explode, parse_expect(EXPECT), desktop=desktop, tool="Click")


# -- wiring: the real registered tool functions, not the helper alone --------


class FakeMCP:
    def __init__(self) -> None:
        self.tools = {}

    def tool(self, *, name: str, **kwargs):
        def decorator(func):
            self.tools[name] = func
            return func

        return decorator


class ToolDesktop(FakeDesktop):
    def __init__(self, *states) -> None:
        super().__init__(*states)
        self.type_calls = []
        self.desktop_state = states[0] if states else _state_with()

    def type(self, **kwargs) -> None:
        self.type_calls.append(kwargs)


def _click_tool(desktop):
    from windows_mcp.tools.input import register

    mcp = FakeMCP()
    register(
        mcp,
        get_desktop=lambda: desktop,
        get_analytics=lambda: None,
        get_guard=lambda: _permissive_guard(),
    )
    return mcp.tools


def _permissive_guard():
    from windows_mcp.desktop.credential_guard import CredentialGuard

    return CredentialGuard(
        enabled=False,
        window_at=lambda x, y: 1,
        process_name=lambda h: None,
        window_title=lambda h: "",
        foreground_window=lambda: 0,
        password_at=lambda x, y: False,
        focused_password=lambda: False,
    )


async def test_click_tool_reports_verified_through_the_real_schema():
    desktop = ToolDesktop(_state_with(), _state_with(TEXT))
    tools = _click_tool(desktop)
    result = await tools["Click"](loc=[1, 2], expect={"condition": "text_exists", "text": TEXT})
    assert "Verified" in result and desktop.click_calls == 1


async def test_click_tool_without_expect_is_byte_identical_to_before():
    # Backward compatibility for every existing caller and script.
    desktop = ToolDesktop(_state_with())
    tools = _click_tool(desktop)
    result = await tools["Click"](loc=[1, 2])
    assert result == "Single left clicked at (1,2)."
    assert desktop.get_state_calls == 0


async def test_click_tool_raises_when_the_effect_never_appears():
    desktop = ToolDesktop(_state_with())
    tools = _click_tool(desktop)
    with pytest.raises(ActionUnverified):
        await tools["Click"](loc=[1, 2], expect='{"condition": "text_exists", "text": "不存在"}')
    assert desktop.click_calls == 1
