"""The credential gate: typing goes nowhere near a password field.

windows-mcp's desktop ownership gate answers "is the human idle?" and nothing
else, so an agent that clears it can type into a bank login form, drive
LogonUI, or paste a secret into a vault. Before this module the tree marked a
field ``is_password`` and then typed into it like any other — the signal was
read and used only for rendering.

These tests pin the three rules (IsPassword target, credential-looking window
title, credential/manager process) plus the two deliberate weaknesses: an
unresolvable window fails *open* (blocking every click on a hit-test hiccup
would be worse than the risk), and browsers are exempt from the title rule
because "登录" in a page title is the normal shape of the web.
"""

from collections.abc import Callable
from types import SimpleNamespace

import pytest

from windows_mcp.desktop import credential_guard
from windows_mcp.desktop.credential_guard import (
    CredentialBlocked,
    CredentialGuard,
)
from windows_mcp.tree.views import BoundingBox, Center, TreeElementNode, TreeState
from windows_mcp.tools.input import register as register_input
from windows_mcp.tools.multi import register as register_multi

FIELD_BOX = (100, 200, 300, 224)  # left, top, right, bottom
FIELD_CENTER = (200, 212)


def _node(*, password: bool = False, focused: bool = False, box=FIELD_BOX) -> TreeElementNode:
    left, top, right, bottom = box
    metadata: dict[str, object] = {}
    if password:
        metadata["is_password"] = True
    if focused:
        metadata["has_focused"] = True
    return TreeElementNode(
        bounding_box=BoundingBox(
            left=left,
            top=top,
            right=right,
            bottom=bottom,
            width=right - left,
            height=bottom - top,
        ),
        center=Center(x=(left + right) // 2, y=(top + bottom) // 2),
        name="密码",
        control_type="edit",
        window_name="示例",
        metadata=metadata,
    )


def _state(*nodes: TreeElementNode) -> SimpleNamespace:
    return SimpleNamespace(tree_state=TreeState(interactive_nodes=list(nodes)))


def _guard(
    *,
    process: str | None = "notepad.exe",
    title: str = "",
    hwnd: int = 1,
    password_at: Callable[[int, int], bool | None] | None = None,
    focused_password: Callable[[], bool | None] | None = None,
    **kwargs: object,
) -> CredentialGuard:
    """A guard whose Win32 *and* UIA lookups are all fakes.

    Both password probes default to None ("could not answer") so these tests
    exercise the snapshot fallback; a test that returns True or False says so
    explicitly rather than letting the real desktop decide the outcome.
    """
    kwargs.setdefault("window_at", lambda x, y: hwnd)
    kwargs.setdefault("process_name", lambda h: process)
    kwargs.setdefault("window_title", lambda h: title)
    kwargs.setdefault("foreground_window", lambda: hwnd)
    return CredentialGuard(
        password_at=password_at or (lambda x, y: None),
        focused_password=focused_password or (lambda: None),
        **kwargs,  # type: ignore[arg-type]
    )


# -- rule 1: the field the OS itself marks as a password --------------------


def test_typing_into_a_password_field_is_refused():
    guard = _guard()
    with pytest.raises(CredentialBlocked, match="IsPassword"):
        guard.check_input(
            *FIELD_CENTER, tool="Type", state=_state(_node(password=True))
        )


def test_clicking_a_password_field_is_allowed():
    # Focus is not disclosure: refusing the click would stop an agent from
    # asking the human to type, which is the intended hand-off.
    _guard().check_input(
        *FIELD_CENTER, tool="Click", state=_state(_node(password=True))
    )


def test_typing_into_an_ordinary_field_is_allowed():
    _guard().check_input(*FIELD_CENTER, tool="Type", state=_state(_node()))


def test_coordinate_string_from_claude_desktop_is_still_checked():
    guard = _guard()
    with pytest.raises(CredentialBlocked, match="IsPassword"):
        guard.check_input("200", "212", tool="Type", state=_state(_node(password=True)))


# The UIA probe is the primary witness because the snapshot tree is budgeted:
# a real WinForms password box passed every interactive filter and still never
# reached interactive_nodes once the 500-element cap was spent elsewhere.


def test_uia_probe_refuses_even_with_no_snapshot_at_all():
    guard = _guard(password_at=lambda x, y: True)
    with pytest.raises(CredentialBlocked, match="UIA reports"):
        guard.check_input(*FIELD_CENTER, tool="Type", state=None)


def test_uia_probe_answer_wins_over_an_empty_tree():
    guard = _guard(password_at=lambda x, y: True)
    with pytest.raises(CredentialBlocked, match="UIA reports"):
        guard.check_input(*FIELD_CENTER, tool="Type", state=_state(_node()))


def test_uia_saying_no_is_not_overruled_by_a_stale_node():
    # A field that stopped being a password box should not stay blocked forever
    # just because an older snapshot still says so.
    _guard(password_at=lambda x, y: False).check_input(
        *FIELD_CENTER, tool="Type", state=_state(_node(password=True))
    )


def test_focused_uia_probe_also_gates_shortcuts():
    guard = _guard(focused_password=lambda: True)
    with pytest.raises(CredentialBlocked, match="focused element"):
        guard.check_foreground(tool="Shortcut", state=None)


def test_a_stale_snapshot_cannot_hide_a_password_field_from_the_process_rule():
    # The window rules do not read the snapshot at all, so skipping Snapshot is
    # not a way to reach LogonUI.
    guard = _guard(process="LogonUI.exe")
    with pytest.raises(CredentialBlocked, match="denylist"):
        guard.check_input(*FIELD_CENTER, tool="Click", state=None)


# -- rule 2: credential-looking titles --------------------------------------


@pytest.mark.parametrize("title", ["Sign in", "输入凭据", "User Account Control"])
def test_typing_into_a_credential_dialog_title_is_refused(title: str):
    guard = _guard(title=title)
    with pytest.raises(CredentialBlocked, match="credential prompt"):
        guard.check_input(*FIELD_CENTER, tool="Type", state=_state(_node()))


def test_windows_security_center_is_left_to_the_process_rule():
    # A title rule cannot claim that surface: "Windows 安全中心" is a shell over
    # many pages, some of which are harmless. AuthHost.exe / CredentialUIBroker
    # are what actually block it, and they do block it.
    guard = _guard(title="Windows 安全中心")
    guard.check_input(*FIELD_CENTER, tool="Type", state=_state(_node()))
    blocked = _guard(title="Windows 安全中心", process="AuthHost.exe")
    with pytest.raises(CredentialBlocked, match="denylist"):
        blocked.check_input(*FIELD_CENTER, tool="Type", state=_state(_node()))


def test_a_click_is_not_blocked_by_the_title_rule():
    _guard(title="登录").check_input(*FIELD_CENTER, tool="Click", state=_state(_node()))


def test_browsers_are_exempt_from_the_title_rule():
    # A page titled "登录" is the ordinary web; IsPassword still guards the field.
    guard = _guard(process="chrome.exe", title="登录 - Chrome")
    guard.check_input(*FIELD_CENTER, tool="Type", state=_state(_node()))


def test_browsers_still_refuse_a_password_field():
    guard = _guard(process="chrome.exe", title="登录 - Chrome")
    with pytest.raises(CredentialBlocked, match="IsPassword"):
        guard.check_input(*FIELD_CENTER, tool="Type", state=_state(_node(password=True)))


# -- rule 3: credential and vault processes ----------------------------------


@pytest.mark.parametrize(
    "process",
    ["LogonUI.exe", "CredentialUIBroker.exe", "AuthHost.exe", "KeePass.exe", "Bitwarden.exe"],
)
def test_denied_processes_block_every_kind_of_input(process: str):
    guard = _guard(process=process)
    for tool in ("Click", "Type", "Scroll", "Move"):
        with pytest.raises(CredentialBlocked, match="denylist"):
            guard.check_input(*FIELD_CENTER, tool=tool, state=_state(_node()))


def test_shortcut_is_refused_while_a_vault_is_foreground():
    guard = _guard(process="KeePassXC.exe")
    with pytest.raises(CredentialBlocked, match="focused window"):
        guard.check_foreground(tool="Shortcut", state=None)


def test_shortcut_is_refused_when_the_caret_sits_in_a_password_field():
    # ctrl+v pastes a secret just as well as Type would have typed it.
    guard = _guard()
    with pytest.raises(CredentialBlocked, match="IsPassword"):
        guard.check_foreground(tool="Shortcut", state=_state(_node(password=True, focused=True)))


def test_shortcut_is_allowed_when_the_focused_field_is_ordinary():
    _guard().check_foreground(tool="Shortcut", state=_state(_node(focused=True)))


def test_an_unresolvable_window_fails_open():
    # WindowFromPoint returning 0 must not turn into "block everything": the
    # gate guards credential surfaces, not the whole desktop.
    _guard(hwnd=0, process=None).check_input(*FIELD_CENTER, tool="Type", state=_state(_node()))


def test_prefix_is_never_matched_without_a_glob_character():
    # "keepass.exe" as a deny entry must not swallow an unrelated "keepass.exe.bak".
    guard = _guard(process="notepad.exe.bak")
    guard.check_input(*FIELD_CENTER, tool="Click", state=None)


def test_glob_in_a_user_supplied_entry_does_broaden_the_match():
    guard = CredentialGuard(
        deny_processes={"bitwarden*.exe"},
        window_at=lambda x, y: 1,
        process_name=lambda h: "bitwarden-1.40.0.exe",
        window_title=lambda h: "",
        foreground_window=lambda: 1,
    )
    with pytest.raises(CredentialBlocked, match="denylist"):
        guard.check_input(*FIELD_CENTER, tool="Click", state=None)


# -- configuration -----------------------------------------------------------


def test_guard_can_be_turned_off_entirely():
    guard = CredentialGuard.from_env({"WINDOWS_MCP_CREDENTIAL_GUARD": "off"})
    assert guard.enabled is False
    guard.check_input(*FIELD_CENTER, tool="Type", state=_state(_node(password=True)))


def test_password_fields_can_be_allowed_explicitly():
    guard = CredentialGuard.from_env({"WINDOWS_MCP_ALLOW_PASSWORD_FIELDS": "1"})
    assert guard.block_password_fields is False
    guard.check_input(*FIELD_CENTER, tool="Type", state=_state(_node(password=True)))


def test_extra_deny_entries_are_honoured():
    guard = CredentialGuard.from_env({"WINDOWS_MCP_CREDENTIAL_DENY": "MyBank.exe"})
    assert "mybank.exe" in guard.deny_processes
    guard.check_input(*FIELD_CENTER, tool="Click", state=None)


def test_default_reads_the_real_environment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("WINDOWS_MCP_CREDENTIAL_GUARD", raising=False)
    assert CredentialGuard.from_env().enabled is True


# -- wiring into the MCP tools ----------------------------------------------


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Callable] = {}

    def tool(self, *, name: str, **kwargs: object) -> Callable:
        def decorator(func: Callable) -> Callable:
            self.tools[name] = func
            return func

        return decorator


class FakeDesktop:
    def __init__(self, state: SimpleNamespace | None = None) -> None:
        self.desktop_state = state if state is not None else object()
        self.type_calls: list[dict[str, object]] = []
        self.edit_calls: list[object] = []

    def type(self, **kwargs: object) -> None:
        self.type_calls.append(kwargs)

    def multi_edit(self, locs: object) -> None:
        self.edit_calls.append(locs)


def _tools(desktop: FakeDesktop, guard: CredentialGuard) -> dict[str, Callable]:
    """Register the real tools against a fake desktop and a fake guard.

    Both collaborators are injected, so these tests never read the live screen:
    the gate hit-tests real windows when it is left at its default, and a test
    must not pass or fail because of whatever happened to be under (200, 212).
    """
    mcp = FakeMCP()
    register_input(
        mcp, get_desktop=lambda: desktop, get_analytics=lambda: None, get_guard=lambda: guard
    )
    register_multi(
        mcp, get_desktop=lambda: desktop, get_analytics=lambda: None, get_guard=lambda: guard
    )
    return mcp.tools


@pytest.fixture
def patched_guard() -> CredentialGuard:
    return _guard()


async def test_type_tool_refuses_before_any_key_reaches_the_desktop(
    patched_guard: CredentialGuard,
):
    desktop = FakeDesktop(_state(_node(password=True)))
    tools = _tools(desktop, patched_guard)
    with pytest.raises(CredentialBlocked):
        await tools["Type"](text="hunter2", loc=list(FIELD_CENTER))
    assert desktop.type_calls == []


async def test_type_tool_still_works_on_an_ordinary_field(patched_guard: CredentialGuard):
    desktop = FakeDesktop(_state(_node()))
    tools = _tools(desktop, patched_guard)
    await tools["Type"](text="hello", loc=list(FIELD_CENTER))
    assert desktop.type_calls


async def test_multi_edit_refuses_the_whole_batch_not_part_of_it(
    patched_guard: CredentialGuard,
):
    # Half a form filled is worse than none: the refusal must land before the
    # first field is written.
    desktop = FakeDesktop(
        _state(_node(password=False), _node(password=True, box=(100, 400, 300, 424)))
    )
    tools = _tools(desktop, patched_guard)
    with pytest.raises(CredentialBlocked):
        await tools["MultiEdit"](locs=[[150, 200, "user"], [200, 412, "hunter2"]])
    assert desktop.edit_calls == []


def test_get_guard_is_a_lazy_singleton(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(credential_guard, "_guard", None)
    first = credential_guard.get_guard()
    assert credential_guard.get_guard() is first
