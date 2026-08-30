import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _pin_tcl_library():
    """Give Tcl an absolute library path.

    Creating and destroying dozens of Tk roots in one process occasionally
    leaves Tcl unable to find init.tcl again ("Can't find a usable init.tcl"),
    which made GUI tests skip at random. Pinning the paths up front removes the
    search entirely.
    """
    if os.environ.get("TCL_LIBRARY"):
        return
    base = os.path.join(sys.base_prefix, "tcl")
    if not os.path.isdir(base):
        return
    for name, prefix in (("TCL_LIBRARY", "tcl"), ("TK_LIBRARY", "tk")):
        # Only versioned directories (tcl8.6, tk8.6) hold init.tcl / tk.tcl;
        # the unversioned "tcl8" module directory does not.
        pattern = re.compile(r"^%s\d+\.\d+$" % prefix)
        for entry in sorted(os.listdir(base), reverse=True):
            if pattern.match(entry) and os.path.isdir(os.path.join(base, entry)):
                os.environ[name] = os.path.join(base, entry)
                break


_pin_tcl_library()


import pytest  # noqa: E402  (the Tcl paths must be pinned before Tk is imported)

import nfc_reader_writer as app_module  # noqa: E402

tk = pytest.importorskip("tkinter")


@pytest.fixture(autouse=True)
def isolated_dialogs(monkeypatch):
    """No test may leave a patched dialog behind for the next one."""
    for name in ("showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(app_module.messagebox, name,
                            lambda *a, **k: None, raising=False)
    monkeypatch.setattr(app_module.messagebox, "askokcancel",
                        lambda *a, **k: False, raising=False)
    for name in ("asksaveasfilename", "askopenfilename"):
        monkeypatch.setattr(app_module.filedialog, name,
                            lambda **k: "", raising=False)


@pytest.fixture(scope="session")
def session_app():
    """One application instance for the whole session.

    Building and tearing down a Tk interpreter per test makes Tcl finalise
    itself at unpredictable moments, after which a fresh Tk() fails; reusing a
    single root and resetting it between tests avoids that entirely.
    """
    try:
        instance = app_module.NfcApp(test_mode=True)
    except tk.TclError as exc:  # pragma: no cover - no display available
        pytest.skip("no Tk display available: %s" % exc)
    instance.withdraw()
    instance.update()
    yield instance
    instance.destroy()


@pytest.fixture
def app(session_app):
    session_app.reset_state()
    session_app.clear_log()
    session_app.update()
    return session_app


@pytest.fixture
def loaded_app(app):
    app.load_dummy_data()
    app.update()
    return app


