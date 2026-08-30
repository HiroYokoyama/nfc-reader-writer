"""The tool windows, and the dialogs the main window shows on failure."""
import pytest

import felica_core as core
import felica_type3 as t3
import ndef_tools
import nfc_reader_writer as app_module
from fake_card import FakeLiteS, install_fake_reader
from felica_core import BLOCK_MC

tk = pytest.importorskip("tkinter")


@pytest.fixture
def keygen(app):
    window = app_module.KeyGenWindow(app)
    yield window
    if window.winfo_exists():
        window.on_close()


@pytest.fixture
def converter(app):
    window = app_module.AsciiHexConverterWindow(app)
    yield window
    if window.winfo_exists():
        window.on_close()


# ==============================================================================
# Key generator
# ==============================================================================
def test_the_key_generator_starts_from_the_card_idm(loaded_app):
    window = app_module.KeyGenWindow(loaded_app)
    try:
        assert window.idm_var.get() == "0123456789ABCDEF"
    finally:
        window.on_close()


def test_a_missing_passphrase_is_refused(keygen, monkeypatch):
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    keygen.idm_var.set("0123456789ABCDEF")
    keygen.password_var.set("")
    keygen.generate()
    assert errors and "passphrase" in errors[0][1]


def test_different_passphrases_give_different_keys(keygen):
    keygen.idm_var.set("0123456789ABCDEF")
    keygen.password_var.set("one")
    keygen.generate()
    first = keygen.result_var.get()
    keygen.password_var.set("two")
    keygen.generate()
    assert keygen.result_var.get() != first


def test_copying_before_generating_warns(keygen, monkeypatch):
    warnings = []
    monkeypatch.setattr(app_module.messagebox, "showwarning",
                        lambda *a, **k: warnings.append(a))
    keygen.copy()
    keygen.transfer()
    assert len(warnings) == 2


def test_copying_a_generated_key_reaches_the_clipboard(keygen, app):
    keygen.idm_var.set("0123456789ABCDEF")
    keygen.password_var.set("secret")
    keygen.generate()
    keygen.copy()
    assert app.clipboard_get() == keygen.result_var.get()
    assert "copied to the clipboard" in app.txt_log.get("1.0", "end")


def test_reading_the_idm_from_the_tool_window(keygen):
    keygen.read_idm()
    keygen.app._poll_queue()
    assert keygen.idm_var.get() == "0123456789ABCDEF"


# ==============================================================================
# Text to HEX converter
# ==============================================================================
def test_the_converter_reports_an_encoding_error(converter):
    converter.encoding_var.set("shift_jis")
    converter.input_var.set("😀")
    converter.on_change()
    assert converter.output_var.get() == "Encoding error"
    assert str(converter.copy_button["state"]) == "disabled"


def test_the_converter_copies_to_the_clipboard(converter, app):
    converter.input_var.set("hello")
    converter.on_change()
    converter.copy()
    assert app.clipboard_get() == converter.output_var.get()


def test_the_converter_transfers_into_the_selected_block(loaded_app):
    window = app_module.AsciiHexConverterWindow(loaded_app)
    try:
        loaded_app.tree.focus("6")
        window.input_var.set("Hi")
        window.on_change()
        window.transfer()
        assert loaded_app.tree.item("6", "values")[1].startswith("4869")
        assert not window.winfo_exists()
    finally:
        if window.winfo_exists():
            window.on_close()


def test_the_converter_refuses_to_transfer_without_data(app, monkeypatch):
    window = app_module.AsciiHexConverterWindow(app)
    try:
        warnings = []
        monkeypatch.setattr(app_module.messagebox, "showwarning",
                            lambda *a, **k: warnings.append(a))
        window.input_var.set("x")
        window.on_change()
        window.transfer()
        assert warnings                      # no card data loaded yet
        assert window.winfo_exists()
    finally:
        window.on_close()


def test_the_converter_refuses_to_transfer_without_a_selection(loaded_app,
                                                               monkeypatch):
    window = app_module.AsciiHexConverterWindow(loaded_app)
    try:
        warnings = []
        monkeypatch.setattr(app_module.messagebox, "showwarning",
                            lambda *a, **k: warnings.append(a))
        loaded_app.tree.selection_remove(loaded_app.tree.get_children())
        loaded_app.tree.focus("")
        window.input_var.set("x")
        window.on_change()
        window.transfer()
        assert warnings and "Select a block" in warnings[0][1]
    finally:
        window.on_close()


# ==============================================================================
# Failure dialogs of the main window
# ==============================================================================
def _wire(app, monkeypatch, tag):
    class ImmediateThread:
        def __init__(self, target=None, daemon=None, args=(), kwargs=None):
            self._target = target

        def start(self):
            self._target()

    monkeypatch.setattr(app_module.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(app, "test_mode", False)
    install_fake_reader(monkeypatch, core, tag)
    install_fake_reader(monkeypatch, t3, tag)
    controller = core.NfcController(
        logger=lambda level, text: app.out_q.put(("LOG", (level, text))))
    monkeypatch.setattr(app, "nfc_controller", controller)
    monkeypatch.setattr(app, "explorer", t3.Type3Explorer(controller))
    monkeypatch.setattr(app, "ndef_manager", ndef_tools.NdefManager(controller))
    return controller


def test_a_failed_key_write_is_reported(app, monkeypatch):
    tag = FakeLiteS()
    controller = _wire(app, monkeypatch, tag)
    monkeypatch.setattr(app_module.messagebox, "askokcancel", lambda *a, **k: True)
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    monkeypatch.setattr(controller, "write_card_key", lambda *a, **k: {
        "ok": False, "error": "the card refused the key", "data": None})

    app.set_card_key("00" * 16)
    app.on_write_key()
    app._poll_queue()

    assert errors and "refused the key" in errors[0][1]


def test_a_failed_lock_is_reported(app, monkeypatch):
    tag = FakeLiteS()
    controller = _wire(app, monkeypatch, tag)
    monkeypatch.setattr(app_module.messagebox, "askokcancel", lambda *a, **k: True)
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    monkeypatch.setattr(controller, "lock_card", lambda *a, **k: {
        "ok": False, "error": "already locked", "data": None})

    app.on_lock_card()
    app._poll_queue()

    assert errors and "already locked" in errors[0][1]
    assert app.is_card_locked is False


def test_a_failed_scan_is_reported(app, monkeypatch):
    tag = FakeLiteS()
    _wire(app, monkeypatch, tag)
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    monkeypatch.setattr(app.explorer, "explore", lambda **k: {
        "ok": False, "error": "no card", "data": None})

    app.on_type3_scan()
    app._poll_queue()

    assert errors and "no card" in errors[0][1]


def test_a_failed_raw_read_is_only_logged(app, monkeypatch):
    tag = FakeLiteS()
    _wire(app, monkeypatch, tag)
    monkeypatch.setattr(app.explorer, "read", lambda *a, **k: {
        "ok": False, "error": "service missing", "data": None})

    app.t3_service_entry.delete(0, "end")
    app.t3_service_entry.insert(0, "000B")
    app.t3_block_entry.delete(0, "end")
    app.t3_block_entry.insert(0, "0")
    app.on_type3_read_block()
    app._poll_queue()

    assert "service missing" in app.txt_log.get("1.0", "end")


def test_a_failed_raw_write_is_reported(app, monkeypatch):
    tag = FakeLiteS()
    _wire(app, monkeypatch, tag)
    monkeypatch.setattr(app_module.messagebox, "askokcancel", lambda *a, **k: True)
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    monkeypatch.setattr(app.explorer, "write", lambda *a, **k: {
        "ok": False, "error": "write refused", "data": None})

    app.t3_service_entry.delete(0, "end")
    app.t3_service_entry.insert(0, "0009")
    app.t3_block_entry.delete(0, "end")
    app.t3_block_entry.insert(0, "0")
    app.t3_data_entry.delete(0, "end")
    app.t3_data_entry.insert(0, "AA" * 16)
    app.on_type3_write_block()
    app._poll_queue()

    assert errors and "write refused" in errors[0][1]


def test_a_declined_raw_write_does_nothing(app, monkeypatch):
    tag = FakeLiteS()
    _wire(app, monkeypatch, tag)
    calls = []
    monkeypatch.setattr(app.explorer, "write",
                        lambda *a, **k: calls.append(a) or {"ok": True})
    monkeypatch.setattr(app_module.messagebox, "askokcancel", lambda *a, **k: False)

    app.t3_data_entry.delete(0, "end")
    app.t3_data_entry.insert(0, "AA" * 16)
    app.on_type3_write_block()

    assert calls == []


def test_a_failed_ndef_read_and_write_are_reported(app, monkeypatch):
    tag = FakeLiteS()
    _wire(app, monkeypatch, tag)
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    monkeypatch.setattr(app.ndef_manager, "read", lambda **k: {
        "ok": False, "error": "no tag", "data": None})
    monkeypatch.setattr(app.ndef_manager, "write", lambda *a, **k: {
        "ok": False, "error": "tag is full", "data": None})
    monkeypatch.setattr(app.ndef_manager, "format", lambda **k: {
        "ok": False, "error": "cannot format", "data": None})
    monkeypatch.setattr(app_module.messagebox, "askokcancel", lambda *a, **k: True)

    app.on_ndef_read()
    app._poll_queue()
    app.ndef_value_entry.delete(0, "end")
    app.ndef_value_entry.insert(0, "text")
    app.on_ndef_write()
    app._poll_queue()
    app.on_ndef_format()
    app._poll_queue()

    assert [e[1] for e in errors] == ["no tag", "tag is full", "cannot format"]


def test_writing_ndef_without_a_value_is_refused(app, monkeypatch):
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    app.ndef_value_entry.delete(0, "end")
    app.on_ndef_write()
    assert errors and "Enter the text" in errors[0][1]


def test_a_declined_format_does_nothing(app, monkeypatch):
    calls = []
    monkeypatch.setattr(app_module.messagebox, "askokcancel", lambda *a, **k: False)
    monkeypatch.setattr(app, "ndef_manager", None)
    app.on_ndef_format()                     # would explode if it went further
    assert calls == []


def test_a_declined_write_confirmation_keeps_the_changes_pending(loaded_app,
                                                                 monkeypatch):
    monkeypatch.setattr(app_module.messagebox, "askokcancel", lambda *a, **k: False)
    values = list(loaded_app.tree.item("2", "values"))
    values[1] = "BB" * 16
    loaded_app.tree.item("2", values=tuple(values))
    loaded_app._update_modified_status("2")

    loaded_app.on_write_changes()

    assert loaded_app._pending_data_changes() == {2: "BB" * 16}


def test_writing_to_a_locked_card_is_refused(loaded_app, monkeypatch):
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    loaded_app.mc_handler.set_access_mode_from_string(1, "RO")
    loaded_app._apply_lock_status(True)
    try:
        loaded_app.on_write_changes()
        assert errors and "permanently locked" in errors[0][1]
    finally:
        loaded_app._apply_lock_status(False)


def test_the_mc_row_is_refreshed_after_an_access_rights_write(loaded_app):
    loaded_app.mc_handler.set_access_mode_from_string(5, "RO")
    loaded_app._after_successful_write({}, True)
    expected = loaded_app.mc_handler.generate_mc_block_data().hex().upper()
    assert loaded_app.tree.item(str(BLOCK_MC), "values")[1] == expected
    assert not loaded_app._mc_state_changed()
