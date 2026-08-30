"""The GUI's card operations, driven end-to-end against the card simulator.

These tests run the same code path a user gets with a real reader: the button
handler, the background worker, the controller, nfcpy's protocol layer and the
simulated card. Only the reader hardware and the thread are stubbed out.
"""
import pytest

import felica_core as core
import felica_type3 as t3
import ndef_tools
import nfc_reader_writer as app_module
from fake_card import (DEFAULT_MC, FakeLite, FakeLiteS, FakeStandard,
                       install_fake_reader, ndef_blocks)
from felica_core import BLOCK_CK, BLOCK_CKV, BLOCK_MC

tk = pytest.importorskip("tkinter")

KEY = bytes(range(16))


class ImmediateThread:
    """Runs the worker inline so the test stays deterministic."""

    def __init__(self, target=None, daemon=None, args=(), kwargs=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


@pytest.fixture
def wired(app, monkeypatch):
    """The session app, wired to a simulated card instead of a reader."""
    monkeypatch.setattr(app_module.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(app, "test_mode", False)

    def use(tag):
        install_fake_reader(monkeypatch, core, tag)
        install_fake_reader(monkeypatch, t3, tag)
        controller = core.NfcController(
            logger=lambda level, text: app.out_q.put(("LOG", (level, text))))
        monkeypatch.setattr(app, "nfc_controller", controller)
        monkeypatch.setattr(app, "explorer", t3.Type3Explorer(controller))
        monkeypatch.setattr(app, "ndef_manager", ndef_tools.NdefManager(controller))
        return tag

    app.use_card = use
    return app


def drain(app):
    """Process everything the worker queued, as the timer would."""
    app._poll_queue()
    app.update()


def row_hex(app, block):
    return app.tree.item(str(block), "values")[1]


def set_row_hex(app, block, hex_value):
    values = list(app.tree.item(str(block), "values"))
    values[1] = hex_value
    app.tree.item(str(block), values=tuple(values))
    app._update_modified_status(str(block))


# ==============================================================================
# Reading
# ==============================================================================
def test_reading_a_card_fills_the_table_and_the_card_panel(wired):
    wired.use_card(FakeLiteS(blocks={0: b"A" * 16, 9: b"J" * 16}))

    wired.on_read_card()
    drain(wired)

    assert row_hex(wired, 0) == (b"A" * 16).hex().upper()
    assert row_hex(wired, 9) == (b"J" * 16).hex().upper()
    assert row_hex(wired, BLOCK_MC) == DEFAULT_MC.hex().upper()
    assert row_hex(wired, BLOCK_CK) == app_module.HEX_NA_SKIPPED
    assert wired.info_labels["idm"]["text"] == "0102030405060708"
    assert wired.info_labels["lock"]["text"] == "Unlocked"
    assert wired.has_data_in_ui
    assert wired._pending_data_changes() == {}


def test_reading_shows_the_access_rights_of_the_card(wired):
    handler = core.MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(5, "RO")
    handler.set_access_mode_from_string(6, "RW (R Auth W MAC)")
    wired.use_card(FakeLiteS(mc=handler.generate_mc_block_data()))

    wired.on_read_card()
    drain(wired)

    assert wired.tree.item("5", "values")[3] == "RO"
    assert wired.tree.item("6", "values")[3] == "RW [RA WM]"
    assert not wired._mc_state_changed()


def test_reading_a_locked_card_disables_the_dangerous_buttons(wired):
    locked = bytearray(DEFAULT_MC)
    locked[2] = 0x00
    wired.use_card(FakeLiteS(mc=bytes(locked)))

    wired.on_read_card()
    drain(wired)

    assert wired.is_card_locked
    assert str(wired.lock_button["state"]) == "disabled"


def test_reading_a_standard_card_points_at_the_explorer(wired, monkeypatch):
    infos = []
    monkeypatch.setattr(app_module.messagebox, "showinfo",
                        lambda *a, **k: infos.append(a))
    wired.use_card(FakeStandard())

    wired.on_read_card()
    drain(wired)

    assert infos and "Type 3 Explorer" in infos[0][1]


def test_a_plain_lite_card_only_offers_rw_and_ro(wired):
    wired.use_card(FakeLite())

    wired.on_read_card()
    drain(wired)

    assert wired.card_kind == core.KIND_LITE
    assert wired.mc_handler.available_modes() == ["RW", "RO"]


def test_a_read_protected_block_needs_the_key_from_the_panel(wired):
    handler = core.MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(2, "RW (R Auth)")
    wired.use_card(FakeLiteS(blocks={2: b"S" * 16}, card_key=KEY,
                             mc=handler.generate_mc_block_data()))

    wired.on_read_card()
    drain(wired)
    assert row_hex(wired, 2) == app_module.HEX_NA_FAILED

    wired.set_card_key(KEY.hex().upper())
    wired.use_auth_key_var.set(True)
    wired.on_read_card()
    drain(wired)
    assert row_hex(wired, 2) == (b"S" * 16).hex().upper()


def test_a_reader_error_is_shown_to_the_user(wired, monkeypatch):
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    tag = FakeLiteS()
    wired.use_card(tag)
    install_fake_reader(monkeypatch, core, tag, sense_failures=10000)

    wired.nfc_controller.read_card = lambda **kwargs: {
        "ok": False, "error": "Timeout: no card detected.", "data": None}
    wired.on_read_card()
    drain(wired)

    assert errors and "Timeout" in errors[0][1]
    assert wired.busy is False


# ==============================================================================
# Writing
# ==============================================================================
def _confirm(monkeypatch):
    monkeypatch.setattr(app_module.messagebox, "askokcancel",
                        lambda *a, **k: True)
    monkeypatch.setattr(app_module.messagebox, "showinfo", lambda *a, **k: None)


def test_writing_edited_blocks_reaches_the_card(wired, monkeypatch):
    tag = wired.use_card(FakeLiteS())
    _confirm(monkeypatch)
    wired.on_read_card()
    drain(wired)

    set_row_hex(wired, 4, "AB" * 16)
    wired.on_write_changes()
    drain(wired)

    assert tag.storage[4] == b"\xAB" * 16
    assert wired._pending_data_changes() == {}
    assert "modified" not in wired.tree.item("4", "tags")


def test_changing_access_rights_writes_the_mc_block(wired, monkeypatch):
    tag = wired.use_card(FakeLiteS())
    _confirm(monkeypatch)
    wired.on_read_card()
    drain(wired)

    wired.mc_handler.set_access_mode_from_string(3, "RO")
    wired._update_all_modified_statuses()
    wired.on_write_changes()
    drain(wired)

    assert tag.is_read_only(3)
    assert not wired._mc_state_changed()
    assert row_hex(wired, BLOCK_MC) == tag.mc.hex().upper()


def test_the_mc_write_keeps_the_bytes_the_app_does_not_manage(wired, monkeypatch):
    custom_mc = bytes([0xFF, 0x7F, 0xFF, 0x01, 0x07, 0x01] + [0] * 10)
    tag = wired.use_card(FakeLiteS(mc=custom_mc))
    _confirm(monkeypatch)
    wired.on_read_card()
    drain(wired)

    wired.mc_handler.set_access_mode_from_string(1, "RO")
    wired._update_all_modified_statuses()
    wired.on_write_changes()
    drain(wired)

    assert tag.mc[2:6] == custom_mc[2:6]


def test_a_failing_write_is_reported_and_nothing_is_adopted(wired, monkeypatch):
    tag = wired.use_card(FakeLiteS())
    _confirm(monkeypatch)
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    wired.on_read_card()
    drain(wired)

    tag.write_without_encryption = lambda *a, **k: None  # a card that ignores writes
    set_row_hex(wired, 4, "AB" * 16)
    wired.on_write_changes()
    drain(wired)

    assert errors and "verification failed" in errors[0][1]
    assert wired._pending_data_changes() == {4: "AB" * 16}


def test_an_authenticated_write_uses_the_key_from_the_panel(wired, monkeypatch):
    handler = core.MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(8, "RW (W MAC)")
    tag = wired.use_card(FakeLiteS(card_key=KEY,
                                   mc=handler.generate_mc_block_data()))
    _confirm(monkeypatch)
    wired.on_read_card()
    drain(wired)

    wired.set_card_key(KEY.hex().upper())
    wired.use_auth_key_var.set(True)
    set_row_hex(wired, 8, "77" * 16)
    wired.on_write_changes()
    drain(wired)

    assert tag.storage[8] == b"\x77" * 16


def test_writing_the_card_key_updates_ck_and_ckv(wired, monkeypatch):
    tag = wired.use_card(FakeLiteS())
    _confirm(monkeypatch)

    wired.entry_ckv.delete(0, "end")
    wired.entry_ckv.insert(0, "0007")
    wired.set_card_key(KEY.hex().upper())
    wired.on_write_key()
    drain(wired)

    assert tag.card_key == KEY
    assert core.decode_ckv(tag.storage[BLOCK_CKV]) == 7
    assert dict(tag.write_log)[BLOCK_CK] == core.encode_card_key(KEY)


def test_locking_the_card_sets_mc_two_and_updates_the_panel(wired, monkeypatch):
    tag = wired.use_card(FakeLiteS())
    _confirm(monkeypatch)
    wired.on_read_card()
    drain(wired)

    wired.on_lock_card()
    drain(wired)

    assert tag.mc[2] == 0x00
    assert wired.is_card_locked
    assert wired.info_labels["lock"]["text"] == "LOCKED"


# ==============================================================================
# The other tabs
# ==============================================================================
def test_the_explorer_tab_lists_systems_and_services(wired):
    wired.use_card(FakeStandard())

    wired.t3_read_data_var.set(True)
    wired.on_type3_scan()
    drain(wired)

    text = wired.t3_text.get("1.0", "end")
    assert "System 0003" in text
    assert "Service 000B" in text
    assert "System 12FC" in text


def test_the_explorer_reads_a_single_block_into_the_data_field(wired):
    wired.use_card(FakeStandard())
    wired.t3_service_entry.delete(0, "end")
    wired.t3_service_entry.insert(0, "000B")
    wired.t3_block_entry.delete(0, "end")
    wired.t3_block_entry.insert(0, "2")

    wired.on_type3_read_block()
    drain(wired)

    assert wired.t3_data_entry.get() == (bytes([2]) * 16).hex().upper()


def test_the_explorer_writes_a_single_block(wired, monkeypatch):
    tag = wired.use_card(FakeStandard())
    _confirm(monkeypatch)
    wired.t3_service_entry.delete(0, "end")
    wired.t3_service_entry.insert(0, "0009")
    wired.t3_block_entry.delete(0, "end")
    wired.t3_block_entry.insert(0, "1")
    wired.t3_data_entry.delete(0, "end")
    wired.t3_data_entry.insert(0, "5A" * 16)

    wired.on_type3_write_block()
    drain(wired)

    assert tag.blocks[0x0009][1] == b"\x5A" * 16


def test_the_ndef_tab_reads_and_writes_records(wired, monkeypatch):
    import ndef

    message = b"".join(ndef.message_encoder([ndef.TextRecord("hello", "en")]))
    wired.use_card(FakeLiteS(blocks=ndef_blocks(message)))

    wired.on_ndef_read()
    drain(wired)
    rows = wired.ndef_tree.get_children()
    assert wired.ndef_tree.item(rows[0], "values") == ("Text", "hello  [en]")

    wired.ndef_kind_var.set("uri")
    wired.ndef_value_entry.delete(0, "end")
    wired.ndef_value_entry.insert(0, "https://example.com")
    wired.on_ndef_write()
    drain(wired)

    wired.on_ndef_read()
    drain(wired)
    rows = wired.ndef_tree.get_children()
    assert wired.ndef_tree.item(rows[0], "values") == ("URI", "https://example.com")


def test_the_ndef_tab_formats_an_empty_tag(wired, monkeypatch):
    _confirm(monkeypatch)
    wired.use_card(FakeLiteS())

    wired.on_ndef_format()
    drain(wired)

    assert "0 record(s)" in wired.ndef_status_var.get()


def test_an_unexpected_worker_error_is_surfaced(wired, monkeypatch):
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    wired.use_card(FakeLiteS())

    def explode(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(wired.nfc_controller, "read_card", explode)
    wired.on_read_card()
    drain(wired)

    assert errors and "boom" in errors[0][1]
    assert wired.busy is False


def test_two_operations_cannot_run_at_once(wired, monkeypatch):
    infos = []
    monkeypatch.setattr(app_module.messagebox, "showinfo",
                        lambda *a, **k: infos.append(a))
    wired.busy = True
    try:
        assert wired._run_worker(lambda: None) is False
        assert infos and "Busy" in infos[0][0]
    finally:
        wired.busy = False
