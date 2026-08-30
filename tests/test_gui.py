"""GUI behaviour, driven against a real (hidden) Tk instance."""
import json

import pytest

import felica_core as core
import nfc_reader_writer as app_module
from fake_card import DEFAULT_MC
from felica_core import BLOCK_CK, BLOCK_MC, BLOCK_REG

tk = pytest.importorskip("tkinter")


def row_values(app, block):
    return app.tree.item(str(block), "values")


def set_row_hex(app, block, hex_value):
    values = list(row_values(app, block))
    values[1] = hex_value
    app.tree.item(str(block), values=tuple(values))
    app._update_modified_status(str(block))


# ==============================================================================
# Start-up
# ==============================================================================
def test_the_table_lists_every_real_block(app):
    blocks = [int(iid) for iid in app.tree.get_children()]
    assert blocks == core.ALL_BLOCKS
    assert 15 not in blocks          # block 15 does not exist on a Lite-S card
    assert BLOCK_MC in blocks        # the MC block is 0x88, not 15


def test_editing_is_disabled_until_data_is_loaded(app):
    assert str(app.write_button["state"]) == "disabled"
    assert str(app.save_bin_button["state"]) == "disabled"
    assert str(app.lock_button["state"]) == "disabled"
    assert str(app.read_button["state"]) == "normal"


def test_loading_dummy_data_enables_the_controls(loaded_app):
    assert loaded_app.has_data_in_ui
    assert str(loaded_app.write_button["state"]) == "normal"
    assert str(loaded_app.lock_button["state"]) == "normal"


# ==============================================================================
# Populating the table
# ==============================================================================
def test_populate_accepts_a_block_dictionary(app):
    app._populate_dump_table({0: b"A" * 16, BLOCK_MC: DEFAULT_MC})
    assert row_values(app, 0)[1] == (b"A" * 16).hex().upper()
    assert row_values(app, BLOCK_MC)[1] == DEFAULT_MC.hex().upper()


def test_populate_accepts_a_flat_binary_dump(app):
    raw = bytes(range(16)) * 16          # 256 bytes: blocks 0..15
    app._populate_dump_table(raw)
    assert row_values(app, 0)[1] == raw[0:16].hex().upper()
    assert row_values(app, BLOCK_REG)[1] == raw[14 * 16:15 * 16].hex().upper()


def test_markers_are_shown_instead_of_fake_data(app):
    app._populate_dump_table({0: core.FAILED_MARKER, BLOCK_CK: core.SKIPPED_MARKER})
    assert row_values(app, 0)[1] == app_module.HEX_NA_FAILED
    assert row_values(app, BLOCK_CK)[1] == app_module.HEX_NA_SKIPPED
    # A marker row is never treated as a pending change.
    assert app._pending_data_changes() == {}


def test_access_rights_are_decoded_from_the_mc_block(app):
    handler = core.MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(3, "RW (W MAC)")
    app._populate_dump_table({BLOCK_MC: handler.generate_mc_block_data()})
    assert row_values(app, 3)[3] == "RW [WM]"
    assert app.mc_handler.needs_write_mac(3)


def test_a_locked_card_is_reported_and_disables_writing(app):
    locked = bytearray(DEFAULT_MC)
    locked[2] = 0x00
    app._populate_dump_table({BLOCK_MC: bytes(locked)})
    assert app.is_card_locked
    assert str(app.lock_button["state"]) == "disabled"
    assert str(app.write_key_button["state"]) == "disabled"


# ==============================================================================
# Editing
# ==============================================================================
def test_edited_blocks_become_pending_changes(loaded_app):
    set_row_hex(loaded_app, 2, "FF" * 16)
    assert loaded_app._pending_data_changes() == {2: "FF" * 16}
    assert "modified" in loaded_app.tree.item("2", "tags")


def test_system_blocks_are_never_offered_as_pending_changes(loaded_app):
    set_row_hex(loaded_app, BLOCK_MC, "AB" * 16)
    assert BLOCK_MC not in loaded_app._pending_data_changes()


def test_changing_access_rights_marks_the_row_and_stages_the_mc_block(loaded_app):
    loaded_app.mc_handler.set_access_mode_from_string(4, "RO")
    loaded_app._update_all_modified_statuses()
    assert loaded_app._mc_state_changed()
    assert "modified" in loaded_app.tree.item("4", "tags")


def test_cell_edit_rejects_bad_hex(loaded_app):
    original = row_values(loaded_app, 1)[1]
    entry = app_module.ttk.Entry(loaded_app.tree)
    entry.insert(0, "not hex")
    loaded_app._save_cell_edit("1", entry)
    assert row_values(loaded_app, 1)[1] == original


def test_cell_edit_accepts_good_hex_and_updates_the_ascii_column(loaded_app):
    entry = app_module.ttk.Entry(loaded_app.tree)
    entry.insert(0, "41" * 16)
    loaded_app._save_cell_edit("1", entry)
    assert row_values(loaded_app, 1)[1] == "41" * 16
    assert row_values(loaded_app, 1)[2] == "A" * 16


def test_transfer_from_the_converter_targets_the_selected_row(loaded_app):
    loaded_app.tree.focus("5")
    assert loaded_app.set_selected_block_hex("42" * 16)
    assert row_values(loaded_app, 5)[1] == "42" * 16


def test_transfer_refuses_a_system_block(loaded_app):
    loaded_app.tree.focus(str(BLOCK_MC))
    calls = []
    app_module.messagebox.showwarning = lambda *a, **k: calls.append(a)
    assert loaded_app.set_selected_block_hex("42" * 16) is False
    assert calls


def test_encoding_change_redecodes_the_ascii_column(loaded_app):
    set_row_hex(loaded_app, 6, "41" * 16)
    loaded_app._save_cell_edit("6", _entry_with(loaded_app, "41" * 16))
    loaded_app.encoding_var.set("utf-8")
    loaded_app._on_encoding_change()
    assert row_values(loaded_app, 6)[2] == "A" * 16


def _entry_with(app, text):
    entry = app_module.ttk.Entry(app.tree)
    entry.insert(0, text)
    return entry


# ==============================================================================
# Files
# ==============================================================================
def test_binary_dump_round_trip(loaded_app, tmp_path):
    set_row_hex(loaded_app, 3, "AA" * 16)
    path = tmp_path / "dump.bin"
    _save_bin(loaded_app, path)

    assert path.stat().st_size == core.FELICA_LITE_S_BYTES
    raw = path.read_bytes()
    assert raw[3 * 16:4 * 16] == b"\xAA" * 16

    fresh = loaded_app
    fresh._populate_dump_table(raw)
    assert row_values(fresh, 3)[1] == "AA" * 16


def _save_bin(app, path):
    app_module.filedialog.asksaveasfilename = lambda **kwargs: str(path)
    app.on_save_bin()


def _save_json(app, path):
    app_module.filedialog.asksaveasfilename = lambda **kwargs: str(path)
    app.on_save_json()


def test_json_round_trip_keeps_data_and_access_rights(loaded_app, tmp_path):
    loaded_app.mc_handler.set_access_mode_from_string(7, "RW (R Auth W MAC)")
    set_row_hex(loaded_app, 7, "CC" * 16)
    path = tmp_path / "state.json"
    _save_json(loaded_app, path)

    state = json.loads(path.read_text(encoding="utf-8"))
    assert state["format_version"] == app_module.JSON_FORMAT_VERSION
    assert state["data_blocks"]["BLOCK_7"] == "CC" * 16
    assert state["access_rights"]["BLOCK_7"]["W_MAC"] == 1
    assert state["card_info"]["idm"] == "0123456789ABCDEF"

    loaded_app.mc_handler.reset()
    app_module.filedialog.askopenfilename = lambda **kwargs: str(path)
    app_module.messagebox.askokcancel = lambda *a, **k: True
    loaded_app.on_load_json()

    assert row_values(loaded_app, 7)[1] == "CC" * 16
    assert loaded_app.mc_handler.r_auth_settings[7] == 1
    assert loaded_app.mc_handler.w_mac_settings[7] == 1
    assert loaded_app.entry_ckv.get() == "0000"


def test_loading_a_json_state_stages_everything_as_a_change(loaded_app, tmp_path):
    path = tmp_path / "state.json"
    _save_json(loaded_app, path)
    app_module.filedialog.askopenfilename = lambda **kwargs: str(path)
    app_module.messagebox.askokcancel = lambda *a, **k: True
    loaded_app.on_load_json()
    # The MC state is deliberately reset to "unknown", so writing the card
    # always includes the access rights from the file.
    assert loaded_app._mc_state_changed()


def test_loading_a_bin_file_of_the_wrong_size_is_reported(loaded_app, tmp_path):
    path = tmp_path / "bad.bin"
    path.write_bytes(b"\x00" * 17)
    app_module.filedialog.askopenfilename = lambda **kwargs: str(path)
    app_module.messagebox.askokcancel = lambda *a, **k: True
    errors = []
    app_module.messagebox.showerror = lambda *a, **k: errors.append(a)
    loaded_app.on_load_bin()
    assert errors


def test_loading_a_bin_file_keeps_the_system_blocks(loaded_app, tmp_path):
    original_mc = row_values(loaded_app, BLOCK_MC)[1]
    path = tmp_path / "user.bin"
    path.write_bytes(b"\x11" * core.FELICA_LITE_S_BYTES)
    app_module.filedialog.askopenfilename = lambda **kwargs: str(path)
    app_module.messagebox.askokcancel = lambda *a, **k: True
    loaded_app.on_load_bin()
    assert row_values(loaded_app, 0)[1] == "11" * 16
    assert row_values(loaded_app, BLOCK_MC)[1] == original_mc


def test_the_report_contains_the_access_table_and_the_dump(loaded_app):
    loaded_app.mc_handler.set_access_mode_from_string(1, "RO")
    text = "\n".join(loaded_app.build_report())
    assert "ACCESS RIGHTS" in text
    assert "S_PAD1" in text
    assert "BLOCK DUMP" in text
    assert "0123456789ABCDEF" in text
    # The card key is a UI field only and must not be exported.
    assert "CK (UI field)" not in text


# ==============================================================================
# Card operations in test mode
# ==============================================================================
def test_write_changes_without_changes_says_so(loaded_app):
    seen = []
    app_module.messagebox.showinfo = lambda *a, **k: seen.append(a)
    loaded_app.on_write_changes()
    assert seen and "No changes" in seen[0][0]


def test_simulated_write_adopts_the_new_baseline(loaded_app):
    set_row_hex(loaded_app, 8, "DD" * 16)
    app_module.messagebox.askokcancel = lambda *a, **k: True
    app_module.messagebox.showinfo = lambda *a, **k: None
    loaded_app.on_write_changes()
    assert loaded_app._pending_data_changes() == {}
    assert "modified" not in loaded_app.tree.item("8", "tags")


def test_a_write_that_needs_a_key_without_one_is_refused(loaded_app):
    loaded_app.mc_handler.set_access_mode_from_string(9, "RW (W Auth)")
    set_row_hex(loaded_app, 9, "EE" * 16)
    app_module.messagebox.askokcancel = lambda *a, **k: True
    errors = []
    app_module.messagebox.showerror = lambda *a, **k: errors.append(a)
    loaded_app.on_write_changes()
    assert errors and "Card key required" in errors[0][0]
    assert loaded_app._pending_data_changes() == {9: "EE" * 16}


def test_the_key_field_is_only_used_when_the_checkbox_is_ticked(app):
    app.set_card_key("00" * 16)
    assert app.key_bytes() is None
    app.use_auth_key_var.set(True)
    assert app.key_bytes() == b"\x00" * 16
    app.set_card_key("nonsense")
    assert app.key_bytes() is None


def test_writing_a_card_key_validates_the_input(app):
    errors = []
    app_module.messagebox.showerror = lambda *a, **k: errors.append(a)
    app.entry_ckv.delete(0, "end")
    app.entry_ckv.insert(0, "ZZZZ")
    app.on_write_key()
    assert errors and "CKV" in errors[0][1]


def test_locking_is_confirmed_twice_and_updates_the_status(loaded_app):
    app_module.messagebox.askokcancel = lambda *a, **k: True
    loaded_app.on_lock_card()
    loaded_app.update()
    assert loaded_app.is_card_locked
    assert loaded_app.info_labels["lock"]["text"] == "LOCKED"


def test_cancelling_the_lock_leaves_the_card_alone(loaded_app):
    app_module.messagebox.askokcancel = lambda *a, **k: False
    loaded_app.on_lock_card()
    assert not loaded_app.is_card_locked


# ==============================================================================
# Tool windows
# ==============================================================================
def test_the_key_generator_derives_a_stable_key(app):
    window = app_module.KeyGenWindow(app)
    window.idm_var.set("0123456789ABCDEF")
    window.password_var.set("secret")
    window.generate()
    first = window.result_var.get()
    assert core.is_hex(first, 32)
    window.generate()
    assert window.result_var.get() == first
    window.transfer()
    assert app.entry_key.get() == first


def test_the_key_generator_rejects_a_bad_idm(app):
    window = app_module.KeyGenWindow(app)
    errors = []
    app_module.messagebox.showerror = lambda *a, **k: errors.append(a)
    window.idm_var.set("nope")
    window.password_var.set("secret")
    window.generate()
    assert errors
    window.on_close()


def test_the_converter_pads_and_flags_overlong_text(app):
    window = app_module.AsciiHexConverterWindow(app)
    window.input_var.set("AB")
    window.on_change()
    assert window.output_var.get() == "4142" + "00" * 14
    window.input_var.set("x" * 20)
    window.on_change()
    assert "too long" in window.length_var.get()
    assert str(window.transfer_button["state"]) == "disabled"
    window.on_close()


# ==============================================================================
# Other tabs in test mode
# ==============================================================================
def test_the_type3_tab_explains_itself_in_test_mode(app):
    app.on_type3_scan()
    assert "Test mode" in app.t3_text.get("1.0", "end")


def test_type3_inputs_are_validated(app):
    errors = []
    app_module.messagebox.showerror = lambda *a, **k: errors.append(a)
    app.t3_service_entry.delete(0, "end")
    app.t3_service_entry.insert(0, "zz")
    assert app._t3_inputs() is None
    app.t3_service_entry.delete(0, "end")
    app.t3_service_entry.insert(0, "000B")
    app.t3_block_entry.delete(0, "end")
    app.t3_block_entry.insert(0, "-1")
    assert app._t3_inputs() is None
    app.t3_block_entry.delete(0, "end")
    app.t3_block_entry.insert(0, "2")
    assert app._t3_inputs(need_data=True) is None      # no data typed yet
    app.t3_data_entry.insert(0, "AA" * 16)
    assert app._t3_inputs(need_data=True) == (0x000B, 2, b"\xAA" * 16)
    assert len(errors) == 3


def test_the_ndef_table_is_filled_from_a_result(app):
    app._show_ndef({"formatted": True, "records": [{"kind": "Text", "text": "hi"}],
                    "length": 5, "capacity": 48, "writeable": True})
    rows = app.ndef_tree.get_children()
    assert len(rows) == 1
    assert app.ndef_tree.item(rows[0], "values") == ("Text", "hi")
    assert "5 of 48" in app.ndef_status_var.get()

    app._show_ndef({"formatted": False, "records": []})
    assert app.ndef_tree.get_children() == ()
    assert "no NDEF" in app.ndef_status_var.get()


def test_command_line_arguments_are_understood(monkeypatch, tmp_path):
    created = {}

    class FakeApp:
        def __init__(self, **kwargs):
            created.update(kwargs)

        def mainloop(self):
            return None

    monkeypatch.setattr(app_module, "NfcApp", FakeApp)
    app_module.main(["--test"])
    assert created == {"test_file": None, "test_mode": True, "device": "usb"}

    dump = tmp_path / "d.bin"
    dump.write_bytes(b"\x00" * 256)
    app_module.main(["--test", str(dump), "--device", "tty:USB0"])
    assert created["test_file"] == str(dump)
    assert created["device"] == "tty:USB0"


def test_test_mode_can_seed_the_table_from_a_file(app, tmp_path):
    dump = tmp_path / "seed.bin"
    dump.write_bytes(bytes([0x5A]) * 256)
    app.test_file_path = str(dump)
    try:
        app.load_dummy_data()
        app.update()
        assert row_values(app, 0)[1] == "5A" * 16
    finally:
        app.test_file_path = None


def test_a_broken_seed_file_is_only_logged(app, tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(bytes(5))
    app.test_file_path = str(bad)
    try:
        app.load_dummy_data()
        assert "Could not load the dummy file" in app.txt_log.get("1.0", "end")
        assert app.has_data_in_ui is False
    finally:
        app.test_file_path = None


def test_the_application_reports_a_missing_reader(app, monkeypatch):
    errors = []
    monkeypatch.setattr(app_module.messagebox, "showerror",
                        lambda *a, **k: errors.append(a))
    monkeypatch.setattr(app, "test_mode", False)
    monkeypatch.setattr(app, "nfc_controller", None)
    monkeypatch.setattr(app, "nfc_error", "nfcpy is not installed")

    assert app.nfc_ready is False
    app.on_read_card()

    assert errors and "nfcpy is not installed" in errors[0][1]
