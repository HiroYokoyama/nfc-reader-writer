"""Mouse interaction with the block table, and the remaining UI plumbing.

The window has to be mapped for Tk to report cell geometry, so these tests
briefly show it and hide it again afterwards.
"""
import pytest

import felica_core as core
import nfc_reader_writer as app_module
from felica_core import BLOCK_CK, BLOCK_MC

tk = pytest.importorskip("tkinter")


class Event:
    """The two attributes the handlers read from a Tk event."""

    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.x_root = x + 100
        self.y_root = y + 100


@pytest.fixture
def visible_app(loaded_app):
    loaded_app.deiconify()
    loaded_app.update()
    loaded_app.update_idletasks()
    yield loaded_app
    loaded_app.on_tree_leave()
    loaded_app._destroy_cell_editors()
    loaded_app.withdraw()
    loaded_app.update()


def cell_event(app, block, column):
    app.tree.see(str(block))
    app.update_idletasks()
    box = app.tree.bbox(str(block), column)
    if not box:
        pytest.skip("the table row is not visible in this environment")
    return Event(box[0] + box[2] // 2, box[1] + box[3] // 2)


def editors(app, kind):
    return [w for w in app.tree.winfo_children() if isinstance(w, kind)]


# ==============================================================================
# Access-rights editing
# ==============================================================================
def test_clicking_the_access_column_opens_a_dropdown(visible_app):
    visible_app.on_tree_click(cell_event(visible_app, 3, "#4"))
    combos = editors(visible_app, app_module.ttk.Combobox)
    assert len(combos) == 1
    assert combos[0].get() == "RW"
    assert list(combos[0]["values"]) == core.MCBlockHandler.LITE_S_MODES


def test_choosing_a_mode_updates_the_row_and_the_handler(visible_app):
    visible_app.on_tree_click(cell_event(visible_app, 3, "#4"))
    combo = editors(visible_app, app_module.ttk.Combobox)[0]
    combo.set("RW (W MAC)")
    combo.event_generate("<<ComboboxSelected>>")
    visible_app.update()

    assert visible_app.mc_handler.needs_write_mac(3)
    assert visible_app.tree.item("3", "values")[3] == "RW [WM]"
    assert "modified" in visible_app.tree.item("3", "tags")
    assert editors(visible_app, app_module.ttk.Combobox) == []


def test_the_access_column_of_a_system_block_is_not_editable(visible_app):
    visible_app.on_tree_click(cell_event(visible_app, BLOCK_MC, "#4"))
    assert editors(visible_app, app_module.ttk.Combobox) == []


def test_a_locked_card_refuses_access_editing(visible_app):
    visible_app.is_card_locked = True
    try:
        visible_app.on_tree_click(cell_event(visible_app, 3, "#4"))
        assert editors(visible_app, app_module.ttk.Combobox) == []
        assert "locked card" in visible_app.txt_log.get("1.0", "end")
    finally:
        visible_app.is_card_locked = False


def test_clicking_selects_the_row(visible_app):
    visible_app.on_tree_click(cell_event(visible_app, 2, "#2"))
    assert visible_app.tree.focus() == "2"


# ==============================================================================
# Hex editing by double click
# ==============================================================================
def test_double_click_opens_an_editor_for_a_user_block(visible_app):
    visible_app.on_tree_double_click(cell_event(visible_app, 2, "#2"))
    entries = editors(visible_app, app_module.ttk.Entry)
    assert len(entries) == 1
    assert entries[0].get() == visible_app.tree.item("2", "values")[1]


def test_double_click_does_not_edit_a_system_block(visible_app):
    visible_app.on_tree_double_click(cell_event(visible_app, BLOCK_CK, "#2"))
    assert editors(visible_app, app_module.ttk.Entry) == []
    assert "not editable here" in visible_app.txt_log.get("1.0", "end")


def test_double_click_does_not_edit_a_read_only_block(visible_app):
    visible_app.mc_handler.set_access_mode_from_string(2, "RO")
    visible_app.on_tree_double_click(cell_event(visible_app, 2, "#2"))
    assert editors(visible_app, app_module.ttk.Entry) == []
    assert "read-only" in visible_app.txt_log.get("1.0", "end")


def test_double_click_on_a_locked_card_is_refused(visible_app):
    visible_app.is_card_locked = True
    try:
        visible_app.on_tree_double_click(cell_event(visible_app, 2, "#2"))
        assert editors(visible_app, app_module.ttk.Entry) == []
    finally:
        visible_app.is_card_locked = False


def test_double_click_on_the_ascii_column_copies_it(visible_app):
    visible_app.on_tree_double_click(cell_event(visible_app, 2, "#3"))
    assert visible_app.clipboard_get() == visible_app.tree.item("2", "values")[2]
    assert editors(visible_app, app_module.ttk.Entry) == []


def test_editing_is_ignored_before_any_data_is_loaded(app):
    app.deiconify()
    app.update()
    try:
        app.on_tree_double_click(Event(200, 60))
        app.on_tree_click(Event(200, 60))
        assert editors(app, app_module.ttk.Entry) == []
        assert editors(app, app_module.ttk.Combobox) == []
    finally:
        app.withdraw()


# ==============================================================================
# Tooltips
# ==============================================================================
def test_hovering_the_access_column_shows_a_tooltip(visible_app):
    visible_app.mc_handler.set_access_mode_from_string(4, "RW (R Auth W Auth)")
    visible_app.on_tree_motion(cell_event(visible_app, 4, "#4"))
    assert visible_app.tooltip_window is not None
    visible_app.on_tree_leave()
    assert visible_app.tooltip_window is None


def test_hovering_another_column_shows_nothing(visible_app):
    visible_app.on_tree_motion(cell_event(visible_app, 4, "#2"))
    assert visible_app.tooltip_window is None


def test_tooltip_text_explains_every_condition(app):
    app.mc_handler.set_access_mode_from_string(1, "RW (R Auth W Auth W MAC)")
    text = app._access_tooltip(1)
    assert "Read/Write" in text
    assert "reading requires authentication" in text
    assert "writing requires authentication" in text
    assert "writing requires a MAC" in text

    app.mc_handler.set_access_mode_from_string(1, "RO")
    assert "no authentication needed" in app._access_tooltip(1)
    assert app._access_tooltip(BLOCK_MC) == core.BLOCK_DESCRIPTIONS[BLOCK_MC]


# ==============================================================================
# Remaining plumbing
# ==============================================================================
def test_cancelled_file_dialogs_do_nothing(loaded_app, monkeypatch):
    monkeypatch.setattr(app_module.filedialog, "asksaveasfilename",
                        lambda **k: "")
    monkeypatch.setattr(app_module.filedialog, "askopenfilename",
                        lambda **k: "")
    before = loaded_app.txt_log.get("1.0", "end")
    loaded_app.on_save_bin()
    loaded_app.on_load_bin()
    loaded_app.on_save_json()
    loaded_app.on_load_json()
    loaded_app.on_export_report()
    loaded_app.on_type3_save()
    assert loaded_app.txt_log.get("1.0", "end") == before


def test_declining_the_confirmation_leaves_the_table_alone(loaded_app, tmp_path,
                                                          monkeypatch):
    path = tmp_path / "other.bin"
    path.write_bytes(b"\x99" * core.FELICA_LITE_S_BYTES)
    monkeypatch.setattr(app_module.filedialog, "askopenfilename",
                        lambda **k: str(path))
    monkeypatch.setattr(app_module.messagebox, "askokcancel", lambda *a, **k: False)
    before = loaded_app.tree.item("0", "values")[1]
    loaded_app.on_load_bin()
    assert loaded_app.tree.item("0", "values")[1] == before


def test_report_export_writes_the_file(loaded_app, tmp_path, monkeypatch):
    path = tmp_path / "report.txt"
    monkeypatch.setattr(app_module.filedialog, "asksaveasfilename",
                        lambda **k: str(path))
    loaded_app.on_export_report()
    text = path.read_text(encoding="utf-8")
    assert "card report" in text
    assert "S_PAD0" in text


def test_explorer_report_export_writes_the_file(app, tmp_path, monkeypatch):
    path = tmp_path / "explorer.txt"
    monkeypatch.setattr(app_module.filedialog, "asksaveasfilename",
                        lambda **k: str(path))
    app.t3_text.delete("1.0", "end")
    app.t3_text.insert("1.0", "System 0003\n")
    app.on_type3_save()
    assert "System 0003" in path.read_text(encoding="utf-8")


def test_reading_the_idm_in_test_mode_fills_the_target(app):
    holder = tk.StringVar(master=app)
    app.read_card_info(target=holder)
    app._poll_queue()
    assert holder.get() == "0123456789ABCDEF"
    assert app.info_labels["idm"]["text"] == "0123456789ABCDEF"


def test_about_dialog_mentions_the_version(app, monkeypatch):
    seen = []
    monkeypatch.setattr(app_module.messagebox, "showinfo",
                        lambda *a, **k: seen.append(a))
    app.show_about()
    assert app_module.APP_VERSION in seen[0][1]


def test_reset_state_clears_everything(loaded_app):
    loaded_app.set_card_key("AB" * 16)
    loaded_app.mc_handler.set_access_mode_from_string(1, "RO")

    loaded_app.reset_state()

    assert loaded_app.has_data_in_ui is False
    assert loaded_app.entry_key.get() == ""
    assert loaded_app.mc_handler.rw_ro_settings[1] == 1
    assert loaded_app.info_labels["idm"]["text"] == "-"
    assert str(loaded_app.write_button["state"]) == "disabled"


def test_the_key_field_visibility_toggles(app):
    app.set_card_key("00" * 16)
    assert str(app.entry_key["show"]) == "*"
    app.show_key_var.set(True)
    app.toggle_key_visibility()
    assert str(app.entry_key["show"]) == ""


def test_hex_to_ascii_falls_back_when_decoding_fails():
    assert app_module.hex_to_ascii(b"AB" + bytes(14), "utf-8").startswith("AB")
    assert app_module.hex_to_ascii(b"\x81\x40" + bytes(14), "shift_jis")[0] != "\x81"
