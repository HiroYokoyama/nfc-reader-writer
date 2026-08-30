"""Error paths and edge cases of the card layer."""
import nfc.tag.tt3 as tt3
import nfc.tag.tt3_sony as sony
import pytest

import felica_core as core
from fake_card import (FakeLiteS, FakeStandard, install_fake_reader, make_target)
from felica_core import BLOCK_CKV, BLOCK_MC, CardError, MCBlockHandler


@pytest.fixture
def controller():
    messages = []
    ctrl = core.NfcController(logger=lambda level, text: messages.append((level, text)))
    ctrl.messages = messages
    return ctrl


def attach(monkeypatch, tag, **kwargs):
    return install_fake_reader(monkeypatch, core, tag, **kwargs)


# ==============================================================================
# Helpers
# ==============================================================================
def test_is_hex_rejects_an_odd_number_of_characters():
    assert not core.is_hex("ABC")
    assert not core.is_hex("AB", 3)
    assert core.is_hex("AB")


def test_card_key_helpers_validate_their_input():
    with pytest.raises(ValueError):
        core.encode_card_key(b"\x00" * 15)
    with pytest.raises(ValueError):
        core.decode_ckv(b"\x01")


def test_access_mode_helpers_ignore_out_of_range_blocks():
    handler = MCBlockHandler()
    assert handler.get_access_mode_string(99) == ""
    assert handler.get_access_mode_string(-1) == ""
    before = handler.state_snapshot()
    handler.set_access_mode_from_string(99, "RO")
    assert handler.state_snapshot() == before
    assert handler.is_read_only(99) is False
    assert handler.needs_read_auth(99) is False


def test_state_snapshots_can_be_restored():
    handler = MCBlockHandler()
    handler.set_access_mode_from_string(2, "RO")
    handler.set_access_mode_from_string(3, "RW (W MAC)")
    snapshot = handler.state_snapshot()

    handler.reset()
    assert handler.rw_ro_settings[2] == 1

    handler.load_state(snapshot)
    assert handler.rw_ro_settings[2] == 0
    assert handler.w_mac_settings[3] == 1

    partial = MCBlockHandler()
    partial.load_state({})       # missing keys keep the current values
    assert partial.rw_ro_settings == [1] * 15


def test_generate_ignores_bit_positions_outside_the_managed_range():
    handler = MCBlockHandler()
    handler.max_blocks = 16      # one block more than MC can address
    handler.rw_ro_settings.append(1)
    handler.r_auth_settings.append(1)
    handler.w_auth_settings.append(1)
    handler.w_mac_settings.append(1)
    mc = handler.generate_mc_block_data()
    assert mc[0] == 0xFF and mc[1] & 0x7F == 0x7F


# ==============================================================================
# Tag classification
# ==============================================================================
def test_every_felica_family_member_is_classified():
    kinds = {}
    for ic_code, expected in ((0xF1, core.KIND_LITE_S), (0xF0, core.KIND_LITE),
                              (0x20, core.KIND_STANDARD)):
        target = make_target(ic_code=ic_code)
        tag = sony.activate(None, target)
        kinds[expected] = core.describe_tag(tag)["kind"]
    assert kinds == {k: k for k in kinds}


def test_a_mobile_felica_is_recognised():
    tag = sony.FelicaMobile(None, make_target(ic_code=0x06))
    info = core.describe_tag(tag)
    assert info["kind"] == core.KIND_MOBILE
    assert info["supports_block_editor"] is False
    assert info["supports_auth"] is False


def test_a_plain_type3_tag_is_recognised():
    target = make_target(ic_code=0xEE)     # an IC nfcpy has no class for
    tag = tt3.Type3Tag(None, target)
    info = core.describe_tag(tag)
    assert info["kind"] == core.KIND_TYPE3
    assert info["kind_label"] == "NFC Forum Type 3"


def test_the_controller_refuses_to_start_without_nfcpy(monkeypatch):
    monkeypatch.setattr(core, "NFC_AVAILABLE", False)
    monkeypatch.setattr(core, "NFC_IMPORT_ERROR", ImportError("no module"))
    with pytest.raises(ImportError) as excinfo:
        core.NfcController()
    assert "no module" in str(excinfo.value)


# ==============================================================================
# Connection handling
# ==============================================================================
def test_a_sense_that_raises_is_retried_until_the_timeout(monkeypatch, controller):
    tag = FakeLiteS()
    frontend = attach(monkeypatch, tag)
    calls = []

    def angry_sense(*targets, **kwargs):
        calls.append(1)
        raise OSError("usb hiccup")

    frontend.sense = angry_sense
    result = controller.get_card_info(timeout=0.2)

    assert result["ok"] is False
    assert "Timeout" in result["error"]
    assert calls


def test_a_failing_activation_reports_the_traceback(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)

    def boom(clf, target):
        raise RuntimeError("activation exploded")

    monkeypatch.setattr(core.nfc.tag, "activate", boom)
    result = controller.get_card_info(timeout=0.5)

    assert result["ok"] is False
    assert "activation exploded" in result["error"]


def test_an_unactivatable_target_is_reported(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    monkeypatch.setattr(core.nfc.tag, "activate", lambda clf, target: None)

    result = controller.get_card_info(timeout=0.5)

    assert result["ok"] is False
    assert "Failed to activate" in result["error"]


def test_a_non_type3_tag_is_rejected_by_the_felica_operations(monkeypatch,
                                                              controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    monkeypatch.setattr(core.nfc.tag, "activate", lambda clf, target: object())

    result = controller.get_card_info(timeout=0.5)

    assert result["ok"] is False
    assert "not a FeliCa" in result["error"]


def test_run_any_accepts_a_tag_of_any_technology(monkeypatch, controller):
    plain = object()
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    monkeypatch.setattr(core.nfc.tag, "activate", lambda clf, target: plain)

    def op(activated, result):
        result["data"] = activated
        result["ok"] = True
        result["error"] = ""

    result = controller.run_any(op, timeout=0.5)

    assert result["ok"]
    assert result["data"] is plain


def test_a_missing_reader_is_reported_clearly(monkeypatch, controller):
    def no_reader(path):
        raise IOError("no such device")

    monkeypatch.setattr(core.nfc, "ContactlessFrontend", no_reader)
    result = controller.get_card_info()

    assert result["ok"] is False
    assert "NFC reader not found" in result["error"]


def test_an_unexpected_frontend_error_is_captured(monkeypatch, controller):
    def broken(path):
        raise ValueError("something else entirely")

    monkeypatch.setattr(core.nfc, "ContactlessFrontend", broken)
    result = controller.get_card_info()

    assert result["ok"] is False
    assert "something else entirely" in result["error"]


def test_a_broken_logger_never_breaks_an_operation(monkeypatch):
    def angry_logger(level, text):
        raise RuntimeError("the log is on fire")

    controller = core.NfcController(logger=angry_logger)
    install_fake_reader(monkeypatch, core, FakeLiteS())

    assert controller.read_card()["ok"]


# ==============================================================================
# Card responses
# ==============================================================================
def test_a_card_that_returns_nothing_is_reported(monkeypatch, controller):
    tag = FakeLiteS()
    tag.read_without_encryption = lambda *a, **k: None
    attach(monkeypatch, tag)

    result = controller.read_card(blocks=[0])

    assert result["ok"]                       # the read as a whole completes
    assert result["data"]["blocks"][0] == core.FAILED_MARKER
    assert any("read failed" in text for _level, text in controller.messages)


def test_a_tag_without_an_authenticate_method_says_so(controller):
    with pytest.raises(CardError) as excinfo:
        controller._authenticate(object(), b"\x00" * 16)
    assert "does not support authentication" in str(excinfo.value)


def test_a_card_that_refuses_authentication_is_reported(monkeypatch, controller):
    handler = MCBlockHandler()
    handler.set_access_mode_from_string(1, "RW (W Auth)")
    tag = FakeStandard()                      # a Standard card has no card key
    attach(monkeypatch, tag)

    result = controller.write_blocks([(1, b"X" * 16)], mc_handler=handler,
                                     key_bytes=b"\x00" * 16)

    assert result["ok"] is False
    assert "Authentication failed" in result["error"]


def test_a_failed_mac_verification_marks_the_block(monkeypatch, controller):
    handler = MCBlockHandler()
    handler.parse_mc_block_data(
        FakeLiteS().mc)                       # start from the card defaults
    handler.set_access_mode_from_string(2, "RW (R Auth)")
    tag = FakeLiteS(mc=handler.generate_mc_block_data())
    attach(monkeypatch, tag)
    # Only the data block fails its MAC; authentication itself still works.
    genuine = tag.read_with_mac
    tag.read_with_mac = lambda *blocks: None if 2 in blocks else genuine(*blocks)

    result = controller.read_card(blocks=[2], key_bytes=b"\x00" * 16)

    assert result["data"]["authenticated"] is True
    assert result["data"]["blocks"][2] == core.FAILED_MARKER


def test_a_write_whose_readback_fails_is_still_accepted(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    real_read = tag.read_without_encryption
    state = {"first": True}

    def flaky_read(service_list, block_list):
        if state["first"]:
            state["first"] = False
            raise tt3.Type3TagCommandError(0x01A2)
        return real_read(service_list, block_list)

    tag.read_without_encryption = flaky_read
    result = controller.write_blocks([(1, b"R" * 16)])

    assert result["ok"], result["error"]
    assert tag.storage[1] == b"R" * 16


def test_a_card_that_ignores_the_ckv_write_is_reported(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    real_store = tag._store

    def skip_ckv(number, payload):
        if number == BLOCK_CKV:
            return
        real_store(number, payload)

    tag._store = skip_ckv
    result = controller.write_card_key(b"\x01" * 16, 0x0042)

    assert result["ok"] is False
    assert "CKV verification failed" in result["error"]


def test_a_card_that_ignores_the_lock_is_reported(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    real_store = tag._store

    def skip_mc(number, payload):
        if number == BLOCK_MC:
            return
        real_store(number, payload)

    tag._store = skip_mc
    result = controller.lock_card()

    assert result["ok"] is False
    assert "did not accept the lock" in result["error"]


def test_reading_a_card_whose_mc_block_is_unreadable_falls_back(monkeypatch,
                                                                controller):
    tag = FakeLiteS()
    del tag.storage[BLOCK_MC]
    attach(monkeypatch, tag)

    result = controller.read_card(blocks=[0, BLOCK_MC])

    assert result["ok"]
    assert result["data"]["blocks"][BLOCK_MC] == core.FAILED_MARKER
    assert any("Could not read the MC block" in text
               for _level, text in controller.messages)
