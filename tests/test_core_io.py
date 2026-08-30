"""Reader-level operations, exercised against the in-memory card simulators.

The simulators only replace the transport, so authentication, ``read_with_mac``
and ``write_with_mac`` run nfcpy's real implementation here.
"""
import pytest

import felica_core as core
from felica_core import (BLOCK_CK, BLOCK_CKV, BLOCK_MC, MCBlockHandler,
                         NfcController, decode_ckv, encode_card_key)
from fake_card import (DEFAULT_MC, FakeLite, FakeLiteS, FakeStandard,
                       install_fake_reader)

KEY = bytes(range(16))


@pytest.fixture
def controller():
    messages = []
    ctrl = NfcController(logger=lambda level, text: messages.append((level, text)))
    ctrl.messages = messages
    return ctrl


def attach(monkeypatch, tag):
    return install_fake_reader(monkeypatch, core, tag)


# ==============================================================================
# Reading
# ==============================================================================
def test_read_card_returns_every_block_and_card_info(monkeypatch, controller):
    tag = FakeLiteS(blocks={0: b"A" * 16, 5: b"E" * 16})
    attach(monkeypatch, tag)

    result = controller.read_card()

    assert result["ok"], result["error"]
    data = result["data"]
    assert data["info"]["kind"] == core.KIND_LITE_S
    assert data["info"]["idm"] == "0102030405060708"
    assert data["info"]["sys_code"] == "88B4"
    assert data["info"]["supports_block_editor"] is True
    assert data["blocks"][0] == b"A" * 16
    assert data["blocks"][5] == b"E" * 16
    assert data["blocks"][BLOCK_MC] == DEFAULT_MC
    # The card key is never readable, so it is reported as skipped.
    assert data["blocks"][BLOCK_CK] == core.SKIPPED_MARKER


def test_read_card_marks_unreadable_blocks_as_failed(monkeypatch, controller):
    tag = FakeLiteS()
    del tag.storage[3]  # simulate a block the card refuses
    attach(monkeypatch, tag)

    blocks = controller.read_card()["data"]["blocks"]

    assert blocks[3] == core.FAILED_MARKER
    assert blocks[4] == bytes(16)


def test_read_card_uses_the_key_for_read_protected_blocks(monkeypatch, controller):
    handler = MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(2, "RW (R Auth)")
    tag = FakeLiteS(blocks={2: b"S" * 16}, card_key=KEY,
                    mc=handler.generate_mc_block_data())
    attach(monkeypatch, tag)

    without_key = controller.read_card()["data"]
    assert without_key["authenticated"] is False
    assert without_key["blocks"][2] == core.FAILED_MARKER

    with_key = controller.read_card(key_bytes=KEY)["data"]
    assert with_key["authenticated"] is True
    assert with_key["blocks"][2] == b"S" * 16


def test_read_card_reports_a_wrong_key_but_still_returns_data(monkeypatch,
                                                              controller):
    handler = MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(2, "RW (R Auth)")
    tag = FakeLiteS(card_key=KEY, mc=handler.generate_mc_block_data())
    attach(monkeypatch, tag)

    result = controller.read_card(key_bytes=b"\xFF" * 16)

    assert result["ok"]
    assert result["data"]["authenticated"] is False
    assert any("Authentication failed" in text
               for _level, text in controller.messages)


def test_read_card_survives_a_card_that_never_appears(monkeypatch, controller):
    tag = FakeLiteS()
    frontend = install_fake_reader(monkeypatch, core, tag, sense_failures=1000)
    result = controller.read_card(timeout=0.2)
    assert result["ok"] is False
    assert "Timeout" in result["error"]
    assert frontend.closed


def test_plain_lite_cards_are_recognised(monkeypatch, controller):
    attach(monkeypatch, FakeLite())
    info = controller.read_card()["data"]["info"]
    assert info["kind"] == core.KIND_LITE
    assert info["supports_write_mac"] is False
    assert info["supports_block_editor"] is True


def test_standard_cards_are_recognised_but_not_editable(monkeypatch, controller):
    attach(monkeypatch, FakeStandard())
    info = controller.get_card_info()["data"]
    assert info["kind"] == core.KIND_STANDARD
    assert info["supports_block_editor"] is False


# ==============================================================================
# Writing
# ==============================================================================
def test_write_blocks_writes_and_verifies(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)

    result = controller.write_blocks([(1, b"1" * 16), (2, b"2" * 16)])

    assert result["ok"], result["error"]
    assert result["data"] == [1, 2]
    assert tag.storage[1] == b"1" * 16
    assert tag.storage[2] == b"2" * 16


def test_write_verification_failure_is_reported(monkeypatch, controller):
    tag = FakeLiteS()

    def swallow(service_list, block_list, data):
        return None  # a card that silently ignores writes

    tag.write_without_encryption = swallow
    attach(monkeypatch, tag)

    result = controller.write_blocks([(1, b"1" * 16)])

    assert result["ok"] is False
    assert "verification failed" in result["error"]
    assert "all zero" in result["error"]


def test_write_to_a_read_only_block_fails(monkeypatch, controller):
    handler = MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(4, "RO")
    tag = FakeLiteS(mc=handler.generate_mc_block_data())
    attach(monkeypatch, tag)

    result = controller.write_blocks([(4, b"X" * 16)], mc_handler=handler)

    assert result["ok"] is False
    assert tag.storage[4] == bytes(16)


def test_authenticated_write_uses_the_card_key(monkeypatch, controller):
    handler = MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(6, "RW (W Auth)")
    tag = FakeLiteS(card_key=KEY, mc=handler.generate_mc_block_data())
    attach(monkeypatch, tag)

    refused = controller.write_blocks([(6, b"N" * 16)], mc_handler=handler)
    assert refused["ok"] is False
    assert "no card key" in refused["error"]

    accepted = controller.write_blocks([(6, b"Y" * 16)], mc_handler=handler,
                                       key_bytes=KEY)
    assert accepted["ok"], accepted["error"]
    assert tag.storage[6] == b"Y" * 16


def test_mac_protected_write_goes_through_write_with_mac(monkeypatch, controller):
    handler = MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(7, "RW (W MAC)")
    tag = FakeLiteS(card_key=KEY, mc=handler.generate_mc_block_data())
    attach(monkeypatch, tag)

    result = controller.write_blocks([(7, b"M" * 16)], mc_handler=handler,
                                     key_bytes=KEY)

    assert result["ok"], result["error"]
    assert tag.storage[7] == b"M" * 16
    # Lite-S mutual authentication itself performs a MAC'd write to the STATE
    # block, so the counter has advanced at least twice.
    assert tag.write_count >= 2
    assert (7, b"M" * 16) in tag.write_log


def test_a_wrong_key_cannot_write_a_mac_protected_block(monkeypatch, controller):
    handler = MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(7, "RW (W MAC)")
    tag = FakeLiteS(card_key=KEY, mc=handler.generate_mc_block_data())
    attach(monkeypatch, tag)

    result = controller.write_blocks([(7, b"M" * 16)], mc_handler=handler,
                                     key_bytes=b"\x01" * 16)

    assert result["ok"] is False
    assert tag.storage[7] == bytes(16)


def test_write_blocks_rejects_a_wrong_payload_size(controller):
    with pytest.raises(ValueError):
        controller.write_blocks([(1, b"short")])


def test_writing_the_mc_block_changes_the_access_rights(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    handler = MCBlockHandler()
    handler.parse_mc_block_data(DEFAULT_MC)
    handler.set_access_mode_from_string(9, "RO")

    result = controller.write_blocks([(BLOCK_MC, handler.generate_mc_block_data())])

    assert result["ok"], result["error"]
    assert tag.is_read_only(9)


# ==============================================================================
# Card key and locking
# ==============================================================================
def test_write_card_key_stores_the_reversed_halves_and_the_version(monkeypatch,
                                                                   controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)

    result = controller.write_card_key(KEY, 0x1234)

    assert result["ok"], result["error"]
    assert tag.card_key == KEY  # the simulator un-reverses on write
    written = dict(tag.write_log)
    assert written[BLOCK_CK] == encode_card_key(KEY)
    assert decode_ckv(tag.storage[BLOCK_CKV]) == 0x1234


def test_the_new_card_key_authenticates(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    controller.write_card_key(KEY, 1)

    handler = MCBlockHandler()
    handler.parse_mc_block_data(tag.mc)
    handler.set_access_mode_from_string(3, "RW (W Auth)")
    controller.write_blocks([(BLOCK_MC, handler.generate_mc_block_data())])

    result = controller.write_blocks([(3, b"K" * 16)], mc_handler=handler,
                                     key_bytes=KEY)
    assert result["ok"], result["error"]


def test_write_card_key_refuses_a_locked_card(monkeypatch, controller):
    locked_mc = bytes([0xFF, 0x7F, 0x00, 0x00, 0x07, 0x00] + [0] * 10)
    tag = FakeLiteS(mc=locked_mc)
    attach(monkeypatch, tag)

    result = controller.write_card_key(KEY, 1)

    assert result["ok"] is False
    assert "permanently locked" in result["error"]


def test_write_card_key_rejects_a_short_key(controller):
    with pytest.raises(ValueError):
        controller.write_card_key(b"\x00" * 8, 0)


def test_lock_card_sets_mc_byte_two(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)

    result = controller.lock_card()

    assert result["ok"], result["error"]
    assert tag.mc[2] == 0x00
    assert MCBlockHandler.is_locked(tag.mc)
    # Everything else in MC is untouched.
    assert tag.mc[0:2] == DEFAULT_MC[0:2]
    assert tag.mc[3:] == DEFAULT_MC[3:]


def test_lock_card_refuses_a_card_that_is_already_locked(monkeypatch, controller):
    locked_mc = bytes([0xFF, 0x7F, 0x00, 0x00, 0x07, 0x00] + [0] * 10)
    attach(monkeypatch, FakeLiteS(mc=locked_mc))

    result = controller.lock_card()

    assert result["ok"] is False
    assert "already permanently locked" in result["error"]


def test_a_locked_card_refuses_further_system_writes(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    controller.lock_card()

    result = controller.write_blocks([(BLOCK_MC, DEFAULT_MC)])

    assert result["ok"] is False


# ==============================================================================
# Helpers
# ==============================================================================
def test_card_key_encoding_is_its_own_inverse():
    assert core.decode_card_key(encode_card_key(KEY)) == KEY
    assert encode_card_key(KEY) == KEY[7::-1] + KEY[15:7:-1]


def test_ckv_encoding_round_trip():
    assert decode_ckv(core.encode_ckv(0xBEEF)) == 0xBEEF
    with pytest.raises(ValueError):
        core.encode_ckv(0x10000)


def test_ensure_bytes_accepts_the_usual_shapes():
    assert core.ensure_bytes(b"ab") == b"ab"
    assert core.ensure_bytes(bytearray(b"ab")) == b"ab"
    assert core.ensure_bytes([1, 2]) == b"\x01\x02"
    assert core.ensure_bytes([b"a", b"b"]) == b"ab"
    with pytest.raises(TypeError):
        core.ensure_bytes("not bytes")


def test_is_hex_validates_length_and_alphabet():
    assert core.is_hex("00FF", 4)
    assert not core.is_hex("00FF", 6)
    assert not core.is_hex("00FG", 4)
    assert not core.is_hex("", 0)
    assert not core.is_hex(None)
