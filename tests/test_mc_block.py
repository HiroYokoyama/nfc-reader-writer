"""MC block encoding/decoding."""
import pytest

import felica_core as core
from felica_core import MCBlockHandler


def test_defaults_are_all_rw_without_auth():
    handler = MCBlockHandler()
    assert handler.rw_ro_settings == [1] * 15
    assert handler.r_auth_settings == [0] * 15
    assert handler.get_access_mode_string(0) == "RW"


def test_bit_positions_match_the_sony_layout():
    # Blocks 0..7 live in the low byte, 8..13 in the high byte, REG at bit 6.
    assert MCBlockHandler._bit_position(0) == (0, 0)
    assert MCBlockHandler._bit_position(7) == (7, 0)
    assert MCBlockHandler._bit_position(8) == (0, 1)
    assert MCBlockHandler._bit_position(13) == (5, 1)
    assert MCBlockHandler._bit_position(core.BLOCK_REG) == (6, 1)
    assert MCBlockHandler._bit_position(15) == (None, None)


def test_rw_ro_mask_matches_nfcpy_protect_semantics():
    """nfcpy writes 0x7FFF ^ (2**14 - 2**n) to protect blocks n..13."""
    handler = MCBlockHandler()
    for block in range(0, 14):
        handler.rw_ro_settings[block] = 0
    mc = handler.generate_mc_block_data()
    expected = 0x7FFF ^ (2 ** 14 - 2 ** 0)
    assert mc[0] | (mc[1] << 8) == expected


def test_round_trip_through_generate_and_parse():
    handler = MCBlockHandler()
    handler.set_access_mode_from_string(0, "RO")
    handler.set_access_mode_from_string(3, "RW (R Auth W MAC)")
    handler.set_access_mode_from_string(13, "RW (W Auth)")
    handler.set_access_mode_from_string(core.BLOCK_REG, "RO (R Auth)")
    mc = handler.generate_mc_block_data()

    other = MCBlockHandler()
    other.parse_mc_block_data(mc)
    assert other.state_snapshot() == handler.state_snapshot()
    assert other.get_access_mode_string(3) == "RW (R Auth W MAC)"
    assert other.get_access_mode_string(core.BLOCK_REG) == "RO (R Auth)"


def test_generate_preserves_unmanaged_bytes_of_the_card_mc():
    base = bytes([0xFF, 0x7F, 0xFF, 0x01, 0x07, 0x01] + [0] * 10)
    handler = MCBlockHandler()
    handler.parse_mc_block_data(base)
    handler.set_access_mode_from_string(2, "RO")
    mc = handler.generate_mc_block_data()
    # SYS_OP, RF_PRM and the CK-write flag survive untouched.
    assert mc[2:6] == base[2:6]
    assert mc[0] & 0x04 == 0


def test_generate_without_a_base_keeps_the_system_blocks_writable():
    mc = MCBlockHandler().generate_mc_block_data()
    assert mc[2] == MCBlockHandler.MC_SP_UNLOCKED
    assert mc[4] == 0x07
    assert not MCBlockHandler.is_locked(mc)


def test_is_locked_reads_mc_byte_two():
    unlocked = bytes([0xFF, 0x7F, 0xFF] + [0] * 13)
    locked = bytes([0xFF, 0x7F, 0x00] + [0] * 13)
    assert not MCBlockHandler.is_locked(unlocked)
    assert MCBlockHandler.is_locked(locked)
    assert not MCBlockHandler.is_locked(b"")


def test_plain_lite_cards_expose_only_rw_and_ro():
    handler = MCBlockHandler(supports_lite_s=False)
    assert handler.available_modes() == ["RW", "RO"]
    handler.set_access_mode_from_string(1, "RW (R Auth W MAC)")
    assert handler.r_auth_settings[1] == 0
    assert handler.w_mac_settings[1] == 0
    # The auth byte pairs are never touched on a Lite card.
    base = bytes([0xFF, 0x7F, 0xFF, 0x00, 0x07, 0x00] + [0x5A] * 10)
    handler.parse_mc_block_data(base)
    assert handler.r_auth_settings == [0] * 15
    assert handler.generate_mc_block_data()[6:12] == base[6:12]


def test_parse_rejects_short_data_and_resets():
    handler = MCBlockHandler()
    handler.set_access_mode_from_string(0, "RO")
    assert handler.parse_mc_block_data(b"\x00" * 4) is None
    assert handler.rw_ro_settings[0] == 1


@pytest.mark.parametrize("mode", MCBlockHandler.LITE_S_MODES)
def test_every_offered_mode_survives_a_round_trip(mode):
    handler = MCBlockHandler()
    handler.set_access_mode_from_string(5, mode)
    assert handler.get_access_mode_string(5) == mode
    other = MCBlockHandler()
    other.parse_mc_block_data(handler.generate_mc_block_data())
    assert other.get_access_mode_string(5) == mode


def test_needs_write_auth_covers_both_auth_and_mac():
    handler = MCBlockHandler()
    handler.set_access_mode_from_string(1, "RW (W Auth)")
    handler.set_access_mode_from_string(2, "RW (W MAC)")
    assert handler.needs_write_auth(1)
    assert handler.needs_write_auth(2)
    assert handler.needs_write_mac(2)
    assert not handler.needs_write_mac(1)
    assert not handler.needs_write_auth(core.BLOCK_MC)
