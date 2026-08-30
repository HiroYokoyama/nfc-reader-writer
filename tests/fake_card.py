#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In-memory FeliCa card simulators used by the test-suite.

The simulators subclass nfcpy's real tag classes and only replace the two
transport primitives (``read_without_encryption`` / ``write_without_encryption``).
Everything above them -- mutual authentication, ``read_with_mac``,
``write_with_mac``, the NDEF machinery -- is nfcpy's own production code, so the
tests exercise the real protocol, including the triple-DES session key maths.
"""
import struct

import nfc.clf
import nfc.tag.tt3 as tt3
import nfc.tag.tt3_sony as sony

IC_CODE_LITE = 0xF0
IC_CODE_LITE_S = 0xF1

BLOCK_RC = 0x80
BLOCK_MAC = 0x81
BLOCK_ID = 0x82
BLOCK_CKV = 0x86
BLOCK_CK = 0x87
BLOCK_MC = 0x88
BLOCK_WCNT = 0x90
BLOCK_MAC_A = 0x91

DEFAULT_MC = (bytes([0xFF, 0x7F, 0xFF, 0x00, 0x07, 0x00])
              + bytes(10))


def make_target(idm=b"\x01\x02\x03\x04\x05\x06\x07\x08", ic_code=IC_CODE_LITE_S,
                sys_code=0x88B4):
    """Build a RemoteTarget whose sensf_res identifies the requested IC."""
    pmm = bytes([0x00, ic_code, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F])
    target = nfc.clf.RemoteTarget("212F")
    target.sensf_res = b"\x01" + idm + pmm + struct.pack(">H", sys_code)
    return target


class _FakeCardMixin:
    """Shared storage and access-control logic for the Lite simulators."""

    supports_write_mac = True

    def setup_card(self, blocks=None, card_key=b"\x00" * 16, mc=None):
        self.storage = {i: bytes(16) for i in range(0, 15)}
        self.storage[BLOCK_ID] = bytes(self.idm) + bytes(8)
        self.storage[BLOCK_CKV] = bytes(16)
        self.storage[BLOCK_MC] = bytes(mc if mc is not None else DEFAULT_MC)
        self.storage[BLOCK_WCNT] = bytes(16)
        self.card_key = bytes(card_key)
        self.session_key = None
        self.session_iv = None
        self.card_authenticated = False
        self.write_count = 0
        self.write_log = []
        if blocks:
            self.storage.update({b: bytes(d) for b, d in blocks.items()})

    # -- access control ---------------------------------------------------
    @property
    def mc(self):
        return self.storage[BLOCK_MC]

    def _mc_bit(self, base, block_num):
        if block_num > 14:
            return 0
        bit = block_num if block_num <= 7 else (
            block_num - 8 if block_num <= 13 else 6)
        offset = 0 if block_num <= 7 else 1
        return (self.mc[base + offset] >> bit) & 1

    def is_read_protected(self, block_num):
        return self.supports_write_mac and self._mc_bit(6, block_num) == 1

    def is_read_only(self, block_num):
        return block_num <= 14 and self._mc_bit(0, block_num) == 0

    def needs_write_auth(self, block_num):
        return self.supports_write_mac and self._mc_bit(8, block_num) == 1

    def needs_write_mac(self, block_num):
        return self.supports_write_mac and self._mc_bit(10, block_num) == 1

    @property
    def system_blocks_locked(self):
        return self.mc[2] == 0x00

    def polling(self, system_code=0xFFFF, request_code=0, time_slots=0):
        """A Lite card answers polling for its own system and for NDEF."""
        if system_code not in (0xFFFF, 0x88B4, 0x12FC):
            raise tt3.Type3TagCommandError(0x01A2)
        return self.idm, self.pmm

    # -- transport --------------------------------------------------------
    def read_without_encryption(self, service_list, block_list):
        del service_list  # the simulator only implements the NDEF services
        out = bytearray()
        for block in block_list:
            number = block.number
            if number == BLOCK_MAC:
                out += self._mac_block(bytes(out))
                continue
            if number == BLOCK_CK:
                out += bytes(16)  # the card key is never readable
                continue
            if number == BLOCK_WCNT:
                out += struct.pack("<I", self.write_count)[:3] + bytes(13)
                continue
            if number not in self.storage:
                raise tt3.Type3TagCommandError(0x01A2)
            if self.is_read_protected(number) and not self.card_authenticated:
                raise tt3.Type3TagCommandError(0x01A2)
            out += self.storage[number]
        return bytearray(out)

    def write_without_encryption(self, service_list, block_list, data):
        del service_list
        data = bytes(data)
        if len(data) != 16 * len(block_list):
            raise ValueError("data length does not match the block list")

        numbers = [block.number for block in block_list]
        if BLOCK_MAC_A in numbers:
            self._write_with_mac(numbers, data)
            return

        for index, number in enumerate(numbers):
            payload = data[index * 16:(index + 1) * 16]
            self._check_writable(number)
            self._store(number, payload)

    def _check_writable(self, number):
        if number == BLOCK_RC:
            return
        if number >= 0x80:
            if self.system_blocks_locked:
                raise tt3.Type3TagCommandError(0x01A2)
            return
        if self.is_read_only(number):
            raise tt3.Type3TagCommandError(0x01A2)
        if self.needs_write_mac(number):
            raise tt3.Type3TagCommandError(0x01A2)  # a plain write is refused
        if self.needs_write_auth(number) and not self.card_authenticated:
            raise tt3.Type3TagCommandError(0x01A2)

    def _store(self, number, payload):
        if number == BLOCK_RC:
            self._start_session(payload)
            return
        if number == BLOCK_CK:
            self.card_key = bytes(payload[7::-1] + payload[15:7:-1])
            self.write_log.append((number, payload))
            return
        self.storage[number] = payload
        self.write_log.append((number, payload))

    # -- authentication ---------------------------------------------------
    def _start_session(self, payload):
        """A write to RC starts a new session, exactly like the real card."""
        rc = bytes(payload[7::-1] + payload[15:7:-1])
        self.session_key = sony.triple_des(self.card_key, sony.CBC,
                                           b"\x00" * 8).encrypt(rc)
        self.session_iv = rc[0:8]
        self.card_authenticated = True
        self.write_log.append((BLOCK_RC, bytes(payload)))

    def _mac_block(self, preceding):
        if self.session_key is None:
            return bytes(16)
        mac = sony.FelicaLite.generate_mac(preceding, self.session_key,
                                           self.session_iv)
        return bytes(mac) + bytes(8)

    def _write_with_mac(self, numbers, data):
        if not self.supports_write_mac:
            raise tt3.Type3TagCommandError(0x01A2)
        if self.session_key is None:
            raise tt3.Type3TagCommandError(0x01A2)
        block = numbers[0]
        payload = data[0:16]
        maca = data[16:32]

        wcnt = struct.pack("<I", self.write_count)[:3]
        signed = (wcnt + b"\x00" + bytes([block]) + b"\x00\x91\x00" + payload)
        flipped = self.session_key[8:16] + self.session_key[0:8]
        expected = sony.FelicaLite.generate_mac(signed, flipped, self.session_iv)
        if bytes(maca[0:8]) != bytes(expected):
            raise tt3.Type3TagCommandError(0x01A2)
        if self.is_read_only(block):
            raise tt3.Type3TagCommandError(0x01A2)
        self.storage[block] = payload
        self.write_count += 1
        self.write_log.append((block, payload))


class FakeLiteS(_FakeCardMixin, sony.FelicaLiteS):
    supports_write_mac = True

    def __init__(self, blocks=None, card_key=b"\x00" * 16, mc=None,
                 idm=b"\x01\x02\x03\x04\x05\x06\x07\x08"):
        super().__init__(None, make_target(idm, IC_CODE_LITE_S))
        self.setup_card(blocks, card_key, mc)


class FakeLite(_FakeCardMixin, sony.FelicaLite):
    """A plain FeliCa Lite: no write-with-MAC and no auth bits in MC."""

    supports_write_mac = False

    def __init__(self, blocks=None, card_key=b"\x00" * 16, mc=None,
                 idm=b"\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11"):
        super().__init__(None, make_target(idm, IC_CODE_LITE))
        self.setup_card(blocks, card_key, mc)


class FakeStandard(sony.FelicaStandard):
    """A FeliCa Standard card with two systems and a few services."""

    def __init__(self, idm=b"\x02\x02\x02\x02\x02\x02\x02\x02"):
        super().__init__(None, make_target(idm, 0x20, sys_code=0x0003))
        self.systems = [0x0003, 0x12FC]
        self.active_system = 0x0003
        self.service_map = {
            0x0003: [(0x0000, 0x000F), (0x000B,), (0x0048,)],
            0x12FC: [(0x000B,)],
        }
        self.blocks = {0x000B: [bytes([i]) * 16 for i in range(3)]}

    # -- commands ---------------------------------------------------------
    def request_system_code(self):
        return list(self.systems)

    def polling(self, system_code=0xFFFF, request_code=0, time_slots=0):
        if system_code not in self.systems and system_code != 0xFFFF:
            raise tt3.Type3TagCommandError(0x01A2)
        self.active_system = (self.systems[0] if system_code == 0xFFFF
                              else system_code)
        return self.idm, self.pmm

    def search_service_code(self, service_index):
        entries = self.service_map.get(self.active_system, [])
        if service_index >= len(entries):
            return None
        return entries[service_index]

    def request_service(self, service_list):
        return [0xFFFF for _ in service_list]

    def read_without_encryption(self, service_list, block_list):
        service = service_list[0]
        code = service.number << 6 | service.attribute
        blocks = self.blocks.get(code)
        if blocks is None:
            raise tt3.Type3TagCommandError(0x01A1)
        out = bytearray()
        for block in block_list:
            if block.number >= len(blocks):
                raise tt3.Type3TagCommandError(0x01A2)
            out += blocks[block.number]
        return out

    def write_without_encryption(self, service_list, block_list, data):
        service = service_list[0]
        code = service.number << 6 | service.attribute
        if code & 1 == 0:
            raise tt3.Type3TagCommandError(0x01A1)  # a key would be required
        blocks = self.blocks.setdefault(code, [])
        for index, block in enumerate(block_list):
            while len(blocks) <= block.number:
                blocks.append(bytes(16))
            blocks[block.number] = bytes(data[index * 16:(index + 1) * 16])


def ndef_attribute_block(message_length, max_blocks=13, writable=True):
    """Build the NFC Forum Type 3 attribute information block (block 0)."""
    attribute = bytearray(16)
    attribute[0] = 0x10                                   # mapping version 1.0
    attribute[1] = 4                                      # Nbr
    attribute[2] = 1                                      # Nbw
    attribute[3:5] = struct.pack(">H", max_blocks)        # Nmaxb
    attribute[10] = 0x01 if writable else 0x00            # RW flag
    attribute[11:14] = struct.pack(">I", message_length)[1:]
    attribute[14:16] = struct.pack(">H", sum(attribute[0:14]))
    return bytes(attribute)


def ndef_blocks(message, writable=True):
    """Storage for a card that already carries the NDEF *message* bytes."""
    blocks = {0: ndef_attribute_block(len(message), writable=writable)}
    for index in range((len(message) + 15) // 16):
        blocks[1 + index] = message[index * 16:(index + 1) * 16].ljust(16, b"\x00")
    return blocks


# ==============================================================================
# Reader plumbing
# ==============================================================================
class FakeContactlessFrontend:
    """Stands in for ``nfc.ContactlessFrontend`` and always returns *tag*."""

    def __init__(self, tag, sense_failures=0):
        self.tag = tag
        self.sense_failures = sense_failures
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True
        return False

    def sense(self, *targets, **kwargs):
        if self.sense_failures > 0:
            self.sense_failures -= 1
            return None
        return self.tag.target


def install_fake_reader(monkeypatch, module, tag, sense_failures=0):
    """Point *module*'s nfc handles at a frontend that yields *tag*."""
    frontend = FakeContactlessFrontend(tag, sense_failures)
    monkeypatch.setattr(module.nfc, "ContactlessFrontend",
                        lambda path: frontend, raising=False)
    monkeypatch.setattr(module.nfc.tag, "activate",
                        lambda clf, target: tag, raising=False)
    return frontend
