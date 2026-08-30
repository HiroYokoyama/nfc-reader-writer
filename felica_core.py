#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Card-level logic for FeliCa Lite-S: memory map, MC block handling and NFC I/O.

This module deliberately contains no GUI code so that it can be imported and
tested without a display or a reader attached.  All block numbers and semantics
follow the FeliCa Lite-S User's Manual and are cross-checked against nfcpy's own
``nfc.tag.tt3_sony`` implementation.

Source code, README, and full license (GNU GPL v3):
    https://github.com/HiroYokoyama/nfc-reader-writer
Copyright (c) HiroYokoyama. Licensed under the GNU General Public License;
see the LICENSE file in the repository above for the full terms.
"""
import binascii
import time
import traceback

try:
    import nfc
    import nfc.tag.tt3
    NFC_AVAILABLE = True
    NFC_IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - depends on the environment
    nfc = None
    NFC_AVAILABLE = False
    NFC_IMPORT_ERROR = exc

# --- Memory map (FeliCa Lite-S User's Manual, section 3.1) --------------------
BLOCK_S_PAD0 = 0x00
BLOCK_S_PAD13 = 0x0D
BLOCK_REG = 0x0E
BLOCK_RC = 0x80
BLOCK_MAC = 0x81
BLOCK_ID = 0x82
BLOCK_D_ID = 0x83
BLOCK_SER_C = 0x84
BLOCK_SYS_C = 0x85
BLOCK_CKV = 0x86
BLOCK_CK = 0x87
BLOCK_MC = 0x88
BLOCK_WCNT = 0x90
BLOCK_MAC_A = 0x91
BLOCK_STATE = 0x92

USER_BLOCKS = list(range(BLOCK_S_PAD0, BLOCK_REG + 1))          # 0..14
SYSTEM_BLOCKS = [BLOCK_RC, BLOCK_MAC, BLOCK_ID, BLOCK_D_ID, BLOCK_SER_C,
                 BLOCK_SYS_C, BLOCK_CKV, BLOCK_CK, BLOCK_MC,
                 BLOCK_WCNT, BLOCK_MAC_A, BLOCK_STATE]
ALL_BLOCKS = USER_BLOCKS + SYSTEM_BLOCKS

#: Blocks that never return meaningful data on a read.
UNREADABLE_BLOCKS = {BLOCK_CK, BLOCK_MAC_A}

#: Blocks the user may type into directly; the rest have dedicated controls.
EDITABLE_BLOCKS = set(USER_BLOCKS)

BLOCK_NAMES = {
    BLOCK_REG: "REG",
    BLOCK_RC: "RC",
    BLOCK_MAC: "MAC",
    BLOCK_ID: "ID",
    BLOCK_D_ID: "D_ID",
    BLOCK_SER_C: "SER_C",
    BLOCK_SYS_C: "SYS_C",
    BLOCK_CKV: "CKV",
    BLOCK_CK: "CK",
    BLOCK_MC: "MC",
    BLOCK_WCNT: "WCNT",
    BLOCK_MAC_A: "MAC_A",
    BLOCK_STATE: "STATE",
}
for _i in range(BLOCK_S_PAD0, BLOCK_S_PAD13 + 1):
    BLOCK_NAMES[_i] = "S_PAD%d" % _i

BLOCK_DESCRIPTIONS = {
    BLOCK_REG: "REG (REGA[4] REGB[4] REGC[8])",
    BLOCK_RC: "RC (RC1[8] RC2[8], challenge)",
    BLOCK_MAC: "MAC (MAC[8], read-only)",
    BLOCK_ID: "ID (IDm[8] DFC[2])",
    BLOCK_D_ID: "D_ID (device identification)",
    BLOCK_SER_C: "SER_C (service code)",
    BLOCK_SYS_C: "SYS_C (system code)",
    BLOCK_CKV: "CKV (card key version)",
    BLOCK_CK: "CK (card key, write-only)",
    BLOCK_MC: "MC (memory configuration)",
    BLOCK_WCNT: "WCNT (write counter)",
    BLOCK_MAC_A: "MAC_A (write-only)",
    BLOCK_STATE: "STATE (Lite-S status flags)",
}

#: The .bin dump format covers the 16 user-area blocks (0..15); block 15 does
#: not exist on a Lite-S card and is always stored as zeros.
FELICA_LITE_S_BLOCKS = 16
FELICA_LITE_S_BYTES = FELICA_LITE_S_BLOCKS * 16
ZERO_BLOCK = b"\x00" * 16
SUPPORTED_ENCODINGS = ["shift_jis", "utf-8", "euc-jp", "latin-1"]

#: Marker stored in a dump map when a block is never readable.
SKIPPED_MARKER = b"?" * 16
#: Marker stored in a dump map when a read was attempted and failed.
FAILED_MARKER = b"!" * 16
MARKERS = (SKIPPED_MARKER, FAILED_MARKER)

SERVICE_RW = 0b001001   # service 0x0009, write without encryption
SERVICE_RO = 0b001011   # service 0x000B, read without encryption


def ensure_bytes(data):
    """Return a ``bytes`` instance for the given payload."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, (list, tuple)):
        if all(isinstance(x, int) for x in data):
            return bytes(data)
        if all(isinstance(x, (bytes, bytearray)) for x in data):
            return b"".join(bytes(x) for x in data)
    raise TypeError("Unsupported data type for FeliCa write: %r" % type(data))


def is_hex(text, length=None):
    """True if *text* is a hex string (optionally of exactly *length* chars)."""
    if not isinstance(text, str) or not text:
        return False
    if length is not None and len(text) != length:
        return False
    if len(text) % 2:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in text)


def encode_card_key(key_bytes):
    """Lay a 16-byte card key out the way the card stores it in block CK.

    The card keeps CK1 and CK2 little-endian, so each 8-byte half is reversed.
    Matches ``nfc.tag.tt3_sony.FelicaLite._protect``.
    """
    key = ensure_bytes(key_bytes)
    if len(key) != 16:
        raise ValueError("card key must be exactly 16 bytes")
    return key[7::-1] + key[15:7:-1]


def decode_card_key(block_bytes):
    """Inverse of :func:`encode_card_key` (the transform is its own inverse)."""
    return encode_card_key(block_bytes)


def encode_ckv(ckv_int):
    """Build the 16-byte CKV block for a key version number."""
    if not 0 <= ckv_int <= 0xFFFF:
        raise ValueError("CKV must fit in 16 bits")
    return bytes([ckv_int & 0xFF, (ckv_int >> 8) & 0xFF]) + b"\x00" * 14


def decode_ckv(block_bytes):
    """Read the key version out of a CKV block (little endian)."""
    data = ensure_bytes(block_bytes)
    if len(data) < 2:
        raise ValueError("CKV block must be at least 2 bytes")
    return data[0] | (data[1] << 8)


# ==============================================================================
# Tag identification
# ==============================================================================
KIND_LITE = "lite"
KIND_LITE_S = "lite-s"
KIND_STANDARD = "standard"
KIND_MOBILE = "mobile"
KIND_PLUG = "plug"
KIND_TYPE3 = "type3"
KIND_OTHER = "other"

KIND_LABELS = {
    KIND_LITE: "FeliCa Lite",
    KIND_LITE_S: "FeliCa Lite-S",
    KIND_STANDARD: "FeliCa Standard",
    KIND_MOBILE: "Mobile FeliCa",
    KIND_PLUG: "FeliCa Plug",
    KIND_TYPE3: "NFC Forum Type 3",
    KIND_OTHER: "Other NFC tag",
}

#: Block editing is only offered for the two cards with a fixed memory map.
BLOCK_EDITOR_KINDS = (KIND_LITE, KIND_LITE_S)


def describe_tag(tag):
    """Classify an activated tag and report what it can do.

    Returns a dict with ``kind``, ``kind_label``, ``product``, ``supports_auth``
    (mutual authentication / read with MAC), ``supports_write_mac`` (Lite-S only)
    and ``supports_block_editor``.
    """
    kind = KIND_OTHER
    if NFC_AVAILABLE:
        import nfc.tag.tt3_sony as sony
        # Most specific first: FelicaLiteS derives from FelicaLite, and
        # FelicaMobile derives from FelicaStandard.
        if isinstance(tag, sony.FelicaLiteS):
            kind = KIND_LITE_S
        elif isinstance(tag, sony.FelicaLite):
            kind = KIND_LITE
        elif isinstance(tag, sony.FelicaMobile):
            kind = KIND_MOBILE
        elif isinstance(tag, sony.FelicaStandard):
            kind = KIND_STANDARD
        elif isinstance(tag, sony.FelicaPlug):
            kind = KIND_PLUG
        elif isinstance(tag, nfc.tag.tt3.Type3Tag):
            kind = KIND_TYPE3
    return {
        "kind": kind,
        "kind_label": KIND_LABELS[kind],
        "product": getattr(tag, "product", "") or KIND_LABELS[kind],
        "type": getattr(tag, "type", ""),
        "supports_auth": kind in (KIND_LITE, KIND_LITE_S),
        "supports_write_mac": kind == KIND_LITE_S,
        "supports_block_editor": kind in BLOCK_EDITOR_KINDS,
    }


# ==============================================================================
# MC block
# ==============================================================================
class MCBlockHandler:
    """Creates and parses the 16-byte MC block (block 88h).

    Only the bits this application manages are touched; every other byte of a
    card's MC block is preserved verbatim when regenerating it, so writing
    access rights never clobbers SYS_OP, RF_PRM or reserved bytes.
    """

    #: Blocks covered by the MC bit pairs: S_PAD0..S_PAD13 plus REG.
    MAX_BLOCKS = 15

    #: First MC byte of each managed permission pair.
    BASE_RW_RO = 0
    BASE_R_AUTH = 6
    BASE_W_AUTH = 8
    BASE_W_MAC = 10

    #: MC[2]; FFh keeps the system blocks writable, 00h locks them forever.
    MC_SP_UNLOCKED = 0xFF
    MC_SP_LOCKED = 0x00

    #: Every access mode the UI can offer, in the order shown.
    LITE_S_MODES = ["RW", "RO", "RW (R Auth)", "RO (R Auth)", "RW (W Auth)",
                    "RW (W MAC)", "RW (R Auth W Auth)", "RW (R Auth W MAC)",
                    "RW (W Auth W MAC)", "RW (R Auth W Auth W MAC)"]
    #: A plain FeliCa Lite only has the RW/RO bits.
    LITE_MODES = ["RW", "RO"]

    def __init__(self, supports_lite_s=True):
        self.max_blocks = self.MAX_BLOCKS
        #: False for a plain FeliCa Lite, whose MC has no auth/MAC bits.
        self.supports_lite_s = supports_lite_s
        self.reset()

    def reset(self):
        """Restore the factory default (everything RW, no authentication)."""
        self.rw_ro_settings = [1] * self.max_blocks   # 1: RW, 0: RO
        self.r_auth_settings = [0] * self.max_blocks  # 1: read needs auth
        self.w_auth_settings = [0] * self.max_blocks  # 1: write needs auth
        self.w_mac_settings = [0] * self.max_blocks   # 1: write needs MAC
        self.raw_mc = None

    def available_modes(self):
        """Access modes the current card type actually supports."""
        return list(self.LITE_S_MODES if self.supports_lite_s else self.LITE_MODES)

    # -- bit addressing --------------------------------------------------
    @staticmethod
    def _bit_position(block_num):
        """Map a block number to its (bit index, byte offset) in an MC pair."""
        if 0 <= block_num <= 7:
            return block_num, 0
        if 8 <= block_num <= 13:
            return block_num - 8, 1
        if block_num == BLOCK_REG:
            return 6, 1
        return None, None

    # -- UI strings ------------------------------------------------------
    def get_access_mode_string(self, block_num):
        if not 0 <= block_num < self.max_blocks:
            return ""
        if self.rw_ro_settings[block_num] == 0:
            return "RO (R Auth)" if self.r_auth_settings[block_num] else "RO"
        conditions = []
        if self.r_auth_settings[block_num]:
            conditions.append("R Auth")
        if self.w_auth_settings[block_num]:
            conditions.append("W Auth")
        if self.w_mac_settings[block_num]:
            conditions.append("W MAC")
        return "RW (%s)" % " ".join(conditions) if conditions else "RW"

    def set_access_mode_from_string(self, block_num, mode_str):
        if not 0 <= block_num < self.max_blocks:
            return
        lite_s = self.supports_lite_s
        self.r_auth_settings[block_num] = 0
        self.w_auth_settings[block_num] = 0
        self.w_mac_settings[block_num] = 0
        if mode_str.startswith("RO"):
            self.rw_ro_settings[block_num] = 0
            if lite_s and "R Auth" in mode_str:
                self.r_auth_settings[block_num] = 1
        elif mode_str.startswith("RW"):
            self.rw_ro_settings[block_num] = 1
            if lite_s:
                self.r_auth_settings[block_num] = 1 if "R Auth" in mode_str else 0
                self.w_auth_settings[block_num] = 1 if "W Auth" in mode_str else 0
                self.w_mac_settings[block_num] = 1 if "W MAC" in mode_str else 0

    def needs_read_auth(self, block_num):
        return (0 <= block_num < self.max_blocks
                and self.r_auth_settings[block_num] == 1)

    def needs_write_auth(self, block_num):
        return (0 <= block_num < self.max_blocks
                and (self.w_auth_settings[block_num] == 1
                     or self.w_mac_settings[block_num] == 1))

    def needs_write_mac(self, block_num):
        return (0 <= block_num < self.max_blocks
                and self.w_mac_settings[block_num] == 1)

    def is_read_only(self, block_num):
        return (0 <= block_num < self.max_blocks
                and self.rw_ro_settings[block_num] == 0)

    # -- serialisation ---------------------------------------------------
    def _managed_pairs(self):
        """MC byte pairs this card type actually uses, keyed by base index."""
        pairs = {self.BASE_RW_RO: self.rw_ro_settings}
        if self.supports_lite_s:
            pairs[self.BASE_R_AUTH] = self.r_auth_settings
            pairs[self.BASE_W_AUTH] = self.w_auth_settings
            pairs[self.BASE_W_MAC] = self.w_mac_settings
        return pairs

    def generate_mc_block_data(self, base=None):
        """Render the managed bits into a 16-byte MC block.

        *base* (defaulting to the MC block last parsed) supplies every byte the
        application does not manage, so unrelated configuration survives a write.
        """
        if base is None:
            base = self.raw_mc
        if base is None:
            mc_data = bytearray(16)
            mc_data[2] = self.MC_SP_UNLOCKED  # system blocks stay writable
            mc_data[3] = 0x00                 # SYS_OP: FeliCa Lite-S mode
            mc_data[4] = 0x07                 # RF_PRM: fixed value per the manual
        else:
            mc_data = bytearray(ensure_bytes(base)[:16].ljust(16, b"\x00"))

        for base_index, values in self._managed_pairs().items():
            mc_data[base_index] = 0
            mc_data[base_index + 1] &= 0x80  # bit 7 of the high byte is reserved
            for block_num in range(self.max_blocks):
                bit_index, byte_offset = self._bit_position(block_num)
                if bit_index is None:
                    continue
                if values[block_num] == 1:
                    mc_data[base_index + byte_offset] |= 1 << bit_index

        return bytes(mc_data)

    def parse_mc_block_data(self, mc_data_bytes):
        """Load the managed bits from a card's MC block."""
        if not mc_data_bytes or len(mc_data_bytes) < 16:
            self.reset()
            return None

        mc_data_bytes = ensure_bytes(mc_data_bytes)[:16]
        managed = self._managed_pairs()
        for block_num in range(self.max_blocks):
            bit_index, byte_offset = self._bit_position(block_num)
            if bit_index is None:
                continue
            for base_index, values in managed.items():
                byte = mc_data_bytes[base_index + byte_offset]
                values[block_num] = (byte >> bit_index) & 1
            if not self.supports_lite_s:
                # A plain FeliCa Lite has no auth bits; never show stale ones.
                self.r_auth_settings[block_num] = 0
                self.w_auth_settings[block_num] = 0
                self.w_mac_settings[block_num] = 0

        self.raw_mc = mc_data_bytes
        return mc_data_bytes

    @staticmethod
    def is_locked(mc_data_bytes):
        """True when MC[2] says the system blocks are permanently read-only."""
        if not mc_data_bytes or len(mc_data_bytes) < 3:
            return False
        return ensure_bytes(mc_data_bytes)[2] == MCBlockHandler.MC_SP_LOCKED

    def state_snapshot(self):
        return {
            "rw_ro": list(self.rw_ro_settings),
            "r_auth": list(self.r_auth_settings),
            "w_auth": list(self.w_auth_settings),
            "w_mac": list(self.w_mac_settings),
        }

    def load_state(self, state):
        self.rw_ro_settings = list(state.get("rw_ro", self.rw_ro_settings))
        self.r_auth_settings = list(state.get("r_auth", self.r_auth_settings))
        self.w_auth_settings = list(state.get("w_auth", self.w_auth_settings))
        self.w_mac_settings = list(state.get("w_mac", self.w_mac_settings))


# ==============================================================================
# NFC controller
# ==============================================================================
class CardError(Exception):
    """A card-level failure that carries a user-readable message."""


class NfcController:
    """All reader communication.

    Every public method opens one connection and performs the whole batch of
    work on a single tag activation, so the card only has to stay on the reader
    once per operation instead of once per block.
    """

    def __init__(self, path="usb", logger=None):
        if not NFC_AVAILABLE:
            raise ImportError(
                "Cannot perform NFC operations because the nfcpy library is not "
                "available. (%s)" % (NFC_IMPORT_ERROR,))
        self.path = path
        self.logger = logger or (lambda level, text: None)

    # -- plumbing --------------------------------------------------------
    def _log(self, level, text):
        try:
            self.logger(level, text)
        except Exception:  # pragma: no cover - a broken logger must not stop I/O
            pass

    def _sense(self, clf, timeout, technologies=("212F",)):
        """Poll for a target until *timeout* seconds have elapsed."""
        targets = [nfc.clf.RemoteTarget(t) for t in technologies]
        deadline = time.time() + timeout
        while True:
            if time.time() >= deadline:
                return None
            try:
                target = clf.sense(*targets, iterations=3, interval=0.1)
            except Exception:
                target = None
            if target is not None:
                return target
            time.sleep(0.05)

    def _connect_and_operate(self, operation_fn, timeout=8, require_type3=True,
                             technologies=("212F",)):
        """Activate a tag and hand it to *operation_fn(tag, result)*."""
        result = {"ok": False, "error": "Timeout: no card detected.",
                  "data": None}
        try:
            with nfc.ContactlessFrontend(self.path) as clf:
                target = self._sense(clf, timeout, technologies)
                if target is None:
                    return result
                try:
                    tag = nfc.tag.activate(clf, target)
                except Exception:
                    result["error"] = traceback.format_exc()
                    return result
                if tag is None:
                    result["error"] = "Failed to activate the card."
                    return result
                if require_type3 and not isinstance(tag, nfc.tag.tt3.Type3Tag):
                    result["error"] = ("The detected tag is not a FeliCa "
                                       "(Type 3) tag: %s" % (tag,))
                    return result
                try:
                    operation_fn(tag, result)
                except CardError as exc:
                    result["ok"] = False
                    result["error"] = str(exc)
                except Exception:
                    result["ok"] = False
                    result["error"] = traceback.format_exc()
                return result
        except IOError as exc:
            return {"ok": False, "error": "NFC reader not found: %s" % (exc,),
                    "data": None}
        except Exception:
            return {"ok": False, "error": traceback.format_exc(), "data": None}

    # -- generic entry points --------------------------------------------
    def run(self, operation_fn, timeout=8):
        """Run *operation_fn(tag, result)* against any activated FeliCa tag."""
        return self._connect_and_operate(operation_fn, timeout=timeout)

    def run_any(self, operation_fn, timeout=8,
                technologies=("106A", "106B", "212F")):
        """Run *operation_fn(tag, result)* against a tag of any technology."""
        return self._connect_and_operate(operation_fn, timeout=timeout,
                                         require_type3=False,
                                         technologies=technologies)

    # -- primitives operating on an activated tag ------------------------
    @staticmethod
    def _card_info(tag):
        info = describe_tag(tag)
        info["idm"] = binascii.hexlify(tag.idm).decode("ascii").upper()
        info["pmm"] = binascii.hexlify(tag.pmm).decode("ascii").upper()
        sys_code = getattr(tag, "sys", None)
        info["sys_code"] = ("%04X" % sys_code if isinstance(sys_code, int)
                            else "FFFF")
        return info

    @staticmethod
    def _read_block(tag, block_num):
        service = nfc.tag.tt3.ServiceCode(0, SERVICE_RO)
        block = nfc.tag.tt3.BlockCode(block_num)
        data = tag.read_without_encryption([service], [block])
        if data is None:
            raise CardError("Block %d: the card returned no data." % block_num)
        return bytes(data)[:16].ljust(16, b"\x00")

    @staticmethod
    def _write_block(tag, block_num, payload):
        service = nfc.tag.tt3.ServiceCode(0, SERVICE_RW)
        block = nfc.tag.tt3.BlockCode(block_num)
        tag.write_without_encryption([service], [block], ensure_bytes(payload))

    def _authenticate(self, tag, key_bytes):
        if not hasattr(tag, "authenticate"):
            raise CardError("This tag does not support authentication.")
        if not tag.authenticate(ensure_bytes(key_bytes)):
            raise CardError("Authentication failed: the card key (CK) is wrong "
                            "or the card is not a FeliCa Lite-S.")

    # -- public operations -----------------------------------------------
    def get_card_info(self, timeout=8):
        def op(tag, result):
            result["data"] = self._card_info(tag)
            result["ok"] = True
            result["error"] = ""
        return self._connect_and_operate(op, timeout=timeout)

    def read_card(self, blocks=None, key_bytes=None, mc_handler=None, timeout=10):
        """Read every requested block in one card session.

        ``data`` is ``{'info': {...}, 'blocks': {block: bytes}, 'authenticated':
        bool}``.  Blocks that cannot be read are stored as
        :data:`FAILED_MARKER`, blocks that are never readable as
        :data:`SKIPPED_MARKER`.
        """
        blocks = list(ALL_BLOCKS if blocks is None else blocks)

        def op(tag, result):
            info = self._card_info(tag)
            dump = {}
            authenticated = False

            # The MC block decides which blocks need authentication, so it is
            # always read first.
            handler = mc_handler if mc_handler is not None else MCBlockHandler()
            try:
                mc_bytes = self._read_block(tag, BLOCK_MC)
                handler.parse_mc_block_data(mc_bytes)
                dump[BLOCK_MC] = mc_bytes
                self._log("SUCCESS", "MC block read; access rights decoded.")
            except Exception as exc:
                handler.reset()
                dump[BLOCK_MC] = FAILED_MARKER
                self._log("WARN", "Could not read the MC block: %s" % exc)

            if key_bytes and any(handler.needs_read_auth(b) for b in blocks):
                try:
                    self._authenticate(tag, key_bytes)
                    authenticated = True
                    self._log("SUCCESS", "Authenticated with the supplied card key.")
                except CardError as exc:
                    self._log("WARN", str(exc))

            for block_num in blocks:
                if block_num in dump:
                    continue
                if block_num in UNREADABLE_BLOCKS:
                    dump[block_num] = SKIPPED_MARKER
                    self._log("INFO", "Block %d: skipped (write-only)." % block_num)
                    continue
                try:
                    if handler.needs_read_auth(block_num) and authenticated:
                        data = tag.read_with_mac(block_num)
                        if data is None:
                            raise CardError("MAC verification failed.")
                        dump[block_num] = bytes(data)[:16].ljust(16, b"\x00")
                    else:
                        dump[block_num] = self._read_block(tag, block_num)
                    self._log("SUCCESS", "Block %d: read successfully." % block_num)
                except Exception as exc:
                    dump[block_num] = FAILED_MARKER
                    self._log("WARN", "Block %d: read failed (%s)." % (block_num, exc))

            result["data"] = {"info": info, "blocks": dump,
                              "authenticated": authenticated}
            result["ok"] = True
            result["error"] = ""

        return self._connect_and_operate(op, timeout=timeout)

    def write_blocks(self, writes, mc_handler=None, key_bytes=None,
                     verify=True, timeout=10):
        """Write ``writes`` -- an iterable of ``(block_num, 16-byte payload)``.

        Blocks whose MC settings demand it are written after authentication and,
        where W MAC is set, with ``write_with_mac``.  ``data`` reports the list
        of blocks that were written.
        """
        writes = [(int(b), ensure_bytes(d)) for b, d in writes]
        for block_num, payload in writes:
            if len(payload) != 16:
                raise ValueError("Block %d: payload must be 16 bytes." % block_num)

        handler = mc_handler if mc_handler is not None else MCBlockHandler()

        def op(tag, result):
            authenticated = False
            if any(handler.needs_write_auth(b) for b, _ in writes):
                if not key_bytes:
                    raise CardError(
                        "One or more blocks require authentication, but no card "
                        "key (CK) was supplied.")
                self._authenticate(tag, key_bytes)
                authenticated = True

            written = []
            for block_num, payload in writes:
                if handler.needs_write_mac(block_num):
                    if not authenticated:  # pragma: no cover - guarded above
                        raise CardError("Block %d requires a MAC write." % block_num)
                    tag.write_with_mac(payload, block_num)
                else:
                    self._write_block(tag, block_num, payload)

                if verify and block_num not in UNREADABLE_BLOCKS:
                    time.sleep(0.05)
                    try:
                        readback = self._read_block(tag, block_num)
                    except Exception:
                        readback = None
                    if readback is not None and readback != payload:
                        hint = ""
                        if readback == ZERO_BLOCK:
                            hint = (" (the read-back is all zero; the block is "
                                    "probably write-protected)")
                        raise CardError(
                            "Block %d: write verification failed.\n"
                            "Expected: %s\nGot:      %s%s"
                            % (block_num, payload.hex().upper(),
                               readback.hex().upper(), hint))
                written.append(block_num)
                self._log("SUCCESS", "Block %d: written." % block_num)

            result["data"] = written
            result["ok"] = True
            result["error"] = ""

        return self._connect_and_operate(op, timeout=timeout)

    def write_card_key(self, key_bytes, ckv_int, timeout=8):
        """Store a new card key (block CK) and its version (block CKV)."""
        key = ensure_bytes(key_bytes)
        if len(key) != 16:
            raise ValueError("The card key must be exactly 16 bytes.")
        ck_payload = encode_card_key(key)
        ckv_payload = encode_ckv(int(ckv_int))

        def op(tag, result):
            mc_bytes = self._read_block(tag, BLOCK_MC)
            if MCBlockHandler.is_locked(mc_bytes):
                raise CardError("The card is permanently locked (MC[2] = 00h); "
                                "the card key can no longer be changed.")
            self._write_block(tag, BLOCK_CK, ck_payload)
            self._write_block(tag, BLOCK_CKV, ckv_payload)
            # CK is write-only, so the key itself cannot be verified; CKV can.
            readback = self._read_block(tag, BLOCK_CKV)
            if decode_ckv(readback) != int(ckv_int):
                raise CardError(
                    "CKV verification failed: the card reports %04X instead of "
                    "%04X." % (decode_ckv(readback), int(ckv_int)))
            result["data"] = {"ckv": int(ckv_int)}
            result["ok"] = True
            result["error"] = ""

        return self._connect_and_operate(op, timeout=timeout)

    def lock_card(self, timeout=8):
        """Set MC[2] to 00h, permanently freezing the system blocks."""
        def op(tag, result):
            mc_bytes = bytearray(self._read_block(tag, BLOCK_MC))
            if MCBlockHandler.is_locked(mc_bytes):
                raise CardError("This card is already permanently locked.")
            mc_bytes[2] = MCBlockHandler.MC_SP_LOCKED
            self._write_block(tag, BLOCK_MC, bytes(mc_bytes))
            readback = self._read_block(tag, BLOCK_MC)
            if not MCBlockHandler.is_locked(readback):
                raise CardError("The card did not accept the lock command.")
            result["data"] = bytes(readback)
            result["ok"] = True
            result["error"] = ""

        return self._connect_and_operate(op, timeout=timeout)
