#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic NFC Forum Type 3 / FeliCa Standard support.

Everything here works on any Type 3 tag, including FeliCa Standard and Mobile
FeliCa cards: it enumerates systems, areas and services, and reads or writes raw
blocks through a caller-chosen service code.  Nothing in this module assumes the
FeliCa Lite memory map.
"""
import struct

from felica_core import CardError, ensure_bytes, describe_tag

try:
    import nfc
    import nfc.tag.tt3
    NFC_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    nfc = None
    NFC_AVAILABLE = False

#: Service attribute (the low 6 bits of a service code) -> human description.
SERVICE_ATTRIBUTES = {
    0b000000: ("Area", False, False),
    0b001000: ("Random RW (key required)", False, False),
    0b001001: ("Random RW", True, True),
    0b001010: ("Random RO (key required)", False, False),
    0b001011: ("Random RO", True, False),
    0b001100: ("Cyclic RW (key required)", False, False),
    0b001101: ("Cyclic RW", True, True),
    0b001110: ("Cyclic RO (key required)", False, False),
    0b001111: ("Cyclic RO", True, False),
    0b010000: ("Purse direct (key required)", False, False),
    0b010001: ("Purse direct", True, True),
    0b010010: ("Purse cashback/decrement (key required)", False, False),
    0b010011: ("Purse cashback/decrement", True, False),
    0b010100: ("Purse decrement (key required)", False, False),
    0b010101: ("Purse decrement", True, False),
    0b010110: ("Purse read-only (key required)", False, False),
    0b010111: ("Purse read-only", True, False),
}

SYSTEM_CODE_NAMES = {
    0x0000: "SDK sample",
    0x0003: "Suica / transit (Common area)",
    0x12FC: "NDEF (NFC Forum Type 3)",
    0x811D: "Rakuten Edy",
    0x8008: "Octopus",
    0x8592: "nanaco / WAON class",
    0x8620: "Blackboard",
    0x88B4: "FeliCa Lite / Lite-S",
    0xFE00: "Common area",
}

#: How far the service enumeration walks before giving up.
MAX_SERVICE_INDEX = 0x1000


def describe_service(service_code):
    """Return ``(label, readable_without_key, writable_without_key)``."""
    attribute = service_code & 0x3F
    label, readable, writable = SERVICE_ATTRIBUTES.get(
        attribute, ("Unknown service type", False, False))
    return label, readable, writable


def describe_system_code(system_code):
    return SYSTEM_CODE_NAMES.get(system_code, "unknown")


def service_object(service_code):
    """Build an nfcpy ServiceCode from a plain 16-bit service code."""
    return nfc.tag.tt3.ServiceCode(service_code >> 6, service_code & 0x3F)


def read_blocks(tag, service_code, block_numbers):
    """Read the given blocks through *service_code*.

    Returns ``{block_number: bytes}``; blocks the card refuses are omitted.
    """
    service = service_object(service_code)
    out = {}
    for block_num in block_numbers:
        try:
            data = tag.read_without_encryption(
                [service], [nfc.tag.tt3.BlockCode(block_num)])
        except Exception:
            continue
        if data is None:
            continue
        out[block_num] = bytes(data)[:16].ljust(16, b"\x00")
    return out


def write_block(tag, service_code, block_num, payload):
    """Write one 16-byte block through *service_code*."""
    payload = ensure_bytes(payload)
    if len(payload) != 16:
        raise ValueError("payload must be exactly 16 bytes")
    service = service_object(service_code)
    tag.write_without_encryption(
        [service], [nfc.tag.tt3.BlockCode(block_num)], payload)


def dump_service(tag, service_code, max_blocks=256):
    """Read blocks 0..n through *service_code* until the card stops answering."""
    service = service_object(service_code)
    blocks = []
    for index in range(max_blocks):
        try:
            data = tag.read_without_encryption(
                [service], [nfc.tag.tt3.BlockCode(index)])
        except Exception:
            break
        if data is None:
            break
        blocks.append(bytes(data)[:16].ljust(16, b"\x00"))
    return blocks


def list_systems(tag):
    """All system codes on the card (falls back to the active one)."""
    if hasattr(tag, "request_system_code"):
        try:
            return list(tag.request_system_code())
        except Exception:
            pass
    return [getattr(tag, "sys", 0xFFFF)]


def activate_system(tag, system_code):
    """Switch the card to another system, as ``FelicaStandard.dump`` does."""
    idm, pmm = tag.polling(system_code)
    tag.idm, tag.pmm = idm, pmm
    tag.sys = system_code
    return idm, pmm


def list_services(tag, max_index=MAX_SERVICE_INDEX):
    """Walk the service/area list of the active system.

    Returns a list of dicts with ``kind`` ('area' or 'service'), ``code``, the
    area end code for areas, and the key version for services.
    """
    if not hasattr(tag, "search_service_code"):
        return []
    entries = []
    for index in range(max_index):
        try:
            found = tag.search_service_code(index)
        except Exception:
            break
        if not found:
            break
        if len(found) == 2:
            entries.append({"kind": "area", "index": index,
                            "code": found[0], "last": found[1]})
        else:
            code = found[0]
            label, readable, writable = describe_service(code)
            entries.append({"kind": "service", "index": index, "code": code,
                            "label": label, "readable": readable,
                            "writable": writable,
                            "key_version": _key_version(tag, code)})
    return entries


def _key_version(tag, service_code):
    if not hasattr(tag, "request_service"):
        return None
    try:
        versions = tag.request_service([service_object(service_code)])
    except Exception:
        return None
    return versions[0] if versions else None


def explore(tag, read_data=False, max_blocks=64, logger=None):
    """Build a full picture of a Type 3 card.

    ``read_data`` also dumps the blocks of every service that is readable
    without a key.  Returns ``{'info': {...}, 'systems': [...]}``.
    """
    log = logger or (lambda level, text: None)
    info = describe_tag(tag)
    info["idm"] = tag.idm.hex().upper()
    info["pmm"] = tag.pmm.hex().upper()

    original_system = getattr(tag, "sys", 0xFFFF)
    systems = []
    for system_code in list_systems(tag):
        entry = {"code": system_code, "name": describe_system_code(system_code),
                 "services": [], "error": None}
        try:
            activate_system(tag, system_code)
        except Exception as exc:
            entry["error"] = "could not activate this system: %s" % exc
            systems.append(entry)
            continue

        log("INFO", "System %04X (%s): enumerating services..."
            % (system_code, entry["name"]))
        for service in list_services(tag):
            if service["kind"] == "service" and read_data and service["readable"]:
                service["blocks"] = dump_service(tag, service["code"], max_blocks)
            entry["services"].append(service)
        systems.append(entry)

    try:
        activate_system(tag, original_system)
    except Exception:
        pass

    return {"info": info, "systems": systems}


class Type3Explorer:
    """Controller-level wrapper around the functions above."""

    def __init__(self, controller):
        self.controller = controller

    def explore(self, read_data=False, max_blocks=64, timeout=10):
        def op(tag, result):
            result["data"] = explore(tag, read_data=read_data,
                                     max_blocks=max_blocks,
                                     logger=self.controller._log)
            result["ok"] = True
            result["error"] = ""
        return self.controller.run(op, timeout=timeout)

    def read(self, service_code, block_numbers, system_code=None, timeout=8):
        def op(tag, result):
            if system_code is not None:
                activate_system(tag, system_code)
            data = read_blocks(tag, service_code, block_numbers)
            if not data:
                raise CardError(
                    "The card returned no data for service %04X. It may not "
                    "exist, or it needs a key." % service_code)
            result["data"] = data
            result["ok"] = True
            result["error"] = ""
        return self.controller.run(op, timeout=timeout)

    def write(self, service_code, block_num, payload, system_code=None,
              verify=True, timeout=8):
        payload = ensure_bytes(payload)

        def op(tag, result):
            if system_code is not None:
                activate_system(tag, system_code)
            write_block(tag, service_code, block_num, payload)
            verified = False
            if verify:
                readback = read_blocks(tag, service_code, [block_num]).get(block_num)
                if readback is None:
                    self.controller._log(
                        "WARN", "Block %d was written but could not be read back "
                                "through service %04X, so the write is "
                                "unverified." % (block_num, service_code))
                elif readback != payload:
                    raise CardError(
                        "Block %d: write verification failed.\nExpected: %s\n"
                        "Got:      %s" % (block_num, payload.hex().upper(),
                                          readback.hex().upper()))
                else:
                    verified = True
            result["data"] = {"block": block_num, "verified": verified}
            result["ok"] = True
            result["error"] = ""
        return self.controller.run(op, timeout=timeout)


def format_explore_report(report):
    """Render :func:`explore` output as printable lines."""
    lines = []
    info = report.get("info", {})
    lines.append("Card:   %s" % info.get("product", "?"))
    lines.append("IDm:    %s" % info.get("idm", "?"))
    lines.append("PMm:    %s" % info.get("pmm", "?"))
    for system in report.get("systems", []):
        lines.append("")
        lines.append("System %04X (%s)" % (system["code"], system["name"]))
        if system.get("error"):
            lines.append("  %s" % system["error"])
            continue
        if not system["services"]:
            lines.append("  (no services reported)")
        for service in system["services"]:
            if service["kind"] == "area":
                lines.append("  Area %04X--%04X"
                             % (service["code"], service["last"]))
                continue
            key_version = service.get("key_version")
            key_text = ("key version %04X" % key_version
                        if isinstance(key_version, int) and key_version != 0xFFFF
                        else "no key")
            lines.append("    Service %04X  %s  (%s)"
                         % (service["code"], service["label"], key_text))
            for index, block in enumerate(service.get("blocks", [])):
                printable = "".join(chr(b) if 32 <= b < 127 else "."
                                    for b in block)
                lines.append("      %04X: %s |%s|"
                             % (index, block.hex().upper(), printable))
    return lines


def parse_service_code(text):
    """Parse a service code typed by the user ('000B', '0x000b', '11')."""
    text = (text or "").strip().lower()
    if not text:
        raise ValueError("no service code given")
    value = int(text, 16) if not text.startswith("0x") else int(text, 16)
    if not 0 <= value <= 0xFFFF:
        raise ValueError("service code must fit in 16 bits")
    return value


def pack_system_code(system_code):
    return struct.pack(">H", system_code)
