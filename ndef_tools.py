#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NDEF reading and writing for any tag type nfcpy supports.

Works with NFC Forum Type 1-5 tags (Topaz, MIFARE Ultralight / NTAG, FeliCa
Lite/Lite-S formatted for NDEF, ISO 15693 ...), because it only uses the generic
``tag.ndef`` interface rather than any card-specific memory map.

Source code, README, and full license (GNU GPL v3):
    https://github.com/HiroYokoyama/nfc-reader-writer
Copyright (c) HiroYokoyama. Licensed under the GNU General Public License;
see the LICENSE file in the repository above for the full terms.
"""
from felica_core import CardError, describe_tag

try:
    import ndef
    NDEF_AVAILABLE = True
except ImportError:  # pragma: no cover - ndeflib ships with nfcpy
    ndef = None
    NDEF_AVAILABLE = False


def _require_ndeflib():
    if not NDEF_AVAILABLE:
        raise CardError("The 'ndeflib' package is required for NDEF support "
                        "(it is installed together with nfcpy).")


def describe_record(record):
    """Return ``(kind, text)`` for a decoded NDEF record."""
    name = type(record).__name__
    if NDEF_AVAILABLE and isinstance(record, ndef.TextRecord):
        return "Text", "%s  [%s]" % (record.text, record.language)
    if NDEF_AVAILABLE and isinstance(record, ndef.UriRecord):
        return "URI", record.iri
    if NDEF_AVAILABLE and isinstance(record, ndef.SmartposterRecord):
        return "Smartposter", record.resource.iri
    data = bytes(getattr(record, "data", b"") or b"")
    try:
        text = data.decode("utf-8")
        printable = text if text.isprintable() else data.hex().upper()
    except UnicodeDecodeError:
        printable = data.hex().upper()
    return name.replace("Record", "") or "Record", printable


def read_ndef(tag):
    """Collect the NDEF state of *tag*."""
    _require_ndeflib()
    info = describe_tag(tag)
    ndef_area = getattr(tag, "ndef", None)
    if ndef_area is None:
        return {"info": info, "formatted": False, "records": [],
                "capacity": 0, "length": 0, "writeable": False,
                "octets": b""}
    records = []
    for record in ndef_area.records:
        kind, text = describe_record(record)
        records.append({"kind": kind, "text": text, "type": record.type,
                        "name": record.name})
    return {
        "info": info,
        "formatted": True,
        "records": records,
        "capacity": ndef_area.capacity,
        "length": ndef_area.length,
        "writeable": bool(ndef_area.is_writeable),
        "octets": bytes(ndef_area.octets),
    }


def build_records(specs):
    """Turn ``[{'kind': 'text'|'uri', 'value': ..., 'language': ...}]`` into records."""
    _require_ndeflib()
    records = []
    for spec in specs:
        kind = (spec.get("kind") or "text").lower()
        value = spec.get("value", "")
        if kind == "text":
            records.append(ndef.TextRecord(value, spec.get("language", "en")))
        elif kind == "uri":
            records.append(ndef.UriRecord(value))
        elif kind == "mime":
            payload = spec.get("data", b"")
            records.append(ndef.Record(spec.get("mime_type", "application/octet-stream"),
                                       spec.get("name", ""), payload))
        else:
            raise ValueError("unsupported record kind: %r" % kind)
    return records


def write_ndef(tag, specs):
    """Replace the tag's NDEF message with the records described by *specs*."""
    _require_ndeflib()
    ndef_area = getattr(tag, "ndef", None)
    if ndef_area is None:
        raise CardError(
            "This tag carries no NDEF area. Format it first (NDEF tab -> "
            "Format tag) or use the block editor.")
    if not ndef_area.is_writeable:
        raise CardError("The NDEF area on this tag is read-only.")
    records = build_records(specs)
    message = b"".join(ndef.message_encoder(records))
    if len(message) > ndef_area.capacity:
        raise CardError("The message needs %d bytes but the tag only has %d."
                        % (len(message), ndef_area.capacity))
    ndef_area.records = records
    return len(message)


def format_tag(tag):
    """Write an empty NDEF structure so the tag can hold NDEF messages."""
    if not hasattr(tag, "format"):
        raise CardError("This tag type cannot be formatted by nfcpy.")
    if not tag.format():
        raise CardError("The tag refused to be formatted for NDEF.")
    return True


class NdefManager:
    """Controller-level wrapper; works with tags of every technology."""

    def __init__(self, controller):
        self.controller = controller

    def read(self, timeout=8):
        def op(tag, result):
            result["data"] = read_ndef(tag)
            result["ok"] = True
            result["error"] = ""
        return self.controller.run_any(op, timeout=timeout)

    def write(self, specs, timeout=8):
        def op(tag, result):
            result["data"] = {"written": write_ndef(tag, specs)}
            result["ok"] = True
            result["error"] = ""
        return self.controller.run_any(op, timeout=timeout)

    def format(self, timeout=8):
        def op(tag, result):
            format_tag(tag)
            result["data"] = read_ndef(tag)
            result["ok"] = True
            result["error"] = ""
        return self.controller.run_any(op, timeout=timeout)
