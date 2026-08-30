"""NDEF reading and writing on top of nfcpy's generic tag interface."""
import ndef
import pytest

import felica_core as core
import ndef_tools
from fake_card import FakeLiteS, install_fake_reader, ndef_blocks

HELLO = b"".join(ndef.message_encoder([ndef.TextRecord("hello", "en")]))


@pytest.fixture
def controller():
    return core.NfcController(logger=lambda level, text: None)


def attach(monkeypatch, tag):
    install_fake_reader(monkeypatch, core, tag)


def test_read_reports_records_and_capacity(monkeypatch, controller):
    tag = FakeLiteS(blocks=ndef_blocks(HELLO))
    attach(monkeypatch, tag)

    result = ndef_tools.NdefManager(controller).read()

    assert result["ok"], result["error"]
    data = result["data"]
    assert data["formatted"] is True
    assert data["writeable"] is True
    assert data["length"] == len(HELLO)
    assert data["records"] == [{"kind": "Text", "text": "hello  [en]",
                                "type": "urn:nfc:wkt:T", "name": ""}]


def test_read_of_an_unformatted_tag_says_so(monkeypatch, controller):
    attach(monkeypatch, FakeLiteS())

    data = ndef_tools.NdefManager(controller).read()["data"]

    assert data["formatted"] is False
    assert data["records"] == []


def test_write_replaces_the_message(monkeypatch, controller):
    tag = FakeLiteS(blocks=ndef_blocks(HELLO))
    attach(monkeypatch, tag)
    manager = ndef_tools.NdefManager(controller)

    result = manager.write([{"kind": "uri", "value": "https://example.com"}])

    assert result["ok"], result["error"]
    records = manager.read()["data"]["records"]
    assert records[0]["kind"] == "URI"
    assert records[0]["text"] == "https://example.com"


def test_write_to_a_read_only_area_is_refused(monkeypatch, controller):
    tag = FakeLiteS(blocks=ndef_blocks(HELLO, writable=False))
    attach(monkeypatch, tag)

    result = ndef_tools.NdefManager(controller).write(
        [{"kind": "text", "value": "nope"}])

    assert result["ok"] is False
    assert "read-only" in result["error"]


def test_write_to_an_unformatted_tag_explains_the_fix(monkeypatch, controller):
    attach(monkeypatch, FakeLiteS())

    result = ndef_tools.NdefManager(controller).write(
        [{"kind": "text", "value": "nope"}])

    assert result["ok"] is False
    assert "Format it first" in result["error"]


def test_a_message_that_exceeds_the_capacity_is_refused(monkeypatch, controller):
    tag = FakeLiteS(blocks=ndef_blocks(HELLO))
    attach(monkeypatch, tag)

    result = ndef_tools.NdefManager(controller).write(
        [{"kind": "text", "value": "x" * 5000}])

    assert result["ok"] is False
    assert "only has" in result["error"]


def test_format_prepares_an_empty_tag(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    manager = ndef_tools.NdefManager(controller)

    result = manager.format()

    assert result["ok"], result["error"]
    assert result["data"]["formatted"] is True
    assert manager.write([{"kind": "text", "value": "after format"}])["ok"]
    assert manager.read()["data"]["records"][0]["text"] == "after format  [en]"


def test_records_are_built_from_specifications():
    records = ndef_tools.build_records([
        {"kind": "text", "value": "hi", "language": "de"},
        {"kind": "uri", "value": "https://example.org"}])
    assert records[0].text == "hi" and records[0].language == "de"
    assert records[1].iri == "https://example.org"
    with pytest.raises(ValueError):
        ndef_tools.build_records([{"kind": "nonsense", "value": ""}])


def test_records_are_described_for_the_table():
    assert ndef_tools.describe_record(ndef.TextRecord("t", "en")) == ("Text",
                                                                     "t  [en]")
    assert ndef_tools.describe_record(ndef.UriRecord("https://a.b"))[0] == "URI"
    other = ndef.Record("application/octet-stream", "", b"\x01\x02")
    assert ndef_tools.describe_record(other)[1] == "0102"
