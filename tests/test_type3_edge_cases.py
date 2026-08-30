"""Error paths of the Type 3 explorer and the NDEF helpers."""
import pytest

import felica_core as core
import felica_type3 as t3
import ndef_tools
from fake_card import FakeLiteS, FakeStandard, install_fake_reader
from felica_core import CardError


@pytest.fixture
def controller():
    messages = []
    ctrl = core.NfcController(logger=lambda level, text: messages.append((level, text)))
    ctrl.messages = messages
    return ctrl


def attach(monkeypatch, tag):
    install_fake_reader(monkeypatch, core, tag)
    install_fake_reader(monkeypatch, t3, tag)


# ==============================================================================
# Enumeration
# ==============================================================================
def test_a_system_that_cannot_be_activated_is_listed_with_its_error(monkeypatch,
                                                                    controller):
    tag = FakeStandard()
    # The card advertises a system that then refuses to be activated.
    tag.request_system_code = lambda: [0x0003, 0x9999]
    attach(monkeypatch, tag)

    report = t3.Type3Explorer(controller).explore()["data"]

    broken = [s for s in report["systems"] if s["code"] == 0x9999][0]
    assert broken["error"] is not None
    assert broken["services"] == []
    text = "\n".join(t3.format_explore_report(report))
    assert "could not activate" in text


def test_a_system_without_services_is_reported(monkeypatch, controller):
    tag = FakeStandard()
    tag.systems = [0x0003]
    tag.service_map[0x0003] = []
    attach(monkeypatch, tag)

    report = t3.Type3Explorer(controller).explore()["data"]

    assert "(no services reported)" in "\n".join(t3.format_explore_report(report))


def test_a_card_that_cannot_list_systems_falls_back_to_the_active_one(monkeypatch,
                                                                     controller):
    tag = FakeStandard()

    def refuse():
        raise RuntimeError("command not supported")

    tag.request_system_code = refuse
    attach(monkeypatch, tag)

    assert t3.list_systems(tag) == [0x0003]


def test_a_service_walk_that_raises_stops_cleanly(monkeypatch, controller):
    tag = FakeStandard()

    def explode(index):
        raise RuntimeError("bad card")

    tag.search_service_code = explode
    attach(monkeypatch, tag)

    assert t3.list_services(tag) == []


def test_the_key_version_is_none_when_the_card_cannot_report_it(monkeypatch):
    tag = FakeStandard()

    def explode(service_list):
        raise RuntimeError("no request service")

    tag.request_service = explode
    assert t3._key_version(tag, 0x000B) is None

    del tag.request_service
    tag.__dict__["request_service"] = None
    assert t3._key_version(tag, 0x000B) is None


def test_dumping_a_service_stops_at_the_first_refusal(monkeypatch):
    tag = FakeStandard()
    assert len(t3.dump_service(tag, 0x000B)) == 3
    assert t3.dump_service(tag, 0x0FFF) == []


def test_restoring_the_original_system_never_breaks_a_scan(monkeypatch, controller):
    tag = FakeStandard()
    attach(monkeypatch, tag)
    calls = {"n": 0}
    genuine = tag.polling

    def flaky(system_code=0xFFFF, request_code=0, time_slots=0):
        calls["n"] += 1
        if calls["n"] > 3:                   # the final restore fails
            raise RuntimeError("card gone")
        return genuine(system_code, request_code, time_slots)

    tag.polling = flaky
    result = t3.Type3Explorer(controller).explore()

    assert result["ok"], result["error"]


def test_reading_after_switching_to_another_system(monkeypatch, controller):
    tag = FakeStandard()
    tag.blocks[0x000B] = [b"N" * 16]
    attach(monkeypatch, tag)

    result = t3.Type3Explorer(controller).read(0x000B, [0], system_code=0x12FC)

    assert result["ok"], result["error"]
    assert tag.active_system == 0x12FC


def test_write_through_a_service_that_needs_a_key_fails(monkeypatch, controller):
    tag = FakeStandard()
    attach(monkeypatch, tag)

    result = t3.Type3Explorer(controller).write(0x0008, 0, b"K" * 16)

    assert result["ok"] is False


def test_read_blocks_skips_blocks_the_card_refuses(monkeypatch):
    tag = FakeStandard()
    data = t3.read_blocks(tag, 0x000B, [0, 99])
    assert list(data) == [0]


def test_service_descriptions_cover_the_purse_types():
    assert t3.describe_service(0x0011)[0].startswith("Purse direct")
    assert t3.describe_service(0x0017)[1] is True
    assert t3.describe_service(0x0000)[0] == "Area"


def test_system_code_packing():
    assert t3.pack_system_code(0x12FC) == b"\x12\xFC"


def test_a_lite_card_has_no_service_list(monkeypatch):
    tag = FakeLiteS()
    assert t3.list_services(tag) == []


# ==============================================================================
# NDEF helpers
# ==============================================================================
def test_ndef_helpers_require_ndeflib(monkeypatch):
    monkeypatch.setattr(ndef_tools, "NDEF_AVAILABLE", False)
    with pytest.raises(CardError) as excinfo:
        ndef_tools.read_ndef(FakeLiteS())
    assert "ndeflib" in str(excinfo.value)


def test_formatting_a_tag_that_cannot_be_formatted(monkeypatch, controller):
    tag = FakeLiteS()
    tag.format = lambda *a, **k: False
    attach(monkeypatch, tag)

    result = ndef_tools.NdefManager(controller).format()

    assert result["ok"] is False
    assert "refused to be formatted" in result["error"]


def test_a_tag_type_without_format_support(monkeypatch, controller):
    class Bare:
        idm = b"\x00" * 8
        pmm = b"\x00" * 8

    tag = FakeLiteS()
    attach(monkeypatch, tag)
    monkeypatch.setattr(core.nfc.tag, "activate", lambda clf, target: Bare())

    result = ndef_tools.NdefManager(controller).format()

    assert result["ok"] is False
    assert "cannot be formatted" in result["error"]
