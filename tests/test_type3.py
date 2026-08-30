"""Generic Type 3 / FeliCa Standard support."""
import pytest

import felica_core as core
import felica_type3 as t3
from fake_card import FakeLiteS, FakeStandard, install_fake_reader


@pytest.fixture
def controller():
    return core.NfcController(logger=lambda level, text: None)


def attach(monkeypatch, tag):
    install_fake_reader(monkeypatch, core, tag)
    install_fake_reader(monkeypatch, t3, tag)


def test_service_codes_are_described():
    assert t3.describe_service(0x000B) == ("Random RO", True, False)
    assert t3.describe_service(0x0009)[2] is True
    assert t3.describe_service(0x0008)[1] is False        # a key is required
    assert t3.describe_service(0x1234)[0] == "Unknown service type"


def test_system_codes_are_named():
    assert "NDEF" in t3.describe_system_code(0x12FC)
    assert t3.describe_system_code(0x4242) == "unknown"


def test_service_code_parsing():
    assert t3.parse_service_code("000B") == 0x000B
    assert t3.parse_service_code("0x9") == 0x0009
    with pytest.raises(ValueError):
        t3.parse_service_code("")
    with pytest.raises(ValueError):
        t3.parse_service_code("nope")


def test_explore_lists_every_system_and_service(monkeypatch, controller):
    tag = FakeStandard()
    attach(monkeypatch, tag)

    result = t3.Type3Explorer(controller).explore()

    assert result["ok"], result["error"]
    report = result["data"]
    assert report["info"]["kind"] == core.KIND_STANDARD
    codes = [system["code"] for system in report["systems"]]
    assert codes == [0x0003, 0x12FC]
    first = report["systems"][0]["services"]
    assert first[0]["kind"] == "area"
    assert [s["code"] for s in first if s["kind"] == "service"] == [0x000B, 0x0048]


def test_explore_can_dump_key_less_services(monkeypatch, controller):
    tag = FakeStandard()
    attach(monkeypatch, tag)

    report = t3.Type3Explorer(controller).explore(read_data=True)["data"]

    service = [s for s in report["systems"][0]["services"]
               if s.get("code") == 0x000B][0]
    assert service["blocks"] == [bytes([i]) * 16 for i in range(3)]


def test_explore_restores_the_original_system(monkeypatch, controller):
    tag = FakeStandard()
    attach(monkeypatch, tag)
    t3.Type3Explorer(controller).explore()
    assert tag.active_system == 0x0003


def test_report_formatting_mentions_systems_and_services(monkeypatch, controller):
    tag = FakeStandard()
    attach(monkeypatch, tag)
    report = t3.Type3Explorer(controller).explore(read_data=True)["data"]

    text = "\n".join(t3.format_explore_report(report))

    assert "System 0003" in text
    assert "Service 000B" in text
    assert "0000: 00000000" in text


def test_raw_block_read_and_write(monkeypatch, controller):
    tag = FakeStandard()
    attach(monkeypatch, tag)
    explorer = t3.Type3Explorer(controller)

    read = explorer.read(0x000B, [1])
    assert read["ok"], read["error"]
    assert read["data"][1] == bytes([1]) * 16

    written = explorer.write(0x0009, 1, b"Z" * 16)
    assert written["ok"], written["error"]
    assert tag.blocks[0x0009][1] == b"Z" * 16


def test_raw_read_of_a_missing_service_reports_an_error(monkeypatch, controller):
    attach(monkeypatch, FakeStandard())

    result = t3.Type3Explorer(controller).read(0x0FFF, [0])

    assert result["ok"] is False
    assert "no data" in result["error"]


def test_raw_write_verification_catches_a_card_that_keeps_the_old_data(
        monkeypatch, controller):
    tag = FakeStandard()
    tag.write_without_encryption = lambda *args, **kwargs: None
    attach(monkeypatch, tag)

    result = t3.Type3Explorer(controller).write(0x000B, 0, b"Q" * 16)

    assert result["ok"] is False
    assert "verification failed" in result["error"]


def test_an_unverifiable_write_is_reported_as_unverified(monkeypatch, controller):
    messages = []
    controller.logger = lambda level, text: messages.append((level, text))
    tag = FakeStandard()
    attach(monkeypatch, tag)
    # A write-only service gives nothing back to compare against.
    monkeypatch.setattr(t3, "read_blocks", lambda *args, **kwargs: {})

    result = t3.Type3Explorer(controller).write(0x0009, 0, b"Q" * 16)

    assert result["ok"], result["error"]
    assert result["data"]["verified"] is False
    assert any("unverified" in text for _level, text in messages)


def test_write_block_requires_sixteen_bytes(monkeypatch, controller):
    tag = FakeStandard()
    attach(monkeypatch, tag)
    with pytest.raises(ValueError):
        t3.write_block(tag, 0x0009, 0, b"short")


def test_a_lite_card_still_works_through_the_generic_reader(monkeypatch,
                                                            controller):
    tag = FakeLiteS(blocks={2: b"L" * 16})
    attach(monkeypatch, tag)

    result = t3.Type3Explorer(controller).read(0x000B, [2])

    assert result["ok"], result["error"]
    assert result["data"][2] == b"L" * 16


def test_list_systems_falls_back_to_the_active_system(monkeypatch, controller):
    tag = FakeLiteS()
    attach(monkeypatch, tag)
    assert t3.list_systems(tag) == [0x88B4]
    assert t3.list_services(tag) == []
