# Testing

```bash
python -m pytest                      # 219 tests, ~5 s, no reader needed
python -m pytest --cov=felica_core --cov=felica_type3 \
    --cov=ndef_tools --cov=nfc_reader_writer --cov-report=term-missing
python -m pytest tests/test_core_io.py -k write -v
```

CI runs the same command on Linux (under Xvfb) and Windows, on Python 3.9 and
3.13, after a `pyflakes` pass.

## The card simulator

`tests/fake_card.py` does not mock the protocol. `FakeLiteS`, `FakeLite` and
`FakeStandard` subclass nfcpy's own `FelicaLiteS`, `FelicaLite` and
`FelicaStandard` and replace only the two transport primitives,
`read_without_encryption` and `write_without_encryption`. Everything above them
is nfcpy's production code, so a test that authenticates really runs the
triple-DES session-key derivation, the MAC over the ID block and the MAC'd write
to the STATE block.

The simulator enforces the same rules as a card:

* MC[0..1] decides whether a write is refused as read-only.
* MC[6..7] hides a block from an unauthenticated read.
* MC[8..9] refuses a write until a session exists; MC[10..11] refuses a plain
  write entirely and only accepts one carrying a valid MAC_A.
* MC[2] = `00h` refuses every system-block write.
* A write to RC derives the session key; a read of MAC returns a MAC over the
  blocks read earlier in the same command; CK reads back as zeros; WCNT counts
  MAC'd writes.

A tag is put in front of the controller with `install_fake_reader`, which points
`nfc.ContactlessFrontend` and `nfc.tag.activate` at it:

```python
def test_something(monkeypatch):
    tag = FakeLiteS(blocks={0: b"A" * 16}, card_key=bytes(range(16)))
    install_fake_reader(monkeypatch, felica_core, tag)
    result = NfcController().read_card()
    assert result["data"]["blocks"][0] == b"A" * 16
```

`sense_failures=N` makes the reader miss the card N times first, which is how
the timeout path is tested.

## GUI tests

`tests/conftest.py` builds **one** `NfcApp` for the whole session and resets it
between tests through `app.reset_state()`. Creating and destroying a Tk
interpreter per test makes Tcl finalise itself at unpredictable moments, after
which a later `Tk()` fails with "Can't find a usable init.tcl"; one root avoids
that entirely. The same file pins `TCL_LIBRARY`/`TK_LIBRARY` before Tk is
imported.

Fixtures:

| Fixture | What it gives |
|---|---|
| `app` | the session application, freshly reset, window hidden |
| `loaded_app` | `app` with the simulated card loaded into the table |
| `visible_app` | `loaded_app` mapped on screen, needed for cell geometry |
| `isolated_dialogs` | autouse; every messagebox and file dialog is neutralised |

Worker tests replace `threading.Thread` with an inline runner and then drain the
queue by hand, so the whole path — button, worker, controller, nfcpy, simulated
card, back through the queue into the widgets — runs deterministically:

```python
app.on_read_card()
app._poll_queue()          # what the 100 ms timer would do
assert app.tree.item("0", "values")[1] == "41" * 16
```

Interaction tests synthesise events with an `Event` object carrying `x`/`y` and
derive the coordinates from `tree.bbox`, verified against Tk's own hit test; if
the environment clips the cell, the test skips with a message rather than
failing for the wrong reason.

## Conventions

* A test states what the software should do, in its name and in one assertion
  block. `test_the_mc_write_keeps_the_bytes_the_app_does_not_manage` is the
  regression guard for a specific defect.
* No test may leave global state behind: dialogs are patched through
  `monkeypatch`, and anything set on the shared app is restored in a `finally`.
* New card behaviour belongs in the simulator, not in a mock inside the test, so
  every test benefits from it.
