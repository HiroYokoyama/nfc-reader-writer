# Architecture

## Modules

```
felica_core.py         memory map, MC block, NfcController (no GUI, no display needed)
felica_type3.py        generic Type 3 / FeliCa Standard: systems, services, raw blocks
ndef_tools.py          NDEF read / write / format for any tag type
nfc_reader_writer.py   the Tkinter application
tests/                 the suite and the card simulator
```

The three lower modules import no Tkinter and can be used from a script:

```python
from felica_core import NfcController

controller = NfcController(logger=lambda level, text: print(level, text))
result = controller.read_card()
if result["ok"]:
    for block, data in sorted(result["data"]["blocks"].items()):
        print("%3d %s" % (block, data.hex()))
```

## The result contract

Every controller method returns the same dictionary:

```python
{"ok": bool, "error": str, "data": ...}
```

`ok` is `False` with a human-readable `error` for anything the user can act on
(no card, wrong key, verification failed) and a full traceback for anything
unexpected. Methods never raise for card-level problems; they raise only for
programming errors such as a payload that is not 16 bytes.

`felica_core.CardError` is the exception used inside an operation to carry a
readable message out to `error`.

## One connection per operation

`NfcController._connect_and_operate` opens the reader, polls for a target until
the timeout, activates the tag and hands it to a callback:

```python
def op(tag, result):
    result["data"] = ...
    result["ok"] = True

controller.run(op, timeout=8)        # FeliCa (Type 3) only
controller.run_any(op, timeout=8)    # any technology, for NDEF
```

Everything a button does happens inside one such callback, so the card has to
stay on the reader once per operation rather than once per block. `read_card`
reads the MC block first, because MC decides which of the remaining blocks need
authentication.

## Threading

Tkinter may only be touched from the thread that created it. The rule in this
application:

* Button handlers run on the main thread. They validate input, ask for
  confirmation and compute everything they need from the widgets **before**
  starting a worker.
* `_run_worker` starts a daemon thread and manages the busy flag, which disables
  the buttons for the duration.
* The worker never touches a widget. It posts messages to `out_q`:

  | Message | Payload | Effect |
  |---|---|---|
  | `LOG` | `(level, text)` | appends to the log pane |
  | `STATUS` | text | the status bar |
  | `CARD_INFO` | info dict | the card panel |
  | `DUMP` | `{block: bytes}` | fills the table |
  | `LOCK` | bool | lock status and button states |
  | `BUSY` | bool | re-enables the buttons |
  | `CALL` | callable | run this on the main thread (dialogs, table updates) |

* `_poll_queue` drains the queue every 100 ms on the main thread, and
  reschedules itself through `_schedule`, which records the timer id so
  `destroy()` can cancel it. A timer that fires into a destroyed window leaves
  the Tcl interpreter in a bad state.

## Table model

Rows are keyed by block number: the Treeview item id of block 136 is `"136"`, so
`self.tree.item(str(block))` addresses a row directly and no parsing of display
strings is needed.

Per row the app keeps:

* the displayed hex, which is what the user edits;
* `original_dump[block]`, the value read from the card;
* `dump_blocks[block]`, the raw bytes, used when a partial dump is loaded.

`_pending_data_changes()` compares the two and returns only user blocks whose hex
is valid and different — a row showing `N/A (read failed)` can never become a
write. Access-right changes are separate: `_mc_state_changed()` compares the MC
handler against `original_mc_state`, and the write path renders the MC block from
the card's own bytes so nothing unmanaged is lost.

## Adding a card type

1. Add the detection to `felica_core.describe_tag`. Order matters: the nfcpy
   classes inherit from each other (`FelicaLiteS` from `FelicaLite`,
   `FelicaMobile` from `FelicaStandard`), so the most specific check comes first.
2. If the card has a fixed memory map, add the block numbers, names and
   descriptions to the constants at the top of `felica_core.py` and add the kind
   to `BLOCK_EDITOR_KINDS`.
3. If it does not, it is already usable through the Type 3 Explorer.
4. Add a simulator to `tests/fake_card.py` and a test that reads it.

## Adding a panel

Tabs are built in `_create_felica_tab`, `_create_type3_tab` and
`_create_ndef_tab`, each a plain method that packs widgets into a frame from the
notebook. A new tab needs a `_create_*_tab` method, a line in `_create_widgets`,
its buttons added to `_update_ui_state`, and handlers that follow the worker
pattern above.
