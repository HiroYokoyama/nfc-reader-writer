# NFC Reader/Writer

[![Tests](https://github.com/HiroYokoyama/nfc-reader-writer/actions/workflows/tests.yml/badge.svg)](https://github.com/HiroYokoyama/nfc-reader-writer/actions/workflows/tests.yml)

A desktop tool for reading and writing NFC tags with an nfcpy-supported reader
(PaSoRi RC-S380, ACR122U, SCL3711, …).

Three panels share one reader:

| Tab | What it does | Cards |
|---|---|---|
| **FeliCa Lite / Lite-S** | Full block editor: dump every block, edit the user area, change per-block access rights, write the card key, lock the card | FeliCa Lite (RC-S965), Lite-S (RC-S966), FeliCa Link in Lite-S mode |
| **Type 3 Explorer** | Enumerate systems, areas and services; dump key-less services; read/write single blocks through any service code | Any NFC Forum Type 3 tag, including FeliCa Standard and Mobile FeliCa |
| **NDEF** | Read, write and format NDEF messages (text and URI records) | Any tag type nfcpy supports — Type 1–5: Topaz, MIFARE Ultralight / NTAG, ISO 15693, FeliCa … |

## Documentation

| Document | Contents |
|---|---|
| [docs/usage.md](docs/usage.md) | Step-by-step walkthroughs: back up a card, edit data, change access rights, protect with a key, lock, explore a Standard card, NDEF |
| [docs/felica-lite-s.md](docs/felica-lite-s.md) | The card itself: memory map, MC block bit layout, authentication, card key and locking |
| [docs/architecture.md](docs/architecture.md) | Module layout, the result contract, the threading model, how to add a card type or a panel |
| [docs/testing.md](docs/testing.md) | The card simulator, the GUI fixtures, how to write a new test |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Reader and driver problems, failed writes, lost keys, locked cards |

## Install

```bash
pip install -r requirements.txt
python nfc_reader_writer.py
```

Requires Python 3.9+ with Tkinter (bundled with the python.org installers).
On Windows the reader needs a libusb-compatible driver — install one with
[Zadig](https://zadig.akeo.ie/) if nfcpy reports "no reader found".

Run without a reader to explore the interface:

```bash
python nfc_reader_writer.py --test              # simulated card
python nfc_reader_writer.py --test dump.bin     # seed the table from a dump
python nfc_reader_writer.py --device tty:USB0   # any nfcpy device path
```

## FeliCa Lite / Lite-S tab

**Read card** dumps every block that exists on the card: the user area
(S_PAD0–S_PAD13), REG, and the system blocks RC, MAC, ID, D_ID, SER_C, SYS_C,
CKV, CK, MC, WCNT, MAC_A and STATE. CK and MAC_A are never readable and are
shown as `N/A (write-only)`; a block the card refuses shows `N/A (read failed)`
— neither is ever mistaken for real data or written back.

* **Editing** — double-click the hex cell of a user block. Changed rows are
  highlighted; nothing reaches the card until you press *Write changes to card*.
* **Access rights** — click the rights cell of blocks S_PAD0…REG to pick a mode.
  Lite-S offers `RW`/`RO` combined with `R Auth`, `W Auth` and `W MAC`; a plain
  Lite card only has `RW` and `RO`. Changes are staged into the MC block and
  written together with the data. Everything in MC the app does not manage
  (SYS_OP, RF_PRM, the CK-write flag, reserved bytes) is preserved byte for byte.
* **Protected blocks** — tick *Use this key for protected reads/writes* and
  enter the 32-hex card key. Reads of `R Auth` blocks then authenticate and use
  read-with-MAC; writes to `W Auth` blocks authenticate first and `W MAC` blocks
  are written with a MAC.
* **Write card key** — writes CK (block 87h) and CKV (block 86h). The key is
  stored the way the card expects it (each 8-byte half reversed) and is never
  readable afterwards, so keep a copy.
* **Permanently lock card** — sets MC[2] to `00h`. This is irreversible: the
  card key and all system blocks are frozen forever.

### File formats

* **`.bin`** — the 256-byte user area, blocks 0…15 in order. Block 15 does not
  exist on a Lite-S card and is stored as zeros. Loading a dump stages it as
  pending changes and leaves the system blocks on screen untouched.
* **`.json`** — the complete state: card identification, access rights, every
  block, the CKV/CK fields and the chosen encoding. Loading one stages
  everything, including the access rights, for the next write.
* **`.txt`** — a human-readable report: card identity, the access-rights table
  and the full dump.

## Type 3 Explorer tab

*Scan card* lists every system on the card and every area and service inside it,
with the key version of each service. Tick *Also dump block data of key-less
services* to read the blocks of services that need no key — this is how far a
FeliCa Standard card (Suica, Edy, …) can be read: services protected by an
issuer key cannot be decrypted and are listed but not read.

The bottom row reads or writes one block through any service code you type,
which is useful for cards whose layout the block editor does not know. Writes
are verified by reading the block back where the service allows it.

## NDEF tab

*Read NDEF* shows the records on any tag; *Write NDEF* replaces the message with
a text or URI record; *Format tag for NDEF* writes a fresh, empty NDEF structure
on a tag that has none. The capacity, used length and the read-only flag of the
NDEF area are shown next to the buttons.

## Safety

* Locking a card, writing a card key and any raw block write can destroy a card.
  Each is behind an explicit confirmation dialog.
* Writes are verified by reading the block back; a mismatch is reported instead
  of being silently accepted. Blocks that cannot be read back are reported as
  unverified.
* Only user blocks can be typed into; system blocks are edited exclusively
  through the dedicated controls.

## Development

```
felica_core.py          memory map, MC block handling, reader operations
felica_type3.py         generic Type 3 / FeliCa Standard support
ndef_tools.py           NDEF reading, writing and formatting
nfc_reader_writer.py    the Tkinter application
tests/                  216 tests, no reader or card required
```

| Test file | Covers |
|---|---|
| `test_mc_block.py` | MC bit layout, round trips, Lite vs Lite-S, nfcpy's own protect masks |
| `test_core_io.py` | read / write / card key / lock against a simulated card |
| `test_core_edge_cases.py` | reader errors, refused activation, failed verification |
| `test_type3.py`, `test_type3_edge_cases.py` | system and service enumeration, raw block access |
| `test_ndef.py` | NDEF read, write, format, capacity and read-only handling |
| `test_gui.py` | table population, editing, file round trips, test mode |
| `test_gui_workers.py` | every button, end-to-end through the controller to the card |
| `test_gui_interaction.py` | mouse clicks, the access-rights dropdown, tooltips |
| `test_gui_tools.py` | the key generator, the converter, failure dialogs |

```bash
python -m pytest                      # 216 tests, ~5 s
python -m pytest --cov=felica_core --cov=felica_type3 \
    --cov=ndef_tools --cov=nfc_reader_writer --cov-report=term-missing
```

Coverage is 95% overall, 99% of the card layer. The suite runs in CI on Linux
(under Xvfb) and Windows, on Python 3.9 and 3.13.

`tests/fake_card.py` is an in-memory FeliCa simulator that subclasses nfcpy's
own tag classes and replaces only the transport, so the tests exercise the real
protocol — including the triple-DES mutual authentication, read-with-MAC and
write-with-MAC paths — against a simulated Lite, Lite-S or Standard card. The
GUI tests drive a real (hidden) Tk instance; a few of them briefly show the
window because Tk only reports cell geometry for a mapped window.
