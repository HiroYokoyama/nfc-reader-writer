# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## 0.1.0 — 2026-08-30

First release of the project under its new name. It replaces the single-file
`felica_gui.py` of `felica-lite-s_reader-writer`, which could not correctly
address a card.

### Added

* **FeliCa Lite / Lite-S tab** — reads every block that exists on the card,
  edits the user area, changes per-block access rights, writes the card key
  (CK + CKV) and locks the card permanently. FeliCa Lite is detected and offered
  only the modes it supports.
* **Type 3 Explorer tab** — enumerates systems, areas and services on any Type 3
  tag, including FeliCa Standard and Mobile FeliCa, dumps services that need no
  key, and reads or writes single blocks through a chosen service code.
* **NDEF tab** — reads, writes and formats NDEF messages on any tag type nfcpy
  supports (Type 1–5).
* Authenticated operation: reads of `R Auth` blocks, writes to `W Auth` blocks
  and MAC-signed writes to `W MAC` blocks.
* `.bin`, `.json` and `.txt` export and import; the `.json` state carries the
  card identity, every block and the access rights.
* Card key generator (HMAC-SHA256 over the IDm) and a text-to-HEX converter.
* `--test` mode that runs the whole interface without a reader, `--device` for
  any nfcpy device path, and `--version`.
* 219 tests against a FeliCa simulator built on nfcpy's own tag classes, running
  in CI on Linux and Windows for Python 3.9 and 3.13.
* Documentation in `docs/`: usage walkthroughs, a FeliCa Lite-S reference, the
  architecture, the testing approach and troubleshooting.
* GPL-3.0 licence and third-party notices.

### Fixed

Relative to the tool this replaces:

* The MC block was read from and written to block 15, which does not exist on a
  FeliCa Lite-S card; the memory configuration is block `88h`. Access rights
  never reached the card.
* Authenticated reads and writes called a method nfcpy does not have
  (`tag.authentication(key_version=…, password=…)`) and passed the wrong
  argument shapes to `read_with_mac` and `write_with_mac`. Every protected
  operation failed.
* "Permanently lock" cleared MC[3] (SYS_OP) instead of MC[2] (MC_SP), so it
  aborted on every unlocked card and would have changed the NDEF setting rather
  than locking.
* The card key was written to block 14 (REG). CK is block `87h`, CKV is `86h`,
  and the key is stored with each 8-byte half reversed.
* Regenerating the MC block overwrote SYS_OP, RF_PRM, the CK-write flag and the
  reserved bytes with hardcoded defaults.
* The system code was read from a non-existent `tag.sys_code`, so it always
  showed a fallback value.
* Loading a `.bin` dump, and `--test`, crashed; saving a dump wrote past the end
  of the buffer and produced a file that could not be loaded back.
* Worker threads updated Tk widgets directly, and timers fired into destroyed
  windows.
* Blocks that failed to read were stored as zeros and offered back as pending
  writes.

### Known limitations

* Not yet tested against real reader hardware; the USB transport is the one
  layer the test suite cannot reach.
* FeliCa Standard services protected by an issuer key cannot be read — that is a
  property of the card.
* NDEF writing supports text and URI records.
