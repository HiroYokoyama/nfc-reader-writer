# Third-party notices

This repository contains no third-party code. Nothing here is vendored,
bundled or copied from another project; the packages below are installed
separately by `pip install -r requirements.txt` and are used through their
public APIs at runtime.

| Package | Used for | License |
|---|---|---|
| [nfcpy](https://github.com/nfcpy/nfcpy) (imported as `nfc`) | all reader and tag communication: polling, activation, read/write without encryption, FeliCa authentication, read/write with MAC, NDEF | EUPL 1.1 (or, at the licensee's option, a later EUPL version) |
| [ndeflib](https://github.com/nfcpy/ndeflib) (imported as `ndef`) | encoding and decoding NDEF records | ISC |
| [pyDes](https://github.com/twhiteman/pyDes) | the triple-DES used by nfcpy's FeliCa session keys | MIT |
| [pyserial](https://github.com/pyserial/pyserial) | serial readers (`--device tty:…`) | BSD-3-Clause |
| [libusb1](https://github.com/vpelletier/python-libusb1) | USB readers (`--device usb`) | LGPL-2.1-or-later |

pyDes, pyserial and libusb1 are dependencies of nfcpy rather than direct
dependencies of this application; they are listed because a normal installation
pulls them in.

## Why GPL-3.0

nfcpy is published under the EUPL. The EUPL is a copyleft licence, and Article 5
of the EUPL together with its compatibility list allows a work that builds on
EUPL-covered software to be distributed under the GNU GPL. Licensing this
application under GPL-3.0 therefore keeps it unambiguously compatible with the
library it depends on, and matches the licence used across this author's other
projects.

Distributing this application does not distribute nfcpy: users install it
themselves from PyPI, under nfcpy's own terms.

## The FeliCa specification

The block numbers, the MC bit layout and the authentication sequence documented
in `docs/felica-lite-s.md` come from the publicly available *FeliCa Lite-S
User's Manual* published by Sony, and were cross-checked against nfcpy's
implementation. FeliCa is a trademark of Sony Corporation. This project is not
affiliated with, endorsed by, or supported by Sony.
