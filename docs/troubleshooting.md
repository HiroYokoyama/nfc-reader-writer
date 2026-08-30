# Troubleshooting

## The reader is not found

`NFC reader not found: no reader available on path usb`

* **Windows** — nfcpy talks to the reader through libusb, not the vendor driver.
  Install a libusb driver for the device with [Zadig](https://zadig.akeo.ie/)
  (WinUSB is the usual choice). A PaSoRi that works in the Sony software but not
  here is still bound to the vendor driver.
* **Linux** — either run as root once to confirm, then add a udev rule:

  ```
  SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="054c", GROUP="plugdev", MODE="0664"
  ```

  and add yourself to `plugdev`. If `pcscd` grabbed the reader, stop it.
* **A serial reader** — start with `--device tty:USB0` (or the port you use)
  instead of the default `usb`.
* Check what nfcpy itself sees:

  ```bash
  python -m nfc
  ```

  That command lists every device it can open and prints the same diagnosis this
  application would.

## Nothing happens when I press Read card

The card must be on the reader during the ten-second poll, not before it. Some
readers need the card moved slightly to be detected. If the log shows
`Timeout: no card detected`, the reader opened fine and simply saw nothing.

## Blocks show "N/A (read failed)"

The card refused the read. Either the block needs authentication — tick **Use
this key for protected reads/writes** and enter the card key — or the card is
not the type the block editor expects. A FeliCa Standard card fails most blocks
here; use the Type 3 Explorer tab instead.

## "Write verification failed … the read-back is all zero"

The card accepted the command but did not store the data. Usual causes:

* the block is read-only (`RO`) in the memory configuration;
* the block needs authentication or a MAC and the key is missing or wrong;
* the card is permanently locked and the block is a system block;
* the card left the field mid-write — try again with the card held still.

The table keeps the change, so nothing is lost; fix the cause and write again.

## "Authentication failed: the card key (CK) is wrong"

The key in the panel is not the key on the card. There is no way to read a card
key back, so a lost key cannot be recovered — a card whose protected blocks need
that key stays unreadable. If the card is not locked and MC[2] is still `FFh`, a
new key can be written over the old one with **Write as new card key**.

## "The card is permanently locked (MC[2] = 00h)"

MC[2] was set to `00h` at some point. System blocks, including the card key and
the memory configuration, are frozen for the life of the card. Data blocks that
were left as `RW` can still be written.

## The card key I wrote does not authenticate

Check that the key was entered as 32 hex characters, and that the card reports
the CKV you expected after a re-read. The application stores the key in the
byte order the card expects (each 8-byte half reversed); if a card was
provisioned by another tool that did not, the two disagree about which key is on
the card. Writing the key again from this application settles it, provided the
card is unlocked.

## An NDEF write says the tag is read-only

The NDEF RW flag in the attribute block is `00h`. Some tools set it deliberately
when they finalise a tag. On a FeliCa Lite-S, **Format tag for NDEF** rewrites
the attribute block and clears the flag — at the cost of the current message.

## The GUI tests skip or fail on my machine

* "no Tk display available" — Tkinter cannot open a display. On a headless Linux
  box run the suite under `xvfb-run -a`.
* "the cell is clipped by the screen size" — the window is larger than the
  screen, so a row is not fully visible. Harmless; use a larger display or
  virtual screen to run those tests.
