# Walkthroughs

Each recipe assumes a reader nfcpy can open and a card on it when a step says so.
Nothing is written to a card until a step says "write".

## Read a card and save a backup

1. Start the app and press **Read card**. Place the card on the reader within
   ten seconds.
2. The card panel fills in (type, system code, IDm, PMm, lock status), and the
   table shows every block. `N/A (write-only)` is CK or MAC_A; `N/A (read
   failed)` is a block the card refused, usually because it needs
   authentication.
3. **Save state (.json)** stores everything, including the access rights, and is
   the format to keep. **Save dump (.bin)** stores only the 256-byte user area
   for tools that expect that layout.

Take the backup before changing anything. A `.json` file plus *Write changes to
card* restores a card as long as it is not locked.

## Edit user data

1. Read the card.
2. Double-click the hex cell of a block between S_PAD0 and REG, type 32 hex
   characters and press Enter. The row turns blue: the change exists only in the
   table.
   * The **Text to HEX converter** (Tools menu) turns text into a padded 16-byte
     block in the encoding of your choice and drops it into the selected row.
3. Press **Write changes to card**, confirm the block list, and keep the card on
   the reader. Each block is written and read back; a mismatch stops the run and
   reports what the card actually holds.

## Change access rights

1. Read the card.
2. Click the *Access rights* cell of a block between S_PAD0 and REG and pick a
   mode. Hover the cell to see what a mode means.
3. Press **Write changes to card**. The access rights travel to the card as one
   MC block write, together with any data changes.

Rights only bite once they are on the card. `RO` cannot be undone from the app
side — the card itself refuses to write the block afterwards, and MC can only be
rewritten while the card is unlocked.

## Protect blocks with a card key

1. Read the card.
2. Choose a key:
   * type a 32-hex key into **Card key (CK)**, or
   * open Tools → **Card key generator**, press *Read IDm*, enter a passphrase,
     press *Generate*, then *Use as card key*.
3. Press **Write as new card key (CK + CKV)** and confirm. Store the key
   somewhere safe — it can never be read back.
4. Set the blocks you want protected to `RW (W Auth)`, `RW (W MAC)` or
   `RW (R Auth …)` and press **Write changes to card**.
5. From now on, tick **Use this key for protected reads/writes** and keep the
   key in the field. Reads of `R Auth` blocks authenticate and verify the MAC;
   writes to protected blocks authenticate first.

To check the protection worked, untick the box and read again: the protected
blocks come back as `N/A (read failed)`.

## Lock a card permanently

Only when the configuration is final:

1. Read the card and confirm every value in the table is what you want.
2. Press **Permanently lock card** and confirm.
3. MC[2] becomes `00h`. The card key, the system blocks and the memory
   configuration are frozen forever; the app disables the write buttons for that
   card.

## Explore a FeliCa Standard card (Suica, Edy, …)

1. Open the **Type 3 Explorer** tab and press **Scan card**.
2. Every system on the card is listed with its areas and services and the key
   version of each service. `Random RO`, `Random RW`, `Cyclic …` and `Purse …`
   without "(key required)" need no key.
3. Tick **Also dump block data of key-less services** and scan again to read the
   blocks of those services. Services protected by an issuer key are listed but
   cannot be read — that is a property of the card, not a limitation to work
   around.
4. **Save report (.txt)** keeps the result.

The bottom row reads or writes a single block through a service code you type,
for cards whose layout the block editor does not know. Use it with care: a wrong
service code and block number can overwrite something the card needs.

## Read and write NDEF

1. Open the **NDEF** tab and press **Read NDEF**. The records appear with the
   used and total capacity of the NDEF area.
2. To write, pick `text` or `uri`, type the value (and a language for text) and
   press **Write NDEF**. The existing message is replaced.
3. A tag with no NDEF area reports "This tag carries no NDEF area". Press
   **Format tag for NDEF** to create one — this destroys whatever the NDEF area
   held before.

This tab works with every tag type nfcpy supports, not only FeliCa.

## Run without a reader

```bash
python nfc_reader_writer.py --test
```

The table fills with simulated data, and every write is logged instead of being
sent anywhere. Useful for learning the interface, checking a `.json` file, or
building a report. Add a file name to seed the table from a dump:

```bash
python nfc_reader_writer.py --test my_card.bin
```
