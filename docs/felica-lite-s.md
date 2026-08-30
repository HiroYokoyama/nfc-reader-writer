# FeliCa Lite / Lite-S reference

Everything this application knows about the card, in one place. Block numbers
follow the FeliCa Lite-S User's Manual; the behaviour was cross-checked against
nfcpy's `nfc/tag/tt3_sony.py`, which is the reference implementation the app
talks through.

## Memory map

| Block | Hex | Name | Contents | Readable | Writable |
|---|---|---|---|---|---|
| 0–13 | 00–0D | S_PAD0…S_PAD13 | 16 bytes of free user data each | yes | yes (unless RO) |
| 14 | 0E | REG | REGA[4], REGB[4], REGC[8] | yes | yes (unless RO) |
| 128 | 80 | RC | Random challenge, written to start a session | yes | yes |
| 129 | 81 | MAC | MAC over the blocks read in the same command | yes | no |
| 130 | 82 | ID | IDm[8] + DFC[2] | yes | only while unlocked |
| 131 | 83 | D_ID | Device identification | yes | only while unlocked |
| 132 | 84 | SER_C | Service code | yes | only while unlocked |
| 133 | 85 | SYS_C | System code | yes | only while unlocked |
| 134 | 86 | CKV | Card key version, little endian | yes | only while unlocked |
| 135 | 87 | CK | Card key | **no** (reads as zeros) | only while unlocked |
| 136 | 88 | MC | Memory configuration | yes | only while unlocked |
| 144 | 90 | WCNT | Write counter, 3 bytes little endian | yes | no |
| 145 | 91 | MAC_A | MAC for write-with-MAC | **no** | yes |
| 146 | 92 | STATE | Lite-S status flags | yes | with MAC |

There is **no block 15**. Older tools that treat block 15 as the memory
configuration are addressing a block the card does not have; the configuration
is block `88h` (136).

Blocks are read through service `000Bh` (read without encryption) and written
through service `0009h` (write without encryption).

## The MC block

16 bytes. The application manages four bit pairs and preserves every other byte
of whatever the card already had.

| Byte | Name | Meaning |
|---|---|---|
| MC[0], MC[1] | — | RW/RO per block. Bit set = read/write, clear = read-only |
| MC[2] | MC_SP | `FFh`: the system blocks can be written. `00h`: locked forever |
| MC[3] | SYS_OP | `00h`: FeliCa Lite-S mode, `01h`: NDEF mode |
| MC[4] | RF_PRM | RF parameter; the manual prescribes `07h` |
| MC[5] | — | Bit 0: the card key may be changed after MC_SP is cleared |
| MC[6], MC[7] | — | Reading the block requires authentication (Lite-S only) |
| MC[8], MC[9] | — | Writing the block requires authentication (Lite-S only) |
| MC[10], MC[11] | — | Writing the block requires a MAC (Lite-S only) |
| MC[12]…MC[15] | — | Reserved |

Each pair is a little-endian 16-bit mask over the blocks:

```
bit   0  1  2  3  4  5  6  7   8  9 10 11 12 13 14   15
block 0  1  2  3  4  5  6  7   8  9 10 11 12 13 REG  reserved
      \________ MC[x] ______/  \________ MC[x+1] ________/
```

So block 8 is bit 0 of the high byte, and REG (block 14) is bit 6 of the high
byte. nfcpy writes `0x7FFF ^ (2**14 - 2**n)` into MC[0..1] to make blocks n…13
read-only, which is the same layout seen from the other side.

A plain FeliCa Lite has no MC[6]…MC[11]; only RW/RO exists, which is why the app
offers just `RW` and `RO` once it detects a Lite card.

## Access modes in the interface

| Shown | MC bits set | Effect |
|---|---|---|
| `RW` | — | Read and write freely |
| `RO` | RW/RO cleared | The card refuses every write |
| `RW [RA]` | MC[6..7] | Reading requires authentication and returns a MAC |
| `RW [WA]` | MC[8..9] | Writing requires a prior authentication |
| `RW [WM]` | MC[10..11] | Writing requires a MAC computed from the session key |

`RA`, `WA` and `WM` can be combined; the tooltip on the rights column spells out
what a given combination means.

## Authentication

1. The reader writes 16 random bytes to RC (block `80h`), each 8-byte half
   reversed.
2. Both sides derive the session key `SK = 3DES(CK, CBC, IV=0).encrypt(RC)`.
3. The reader reads ID and MAC together (`82h`, `81h`); the card returns a MAC
   over the ID block computed with SK and IV = RC1. Matching MACs prove the card
   holds the same card key — this is *internal* authentication.
4. On Lite-S the reader then writes `01h` into the ext_auth byte of STATE
   (`92h`) with a MAC, proving to the card that the reader holds the key —
   *external* authentication, which is what unlocks the protected blocks.

After that, `read_with_mac` verifies the MAC over each response, and
`write_with_mac` signs each write with the write counter, the block number and
the key halves swapped. The application never implements any of this itself; it
calls nfcpy's `authenticate()`, `read_with_mac()` and `write_with_mac()`.

## Card key and key version

* The card key (CK) is 16 bytes and lives in block `87h`. It is stored with each
  8-byte half reversed: the bytes written are `key[7::-1] + key[15:7:-1]`.
* CK can never be read back. The application writes it, then verifies the key
  version instead.
* The key version (CKV) is a 16-bit little-endian value in block `86h`. It has
  no cryptographic role; it labels which key is on the card.
* The *Card key generator* tool derives a key deterministically as
  `HMAC-SHA256(passphrase, IDm)[:16]`, so the same passphrase and card always
  give the same key. This is a convenience, not a standard.

## Locking

Writing `00h` to MC[2] makes every system block permanently read-only: the card
key, the system codes and the memory configuration itself can never be changed
again. Access rights that were already set stay in force. There is no way back —
the application asks for confirmation and refuses to write to a card it knows is
locked.

If MC[5] bit 0 was set before locking, the card key can still be replaced by an
authenticated reader; this application does not offer that path.
