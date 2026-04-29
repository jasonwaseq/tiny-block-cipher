<!---

This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

## How it works

This project implements a compact 64-bit lightweight block cipher core designed for TinyTapeout.

Core properties:
- Block size: 64 bits
- Key size: 80 bits
- Rounds: 16
- Architecture: sequential, one round per cycle

At the algorithm level, each round performs:
1. AddRoundKey (XOR state with 64-bit round key)
2. 4-bit S-box layer (PRESENT-style)
3. Fixed bit permutation layer

The key schedule is updated every cycle by:
1. Rotating the 80-bit key
2. Applying the S-box to the most-significant nibble
3. XORing the round counter into key bits [19:15]

The controller is an FSM with states IDLE, LOAD, ROUND, and DONE.
The same datapath logic is reused for every round to reduce area.

Because one 4-bit S-box instance is reused across nibble operations, encryption latency is deterministic and longer than a fully parallel round implementation.

Top-level TinyTapeout interface (`tt_um_example`) uses byte-wise loading:
- `ui[0]`: load plaintext byte
- `ui[1]`: load key byte
- `ui[2]`: start pulse
- `ui[6:3]`: byte index
- `uio_in[7:0]`: input data byte while loading
- `uo_out[7:0]`: selected ciphertext byte
- `uio_out[0]`: done flag

## How to test

1. Apply reset (`rst_n = 0`) for a few cycles, then deassert reset (`rst_n = 1`).
2. Load plaintext bytes through `uio_in[7:0]` with `ui[0]=1` and `ui[6:3]` as byte index 0..7 (little-endian byte order).
3. Load key bytes through `uio_in[7:0]` with `ui[1]=1` and `ui[6:3]` as byte index 0..9 (little-endian byte order).
4. Pulse `ui[2]` high for one cycle to start encryption.
5. Wait until `uio_out[0]` becomes 1 (done).
6. Read ciphertext bytes from `uo_out[7:0]` by selecting byte index on `ui[6:3]`.

Reference test vector for the core:
- Plaintext: `0x0123456789ABCDEF`
- Key: `0x00010203040506070809`
- Ciphertext: `0x389C40E26AC9BE52`

Local regression command:

```sh
cd test
make
```

## External hardware

No external hardware is required.
