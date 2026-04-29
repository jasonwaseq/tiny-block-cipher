![](../../workflows/gds/badge.svg) ![](../../workflows/docs/badge.svg) ![](../../workflows/test/badge.svg) ![](../../workflows/fpga/badge.svg)

# Tiny Lightweight Block Cipher (TinyTapeout)

This project implements a compact, sequential, TinyTapeout-compatible lightweight block cipher core.

The design is inspired by PRESENT-style structure and optimized for small area:
- 64-bit block size
- 80-bit key size
- 16 rounds (one round per cycle)
- FSM control with deterministic latency
- Reused datapath hardware across rounds

## Core Architecture

The cipher datapath includes:
- AddRoundKey (XOR with 64-bit round key)
- 4-bit PRESENT S-box layer
- Fixed bit permutation layer
- 80-bit key schedule (rotate, S-box on MS nibble, round counter XOR)

Control uses FSM states:
- IDLE
- LOAD
- ROUND
- DONE

With the current wrapper protocol, encryption completion is deterministic at 18 cycles from start pulse observation at top-level I/O.

## TinyTapeout I/O Protocol

Top module: `tt_um_example`

Control on `ui_in`:
- `ui_in[0]`: load plaintext byte
- `ui_in[1]`: load key byte
- `ui_in[2]`: start pulse
- `ui_in[6:3]`: byte index
- `ui_in[7]`: unused

Data path:
- `uio_in[7:0]`: input byte during load operations
- `uo_out[7:0]`: selected ciphertext byte (indexed by `ui_in[6:3]`)
- `uio_out[0]`: done flag

## Known Test Vector (Core)

- Plaintext: `0x0123456789ABCDEF`
- Key: `0x00010203040506070809`
- Ciphertext: `0x389C40E26AC9BE52`

## Running Tests

Run the cocotb wrapper-level test:

```sh
cd test
make
```

Run direct core known-vector testbench:

```sh
cd ..
iverilog -g2005-sv -s tiny_cipher_core_tb -o /tmp/tiny_cipher_core_tb.out src/project.v test/tiny_cipher_core_tb.v
vvp /tmp/tiny_cipher_core_tb.out
```

## References

- Tiny Tapeout: https://tinytapeout.com
- Project documentation: [docs/info.md](docs/info.md)
