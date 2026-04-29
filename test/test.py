# SPDX-FileCopyrightText: © 2024 Tiny Tapeout
# SPDX-License-Identifier: Apache-2.0

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles


PLAINTEXT = 0x0123456789ABCDEF
KEY = 0x00010203040506070809
EXPECTED_CIPHERTEXT = 0x389C40E26AC9BE52


def get_byte(value: int, index: int) -> int:
    return (value >> (8 * index)) & 0xFF


async def write_byte(dut, index: int, data: int, load_pt: bool, load_key: bool):
    ctrl = ((index & 0xF) << 3)
    if load_pt:
        ctrl |= 0x01
    if load_key:
        ctrl |= 0x02

    dut.ui_in.value = ctrl
    dut.uio_in.value = data
    await ClockCycles(dut.clk, 1)
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 1)


async def read_ciphertext_byte(dut, index: int) -> int:
    dut.ui_in.value = ((index & 0x7) << 3)
    await ClockCycles(dut.clk, 1)
    return int(dut.uo_out.value)


@cocotb.test()
async def test_project(dut):
    dut._log.info("Start TinyTapeout cipher test")

    clock = Clock(dut.clk, 10, unit="us")
    cocotb.start_soon(clock.start())

    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 4)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)

    dut._log.info("Loading plaintext bytes")
    for i in range(8):
        await write_byte(dut, i, get_byte(PLAINTEXT, i), load_pt=True, load_key=False)

    dut._log.info("Loading key bytes")
    for i in range(10):
        await write_byte(dut, i, get_byte(KEY, i), load_pt=False, load_key=True)

    dut._log.info("Issuing start pulse")
    dut.ui_in.value = 0x04
    await ClockCycles(dut.clk, 1)
    dut.ui_in.value = 0x00

    done_cycle = None
    for cycle in range(40):
        await ClockCycles(dut.clk, 1)
        if int(dut.uio_out.value) & 0x1:
            done_cycle = cycle + 1
            break

    assert done_cycle is not None, "Timeout waiting for done"
    assert done_cycle == 18, f"Unexpected latency: {done_cycle} cycles (expected 18)"

    dut._log.info("Reading ciphertext bytes")
    observed = 0
    for i in range(8):
        b = await read_ciphertext_byte(dut, i)
        observed |= (b & 0xFF) << (8 * i)

    dut._log.info(f"Observed ciphertext: 0x{observed:016X}")
    assert observed == EXPECTED_CIPHERTEXT, (
        f"Cipher mismatch: got 0x{observed:016X}, expected 0x{EXPECTED_CIPHERTEXT:016X}"
    )
