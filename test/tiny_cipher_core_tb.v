`default_nettype none
`timescale 1ns / 1ps

module tiny_cipher_core_tb;
  reg clk;
  reg rst;
  reg start;
  reg [63:0] plaintext;
  reg [79:0] key;
  wire [63:0] ciphertext;
  wire done;
  integer cycles;

  localparam [63:0] EXPECTED_CIPHERTEXT = 64'h389c40e26ac9be52;

  tiny_cipher #(
      .ROUNDS(16)
  ) dut (
      .clk(clk),
      .rst(rst),
      .start(start),
      .plaintext(plaintext),
      .key(key),
      .ciphertext(ciphertext),
      .done(done)
  );

  initial begin
    clk = 1'b0;
    forever #5 clk = ~clk;
  end

  initial begin
    rst = 1'b1;
    start = 1'b0;
    plaintext = 64'h0123456789abcdef;
    key = 80'h00010203040506070809;

    repeat (4) @(posedge clk);
    @(negedge clk);
    rst = 1'b0;

    @(negedge clk);
    start = 1'b1;
    @(negedge clk);
    start = 1'b0;

    cycles = 0;
    while ((done != 1'b1) && (cycles < 400)) begin
      @(posedge clk);
      cycles = cycles + 1;
    end

    if (done != 1'b1) begin
      $display("FAIL: timeout waiting for done");
      $fatal(1);
    end

    if (cycles != 290) begin
      $display("FAIL: expected done in 290 cycles, got %0d", cycles);
      $fatal(1);
    end

    $display("ciphertext = %h", ciphertext);
    if (ciphertext !== EXPECTED_CIPHERTEXT) begin
      $display("FAIL: expected %h", EXPECTED_CIPHERTEXT);
      $fatal(1);
    end

    $display("PASS: tiny_cipher known vector matched in %0d cycles", cycles);
    $finish;
  end
endmodule
