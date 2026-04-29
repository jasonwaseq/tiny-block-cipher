/*
 * Copyright (c) 2024 Jason Waseq
 * SPDX-License-Identifier: Apache-2.0
 */

`default_nettype none

module tt_um_example (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,
    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);

  // ui_in[0]: load plaintext byte
  // ui_in[1]: load key byte
  // ui_in[2]: start pulse input
  // ui_in[6:3]: byte index (0..7 for plaintext/ciphertext, 0..9 for key)
  wire load_pt = ui_in[0];
  wire load_key = ui_in[1];
  wire start_cmd = ui_in[2];
  wire [3:0] byte_sel = ui_in[6:3];

  reg [63:0] plaintext_reg;
  reg [79:0] key_reg;
  reg start_d;
  wire start_pulse;

  wire [63:0] cipher_out;
  wire done_out;

  tiny_cipher #(
      .ROUNDS(16)
  ) u_cipher (
      .clk(clk),
      .rst(~rst_n),
      .start(start_pulse),
      .plaintext(plaintext_reg),
      .key(key_reg),
      .ciphertext(cipher_out),
      .done(done_out)
  );

  assign start_pulse = start_cmd & ~start_d;

  always @(posedge clk) begin
    if (!rst_n) begin
      plaintext_reg <= 64'h0;
      key_reg <= 80'h0;
      start_d <= 1'b0;
    end else begin
      start_d <= start_cmd;

      if (load_pt) begin
        case (byte_sel)
          4'd0: plaintext_reg[7:0] <= uio_in;
          4'd1: plaintext_reg[15:8] <= uio_in;
          4'd2: plaintext_reg[23:16] <= uio_in;
          4'd3: plaintext_reg[31:24] <= uio_in;
          4'd4: plaintext_reg[39:32] <= uio_in;
          4'd5: plaintext_reg[47:40] <= uio_in;
          4'd6: plaintext_reg[55:48] <= uio_in;
          4'd7: plaintext_reg[63:56] <= uio_in;
          default: plaintext_reg <= plaintext_reg;
        endcase
      end

      if (load_key) begin
        case (byte_sel)
          4'd0: key_reg[7:0] <= uio_in;
          4'd1: key_reg[15:8] <= uio_in;
          4'd2: key_reg[23:16] <= uio_in;
          4'd3: key_reg[31:24] <= uio_in;
          4'd4: key_reg[39:32] <= uio_in;
          4'd5: key_reg[47:40] <= uio_in;
          4'd6: key_reg[55:48] <= uio_in;
          4'd7: key_reg[63:56] <= uio_in;
          4'd8: key_reg[71:64] <= uio_in;
          4'd9: key_reg[79:72] <= uio_in;
          default: key_reg <= key_reg;
        endcase
      end
    end
  end

  assign uo_out =
      (byte_sel[2:0] == 3'd0) ? cipher_out[7:0] :
      (byte_sel[2:0] == 3'd1) ? cipher_out[15:8] :
      (byte_sel[2:0] == 3'd2) ? cipher_out[23:16] :
      (byte_sel[2:0] == 3'd3) ? cipher_out[31:24] :
      (byte_sel[2:0] == 3'd4) ? cipher_out[39:32] :
      (byte_sel[2:0] == 3'd5) ? cipher_out[47:40] :
      (byte_sel[2:0] == 3'd6) ? cipher_out[55:48] :
      cipher_out[63:56];

  assign uio_out = {7'b0, done_out};
  assign uio_oe = 8'b00000001;

  wire _unused = &{ena, ui_in[7], 1'b0};

endmodule

module tiny_cipher (
    input clk,
    input rst,
    input start,
    input [63:0] plaintext,
    input [79:0] key,
    output reg [63:0] ciphertext,
    output reg done
);
  parameter integer ROUNDS = 16;

  localparam [2:0] ST_IDLE = 3'd0;
  localparam [2:0] ST_LOAD = 3'd1;
  localparam [2:0] ST_PREP = 3'd2;
  localparam [2:0] ST_SUBST = 3'd3;
  localparam [2:0] ST_PERM = 3'd4;
  localparam [2:0] ST_DONE = 3'd5;

  reg [2:0] fsm_state;
  reg [63:0] state_reg;
  reg [63:0] mixed_shift_reg;
  reg [63:0] sbox_accum_reg;
  reg [79:0] round_key_reg;
  reg [5:0] round_counter;
  reg [3:0] nibble_counter;

  wire [3:0] sbox_nibble_out;
  wire [63:0] perm_state;
  wire [79:0] next_key;

  tiny_cipher_sbox4 u_sbox_serial (
      .in_nibble(mixed_shift_reg[3:0]),
    .out_nibble(sbox_nibble_out)
  );

  tiny_cipher_permute u_permute (
    .sbox_state(sbox_accum_reg),
    .perm_state(perm_state)
  );

  tiny_cipher_key_schedule u_key_sched (
      .key_in(round_key_reg),
      .round_count(round_counter[4:0] + 5'd1),
      .key_out(next_key)
  );

  always @(posedge clk) begin
    if (rst) begin
      fsm_state <= ST_IDLE;
      state_reg <= 64'h0;
      mixed_shift_reg <= 64'h0;
      sbox_accum_reg <= 64'h0;
      round_key_reg <= 80'h0;
      round_counter <= 6'd0;
      nibble_counter <= 4'd0;
      ciphertext <= 64'h0;
      done <= 1'b0;
    end else begin
      case (fsm_state)
        ST_IDLE: begin
          done <= 1'b0;
          if (start) begin
            fsm_state <= ST_LOAD;
          end
        end

        ST_LOAD: begin
          state_reg <= plaintext;
          mixed_shift_reg <= 64'h0;
          sbox_accum_reg <= 64'h0;
          round_key_reg <= key;
          round_counter <= 6'd0;
          nibble_counter <= 4'd0;
          fsm_state <= ST_PREP;
        end

        ST_PREP: begin
          mixed_shift_reg <= state_reg ^ round_key_reg[79:16];
          sbox_accum_reg <= 64'h0;
          nibble_counter <= 4'd0;
          fsm_state <= ST_SUBST;
        end

        ST_SUBST: begin
          mixed_shift_reg <= {4'b0000, mixed_shift_reg[63:4]};
          sbox_accum_reg <= {sbox_nibble_out, sbox_accum_reg[63:4]};
          if (nibble_counter == 4'd15) begin
            nibble_counter <= 4'd0;
            fsm_state <= ST_PERM;
          end else begin
            nibble_counter <= nibble_counter + 4'd1;
          end
        end

        ST_PERM: begin
          state_reg <= perm_state;
          round_key_reg <= next_key;
          if (round_counter == (ROUNDS - 1)) begin
            ciphertext <= perm_state;
            done <= 1'b1;
            fsm_state <= ST_DONE;
          end else begin
            round_counter <= round_counter + 6'd1;
            fsm_state <= ST_PREP;
          end
        end

        ST_DONE: begin
          if (!start) begin
            fsm_state <= ST_IDLE;
          end
        end

        default: begin
          fsm_state <= ST_IDLE;
        end
      endcase
    end
  end
endmodule

module tiny_cipher_permute (
    input [63:0] sbox_state,
    output [63:0] perm_state
);
  assign perm_state[0] = sbox_state[0];
  assign perm_state[16] = sbox_state[1];
  assign perm_state[32] = sbox_state[2];
  assign perm_state[48] = sbox_state[3];
  assign perm_state[1] = sbox_state[4];
  assign perm_state[17] = sbox_state[5];
  assign perm_state[33] = sbox_state[6];
  assign perm_state[49] = sbox_state[7];
  assign perm_state[2] = sbox_state[8];
  assign perm_state[18] = sbox_state[9];
  assign perm_state[34] = sbox_state[10];
  assign perm_state[50] = sbox_state[11];
  assign perm_state[3] = sbox_state[12];
  assign perm_state[19] = sbox_state[13];
  assign perm_state[35] = sbox_state[14];
  assign perm_state[51] = sbox_state[15];
  assign perm_state[4] = sbox_state[16];
  assign perm_state[20] = sbox_state[17];
  assign perm_state[36] = sbox_state[18];
  assign perm_state[52] = sbox_state[19];
  assign perm_state[5] = sbox_state[20];
  assign perm_state[21] = sbox_state[21];
  assign perm_state[37] = sbox_state[22];
  assign perm_state[53] = sbox_state[23];
  assign perm_state[6] = sbox_state[24];
  assign perm_state[22] = sbox_state[25];
  assign perm_state[38] = sbox_state[26];
  assign perm_state[54] = sbox_state[27];
  assign perm_state[7] = sbox_state[28];
  assign perm_state[23] = sbox_state[29];
  assign perm_state[39] = sbox_state[30];
  assign perm_state[55] = sbox_state[31];
  assign perm_state[8] = sbox_state[32];
  assign perm_state[24] = sbox_state[33];
  assign perm_state[40] = sbox_state[34];
  assign perm_state[56] = sbox_state[35];
  assign perm_state[9] = sbox_state[36];
  assign perm_state[25] = sbox_state[37];
  assign perm_state[41] = sbox_state[38];
  assign perm_state[57] = sbox_state[39];
  assign perm_state[10] = sbox_state[40];
  assign perm_state[26] = sbox_state[41];
  assign perm_state[42] = sbox_state[42];
  assign perm_state[58] = sbox_state[43];
  assign perm_state[11] = sbox_state[44];
  assign perm_state[27] = sbox_state[45];
  assign perm_state[43] = sbox_state[46];
  assign perm_state[59] = sbox_state[47];
  assign perm_state[12] = sbox_state[48];
  assign perm_state[28] = sbox_state[49];
  assign perm_state[44] = sbox_state[50];
  assign perm_state[60] = sbox_state[51];
  assign perm_state[13] = sbox_state[52];
  assign perm_state[29] = sbox_state[53];
  assign perm_state[45] = sbox_state[54];
  assign perm_state[61] = sbox_state[55];
  assign perm_state[14] = sbox_state[56];
  assign perm_state[30] = sbox_state[57];
  assign perm_state[46] = sbox_state[58];
  assign perm_state[62] = sbox_state[59];
  assign perm_state[15] = sbox_state[60];
  assign perm_state[31] = sbox_state[61];
  assign perm_state[47] = sbox_state[62];
  assign perm_state[63] = sbox_state[63];
endmodule

module tiny_cipher_round (
    input [63:0] state_in,
    input [63:0] round_key,
    output [63:0] state_out
);
  wire [63:0] key_mixed_state;
  wire [63:0] sbox_state;
  wire [63:0] perm_state;

  assign key_mixed_state = state_in ^ round_key;

  tiny_cipher_sbox4 sbox0 (.in_nibble(key_mixed_state[3:0]), .out_nibble(sbox_state[3:0]));
  tiny_cipher_sbox4 sbox1 (.in_nibble(key_mixed_state[7:4]), .out_nibble(sbox_state[7:4]));
  tiny_cipher_sbox4 sbox2 (.in_nibble(key_mixed_state[11:8]), .out_nibble(sbox_state[11:8]));
  tiny_cipher_sbox4 sbox3 (.in_nibble(key_mixed_state[15:12]), .out_nibble(sbox_state[15:12]));
  tiny_cipher_sbox4 sbox4 (.in_nibble(key_mixed_state[19:16]), .out_nibble(sbox_state[19:16]));
  tiny_cipher_sbox4 sbox5 (.in_nibble(key_mixed_state[23:20]), .out_nibble(sbox_state[23:20]));
  tiny_cipher_sbox4 sbox6 (.in_nibble(key_mixed_state[27:24]), .out_nibble(sbox_state[27:24]));
  tiny_cipher_sbox4 sbox7 (.in_nibble(key_mixed_state[31:28]), .out_nibble(sbox_state[31:28]));
  tiny_cipher_sbox4 sbox8 (.in_nibble(key_mixed_state[35:32]), .out_nibble(sbox_state[35:32]));
  tiny_cipher_sbox4 sbox9 (.in_nibble(key_mixed_state[39:36]), .out_nibble(sbox_state[39:36]));
  tiny_cipher_sbox4 sbox10 (.in_nibble(key_mixed_state[43:40]), .out_nibble(sbox_state[43:40]));
  tiny_cipher_sbox4 sbox11 (.in_nibble(key_mixed_state[47:44]), .out_nibble(sbox_state[47:44]));
  tiny_cipher_sbox4 sbox12 (.in_nibble(key_mixed_state[51:48]), .out_nibble(sbox_state[51:48]));
  tiny_cipher_sbox4 sbox13 (.in_nibble(key_mixed_state[55:52]), .out_nibble(sbox_state[55:52]));
  tiny_cipher_sbox4 sbox14 (.in_nibble(key_mixed_state[59:56]), .out_nibble(sbox_state[59:56]));
  tiny_cipher_sbox4 sbox15 (.in_nibble(key_mixed_state[63:60]), .out_nibble(sbox_state[63:60]));

  assign perm_state[0] = sbox_state[0];
  assign perm_state[16] = sbox_state[1];
  assign perm_state[32] = sbox_state[2];
  assign perm_state[48] = sbox_state[3];
  assign perm_state[1] = sbox_state[4];
  assign perm_state[17] = sbox_state[5];
  assign perm_state[33] = sbox_state[6];
  assign perm_state[49] = sbox_state[7];
  assign perm_state[2] = sbox_state[8];
  assign perm_state[18] = sbox_state[9];
  assign perm_state[34] = sbox_state[10];
  assign perm_state[50] = sbox_state[11];
  assign perm_state[3] = sbox_state[12];
  assign perm_state[19] = sbox_state[13];
  assign perm_state[35] = sbox_state[14];
  assign perm_state[51] = sbox_state[15];
  assign perm_state[4] = sbox_state[16];
  assign perm_state[20] = sbox_state[17];
  assign perm_state[36] = sbox_state[18];
  assign perm_state[52] = sbox_state[19];
  assign perm_state[5] = sbox_state[20];
  assign perm_state[21] = sbox_state[21];
  assign perm_state[37] = sbox_state[22];
  assign perm_state[53] = sbox_state[23];
  assign perm_state[6] = sbox_state[24];
  assign perm_state[22] = sbox_state[25];
  assign perm_state[38] = sbox_state[26];
  assign perm_state[54] = sbox_state[27];
  assign perm_state[7] = sbox_state[28];
  assign perm_state[23] = sbox_state[29];
  assign perm_state[39] = sbox_state[30];
  assign perm_state[55] = sbox_state[31];
  assign perm_state[8] = sbox_state[32];
  assign perm_state[24] = sbox_state[33];
  assign perm_state[40] = sbox_state[34];
  assign perm_state[56] = sbox_state[35];
  assign perm_state[9] = sbox_state[36];
  assign perm_state[25] = sbox_state[37];
  assign perm_state[41] = sbox_state[38];
  assign perm_state[57] = sbox_state[39];
  assign perm_state[10] = sbox_state[40];
  assign perm_state[26] = sbox_state[41];
  assign perm_state[42] = sbox_state[42];
  assign perm_state[58] = sbox_state[43];
  assign perm_state[11] = sbox_state[44];
  assign perm_state[27] = sbox_state[45];
  assign perm_state[43] = sbox_state[46];
  assign perm_state[59] = sbox_state[47];
  assign perm_state[12] = sbox_state[48];
  assign perm_state[28] = sbox_state[49];
  assign perm_state[44] = sbox_state[50];
  assign perm_state[60] = sbox_state[51];
  assign perm_state[13] = sbox_state[52];
  assign perm_state[29] = sbox_state[53];
  assign perm_state[45] = sbox_state[54];
  assign perm_state[61] = sbox_state[55];
  assign perm_state[14] = sbox_state[56];
  assign perm_state[30] = sbox_state[57];
  assign perm_state[46] = sbox_state[58];
  assign perm_state[62] = sbox_state[59];
  assign perm_state[15] = sbox_state[60];
  assign perm_state[31] = sbox_state[61];
  assign perm_state[47] = sbox_state[62];
  assign perm_state[63] = sbox_state[63];

  assign state_out = perm_state;
endmodule

module tiny_cipher_key_schedule (
    input [79:0] key_in,
    input [4:0] round_count,
    output [79:0] key_out
);
  wire [79:0] key_rot;
  wire [3:0] sbox_top;

  assign key_rot = {key_in[18:0], key_in[79:19]};

  tiny_cipher_sbox4 ks_sbox (
      .in_nibble(key_rot[79:76]),
      .out_nibble(sbox_top)
  );

  assign key_out = {
      sbox_top,
      key_rot[75:20],
      key_rot[19:15] ^ round_count,
      key_rot[14:0]
  };
endmodule

module tiny_cipher_sbox4 (
    input [3:0] in_nibble,
    output reg [3:0] out_nibble
);
  always @(*) begin
    case (in_nibble)
      4'h0: out_nibble = 4'hc;
      4'h1: out_nibble = 4'h5;
      4'h2: out_nibble = 4'h6;
      4'h3: out_nibble = 4'hb;
      4'h4: out_nibble = 4'h9;
      4'h5: out_nibble = 4'h0;
      4'h6: out_nibble = 4'ha;
      4'h7: out_nibble = 4'hd;
      4'h8: out_nibble = 4'h3;
      4'h9: out_nibble = 4'he;
      4'ha: out_nibble = 4'hf;
      4'hb: out_nibble = 4'h8;
      4'hc: out_nibble = 4'h4;
      4'hd: out_nibble = 4'h7;
      4'he: out_nibble = 4'h1;
      default: out_nibble = 4'h2;
    endcase
  end
endmodule
