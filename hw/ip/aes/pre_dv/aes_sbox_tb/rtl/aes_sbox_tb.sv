// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// AES SBox testbench

module aes_sbox_tb #(
) (
  input  logic clk_i,
  input  logic rst_ni,

  output logic test_done_o,
  output logic test_passed_o
);

  import aes_pkg::*;

  logic [9:0] count_d, count_q;
  logic [7:0] stimulus;
  ciph_op_e   op;

  int eff_faults;
  int ineff_faults;

  localparam int NUM_SBOX_IMPLS = 1;
  localparam int NUM_SBOX_IMPLS_MASKED = 1;
  localparam int NumSBoxImplsTotal = NUM_SBOX_IMPLS + NUM_SBOX_IMPLS_MASKED;
  logic [7:0] responses[NumSBoxImplsTotal];

  // Generate the stimuli
  assign count_d = count_q + 10'h1;
  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_count
    if (!rst_ni) begin
      count_q <= 9'h100;
    end else if (dom_done) begin
      count_q <= count_d;
    end
  end

  assign op = count_q[8] ? CIPH_FWD : CIPH_INV;
  assign stimulus = count_q[7:0];

  // Instantiate SBox Implementations
  aes_sbox_lut aes_sbox_lut (
    .op_i   ( op           ),
    .data_i ( stimulus     ),
    .data_o ( responses[0] )
  );


  // Mask Generation
  logic  [7:0] masked_stimulus;
  logic  [7:0] in_mask;

  logic  [7:0] masked_response [NUM_SBOX_IMPLS_MASKED];
  logic  [7:0] out_mask [NUM_SBOX_IMPLS_MASKED];

  logic [31:0] mask;
  logic [23:0] unused_mask;

  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_mask
    if (!rst_ni) begin
      mask <= 32'hAAFF;
    end else if (dom_done) begin
      mask <= $random;
    end
  end
  assign in_mask     = mask[7:0];
  assign unused_mask = mask[31:8];

  assign masked_stimulus = stimulus ^ in_mask;

  // PRD Generation
  localparam int unsigned WidthPRDSBoxDOM = 28;
  logic                 [31:0] prd;
  logic [31-WidthPRDSBoxDOM:0] unused_prd;

  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_prd
    if (!rst_ni) begin
      prd <= 32'h4321;
    end else begin
      prd <= {$random};
    end
  end
  assign unused_prd = prd[31:WidthPRDSBoxDOM];




  // Instantiate DOM SBox Implementation
  logic        dom_done;
  logic [19:0] unused_out_prd, out_prd;
  aes_sbox_dom_faulted aes_sbox_dom_faulted (
    .clk_i     ( clk_i                    ),
    .rst_ni    ( rst_ni                   ),
    .fault_en  ( 1'b1),
    .en_i      ( 1'b1                     ),
    .out_req_o ( dom_done                 ),
    .out_ack_i ( 1'b1                     ),
    .op_i      ( op                       ),
    .data_i    ( masked_stimulus          ),
    .mask_i    ( in_mask                  ),
    .prd_i     ( prd[WidthPRDSBoxDOM-1:0] ),
    .data_o    ( masked_response[0]       ),
    .mask_o    ( out_mask[0]              ),
    .prd_o     ( out_prd                  )
  );
  assign unused_out_prd = out_prd;

  // Unmask responses
  always_comb begin : unmask_resp
    for (int i=0; i<NUM_SBOX_IMPLS_MASKED; i++) begin
      responses[NUM_SBOX_IMPLS+i] = masked_response[i] ^ out_mask[i];
    end
  end

  logic [7:0] internal_value;
  //assign internal_value = aes_sbox_dom_faulted.out_mask_basis_x ^ aes_sbox_dom_faulted.out_data_basis_x;
  assign internal_value = responses[1];

  // Check responses, signal end of simulation
  always_ff @(posedge clk_i or negedge rst_ni) begin : tb_ctrl
    if (!rst_ni) begin
      eff_faults <= 0;
      ineff_faults <= 0;
    end else begin

      test_done_o   <= 1'b0;
      test_passed_o <= 1'b1; // do never abort. we know that there might be missmatches

      for (int i=1; i<NumSBoxImplsTotal; i++) begin
        if (rst_ni && dom_done) begin
          if (responses[i] != responses[0]) begin
            test_passed_o <= 1'b0;
            eff_faults <= eff_faults +1;
          end else begin
            ineff_faults <= ineff_faults +1;
            $display("ineff_output: %d", internal_value);
          end
        end
      end
    
      if (count_q == 10'h200 && test_done_o == 1'b0) begin
        $display("\nineff faults: %0d", ineff_faults);
        $display("eff faults: %0d\n", eff_faults);
        test_done_o <= 1'b1;
      end
    end
  end

endmodule
