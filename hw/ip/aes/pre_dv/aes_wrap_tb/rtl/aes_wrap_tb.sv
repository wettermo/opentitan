// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// AES wrap testbench

module aes_wrap_tb #(
) (
  input  logic clk_i,
  input  logic rst_ni,

  output logic test_done_o,
  output logic test_passed_o
);

  logic [127:0] aes_output;
  logic [127:0] aes_input;
  logic [255:0] aes_key;
  logic  [31:0] entropy_mask = $random;

  logic         test_done;
  logic         alert_recov, alert_fatal;
  logic  [15:0] count_d, count_q;
  int           count_enc = 32'h0;

  logic [127:0] expected_cipher;

  int fd;
  int fd_2;
  int fgets_ret;
  int sscanf_ret;
  int init_mark = 1;
  int read_next_line = 0;
  string line;

  // Instantiate DUT
  aes_wrap aes_wrap (
    .clk_i,
    .rst_ni,

    .entropy_mask  ( entropy_mask ),

    .aes_input     ( aes_input    ),
    .aes_key       ( aes_key      ),
    .aes_output    ( aes_output   ),

    .alert_recov_o ( alert_recov  ),
    .alert_fatal_o ( alert_fatal  ),

    .test_done_o   ( test_done    )
  );

  // Count the time.
  assign count_d = count_q + 16'h1;
  always_ff @(posedge clk_i or negedge rst_ni) begin : reg_count
    if (!rst_ni) begin
      count_q <= '0;
    end else begin
      count_q <= count_d;
    end
  end

  // Check responses, signal end of simulation
  always_ff @(posedge clk_i or negedge rst_ni) begin : tb_ctrl
    test_done_o   <= 1'b0;
    test_passed_o <= 1'b0;

    if (init_mark) begin
      // create and open output file for encryption results
      fd = $fopen("../ot-sca/cw/cw305/sifa_aes_output_verilator_sim.csv", "w");
      // open plaintext and key input file
      fd_2 = $fopen("../ot-sca/cw/cw305/sifa_aes_input_verilator_sim.csv", "r");

      fgets_ret = $fgets(line, fd_2);
      if (fgets_ret == 0) begin
        test_done_o <= 1'b1; // end simulation, nothing to read
        $fclose(fd);
        $fclose(fd_2);
      end
      // omit first read input line as it is the title line -> do nothing with line
      read_next_line = 1;

      $display("Plaintext, Ciphertext, Key, Expected Ciphertext");
      $fdisplay(fd, "Plaintext,Ciphertext,Key,Expected Ciphertext");
      init_mark = 0;
    end

    if (read_next_line) begin
      fgets_ret = $fgets(line, fd_2);
      if (fgets_ret == 0) begin
        test_done_o <= 1'b1; // end simulation, nothing to read
        $fclose(fd);
        $fclose(fd_2);
      end else begin
        sscanf_ret <= $sscanf(line, "%h,%h,%h", aes_input, aes_key, expected_cipher);
      end
      read_next_line = 0;
    end

    if (rst_ni && test_done) begin
      $display("\nEncryption no. %d", count_enc);

      if (alert_recov) begin
        $display("\nINFO: Recoverable alert condition detected.");
      end
      if (alert_fatal) begin
        $display("\nINFO: Fatal alert condition detected.");
      end

      $display("%h,%h,%h,%h", aes_input, aes_output, aes_key, expected_cipher);
      $fdisplay(fd, "%h,%h,%h,%h", aes_input, aes_output, aes_key, expected_cipher);

      read_next_line = 1;

      entropy_mask = $random;
      count_enc = count_enc + 32'h1;
      count_d = 16'h0;
    end

    if (count_q == 16'h2ff) begin
      $display("\nERROR: Simulation timed out.");
      test_done_o <= 1'b1;
    end

  end

endmodule
