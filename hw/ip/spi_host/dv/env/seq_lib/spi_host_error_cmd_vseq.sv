// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// error_cmd test vseq
// test tries to capture error interrupt when cmd invalid condition appears
// cmd invalid is created when cmd sent and host isnt ready
class spi_host_error_cmd_vseq extends spi_host_tx_rx_vseq;
  `uvm_object_utils(spi_host_error_cmd_vseq)
  `uvm_object_new


 virtual task pre_start();
   cfg.en_scb = 0;
   super.pre_start();
 endtask

 virtual task body();
    int num_transactions = 4;
    bit cmd_not_ready = 1'b0;
    bit error_cmd = 1'b1;
    csr_wr(.ptr(ral.intr_enable), .value(2'b11)); // interrupt enable for err and event
    fork
        begin
        while (error_cmd) check_error_cmdbusy_cmdinval();
        end
        begin
          start_spi_host_trans(num_transactions,cmd_not_ready);
          cfg.clk_rst_vif.wait_clks(100);
          error_cmd = 0;
          cfg.clk_rst_vif.wait_clks(100);
          csr_spinwait(.ptr(ral.status.active), .exp_data(1'b0));
        end
    join

      csr_rd_check(.ptr(ral.error_status), .compare_value(0));
  endtask : body

  virtual task check_error_cmdbusy_cmdinval();
    spi_host_error_status_t error_status;
    spi_host_intr_state_t intr_state;
    bit error = 1'b0;

       csr_rd(.ptr(ral.intr_state.error), .value(error));
       if (error) begin
       csr_rd(.ptr(ral.error_status), .value(error_status));
       if(error_status.cmdbusy) begin
        csr_wr(.ptr(ral.error_status.cmdbusy), .value(1));
        error_status.cmdbusy = 0;
       end
       csr_wr(.ptr(ral.intr_state.error), .value(1));
       end

  endtask

endclass : spi_host_error_cmd_vseq
