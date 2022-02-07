// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// passthrough_mode test vseq
// SPI_HOST HWIP Technical Specification Block Diagram
class spi_host_passthrough_mode_vseq extends spi_host_tx_rx_vseq;
  `uvm_object_utils(spi_host_passthrough_mode_vseq)
  `uvm_object_new

  bit [3:0]   passthrough_i_s;
  bit [3:0]   passthrough_o_s;
  bit [3:0]   cio_sd_o;
  bit [3:0]   cio_sd_i;

  virtual task body();
    begin
    cfg.clk_rst_vif.wait_clks(5);
    uvm_hdl_force("tb.passthrough_i.passthrough_en", 1'b1);
    uvm_hdl_force("tb.passthrough_i.csb", 1'b1);
    for (int i = 0; i < 1000; i++) begin
    passthrough_check();
    end
    uvm_hdl_force("tb.passthrough_i.passthrough_en", 1'b0);
    uvm_hdl_force("tb.passthrough_i.csb", 1'b0);
    cfg.clk_rst_vif.wait_clks(10);
    end
  endtask : body
 
  task passthrough_check();
  @(posedge cfg.clk_rst_vif.clk);
  uvm_hdl_read("tb.passthrough_i.s", passthrough_i_s);
  uvm_hdl_read("tb.passthrough_o.s", passthrough_o_s);
  uvm_hdl_read("tb.dut.cio_sd_i", cio_sd_i);
  uvm_hdl_read("tb.dut.cio_sd_o", cio_sd_o);
  `DV_CHECK_EQ(passthrough_i_s, cio_sd_o)
  `DV_CHECK_EQ(passthrough_o_s, cio_sd_i)
  endtask : passthrough_check

endclass : spi_host_passthrough_mode_vseq
