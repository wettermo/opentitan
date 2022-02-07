// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// sw_reset test vseq
// sequence contraints min values on latency and delays
// enables standard , dual and quad modes
// resets after every iteration of transfers
// checks for fifo and register reset values post applying sw reset
class spi_host_stress_all_vseq extends spi_host_sw_reset_vseq;
  `uvm_object_utils(spi_host_stress_all_vseq)
  `uvm_object_new

  bit rxempty;
  bit txempty;

// constraints for simulation loops
  constraint num_trans_c {num_trans  == cfg.seq_cfg.host_spi_max_trans;}
  constraint intr_dly_c {clear_intr_dly == cfg.seq_cfg.host_spi_min_dly;}
  constraint fifo_dly_c {
    rx_fifo_access_dly == cfg.seq_cfg.host_spi_min_dly;
    tx_fifo_access_dly == cfg.seq_cfg.host_spi_min_dly;
  }

  constraint spi_config_regs_c {
      // configopts regs
      foreach (spi_config_regs.cpol[i]) {spi_config_regs.cpol[i] == 1'b0;}
      foreach (spi_config_regs.cpha[i]) {spi_config_regs.cpha[i] == 1'b0;}
      foreach (spi_config_regs.csnlead[i]) {
        spi_config_regs.csnlead[i] == cfg.seq_cfg.host_spi_min_csn_latency;
      }
      foreach (spi_config_regs.csntrail[i]) {
        spi_config_regs.csntrail[i] == cfg.seq_cfg.host_spi_min_csn_latency;
      }
      foreach (spi_config_regs.csnidle[i]) {
        spi_config_regs.csnidle[i] == cfg.seq_cfg.host_spi_min_csn_latency;
      }
      foreach (spi_config_regs.clkdiv[i]) {
        spi_config_regs.clkdiv[i] == cfg.seq_cfg.host_spi_min_clkdiv;
      }
  }


  virtual task body();
    cfg.seq_cfg.std_en  = 1;
    cfg.seq_cfg.dual_en = 1;
    cfg.seq_cfg.quad_en = 1;
    super.body();
  endtask : body

endclass : spi_host_stress_all_vseq
