// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// error test vseq
// empty read error underflow
// write tx full fifo error overflow

class spi_host_error_txrx_vseq extends spi_host_tx_rx_vseq;
  `uvm_object_utils(spi_host_error_txrx_vseq)
  `uvm_object_new


  virtual task body();
    bit [7:0] read_q[$];
    spi_segment_item segment;
    bit overflow;
    spi_host_intr_state_t intr_state;
    spi_host_error_status_t error_status;

    csr_rd_check(.ptr(ral.error_enable), .compare_value(32'h1f));
    csr_wr(.ptr(ral.intr_enable), .value(2'b11)); // interrupt enable for err and event
    program_spi_host_regs();
    csr_spinwait(.ptr(ral.status.ready), .exp_data(1'b1));
    access_data_fifo(read_q, RxFifo, 1'b0); // attempting empty read error underflow
    cfg.clk_rst_vif.wait_clks(10);
    csr_rd_check(.ptr(ral.intr_state.error), .compare_value(1)); // check intr state error
    csr_rd_check(.ptr(ral.error_status.underflow), .compare_value(1)); // check underflow error
    csr_wr(.ptr(ral.error_status), .value(0)); // clear underflow error
    csr_wr(.ptr(ral.intr_state), .value(0)); // clear interrupt error

    cfg.seq_cfg.host_spi_min_len = 4;
    cfg.seq_cfg.host_spi_max_len = 16;
    for (int i = 0; i < 50; i++) begin
      generate_transaction();
      while (transaction.segments.size() > 0) begin
        // wait on DUT ready
        segment = transaction.segments.pop_back();
        // lock fifo to this seq
        spi_host_atomic.get(1);
        if (segment.command_reg.direction != RxOnly) begin
          access_data_fifo(segment.spi_data, TxFifo,1'b0); // write tx fifo to overflow
        end
        spi_host_atomic.put(1);
        csr_rd(.ptr(ral.intr_state.error), .value(intr_state.error));
        if(intr_state.error) begin
        csr_rd(.ptr(ral.error_status.overflow), .value(error_status.overflow));
        end
      end
        if (error_status.overflow) begin
        break;
        end
    end // end for

    `DV_CHECK_EQ(error_status.overflow, 1)
    csr_wr(.ptr(ral.error_status), .value(0)); // clear underflow error
    csr_wr(.ptr(ral.intr_state), .value(0)); // clear interrupt error

  endtask : body

endclass : spi_host_error_txrx_vseq
