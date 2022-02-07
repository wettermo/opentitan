// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// event test vseq
// sequence verifies all events occur in event_enable register
class spi_host_event_vseq extends spi_host_tx_rx_vseq;
  `uvm_object_utils(spi_host_event_vseq)
  `uvm_object_new

bit drain_rx;

constraint spi_ctrl_regs_c {
    // csid reg
    spi_host_ctrl_reg.csid inside {[0 : SPI_HOST_NUM_CS-1]};
    // control reg
    spi_host_ctrl_reg.tx_watermark inside { [1:5] };
    spi_host_ctrl_reg.rx_watermark inside { [1:5] };
  }
constraint num_trans_c {num_trans  == cfg.seq_cfg.host_spi_min_trans;}

 virtual task body();
    csr_wr(.ptr(ral.intr_enable), .value(2'b11)); // interrupt enable for err and event
    csr_wr(.ptr(ral.event_enable), .value(32'h3f)); // interrupt enable for err and event
    fork
      begin : isolation_fork
        fork
          begin
          start_reactive_seq();
          end
        join_none

        begin
          wait_ready_for_command();
          start_spi_host_trans(num_trans);
          `uvm_info(`gfn, $sformatf("\n NUM TRANS %d ", num_trans), UVM_LOW)
          csr_spinwait(.ptr(ral.status.active), .exp_data(1'b0));
          drain_rx = 1'b1;
          csr_spinwait(.ptr(ral.status.rxqd), .exp_data(8'h0));
          cfg.clk_rst_vif.wait_clks(100);
        end

        disable fork;
      end
      begin
        check_events();
      end
    join

    csr_rd_check(.ptr(ral.event_enable), .compare_value(0));
  endtask : body

 virtual task check_events();
    bit [7:0] read_q[$];
    spi_host_status_t status;
    spi_host_intr_state_t intr_state;
    spi_host_event_enable_t event_enable;
    spi_segment_item segment;

    cfg.seq_cfg.host_spi_min_len = 4;
    cfg.seq_cfg.host_spi_max_len = 16;

    forever begin

        csr_spinwait(.ptr(ral.intr_state.spi_event), .exp_data(1));
        csr_rd(.ptr(ral.event_enable), .value(event_enable));
        csr_rd(.ptr(ral.status), .value(status));
        if(event_enable.txempty && status.txempty) begin
        csr_wr(.ptr(ral.event_enable.txempty), .value(0));
        event_enable.txempty = 0;
        end
        if(event_enable.txwm && status.tx_wm) begin
        csr_wr(.ptr(ral.event_enable.txwm), .value(0));
        event_enable.txwm = 0;
        end
        if(event_enable.rxwm && status.rx_wm) begin
        csr_wr(.ptr(ral.event_enable.rxwm), .value(0));
        event_enable.rxwm = 0;
            do begin
            for (int i = 0; i < status.rx_qd; i++) begin
              access_data_fifo(read_q, RxFifo);
            end
            status.rx_qd = 0;
            end while (status.rx_qd > 0);
        end

        if((event_enable.rxfull && status.rxfull) || drain_rx) begin
          if(drain_rx) begin
          csr_wr(.ptr(ral.event_enable.rxfull), .value(0));
          event_enable.rxfull = 0;
          end
            do begin
            for (int i = 0; i < status.rx_qd; i++) begin
              access_data_fifo(read_q, RxFifo, 1'b0);
            end
            status.rx_qd = 0;
            end while (status.rx_qd > 0);
        end

        if(event_enable.idle && (!status.active)) begin
        csr_wr(.ptr(ral.event_enable.idle), .value(0));
        event_enable.idle = 0;
        end
        if(event_enable.ready && status.ready) begin
        csr_wr(.ptr(ral.event_enable.ready), .value(0));
        event_enable.ready = 0;
        end

        csr_wr(.ptr(ral.intr_state.spi_event), .value(1));

        if (event_enable == 0) break;

    end  // forever loop

  endtask

endclass : spi_host_event_vseq

