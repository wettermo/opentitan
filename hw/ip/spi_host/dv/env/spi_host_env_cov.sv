// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

/**
 * Covergoups that are dependent on run-time parameters that may be available
 * only in build_phase can be defined here
 * Covergroups may also be wrapped inside helper classes if needed.
 */

class spi_host_env_cov extends cip_base_env_cov #(.CFG_T(spi_host_env_cfg));
  `uvm_component_utils(spi_host_env_cov)

      covergroup config_opts_cg with function sample(spi_host_configopts_t spi_configopts);
        cpol_cp : coverpoint spi_configopts.cpol[SPI_HOST_NUM_CS];
        cpha_cp : coverpoint spi_configopts.cpha[SPI_HOST_NUM_CS];
        fullcyc_cp : coverpoint spi_configopts.fullcyc[SPI_HOST_NUM_CS];
        csnlead_cp : coverpoint spi_configopts.csnlead[SPI_HOST_NUM_CS];
        csnidle_cp : coverpoint spi_configopts.csnidle[SPI_HOST_NUM_CS];
        clkdiv_cp : coverpoint spi_configopts.clkdiv[SPI_HOST_NUM_CS];
        csntrail_cp : coverpoint spi_configopts.csntrail[SPI_HOST_NUM_CS];
        cpol_cpha_cross :  cross cpol_cp, cpha_cp;
        csnlead_csnidle_csntrail_cross: cross csnlead_cp, csnidle_cp, csntrail_cp;
      endgroup

      covergroup unaligned_data_cg with function sample(bit [3:0] mask);
        unaligned_data_cp: coverpoint mask;
      endgroup

      covergroup duplex_cg with function sample(spi_dir_e  direction);
        duplex_cp : coverpoint direction;
      endgroup

      covergroup control_cg with function sample(spi_host_ctrl_t spi_ctrl_reg, bit spien,
                                                 bit output_en, bit sw_rst);
        tx_watermark_cp : coverpoint spi_ctrl_reg.tx_watermark;
        rx_watermark_cp : coverpoint spi_ctrl_reg.rx_watermark;
        spien_cp : coverpoint spien;
        output_en_cp : coverpoint output_en;
        sw_rst_cp : coverpoint sw_rst;
      endgroup

      covergroup status_cg with function sample(spi_host_status_t spi_status_reg);
        ready_cp : coverpoint spi_status_reg.ready;
        active_cp : coverpoint spi_status_reg.active;
        txfull_cp : coverpoint spi_status_reg.txfull;
        txempty_cp : coverpoint spi_status_reg.txempty;
        txstall_cp : coverpoint spi_status_reg.txstall;
        tx_wm_cp : coverpoint spi_status_reg.tx_wm;
        rxfull_cp : coverpoint spi_status_reg.rxfull;
        rxempty_cp : coverpoint spi_status_reg.rxempty;
        rxstall_cp : coverpoint spi_status_reg.rxstall;
        byteorder_cp : coverpoint spi_status_reg.byteorder;
        rx_wm_cp : coverpoint spi_status_reg.rx_wm;
        cmd_qd_cp : coverpoint spi_status_reg.cmd_qd;
        rx_qd_cp : coverpoint spi_status_reg.rx_qd;
        tx_qd_cp : coverpoint spi_status_reg.tx_qd;
      endgroup

      covergroup csid_cg with function sample(spi_host_ctrl_t spi_ctrl_reg);
        csid_cp : coverpoint spi_ctrl_reg.csid {
        bins csids = {[0:SPI_HOST_NUM_CS-1]};
        }
      endgroup

      covergroup command_cg with function sample(spi_host_command_t spi_cmd_reg);
        direction_cp : coverpoint spi_cmd_reg.direction;
        mode_cp : coverpoint spi_cmd_reg.mode {
        bins modes = {[0:2]};
        }
        csaat_cp : coverpoint spi_cmd_reg.csaat;
        len_cp : coverpoint spi_cmd_reg.len;
        direction_mode_cross: cross  direction_cp, mode_cp;
        csaat_mode_cross: cross csaat_cp, mode_cp;
      endgroup

      covergroup error_en_cg with function sample(spi_host_error_enable_t spi_error_enable_reg);
        ere_csidinval_cp : coverpoint spi_error_enable_reg.csidinval;
        ere_cmdinval_cp : coverpoint spi_error_enable_reg.cmdinval;
        ere_underflow_cp : coverpoint spi_error_enable_reg.underflow;
        ere_overflow_cp : coverpoint spi_error_enable_reg.overflow;
        ere_cmdbusy_cp : coverpoint spi_error_enable_reg.cmdbusy;
      endgroup

      covergroup error_status_cg with function sample(spi_host_error_status_t spi_error_status_reg);
        es_accessinval_cp : coverpoint spi_error_status_reg.accessinval;
        es_csidinval_cp : coverpoint spi_error_status_reg.csidinval;
        es_cmdinval_cp : coverpoint spi_error_status_reg.cmdinval;
        es_underflow_cp : coverpoint spi_error_status_reg.underflow;
        es_overflow_cp : coverpoint spi_error_status_reg.overflow;
        es_cmdbusy_cp : coverpoint spi_error_status_reg.cmdbusy;
      endgroup

      covergroup event_en_cg with function sample(spi_host_event_enable_t spi_event_enable_reg);
        idle_cp : coverpoint spi_event_enable_reg.idle;
        ready_cp : coverpoint spi_event_enable_reg.ready;
        txwm_cp : coverpoint spi_event_enable_reg.txwm;
        rxwm_cp : coverpoint spi_event_enable_reg.rxwm;
        txempty_cp : coverpoint spi_event_enable_reg.txempty;
        rxfull_cp : coverpoint spi_event_enable_reg.rxfull;
      endgroup

      covergroup interrupt_cg with function sample(spi_host_intr_state_t spi_intr_state_reg,
                                                   spi_host_intr_enable_t spi_intr_enable_reg,
                                                   spi_host_intr_test_t spi_intr_test_reg);
        state_error_cp: coverpoint spi_intr_state_reg.error;
        state_event_cp: coverpoint spi_intr_state_reg.spi_event;
        enable_error_cp: coverpoint spi_intr_enable_reg.error;
        enable_event_cp: coverpoint spi_intr_enable_reg.spi_event;
        test_error_cp: coverpoint spi_intr_test_reg.error;
        test_event_cp: coverpoint spi_intr_test_reg.spi_event;
      endgroup

      covergroup num_segment_cg with function sample(spi_host_command_t spi_cmd_reg);
      endgroup

      //covergroup cdc_cg with function sample(spi_host_configopts_t spi_configopts);
      //endgroup

  // covergroups
  // [add covergroups here]

  function new(string name, uvm_component parent);
    super.new(name, parent);
   
    config_opts_cg = new();
    unaligned_data_cg = new();
    duplex_cg = new();
    control_cg = new();
    status_cg = new();
    csid_cg = new();
    command_cg = new();
    error_en_cg = new();
    error_status_cg = new();
    event_en_cg = new();
    interrupt_cg = new();
    num_segment_cg = new();

  endfunction : new

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    // [or instantiate covergroups here]
    // Please instantiate sticky_intr_cov array of objects for all interrupts that are sticky
    // See cip_base_env_cov for details
  endfunction

endclass
