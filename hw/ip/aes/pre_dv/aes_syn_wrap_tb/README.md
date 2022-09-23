AES Syn Wrap Verilator Testbench
============================

This directory contains a basic, scratch Verilator testbench targeting
functional verification of the AES wrapper containing a synthesized AES netlist.

How to build and run the testbench
----------------------------------

From the OpenTitan top level execute

   ```sh
   fusesoc --cores-root=. run --setup --build lowrisc:dv_verilator:aes_syn_wrap_tb
   ```
to build the testbench and afterwards

   ```sh
   ./build/lowrisc_dv_verilator_aes_syn_wrap_tb_0/default-verilator/Vaes_syn_wrap_tb
   ```
to run it.

Details of the testbench
------------------------

- `rtl/aes_syn_wrap_tb.sv`: SystemVerilog testbench, instantiates and drives the
  different AES wrapper, signals test end to C++ via output ports and writes 
  AES results to a CSV file.
- `cpp/aes_syn_wrap_tb.cc`: Contains main function and instantiation of SimCtrl,
  reads output ports of DUT and signals simulation termination to Verilator.
