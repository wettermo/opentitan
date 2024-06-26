// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

class usb20_item extends uvm_sequence_item;
  // Bus-level events
  ev_type_e  m_ev_type;
  // in microseconds, 0 = default (minimum specification-compliant delay).
  int unsigned m_ev_duration_usecs;

  pid_type_e m_pid_type;
  pkt_type_e m_pkt_type;
  usb_transfer_e m_usb_transfer;

  // Indicates that a timeout occurred when awaiting a response from the device.
  bit timed_out = 1'b0;

  `uvm_object_utils_begin(usb20_item)
  `uvm_object_utils_end

  `uvm_object_new

  // Check the PID type of this item is the expected value. If not, raise a fatal error.
  function void check_pid_type(pid_type_e expected);
    `DV_CHECK_EQ_FATAL(m_pid_type, expected)
  endfunction

  // Calculate the CRC5 used in token packets.
  static function bit [4:0] generate_crc5(bit [10:0] data);
    bit [4:0] crc_reg = 5'b1_1111;
    bit [4:0] crc;
    for (int i = 0; i <= 10; i++) begin
      bit as1 = crc_reg[4] ^ data[i];
      crc_reg = ({crc_reg[3:2], (as1 ^ crc_reg[1]), crc_reg[0], as1});
    end
    crc = ~{crc_reg[0], crc_reg[1], crc_reg[2], crc_reg[3], crc_reg[4]};
    return crc;
  endfunction
endclass

class token_pkt extends usb20_item;
  // Device Address of the intended recipient.
  rand bit [6:0] address;
  // Endpoint to which the packet is addressed.
  rand bit [3:0] endpoint;
  // Checksum over Device Address and Endpoint.
  bit [4:0] crc5;

  `uvm_object_utils_begin(token_pkt)
    `uvm_field_enum(pid_type_e, m_pid_type, UVM_DEFAULT)
    `uvm_field_int(address,                 UVM_DEFAULT)
    `uvm_field_int(endpoint,                UVM_DEFAULT)
    `uvm_field_int(crc5,                    UVM_DEFAULT)
  `uvm_object_utils_end

  `uvm_object_new

  function void post_randomize();
    // Calculate the CRC of non-SOF Token packets.
    crc5 = generate_crc5({endpoint, address});
  endfunction
endclass

class data_pkt extends usb20_item;
  bit [15:0] crc16;
  rand byte unsigned data[]; // Dynamic array

  `uvm_object_utils_begin(data_pkt)
    `uvm_field_enum(pid_type_e, m_pid_type, UVM_DEFAULT)
    `uvm_field_array_int(data,              UVM_DEFAULT)
    `uvm_field_int(crc16,                   UVM_DEFAULT)
  `uvm_object_utils_end

  `uvm_object_new

  constraint data_c {
    data.size() <= 64;
  }

  // Set the data contents to form the Setup packet of a USB device request, as described in section
  // 9.3 of the USB spec.
  //
  // Argument names match the field names in the spec except that the wValue field is split into its
  // lower and upper bytes (wVL, wVH), matching the way that wValue is often split into a descriptor
  // type and descriptor index.
  function void make_device_request(bit [7:0]  bmRequestType,
                                    bit [7:0]  bRequest,
                                    bit [7:0]  wVL,
                                    bit [7:0]  wVH,
                                    bit [15:0] wIndex,
                                    bit [15:0] wLength);
    // Construct the data array by ordering bytes with increasing address. USB fields must always be
    // sent little-endian. Since our driver already sends bytes little-endian, we can send a
    // multi-byte field in the correct order by supplying its bytes from low to high.
    data = '{bmRequestType, bRequest,
             wVL, wVH,
             wIndex[7:0], wIndex[15:8],
             wLength[7:0], wLength[15:8]};
    crc16 = generate_crc16(data);
  endfunction

  // Set the content of the data packet and ensure that the CRC is set accordingly.
  function void set_data(byte unsigned content[]);
    data = content;
    crc16 = generate_crc16(data);
  endfunction

  function void post_randomize();
    // CRC16 is calculated across the entire data field of the Data Packet.
    crc16 = generate_crc16(data);
  endfunction

  static function bit [15:0] generate_crc16(input byte unsigned data[]);
    bit [15:0] crc = 16'b1111_1111_1111_1111;
    bit [15:0] polynomial = 16'h8005;
    typedef bit data_result[];
    data_result data_array;
    data_array = data_result'(data);
    data_array = {<<8{data_array}};
    data_array = {<<{data_array}};
    for (int i = 0; i < data_array.size(); i++) begin
      if ((crc[15] ^ data_array[i]) == 1) begin
        crc = {crc[14:0], 1'b0} ^ polynomial;
      end else begin
        crc = {crc[14:0], 1'b0};
      end
    end
    crc = ~crc;
    crc = {<<{crc}};
    return crc;
  endfunction
endclass

class sof_pkt extends usb20_item;
  // Frame Number of this SOF packet.
  rand bit [10:0] framenum;
  // Checksum over the bits of the Frame number.
  bit [4:0] crc5;

  `uvm_object_utils_begin(sof_pkt)
    `uvm_field_enum(pid_type_e, m_pid_type, UVM_DEFAULT)
    `uvm_field_int(framenum,                UVM_DEFAULT)
    `uvm_field_int(crc5 ,                   UVM_DEFAULT)
  `uvm_object_utils_end

  `uvm_object_new

  function void post_randomize();
    crc5 = generate_crc5(framenum);
  endfunction
endclass

class handshake_pkt extends usb20_item;
  // Handshake packets have no payload being the Packet IDentifier.
  `uvm_object_utils_begin(handshake_pkt)
    `uvm_field_enum(pid_type_e, m_pid_type, UVM_DEFAULT)
  `uvm_object_utils_end

  `uvm_object_new
endclass
