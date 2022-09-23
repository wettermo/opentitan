#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

import matplotlib.pyplot as plt
import numpy as np
import os
import random

if __name__ == "__main__":

    numb_of_runs = 100
    csv_file = "sbox_out.csv"
    verilator_cmd = "./build/lowrisc_dv_verilator_aes_sbox_tb_0/default-verilator/Vaes_sbox_tb +verilator+seed+"
    #verilator_cmd = "./build/lowrisc_dv_verilator_aes_sbox_tb_0/default-verilator/Vaes_sbox_tb --trace +verilator+seed+"
    verilator_output_filter =  " | grep ineff_output | cut -d: -f2 >> "

    for i in range(numb_of_runs):
        seed = str(random.randint(0,10000))
        cmd = verilator_cmd + seed + verilator_output_filter + csv_file
        os.system(cmd)

    data = np.loadtxt(csv_file,delimiter=';', dtype=int)
    plt.hist(data,bins=256,histtype='bar', rwidth=1, align='mid')
    plt.xlabel('Value')
    plt.ylabel('Frequency')
    plt.title(f'sbox output')
    plt.show()
