/* Copyright lowRISC contributors. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Standalone elliptic curve P-256 scalar multiplication test
 *
 * Uses OTBN ECC P-256 lib to perform a scalar multiplication with a valid
 * example curve point and an example scalar. Both scalar and coordinates of
 * the curve point are contained in the .data section below.
 *
 * x and y cordinates of the resulting curve points are copied to wide
 * registers. See comment at the end of the file for expected values.
 */

.section .text.start

p256_ecdh_shared_key_test:

  /* init all-zero register */
  bn.xor    w31, w31, w31

  /* Load domain parameter.
     w29 = dmem[p256_p] */
  li        x2, 29
  la        x4, p256_p
  bn.lid    x2, 0(x4)

  /* Set MOD to p */
  bn.wsrw   0x00, w29

  /* Call scalar point multiplication routine for shared key generation in P-256 lib. */
  jal      x1, p256_ecdh_shared_key

  /* Arithmetical unmasking of the x coordinate (shared key).
       w0 <= dmem[x] + dmem[m_x] mod p */

  /* w3 <= dmem[x] */
  li        x3, 3
  la        x4, x
  bn.lid    x3, 0(x4)

  /* w4 <= dmem[m_x] */
  li        x3, 4
  la        x4, m_x
  bn.lid    x3, 0(x4)

  /* w0 <= dmem[x] + dmem[m_x] mod p*/
  bn.addm    w0, w3, w4

  /* Store unmasked x to DMEM for comparison with boolean masking
       dmem[x_a] <= w0 */
  li        x3, 0
  la        x4, x_a
  bn.sid    x3, 0(x4)

  /* Arithmetic-to-boolean conversion*/

  /* w11 <= dmem[x] */
  li        x3, 11
  la        x4, x
  bn.lid    x3, 0(x4)

  /* w19 <= dmem[m_x] */
  li        x3, 19
  la        x4, m_x
  bn.lid    x3, 0(x4)

  jal       x1, arithmetic_to_boolean_mod

  /* Unmask and compare values
     after conversion */

  /* w20 <= w20 ^ w19 = x' ^ r */
  bn.xor    w20, w20, w19

  /* w10 <= dmem[x_a] */
  li        x3, 10
  la        x4, x_a
  bn.lid    x3, 0(x4)

  /* w1 <= w10 - w20 */
  bn.sub    w1, w10, w20

  ecall


.data

/* scalar k */
.globl k0
.balign 32
k0:
  .word 0xfe6d1071
  .word 0x21d0a016
  .word 0xb0b2c781
  .word 0x9590ef5d
  .word 0x3fdfa379
  .word 0x1b76ebe8
  .word 0x74210263
  .word 0x1420fc41
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
.globl k1
.balign 32
k1:
  .zero 64

/* example curve point x-coordinate */
.globl x
.balign 32
x:
  .word 0xbfa8c334
  .word 0x9773b7b3
  .word 0xf36b0689
  .word 0x6ec0c0b2
  .word 0xdb6c8bf3
  .word 0x1628ce58
  .word 0xfacdc546
  .word 0xb5511a6a

/* example curve point y-coordinate */
.globl y
.balign 32
y:
  .word 0x9e008c2e
  .word 0xa8707058
  .word 0xab9c6924
  .word 0x7f7a11d0
  .word 0xb53a17fa
  .word 0x43dd09ea
  .word 0x1f31c143
  .word 0x42a1c697

/* shared key mask value */
.globl m_x
.balign 32
m_x:
  .zero 32

/* affine x-coordinate value before A2B */
.globl x_a
.balign 32
x_a:
  .zero 32