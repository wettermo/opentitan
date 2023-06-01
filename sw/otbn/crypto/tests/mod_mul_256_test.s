
.section .text.start

mod_mul_256_test:

  /* init all-zero register */
  bn.xor    w31, w31, w31

  /* Load barrett constant as input for
     mod_mul_256x256.
     w28 = dmem[p256_u_p] */
  li        x2, 28
  la        x4, p256_u_p
  bn.lid    x2, 0(x4)

  /* Load domain parameter as input for
     mod_mul_256x256.
     w29 = dmem[p256_p] */
  li        x2, 29
  la        x4, p256_p
  bn.lid    x2, 0(x4)

  /* Set MOD to p */
  bn.wsrw   0x00, w29

  /* Load multiplicants
     w24 <= a
     w25 <= b */
  li        x2, 24
  li        x3, 25
  la        x4, a
  la        x5, b
  bn.lid    x2, 0(x4)
  bn.lid    x3, 0(x5)

  /* Call mod_mul_256
     w19 = w24 * w25 mod w29 = a * b mod p */
  jal       x1, mod_mul_256x256

  /* Copy result to wide reg file */
  bn.mov    w0, w19

  ecall

.data

.globl a
.balign 32
a:
  .word 0x2ab77ca0
  .word 0x8031ceb8
  .word 0xff3e1afa
  .word 0x353ec814
  .word 0x22fe027b
  .word 0x8a29dc16
  .word 0xf7109d54
  .word 0x762c5d06

.globl b
.balign 32
b:
  .word 0x45bffc62
  .word 0x175e3fba
  .word 0xfc769b39
  .word 0x0239bbef
  .word 0xdabab471
  .word 0x9b9106af
  .word 0x0a62ef58
  .word 0x0641ceb9
/*b:
  .word 0x00000001
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000*/
