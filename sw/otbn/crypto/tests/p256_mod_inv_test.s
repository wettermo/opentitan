
.section .text.start

p256_mod_inv_test:

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

  /* Load value to invert
     w0 <= z */
  li        x2, 0
  la        x4, z
  bn.lid    x2, 0(x4)

  /* Call mod_inv
     w1 <= w0^-1 mod p */
  jal       x1, mod_inv

  /* Copy result to wide reg file */
  bn.mov    w0, w1

  ecall

.data

.globl z
.balign 32
z:
  .word 0x2ab77ca0
  .word 0x8031ceb8
  .word 0xff3e1afa
  .word 0x353ec814
  .word 0x22fe027b
  .word 0x8a29dc16
  .word 0xf7109d54
  .word 0x762c5d06