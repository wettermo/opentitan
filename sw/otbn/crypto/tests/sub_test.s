.section .text.start

sub_test:

  /* w3 <= dmem[a] */
  li        x3, 3
  la        x4, a
  bn.lid    x3, 0(x4)

  /* w4 <= dmem[b] */
  li        x3, 4
  la        x4, b
  bn.lid    x3, 0(x4)

  bn.sub    w0, w3, w4

  ecall


.data

.globl a
.balign 32
a:
  .word 0x0000000f
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000

.globl b
.balign 32
b:
  .word 0x00000010
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000
  .word 0x00000000