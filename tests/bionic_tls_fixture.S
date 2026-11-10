/* Trusted synthetic guard-check fixture. No instructions come from an APK. */
.text
.p2align 2
.global bionic_tls_fixture_start
.global bionic_tls_fixture_save
.global bionic_tls_fixture_check
.global bionic_tls_fixture_end
.type bionic_tls_fixture_start, %function
bionic_tls_fixture_start:
  stp x29, x30, [sp, #-48]!
  stp x19, x20, [sp, #16]
  str x21, [sp, #32]
  mov x29, sp
  mov x21, x0
  mrs x19, tpidr_el0
bionic_tls_fixture_save:
  ldr x20, [x19, #40]
  str x20, [sp, #40]
  add x0, sp, #40
  blr x21
bionic_tls_fixture_check:
  ldr x20, [x19, #40]
  ldr x8, [sp, #40]
  cmp x20, x8
  cset w0, ne
  ldp x19, x20, [sp, #16]
  ldr x21, [sp, #32]
  ldp x29, x30, [sp], #48
  ret
bionic_tls_fixture_end:
.size bionic_tls_fixture_start, .-bionic_tls_fixture_start
.section .note.GNU-stack,"",%progbits
