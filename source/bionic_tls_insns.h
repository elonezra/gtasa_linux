/* Rebase only validated AArch64 LDR guard offsets; never remove checks. */
#ifndef GTASA_BIONIC_TLS_INSNS_H
#define GTASA_BIONIC_TLS_INSNS_H
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Catalog entry: bits 31:10 = instruction address / 4; bits 9:0 = Rn/Rt.
 * The exact original instruction must be LDR Xt, [Xn, #0x28].
 * Validate the complete plan before changing any instruction.
 */
static inline int bionic_tls_rebase_sites(void *image, size_t image_size,
                                         const uint32_t *sites, size_t count,
                                         size_t guard_offset) {
  if (!image || !sites || image_size < 4 || guard_offset < 16 ||
      guard_offset % 8 || guard_offset / 8 > 4095) {
    errno = EINVAL;
    return -1;
  }
  size_t previous = 0;
  for (size_t i = 0; i < count; i++) {
    size_t address = (size_t)(sites[i] >> 10) * 4;
    if (((sites[i] >> 5) & 31) >= 29 || address > image_size - 4 ||
        (i && address <= previous)) {
      errno = EINVAL;
      return -1;
    }
    uint32_t word;
    memcpy(&word, (uint8_t *)image + address, sizeof(word));
    if (word != (UINT32_C(0xf9401400) | (sites[i] & 1023))) {
      errno = ENOEXEC;
      return -1;
    }
    previous = address;
  }
  for (size_t i = 0; i < count; i++) {
    size_t address = (size_t)(sites[i] >> 10) * 4;
    uint32_t word = UINT32_C(0xf9400000) | (sites[i] & 1023) |
                    ((uint32_t)(guard_offset / 8) << 10);
    memcpy((uint8_t *)image + address, &word, sizeof(word));
  }
  return 0;
}
#endif
