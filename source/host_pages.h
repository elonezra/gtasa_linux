/* Host VM page geometry. Never substitute an ELF p_align or a fixed 4 KiB. */
#ifndef GTASA_HOST_PAGES_H
#define GTASA_HOST_PAGES_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

static inline int host_page_size_valid(size_t size) {
  return size != 0 && (size & (size - 1)) == 0;
}

static inline long host_page_size(void) {
  long size = sysconf(_SC_PAGESIZE);
  if (size <= 0 || !host_page_size_valid((size_t)size)) {
    errno = EINVAL;
    return -1;
  }
  return size;
}

/* Checked rounding: callers must not map a wrapped or empty image. */
static inline int host_page_round_up(size_t size, size_t page, size_t *out) {
  if (!host_page_size_valid(page) || size > SIZE_MAX - (page - 1)) {
    errno = EOVERFLOW;
    return -1;
  }
  *out = (size + page - 1) & ~(page - 1);
  return 0;
}

#endif
