/* Build permissions for an anonymous, memcpy-loaded ELF image.
 * A host page shared by segments needs the union of their permissions.
 * Reject W+X rather than silently breaking writable data or relaxing W^X.
 */
#ifndef GTASA_ELF_PAGES_H
#define GTASA_ELF_PAGES_H

#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include "host_pages.h"

static inline int elf_page_protections(const Elf64_Phdr *phdr, size_t phnum,
                                      size_t image_size, size_t page_size,
                                      uint8_t *protections) {
  if (!host_page_size_valid(page_size) || image_size == 0 ||
      image_size % page_size != 0) {
    errno = EINVAL;
    return -1;
  }
  const size_t pages = image_size / page_size;
  memset(protections, PROT_NONE, pages);
  for (size_t i = 0; i < phnum; i++) {
    const Elf64_Phdr *p = &phdr[i];
    if (p->p_type != PT_LOAD || p->p_memsz == 0)
      continue;
    if (p->p_vaddr > image_size || p->p_memsz > image_size - p->p_vaddr) {
      errno = EINVAL;
      return -1;
    }
    const size_t first = p->p_vaddr / page_size;
    /* Inclusive last page without rounding overflow or zero-size underflow. */
    const size_t last = (p->p_vaddr + p->p_memsz - 1) / page_size;
    int prot = 0;
    if (p->p_flags & PF_R) prot |= PROT_READ;
    if (p->p_flags & PF_W) prot |= PROT_WRITE;
    if (p->p_flags & PF_X) prot |= PROT_EXEC;
    for (size_t pg = first; pg <= last; pg++)
      protections[pg] |= prot;
  }
  /* Validate the entire plan before changing any mapping permissions. */
  for (size_t pg = 0; pg < pages; pg++) {
    if ((protections[pg] & (PROT_WRITE | PROT_EXEC)) ==
        (PROT_WRITE | PROT_EXEC)) {
      errno = ENOTSUP;
      return -1;
    }
  }
  return 0;
}

#endif
