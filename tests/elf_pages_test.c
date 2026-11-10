/* Synthetic ELF and anonymous memory only; no Android library or game code.
 * Standalone: cc -D_GNU_SOURCE -std=c11 -Wall -Wextra -Isource \
 *   tests/elf_pages_test.c source/so_util.c source/error_linux.c -o elf_pages_test
 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "elf_pages.h"
#include "so_util.h"

int debugPrintf(char *fmt, ...) { (void)fmt; return 0; }

static void geometry_test(size_t page) {
  size_t rounded;
  assert(host_page_round_up(0, page, &rounded) == 0 && rounded == 0);
  assert(host_page_round_up(page, page, &rounded) == 0 && rounded == page);
  assert(host_page_round_up(page + 1, page, &rounded) == 0 && rounded == 2 * page);
  assert(host_page_round_up(SIZE_MAX, page, &rounded) == -1);
  assert(host_page_round_up(1, 0, &rounded) == -1);
  assert(host_page_round_up(1, 123, &rounded) == -1);

  uint8_t prot[4];
  Elf64_Phdr p[] = {
    {.p_type=PT_LOAD, .p_vaddr=17, .p_memsz=page-17, .p_flags=PF_R|PF_X},
    {.p_type=PT_LOAD, .p_vaddr=page, .p_memsz=page, .p_flags=PF_R},
    {.p_type=PT_LOAD, .p_vaddr=3*page+1, .p_memsz=page-1, .p_flags=PF_R|PF_W},
    /* Empty executable LOAD must not mark page zero (or underflow last). */
    {.p_type=PT_LOAD, .p_vaddr=0, .p_memsz=0, .p_flags=PF_X|PF_W}
  };
  assert(elf_page_protections(p, 4, 4*page, page, prot) == 0);
  assert(prot[0] == (PROT_READ|PROT_EXEC));
  assert(prot[1] == PROT_READ && prot[2] == PROT_NONE);
  assert(prot[3] == (PROT_READ|PROT_WRITE));
  p[1].p_vaddr = 1; /* R and RX may share. */
  assert(elf_page_protections(p, 4, 4*page, page, prot) == 0);
  p[1].p_flags |= PF_W;
  assert(elf_page_protections(p, 4, 4*page, page, prot) == -1 && errno == ENOTSUP);
  p[1].p_vaddr = UINT64_MAX-1;
  assert(elf_page_protections(p, 4, 4*page, page, prot) == -1 && errno == EINVAL);
  assert(elf_page_protections(p, 4, 4*page-1, page, prot) == -1);
}

static void shared_page_test(void) {
  uint8_t prot[8];
  Elf64_Phdr p[] = {
    {.p_type=PT_LOAD, .p_vaddr=0, .p_memsz=0x1000, .p_flags=PF_R|PF_X},
    {.p_type=PT_LOAD, .p_vaddr=0x2000, .p_memsz=0x1000, .p_flags=PF_R|PF_W}
  };
  assert(elf_page_protections(p, 2, 0x8000, 4096, prot) == 0);
  assert(elf_page_protections(p, 2, 0x8000, 16384, prot) == -1 && errno == ENOTSUP);
}

/* Installed payload PT_LOAD geometry only; no proprietary bytes are loaded.
 * These fixtures reproduce the exact boundaries audited on Recalbox.
 */
static void installed_layout_test(void) {
  Elf64_Phdr game[] = {
    {.p_type=PT_LOAD, .p_vaddr=0, .p_memsz=0x816470, .p_flags=PF_R|PF_X},
    {.p_type=PT_LOAD, .p_vaddr=0x81a470, .p_memsz=0x35b90, .p_flags=PF_R|PF_W},
    {.p_type=PT_LOAD, .p_vaddr=0x853c78, .p_memsz=0x4c7608, .p_flags=PF_R|PF_W}
  };
  Elf64_Phdr cxx[] = {
    {.p_type=PT_LOAD, .p_vaddr=0, .p_memsz=0x144af8, .p_flags=PF_R|PF_X},
    {.p_type=PT_LOAD, .p_vaddr=0x148af8, .p_memsz=0xa508, .p_flags=PF_R|PF_W},
    {.p_type=PT_LOAD, .p_vaddr=0x156b88, .p_memsz=0x7dc0, .p_flags=PF_R|PF_W}
  };
  const size_t sizes[] = {4096, 16384, 65536};
  for (size_t i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
    const size_t page = sizes[i];
    size_t image;
    assert(host_page_round_up(0xd1b280, page, &image) == 0);
    uint8_t *prot = calloc(image/page, 1);
    assert(prot);
    int rc = elf_page_protections(game, 3, image, page, prot);
    if (page == 65536) {
      assert(rc == -1 && errno == ENOTSUP);
    } else {
      assert(rc == 0);
      assert(prot[0x81646f/page] == (PROT_READ|PROT_EXEC));
      assert(prot[0x81a470/page] == (PROT_READ|PROT_WRITE));
    }
    free(prot);
    assert(host_page_round_up(0x15e948, page, &image) == 0);
    prot = calloc(image/page, 1);
    assert(prot);
    rc = elf_page_protections(cxx, 3, image, page, prot);
    if (page == 65536) {
      assert(rc == -1 && errno == ENOTSUP);
    } else {
      assert(rc == 0);
      assert(prot[0x144af7/page] == (PROT_READ|PROT_EXEC));
      assert(prot[0x148af8/page] == (PROT_READ|PROT_WRITE));
    }
    free(prot);
  }
}

static void expect_permissions(void *address, const char *expected) {
  FILE *f = fopen("/proc/self/maps", "r");
  assert(f);
  char line[512], perms[5];
  unsigned long start, end;
  int found = 0;
  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3 &&
        (uintptr_t)address >= start && (uintptr_t)address < end) {
      assert(strncmp(perms, expected, 3) == 0);
      found = 1;
      break;
    }
  }
  fclose(f);
  assert(found);
}

static void loader_test(void) {
  const long page = host_page_size();
  assert(page > 0);
  /* Deliberately 4K-granular tail: round allocation on the actual host. */
  const size_t tail = 2*(size_t)page + 0x1001;
  size_t rounded;
  assert(host_page_round_up(tail, page, &rounded) == 0);
  _Alignas(Elf64_Ehdr) unsigned char file[2048] = {0};
  Elf64_Ehdr *eh = (void *)file;
  memcpy(eh->e_ident, ELFMAG, SELFMAG);
  eh->e_ident[EI_CLASS] = ELFCLASS64;
  eh->e_ident[EI_DATA] = ELFDATA2LSB;
  eh->e_type = ET_DYN;
  eh->e_machine = EM_AARCH64;
  eh->e_phoff = sizeof(*eh);
  eh->e_phentsize = sizeof(Elf64_Phdr);
  eh->e_phnum = 2;
  eh->e_shoff = 0x300;
  eh->e_shentsize = sizeof(Elf64_Shdr);
  eh->e_shnum = 4;
  eh->e_shstrndx = 1;
  Elf64_Phdr *ph = (void *)(file+eh->e_phoff);
  ph[0] = (Elf64_Phdr){.p_type=PT_LOAD, .p_offset=0, .p_vaddr=0,
                      .p_filesz=sizeof(file), .p_memsz=page,
                      .p_flags=PF_R|PF_X, .p_align=0x1000};
  ph[1] = (Elf64_Phdr){.p_type=PT_LOAD, .p_vaddr=2*page,
                      .p_memsz=0x1001, .p_flags=PF_R|PF_W, .p_align=0x1000};
  memcpy(file+0x280, "\0.shstrtab\0.dynsym\0.dynstr\0", 27);
  Elf64_Shdr *sh = (void *)(file+eh->e_shoff);
  sh[1] = (Elf64_Shdr){.sh_name=1, .sh_type=SHT_STRTAB, .sh_offset=0x280};
  sh[2] = (Elf64_Shdr){.sh_name=11, .sh_type=SHT_DYNSYM, .sh_addr=0x200,
                      .sh_size=sizeof(Elf64_Sym)};
  sh[3] = (Elf64_Shdr){.sh_name=19, .sh_type=SHT_STRTAB, .sh_addr=0x220};
  char path[] = "./synthetic-elf-XXXXXX";
  int fd = mkstemp(path);
  assert(fd >= 0);
  assert(write(fd, file, sizeof(file)) == (ssize_t)sizeof(file));
  assert(close(fd) == 0);
  so_module mod;
  assert(so_load(&mod, path, NULL, rounded-1) == -3);
  assert(so_load(&mod, path, NULL, rounded) == 0);
  assert(unlink(path) == 0);
  assert(mod.load_size == rounded);
  assert((uintptr_t)mod.load_base % page == 0);
  assert(memcmp(mod.load_base, file, sizeof(file)) == 0);
  unsigned char *data = (unsigned char *)mod.load_base + 2*page;
  assert(data[0] == 0 && data[0x1000] == 0); /* BSS from anonymous mapping. */
  so_finalize(&mod);
  expect_permissions(mod.load_base, "r-x");
  expect_permissions((char *)mod.load_base+page, "rw-");
  expect_permissions(data, "rw-");
  data[0] = 42;
  data[0x1000] = 43;
  so_free_temp(&mod);
  assert(so_unload(&mod) == 0);
}

int main(void) {
  geometry_test(4096);
  geometry_test(16384);
  geometry_test(65536);
  shared_page_test();
  installed_layout_test();
  loader_test();
  puts("PASS: page geometry, permission plans, synthetic ELF load/finalize/unload");
  return 0;
}
