/* Android ARM64 TLS_SLOT_STACK_GUARD is TP+0x28. On glibc that address can
 * belong to native TLS, so it is not a stable Android stack guard. Keep the
 * real thread pointer and translate verified guard loads to our own TLS slot.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/auxv.h>
#include "bionic_tls.h"
#include "bionic_tls_insns.h"
#include "util.h"

static _Thread_local uint64_t native_guard
    __attribute__((tls_model("local-exec")));
static uint64_t guard_seed;
static pthread_once_t seed_once = PTHREAD_ONCE_INIT;

static void seed_guard(void) {
  const void *random = (const void *)getauxval(AT_RANDOM);
  if (random) {
    memcpy(&guard_seed, random, sizeof(guard_seed));
    guard_seed &= ~UINT64_C(0xff);
  }
}

int bionic_tls_prepare_thread(void) {
  int result = pthread_once(&seed_once, seed_guard);
  if (result || !guard_seed) {
    errno = result ? result : ENOSYS;
    return -1;
  }
  if (!native_guard)
    native_guard = guard_seed;
  return 0;
}

int bionic_tls_guard_offset(size_t *offset) {
  if (bionic_tls_prepare_thread() != 0)
    return -1;
#ifdef __aarch64__
  uintptr_t tp = (uintptr_t)__builtin_thread_pointer();
  uintptr_t address = (uintptr_t)&native_guard;
  if (address < tp || address-tp < 16 || (address-tp)%8 ||
      (address-tp)/8 > 4095) {
    errno = ENOTSUP;
    return -1;
  }
  *offset = address-tp;
  return 0;
#else
  (void)offset;
  errno = ENOTSUP;
  return -1;
#endif
}

static int supported_build(const so_module *module) {
  static const uint8_t build_id[20] = {
    0x84,0xa3,0xaf,0x6e,0x60,0x20,0x3e,0xfe,0x45,0xdc,
    0x9f,0x06,0xb7,0x7c,0xe5,0xca,0x9e,0x9d,0xac,0xc9
  };
  if (module->so_size != 8943088)
    return 0;
  for (int i = 0; i < module->phnum; i++) {
    const Elf64_Phdr *p = &module->phdr[i];
    if (p->p_type != PT_NOTE || p->p_offset > module->so_size ||
        p->p_filesz > module->so_size-p->p_offset)
      continue;
    size_t end = p->p_offset+p->p_filesz;
    for (size_t pos = p->p_offset; pos+sizeof(Elf64_Nhdr) <= end;) {
      Elf64_Nhdr note;
      memcpy(&note, (uint8_t *)module->so_base+pos, sizeof(note));
      size_t name = pos+sizeof(note);
      size_t desc = name+(((size_t)note.n_namesz+3)&~(size_t)3);
      size_t next = desc+(((size_t)note.n_descsz+3)&~(size_t)3);
      if (desc > end || next > end || next <= pos)
        break;
      if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
          note.n_descsz == sizeof(build_id) &&
          memcmp((uint8_t *)module->so_base+name, "GNU", 4) == 0 &&
          memcmp((uint8_t *)module->so_base+desc, build_id, sizeof(build_id)) == 0)
        return 1;
      pos = next;
    }
  }
  return 0;
}

#include "bionic_tls_sites.inc"

int bionic_tls_patch_module(so_module *module) {
  if (!so_try_find_addr_rx(module, "_Z20AND_CreateEglSurfacev"))
    return 0;
  if (!supported_build(module)) {
    debugPrintf("TLS: unsupported game build; refusing guard-site translation\n");
    errno = ENOTSUP;
    return -1;
  }
  size_t offset;
  if (bionic_tls_guard_offset(&offset) != 0)
    return -1;
  const size_t count = sizeof(bionic_tls_guard_sites)/sizeof(bionic_tls_guard_sites[0]);
  if (bionic_tls_rebase_sites(module->load_base, module->load_size,
                             bionic_tls_guard_sites, count, offset) != 0) {
    debugPrintf("TLS: guard-site instruction validation failed: %s\n", strerror(errno));
    return -1;
  }
  debugPrintf("TLS: translated %zu verified guard loads from TP+0x28 to owned TP+0x%zx; checks retained\n",
              count, offset);
  return 0;
}
