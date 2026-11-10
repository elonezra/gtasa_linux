/* Synthetic instruction validation and real ARM64 TLS isolation tests. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "bionic_tls.h"
#include "bionic_tls_insns.h"

int debugPrintf(char *fmt, ...) { (void)fmt; return 0; }

static void plan_test(void) {
  uint32_t image[] = {0xf9401668, 0xd503201f, 0xf9401669, 0xd65f03c0};
  uint32_t original[4];
  memcpy(original, image, sizeof(image));
  const uint32_t sites[] = {0x268, (2u<<10)|0x269};
  assert(bionic_tls_rebase_sites(image, sizeof(image), sites, 2, 80) == 0);
  assert(image[0] == 0xf9402a68 && image[2] == 0xf9402a69);
  assert(image[1] == original[1] && image[3] == original[3]);
  memcpy(image, original, sizeof(image));
  uint32_t invalid[] = {sites[0], (2u<<10)|0x260};
  assert(bionic_tls_rebase_sites(image, sizeof(image), invalid, 2, 80) == -1);
  assert(errno == ENOEXEC && memcmp(image, original, sizeof(image)) == 0);
  invalid[1] = 100u<<10;
  assert(bionic_tls_rebase_sites(image, sizeof(image), invalid, 2, 80) == -1);
  assert(memcmp(image, original, sizeof(image)) == 0);
  assert(bionic_tls_rebase_sites(image, sizeof(image), sites, 2, 0) == -1);
  assert(bionic_tls_rebase_sites(image, sizeof(image), sites, 2, 17) == -1);
  assert(bionic_tls_rebase_sites(image, sizeof(image), sites, 2, 32768) == -1);
  uint32_t duplicate[] = {sites[0], sites[0]};
  assert(bionic_tls_rebase_sites(image, sizeof(image), duplicate, 2, 80) == -1);
  assert(memcmp(image, original, sizeof(image)) == 0);
}

#ifdef __aarch64__
/* This owns the old TP+0x28 slot in this synthetic executable. The test asserts
 * that fact before writing, so no unrelated glibc TLS field can be touched.
 */
static _Thread_local uint64_t simulated_native_tls[8] = {1,2,3,4,5,6,7,8};
static _Thread_local int damage_saved_guard;
extern const unsigned char bionic_tls_fixture_start[], bionic_tls_fixture_end[];
extern const unsigned char bionic_tls_fixture_save[], bionic_tls_fixture_check[];
typedef int (*fixture_fn)(void (*callback)(uint64_t *));
static fixture_fn original_fixture, translated_fixture;
static size_t expected_guard_offset;

static void host_context_switch(uint64_t *saved_guard) {
  uintptr_t tp = (uintptr_t)__builtin_thread_pointer();
  uintptr_t old_slot = tp+0x28;
  assert(old_slot >= (uintptr_t)simulated_native_tls);
  assert(old_slot+8 <= (uintptr_t)(simulated_native_tls+8));
  ++*(uint64_t *)old_slot;
  if (damage_saved_guard)
    *saved_guard ^= UINT64_C(1);
}

static void exercise(void) {
  uintptr_t before = (uintptr_t)__builtin_thread_pointer();
  size_t offset;
  assert(bionic_tls_guard_offset(&offset) == 0 && offset == expected_guard_offset);
  damage_saved_guard = 0;
  assert(original_fixture(host_context_switch) == 1); /* False mismatch. */
  assert(translated_fixture(host_context_switch) == 0); /* Owned guard stable. */
  damage_saved_guard = 1;
  assert(translated_fixture(host_context_switch) == 1); /* Corruption detected. */
  damage_saved_guard = 0;
  assert((uintptr_t)__builtin_thread_pointer() == before);
}

static void *worker(void *unused) {
  (void)unused;
  assert(bionic_tls_prepare_thread() == 0);
  exercise();
  return NULL;
}

static void fixture_test(void) {
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  assert(page > 0);
  size_t length = (uintptr_t)bionic_tls_fixture_end-(uintptr_t)bionic_tls_fixture_start;
  assert(length < page);
  uint32_t sites[2];
  size_t addresses[] = {
    (uintptr_t)bionic_tls_fixture_save-(uintptr_t)bionic_tls_fixture_start,
    (uintptr_t)bionic_tls_fixture_check-(uintptr_t)bionic_tls_fixture_start
  };
  for (size_t i = 0; i < 2; i++) {
    uint32_t word;
    memcpy(&word, bionic_tls_fixture_start+addresses[i], 4);
    assert((word & ~UINT32_C(1023)) == UINT32_C(0xf9401400));
    sites[i] = (uint32_t)(addresses[i]/4<<10) | (word & 1023);
  }
  assert(bionic_tls_guard_offset(&expected_guard_offset) == 0);
  void *maps[2];
  for (size_t i = 0; i < 2; i++) {
    maps[i] = mmap(NULL, page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(maps[i] != MAP_FAILED);
    memcpy(maps[i], bionic_tls_fixture_start, length);
    if (i)
      assert(bionic_tls_rebase_sites(maps[i], page, sites, 2, expected_guard_offset) == 0);
    __builtin___clear_cache(maps[i], (char *)maps[i]+length);
    assert(mprotect(maps[i], page, PROT_READ|PROT_EXEC) == 0);
  }
  original_fixture = (fixture_fn)maps[0];
  translated_fixture = (fixture_fn)maps[1];
  exercise();
  pthread_t threads[2];
  for (size_t i = 0; i < 2; i++)
    assert(pthread_create(&threads[i], NULL, worker, NULL) == 0);
  for (size_t i = 0; i < 2; i++)
    assert(pthread_join(threads[i], NULL) == 0);
  for (size_t i = 0; i < 2; i++)
    assert(munmap(maps[i], page) == 0);
  printf("PASS: real ARM64 TLS guard isolation, saved-guard corruption detection, threads, %zu-byte pages\n", page);
}
#endif

int main(void) {
  plan_test();
#ifdef __aarch64__
  fixture_test();
#endif
  puts("PASS: guard instruction plans and fail-before-write validation");
  return 0;
}
