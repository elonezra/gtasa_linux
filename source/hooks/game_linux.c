/* Linux platform hooks for the Android ARM64 game.
 *
 * Derived from the MIT-licensed gtasa_nx thread/platform hooks (game.c).
 * Do NOT apply that file's instruction-offset gameplay patches here: those
 * offsets target a different game build. The known v2.11.264 BuildPixelSource
 * offset is strcat, not the specular-lighting instruction; patching it corrupts
 * GLSL. The Linux path uses symbol-only platform hooks for v2.11.311 instead.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../hooks.h"
#include "../config.h"
#include "../jni_fake.h"
#include "../so_util.h"
#include "../util.h"
#include "../bionic_tls.h"

extern so_module game_mod;
extern void linux_release_sdl_context(void);

#ifdef GTASA_FREE_AIM
extern volatile int g_dpad_down; // main_linux.c, published by input_linux.c

/* Weak refs to the AArch64 free-aim trampoline (source/hooks/free_aim_stub.s).
 * The stub is linked only on AArch64 (see CMakeLists); on host builds these
 * stay NULL and the offset hook below is skipped. */
__attribute__((weak)) extern void free_aim_stub(void);
__attribute__((weak)) extern void FindWeaponLockOnTarget_orig(void *this);
#endif



typedef struct {
  void *(*func)(void *);
  void *arg;
  char name[16];
} GameThreadStart;

static void *game_thread_start(void *arg) {
  GameThreadStart start = *(GameThreadStart *)arg;
  free(arg);
  pthread_setname_np(pthread_self(), start.name);
  if (strcmp(start.name, "RenderQueue") == 0)
    linux_release_sdl_context();
  thread_registry_add();
  if (bionic_tls_prepare_thread() != 0)
    return NULL;
  /* Leave glibc's thread pointer intact. The game obtains JNIEnv through the
   * hook below and pthread TLS through our Bionic import adapters. */
  return start.func(start.arg);
}

static void *current_jni_env(void) {
  return fake_env;
}

/* NVThreadSpawnJNIThread(long*, const Android pthread_attr_t*, const char*,
 *                        void* (*)(void*), void*)
 * Android attributes are not layout-compatible with glibc. Use Linux defaults
 * rather than reinterpret them; retain a joinable native pthread_t handle.
 */
static int spawn_jni_thread(long *tid, const void *attr, const char *name,
                            void *(*func)(void *), void *arg) {
  (void)attr;
  _Static_assert(sizeof(pthread_t) == sizeof(long), "Android thread handle size");
  GameThreadStart *start = calloc(1, sizeof(*start));
  if (!start)
    return ENOMEM;
  start->func = func;
  start->arg = arg;
  strlcpy(start->name, name ? name : "game", sizeof(start->name));
  pthread_t thread;
  int err = pthread_create(&thread, NULL, game_thread_start, start);
  if (err) {
    free(start);
    return err;
  }
  if (tid)
    memcpy(tid, &thread, sizeof(thread));
  debugPrintf("thread: started %s\n", name ? name : "game");
  return 0;
}

static int screen_get_width(void) { return screen_width; }
static int screen_get_height(void) { return screen_height; }

#ifdef GTASA_FREE_AIM
/* D-pad Down free-aim latch (ported from hooks/game.c).
 *
 * Stock v2.11.311 hides the free-aim SettingSelection (id 6) whenever the
 * input type is gamepad (GameScreen adds id 6 only if GetInputType() != 1,
 * and CHIDJoystick::InternalGetInputType returns 1), forcing lock-on.
 * This latch restores a manual opt-out: pressing D-pad Down during auto-aim
 * drops the lock into free aim until aiming ends.
 *
 * Exact-version validation on the v2.11.311 payload (IDA, libGame.so
 * md5 f4fe05eb6b26608d27b23cf2ecdf9da8):
 * - ProcessPlayerWeapon base 0x689224; +0x14ac = 0x68a6d0
 *   `TBZ W0,#0,loc_68A7B0`, with the ShiftRight path reproducing
 *   `LDR X1,[X19,#0x8E0]; MOV X0,X19; MOV W2,WZR; B loc_68A7AC`.
 *   Rejoins rx+0x1588 (0x68a7ac, FindNext call) / rx+0x158c (0x68a7b0).
 * - FindWeaponLockOnTarget start 0x5b93c8 prologue
 *   `SUB SP,#0xB0; STP D13,D12; STP D11,D10; STP D9,D8`, rejoin +0x10.
 * - Clear3rdPersonMouseTarget uses [this+0x988] + CleanUpOldReference,
 *   matching the wrapper below.
 */
static int g_free_aim = 0;
__attribute__((visibility("hidden"))) uintptr_t faim_ret_shift, faim_ret_else;
__attribute__((visibility("hidden"))) uintptr_t findlock_cont;
static void (*CPlayerPed__ClearWeaponTarget)(void *playerPed);
static void (*CEntity__CleanUpOldReference)(void *entity, void **ref);
static int (*CGameLogic__IsCoopGameGoingOn)(void);
static int (*CHID__GetInputType)(void);
static void *MobileSettings_settings;

/* Called from free_aim_stub.s when a lock-on target exists but isn't being
 * cycled. Edge-detects D-pad Down so holding it doesn't retrigger. */
__attribute__((visibility("hidden"))) void free_aim_maybe(void *playerPed) {
  static int prev = 0;
  int now = g_dpad_down;
  if (now && !prev) {
    g_free_aim = 1;
    if (CPlayerPed__ClearWeaponTarget)
      CPlayerPed__ClearWeaponTarget(playerPed);
  }
  prev = now;
}

static int MobileSettings__IsFreeAimMode(void *this) {
  (void)this;
  if (g_free_aim)
    return 1;
  if (CHID__GetInputType && CHID__GetInputType() == 1)
    return 0;
  if (!MobileSettings_settings ||
      *(int *)((uint8_t *)MobileSettings_settings + 256) != 1)
    return 0;
  if (CGameLogic__IsCoopGameGoingOn)
    return CGameLogic__IsCoopGameGoingOn() ? 0 : 1;
  return 1;
}

static int MobileSettings__IsLockOnMode(void *this) {
  (void)this;
  if (g_free_aim)
    return 0;
  if (CHID__GetInputType && CHID__GetInputType() == 1)
    return 1;
  if (!MobileSettings_settings ||
      *(int *)((uint8_t *)MobileSettings_settings + 256) == 0)
    return 1;
  if (CGameLogic__IsCoopGameGoingOn)
    return CGameLogic__IsCoopGameGoingOn();
  return 0;
}

/* While free aim is active, don't let the engine re-acquire a lock target. */
static void CPlayerPed__FindWeaponLockOnTarget(void *this) {
  if (g_free_aim)
    return;
  if (FindWeaponLockOnTarget_orig)
    FindWeaponLockOnTarget_orig(this);
}

/* Clears the free-aim latch when aiming ends, then does the stock cleanup
 * (release the 3rd-person target reference at this+0x988). */
static void CPlayerPed__Clear3rdPersonMouseTarget(void *this) {
  g_free_aim = 0;
  void **ref = (void **)((uint8_t *)this + 0x988);
  if (*ref != NULL) {
    if (CEntity__CleanUpOldReference)
      CEntity__CleanUpOldReference(*ref, ref);
    *ref = NULL;
  }
}
#endif

void patch_game(void) {
  /* Whole-function replacements only, no displaced-instruction trampolines.
   * These platform entry signatures are present in the target v2.11.311
   * Android library; no version-sensitive gameplay offsets are applied. */
  const DynLibFunction hooks[] = {
    {"_Z22NVThreadSpawnJNIThreadPlPK14pthread_attr_tPKcPFPvS5_ES5_",
     (uintptr_t)spawn_jni_thread},
    {"_Z24NVThreadGetCurrentJNIEnvv", (uintptr_t)current_jni_env},
    {"_Z17OS_ScreenGetWidthv", (uintptr_t)screen_get_width},
    {"_Z18OS_ScreenGetHeightv", (uintptr_t)screen_get_height},
  };
  for (size_t i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++)
    hook_arm64(so_find_addr(&game_mod, hooks[i].symbol), hooks[i].func);

  uintptr_t cloud_saves = so_try_find_addr_rx(&game_mod, "UseCloudSaves");
  if (cloud_saves)
    *(uint8_t *)cloud_saves = 0;

#ifdef GTASA_FREE_AIM
  /* Free-aim latch. Symbol-resolved targets; the two numeric offsets below
   * are validated for v2.11.311 (see block comment above) and guarded by
   * symbol presence. The ProcessPlayerWeapon mid-function hook additionally
   * requires the AArch64 stub (weak-linked, NULL on host builds). */
  CPlayerPed__ClearWeaponTarget =
      (void *)so_try_find_addr_rx(&game_mod, "_ZN10CPlayerPed17ClearWeaponTargetEv");
  CEntity__CleanUpOldReference =
      (void *)so_try_find_addr_rx(&game_mod, "_ZN7CEntity19CleanUpOldReferenceEPPS_");
  CGameLogic__IsCoopGameGoingOn =
      (void *)so_try_find_addr_rx(&game_mod, "_ZN10CGameLogic17IsCoopGameGoingOnEv");
  CHID__GetInputType =
      (void *)so_try_find_addr_rx(&game_mod, "_ZN4CHID12GetInputTypeEv");
  MobileSettings_settings =
      (void *)so_try_find_addr_rx(&game_mod, "_ZN14MobileSettings8settingsE");
  if (so_try_find_addr_rx(&game_mod, "_ZN14MobileSettings13IsFreeAimModeEv"))
    hook_arm64(so_find_addr(&game_mod, "_ZN14MobileSettings13IsFreeAimModeEv"),
               (uintptr_t)MobileSettings__IsFreeAimMode);
  if (so_try_find_addr_rx(&game_mod, "_ZN14MobileSettings12IsLockOnModeEv"))
    hook_arm64(so_find_addr(&game_mod, "_ZN14MobileSettings12IsLockOnModeEv"),
               (uintptr_t)MobileSettings__IsLockOnMode);
  if (FindWeaponLockOnTarget_orig &&
      so_try_find_addr_rx(&game_mod, "_ZN10CPlayerPed22FindWeaponLockOnTargetEv")) {
    findlock_cont =
        so_find_addr_rx(&game_mod, "_ZN10CPlayerPed22FindWeaponLockOnTargetEv") + 0x10;
    hook_arm64(so_find_addr(&game_mod, "_ZN10CPlayerPed22FindWeaponLockOnTargetEv"),
               (uintptr_t)CPlayerPed__FindWeaponLockOnTarget);
  }
  if (so_try_find_addr_rx(&game_mod, "_ZN10CPlayerPed25Clear3rdPersonMouseTargetEv"))
    hook_arm64(so_find_addr(&game_mod, "_ZN10CPlayerPed25Clear3rdPersonMouseTargetEv"),
               (uintptr_t)CPlayerPed__Clear3rdPersonMouseTarget);
  if (free_aim_stub &&
      so_try_find_addr_rx(&game_mod,
                          "_ZN23CTaskSimplePlayerOnFoot19ProcessPlayerWeaponEP10CPlayerPed")) {
    uintptr_t rx = so_find_addr_rx(
        &game_mod, "_ZN23CTaskSimplePlayerOnFoot19ProcessPlayerWeaponEP10CPlayerPed");
    faim_ret_shift = rx + 0x1588; // bl FindNextWeaponLockOnTarget (0x68a7ac)
    faim_ret_else = rx + 0x158c;  // fall-through (0x68a7b0)
    hook_arm64(so_find_addr(
                   &game_mod,
                   "_ZN23CTaskSimplePlayerOnFoot19ProcessPlayerWeaponEP10CPlayerPed") +
                   0x14ac, // TBZ W0,#0 (0x68a6d0)
               (uintptr_t)free_aim_stub);
  }
#endif
#ifdef GTASA_FREE_AIM
  debugPrintf("hooks: Linux platform + v2.11.311-validated free-aim latch\n");
#else
  debugPrintf("hooks: Linux platform only; version-sensitive gameplay offsets disabled\n");
#endif
}
