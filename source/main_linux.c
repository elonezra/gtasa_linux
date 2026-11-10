/* main_linux.c -- generic Linux SDL3 entry point
 *
 * Loads the Android ARM64 game libraries through the custom ELF loader and
 * replaces the Android Activity/GLSurfaceView lifecycle with SDL3 + EGL/GLES.
 */

#define _GNU_SOURCE
#include <SDL3/SDL.h>
#include <GLES2/gl2.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>

#include "aml_mod.h"
#include "config.h"
#include "audio_linux.h"
#include "error.h"
#include "hooks.h"
#include "imports.h"
#include "input_linux.h"
#include "jni_fake.h"
#include "so_util.h"
#include "util.h"

extern void linux_release_sdl_context(void);

#ifndef GTASA_PRODUCT_NAME
#define GTASA_PRODUCT_NAME "Grand Theft Auto: San Andreas"
#endif

so_module donor_mod;
so_module game_mod;

/* Preserve fatal signals while recording enough information to symbolize a
 * crash in a library mapped by our custom loader. Only async-signal-safe
 * operations are used in the handler; no stack walk or allocator is needed. */
static char *fault_hex(char *out, uintptr_t value) {
  static const char digits[] = "0123456789abcdef";
  *out++ = '0'; *out++ = 'x';
  for (int shift = (int)(sizeof(value) * 8) - 4; shift >= 0; shift -= 4)
    *out++ = digits[(value >> shift) & 15];
  return out;
}

static char *fault_label(char *out, const char *label, uintptr_t value) {
  while (*label) *out++ = *label++;
  return fault_hex(out, value);
}

static void fatal_signal_trace(int sig, siginfo_t *info, void *context) {
  uintptr_t pc = 0, lr = 0, sp = 0;
#if defined(__aarch64__)
  const ucontext_t *state = context;
  pc = state->uc_mcontext.pc;
  lr = state->uc_mcontext.regs[30];
  sp = state->uc_mcontext.sp;
#else
  (void)context;
#endif
  char line[512], *out = line;
  out = fault_label(out, "FATAL_SIGNAL signal=", (uintptr_t)sig);
  out = fault_label(out, " address=", (uintptr_t)info->si_addr);
  out = fault_label(out, " pc=", pc);
  out = fault_label(out, " lr=", lr);
  out = fault_label(out, " sp=", sp);
  out = fault_label(out, " game_base=", (uintptr_t)game_mod.load_base);
  if (pc >= (uintptr_t)game_mod.load_base &&
      pc - (uintptr_t)game_mod.load_base < game_mod.load_size)
    out = fault_label(out, " game_offset=", pc - (uintptr_t)game_mod.load_base);
  *out++ = '\n';
  (void)write(STDERR_FILENO, line, (size_t)(out - line));
  /* SA_RESETHAND has restored the default disposition. Re-raise while the
   * signal is blocked; returning delivers it normally with its fatal status. */
  (void)raise(sig);
}

static void install_fatal_signal_trace(void) {
  struct sigaction action = {0};
  action.sa_sigaction = fatal_signal_trace;
  action.sa_flags = SA_SIGINFO | SA_RESETHAND;
  sigemptyset(&action.sa_mask);
  sigaction(SIGSEGV, &action, NULL);
  sigaction(SIGBUS, &action, NULL);
  sigaction(SIGILL, &action, NULL);
  sigaction(SIGABRT, &action, NULL);
}

volatile int g_hide_saves;
int g_hide_saves_frames;
volatile int g_escape_pressed;
volatile int g_select_pressed;
volatile float g_right_stick_y;
volatile int g_r3_down, g_l3_down;
volatile int g_dpad_down;
volatile int g_l1_down, g_r1_down;

static void *implOnActivityCreated;
static void *implOnInitialSetup;
static void *implOnSurfaceCreated;
static void *implOnSurfaceChanged;
static void *implOnDrawFrame;
static void *implOnResume;

static void *implOnPlaylistOpenComplete;
static void *implOnRockstarInitialComplete;
static void *implOnRockstarGateComplete;
static void *implOnRockstarSignInComplete;
static void *implOnRockstarSignOutComplete;

static void resolve_entry_points(void) {
#define ENT(var, sym) var = (void *)so_find_addr_rx(&game_mod, \
    "Java_com_rockstargames_oswrapper_GameNative_" sym)
  ENT(implOnActivityCreated, "implOnActivityCreated");
  ENT(implOnInitialSetup, "implOnInitialSetup");
  ENT(implOnSurfaceCreated, "implOnSurfaceCreated");
  ENT(implOnSurfaceChanged, "implOnSurfaceChanged");
  ENT(implOnDrawFrame, "implOnDrawFrame");
  ENT(implOnResume, "implOnResume");
  implOnPlaylistOpenComplete = (void *)so_try_find_addr_rx(&game_mod,
      "Java_com_rockstargames_oswrapper_GameNative_implOnPlaylistOpenComplete");
  implOnRockstarInitialComplete = (void *)so_try_find_addr_rx(&game_mod,
      "Java_com_rockstargames_oswrapper_GameNative_implOnRockstarInitialComplete");
  implOnRockstarGateComplete = (void *)so_try_find_addr_rx(&game_mod,
      "Java_com_rockstargames_oswrapper_GameNative_implOnRockstarGateComplete");
  implOnRockstarSignInComplete = (void *)so_try_find_addr_rx(&game_mod,
      "Java_com_rockstargames_oswrapper_GameNative_implOnRockstarSignInComplete");
  implOnRockstarSignOutComplete = (void *)so_try_find_addr_rx(&game_mod,
      "Java_com_rockstargames_oswrapper_GameNative_implOnRockstarSignOutComplete");

#undef ENT
}

static void dispatch_jni_callbacks(void) {
  JniCallback cb;
  int n = 0;
  while (n++ < 16 && jni_pop_callback(&cb)) {
    switch (cb.type) {
      case JNI_CB_PLAYLIST_OPEN_COMPLETE:
        debugPrintf("cb: implOnPlaylistOpenComplete(%d, %d)\n", cb.arg0, cb.arg1);
        if (implOnPlaylistOpenComplete)
          ((void (*)(void *, void *, int, int))implOnPlaylistOpenComplete)(
              fake_env, NULL, cb.arg0, cb.arg1);
        debugPrintf("cb: implOnPlaylistOpenComplete returned\n");
        break;
      case JNI_CB_ROCKSTAR_INITIAL_COMPLETE:
        debugPrintf("cb: implOnRockstarInitialComplete\n");
        if (implOnRockstarInitialComplete)
          ((void (*)(void *, void *))implOnRockstarInitialComplete)(fake_env, NULL);
        debugPrintf("cb: implOnRockstarInitialComplete returned\n");
        break;
      case JNI_CB_ROCKSTAR_GATE_COMPLETE:
        debugPrintf("cb: implOnRockstarGateComplete(%d, %d)\n", cb.arg0, cb.arg1);
        if (implOnRockstarGateComplete)
          ((void (*)(void *, void *, int, int))implOnRockstarGateComplete)(
              fake_env, NULL, cb.arg0, cb.arg1);
        break;
      case JNI_CB_ROCKSTAR_SIGNIN_COMPLETE:
        debugPrintf("cb: implOnRockstarSignInComplete\n");
        if (implOnRockstarSignInComplete)
          ((void (*)(void *, void *))implOnRockstarSignInComplete)(fake_env, NULL);
        break;
      case JNI_CB_ROCKSTAR_SIGNOUT_COMPLETE:
        debugPrintf("cb: implOnRockstarSignOutComplete\n");
        if (implOnRockstarSignOutComplete)
          ((void (*)(void *, void *))implOnRockstarSignOutComplete)(fake_env, NULL);
        break;
      default:
        break;
    }
  }
}

static void check_data(void) {
  struct stat st;
  if (stat(SO_NAME, &st) < 0)
    fatal_error("Could not find %s", SO_NAME);
}

static int make_window(SDL_Window **window, SDL_GLContext *context) {
  if (!SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS | SDL_INIT_GAMEPAD)) {
    fatal_error("SDL_Init failed: %s", SDL_GetError());
    return -1;
  }

  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
  SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);

  *window = SDL_CreateWindow(GTASA_PRODUCT_NAME, 1280, 720,
                             SDL_WINDOW_OPENGL | SDL_WINDOW_FULLSCREEN);
  if (!*window) {
    fatal_error("SDL_CreateWindow failed: %s", SDL_GetError());
    return -1;
  }

  *context = SDL_GL_CreateContext(*window);
  if (!*context) {
    fatal_error("SDL_GL_CreateContext failed: %s", SDL_GetError());
    return -1;
  }
  linux_set_sdl_context(*window, *context);

  int w = 0, h = 0;
  SDL_GetWindowSizeInPixels(*window, &w, &h);
  screen_width = w > 0 ? w : 1280;
  screen_height = h > 0 ? h : 720;
  SDL_GL_SetSwapInterval(1);
  debugPrintf("SDL3: drawable=%dx%d\n", screen_width, screen_height);
  return 0;
}

static void pump_events(SDL_Window *window) {
  SDL_Event event;
  while (SDL_PollEvent(&event)) {
    linux_input_event(&event);
    switch (event.type) {
      case SDL_EVENT_QUIT:
        jni_quit_requested = 1;
        break;
      case SDL_EVENT_WINDOW_PIXEL_SIZE_CHANGED:
        SDL_GetWindowSizeInPixels(window, &screen_width, &screen_height);
        break;
      default:
        break;
    }
  }
}

void hard_exit(void) {
  linux_input_shutdown();
  thread_registry_pause_others();
  deinit_openal();
  /* The Android game leaves worker threads running. POSIX has no safe
   * equivalent to the Switch thread-freeze path, so exit() would run
   * atexit/SDL/OpenAL destructors concurrently with live game threads. */
  _exit(0);
}

int main(void) {
  install_fatal_signal_trace();
  fprintf(stderr, "graphics: direct GL state dispatch; fatal address tracing enabled\n");
  setenv("MESA_GLTHREAD", "true", 1);
  setenv("GALLIUM_THREAD", "0", 1);

  userAppInit();
  if (read_config(CONFIG_NAME) < 0)
    write_config(CONFIG_NAME);
  check_data();

  SDL_Window *window = NULL;
  SDL_GLContext context = NULL;
  if (make_window(&window, &context) < 0)
    return 1;
  if (!linux_audio_init())
    fprintf(stderr, "audio: continuing without a playback device\n");

  const int have_cxx_donor = access(CXX_DONOR_SO_NAME, R_OK) == 0;
  if (have_cxx_donor && so_load(&donor_mod, CXX_DONOR_SO_NAME, NULL, 0) < 0)
    fatal_error("Could not load %s", CXX_DONOR_SO_NAME);
  if (so_load(&game_mod, SO_NAME, NULL, 0) < 0)
    fatal_error("Could not load %s", SO_NAME);

  update_imports();
  if (have_cxx_donor)
    so_relocate(&donor_mod);
  so_relocate(&game_mod);
  if (have_cxx_donor)
    so_resolve(&donor_mod, dynlib_functions, dynlib_numfunctions, 1);
  so_resolve(&game_mod, dynlib_functions, dynlib_numfunctions, 1);
  patch_game();
  resolve_entry_points();

  int (*JNI_OnLoad)(void *, void *) =
      (void *)so_find_addr_rx(&game_mod, "JNI_OnLoad");
  if (have_cxx_donor)
    so_finalize(&donor_mod);
  so_finalize(&game_mod);
  if (have_cxx_donor)
    so_flush_caches(&donor_mod);
  so_flush_caches(&game_mod);
  if (have_cxx_donor)
    so_execute_init_array(&donor_mod);
  so_execute_init_array(&game_mod);
  if (have_cxx_donor)
    so_free_temp(&donor_mod);
  so_free_temp(&game_mod);
  aml_load_mods("mods", &game_mod);

  jni_init();
  JNI_OnLoad(fake_vm, NULL);

  void *gn = jni_make_object("com/rockstargames/oswrapper/GameNative");
  void *activity = jni_make_object("GameActivity");
  void *assets = jni_make_object("AssetManager");
  void *surface = jni_make_object("Surface");
  void *names = jni_make_string_array(0, NULL);
  void *paths = jni_make_string_array(0, NULL);

  debugPrintf("lifecycle: implOnActivityCreated\n");
  ((void (*)(void *, void *, void *))implOnActivityCreated)(fake_env, gn, activity);
  debugPrintf("lifecycle: implOnActivityCreated returned\n");
  debugPrintf("lifecycle: implOnInitialSetup\n");
  ((void (*)(void *, void *, void *, void *, void *, void *))implOnInitialSetup)(
      fake_env, gn, activity, assets, names, paths);
  debugPrintf("lifecycle: implOnInitialSetup returned\n");
  debugPrintf("lifecycle: implOnSurfaceCreated\n");
  ((void (*)(void *, void *))implOnSurfaceCreated)(fake_env, gn);
  debugPrintf("lifecycle: implOnSurfaceCreated returned\n");
  debugPrintf("lifecycle: implOnSurfaceChanged\n");
  ((void (*)(void *, void *, void *, int, int))implOnSurfaceChanged)(
      fake_env, gn, surface, screen_width, screen_height);
  debugPrintf("lifecycle: implOnSurfaceChanged returned\n");
  debugPrintf("lifecycle: implOnResume\n");
  ((void (*)(void *, void *))implOnResume)(fake_env, gn);
  debugPrintf("lifecycle: implOnResume returned\n");
  linux_release_sdl_context();

  if (linux_input_init(&game_mod) < 0)
    fatal_error("Could not initialize the native SDL gamepad interface");

  uint64_t last = SDL_GetTicksNS();
  uint64_t last_audio_report = last;
  const int audio_debug = getenv("GTASA_AUDIO_DEBUG") != NULL;
  unsigned long frames = 0;
  const char *test_color = getenv("GTASA_TEST_COLOR");
  while (!jni_quit_requested) {
    pump_events(window);
    linux_input_update();
    dispatch_jni_callbacks();
    uint64_t now = SDL_GetTicksNS();
    if (audio_debug && now - last_audio_report >= 5000000000ULL) {
      uint64_t mixed, nonzero;
      linux_audio_get_stats(&mixed, &nonzero);
      fprintf(stderr, "audio: mixed=%llu nonzero=%llu frames\n",
              (unsigned long long)mixed, (unsigned long long)nonzero);
      last_audio_report = now;
    }
    float dt = (float)(now - last) / 1000000000.0f;
    last = now;
    if (dt <= 0.0f || dt > 0.5f)
      dt = 1.0f / 60.0f;

    if ((frames % 60) == 0)
      debugPrintf("main: implOnDrawFrame begin (%lu)\n", frames);
    ((void (*)(void *, void *, float))implOnDrawFrame)(fake_env, NULL, dt);
    if ((frames % 60) == 0)
      debugPrintf("main: implOnDrawFrame returned (%lu)\n", frames);
    frames++;
    // Android's GLSurfaceView presents after onDrawFrame returns. The native
    // libGame.so callback does not swap its EGL surface itself, so SDL owns the
    // single presentation here, matching re3's RwCameraShowRaster path.
    if (test_color && strcmp(test_color, "red") == 0) {
      glClearColor(1.0f, 0.0f, 0.0f, 1.0f);
      glClear(GL_COLOR_BUFFER_BIT);
    }
    if (test_color && strcmp(test_color, "red") == 0)
      SDL_GL_SwapWindow(window);
    SDL_Delay(1);
  }

  hard_exit();
  return 0;
}
