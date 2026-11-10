/* imports.c -- .so import resolution
 *
 * Copyright (C) 2021 fgsfds, Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * Serves both libGame.so and the vendored Android NDK C++ runtime.
 * C++ runtime symbols (std::*, __cxa_*) resolve module-to-module from the donor,
 * not here. The table takes priority during resolution (see so_resolve_symbol).
 */

#define _GNU_SOURCE // vasprintf and friends

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <wchar.h>
#include <wctype.h>
#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <setjmp.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <locale.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <SDL3/SDL_video.h>
#include <AL/al.h>
#include <AL/alc.h>
#include <mpg123.h>


#include "config.h"
#include "so_util.h"
#include "util.h"
#include "libc_shim.h"
#include "overlay.h"
#include "bionic_tls.h"

extern uintptr_t __cxa_atexit;

extern uintptr_t __stack_chk_fail;

static char *__ctype_;

static int *errno_fake(void) {
  return &errno;
}

static uint64_t __stack_chk_guard_fake = 0x4242424242424242;

// Per-thread cache of the last successful eglMakeCurrent: the engine re-binds
// the same context+surface many times per frame and mesa revalidates each time,
// so skip the redundant bind (a no-op per the EGL spec). Keyed by TPIDR_EL0.
#define MC_SLOTS 8
static struct {
  void *key;
  EGLDisplay dpy; EGLSurface draw, read; EGLContext ctx;
} g_mc[MC_SLOTS];

static inline void *mc_thread_key(void) {
  static _Thread_local int key;
  return &key;
}

// ---------------------------------------------------------------------------
// GL redundant-state cache. RenderWare / GTA SA re-set the same GL state (blend,
// depth, cull, texture bindings, active unit, program, ...) many times per frame.
// On the Switch mesa/nouveau driver every GL call is expensive and the game is
// CPU-bound on call count (GPU mostly idle), so drop calls that don't change
// state. Correct because the engine renders through one GL context at a time (EGL
// make-current transfers ownership): glc_reset() runs on every REAL eglMakeCurrent
// so the cache is never trusted across a context switch, and glDelete{Textures,
// Program} invalidate the bind caches so a reused id is never wrongly skipped.
// Set glc_enabled = 0 for a pure pass-through if a rendering glitch is suspected.
// ---------------------------------------------------------------------------
static int glc_enabled = 1;

#define GLC_MAXCAPS 24
static struct { GLenum cap; GLboolean on; } glc_caps[GLC_MAXCAPS];
static int glc_ncaps;

static struct {
  int have_blend;  GLenum bsf, bdf;
  int have_dfunc;  GLenum dfunc;
  int have_dmask;  GLboolean dmask;
  int have_cull;   GLenum cull;
  int have_front;  GLenum front;
  int have_cmask;  GLboolean cr, cg, cb, ca;
  int have_active; GLenum active;
  int have_prog;   GLuint prog;
  GLuint tex2d[8]; int have_tex2d[8];
} glc;

// Invalidate the cache. Called on every real eglMakeCurrent (context ownership
// transfer) and once per frame from eglSwapBuffers_cache (so the wrapper's own
// direct GL -- movie player, FPS overlay -- can't leave the cache stale).
static void gl_state_cache_reset(void) {
  glc_ncaps = 0;
  memset(&glc, 0, sizeof(glc));
}

static void glEnable_c(GLenum cap) {
  if (glc_enabled) {
    for (int i = 0; i < glc_ncaps; i++)
      if (glc_caps[i].cap == cap) {
        if (glc_caps[i].on) return;
        glc_caps[i].on = GL_TRUE; glEnable(cap); return;
      }
    if (glc_ncaps < GLC_MAXCAPS) {
      glc_caps[glc_ncaps].cap = cap; glc_caps[glc_ncaps].on = GL_TRUE; glc_ncaps++;
    }
  }
  glEnable(cap);
}
static void glDisable_c(GLenum cap) {
  if (glc_enabled) {
    for (int i = 0; i < glc_ncaps; i++)
      if (glc_caps[i].cap == cap) {
        if (!glc_caps[i].on) return;
        glc_caps[i].on = GL_FALSE; glDisable(cap); return;
      }
    if (glc_ncaps < GLC_MAXCAPS) {
      glc_caps[glc_ncaps].cap = cap; glc_caps[glc_ncaps].on = GL_FALSE; glc_ncaps++;
    }
  }
  glDisable(cap);
}
static void glBlendFunc_c(GLenum s, GLenum d) {
  if (glc_enabled && glc.have_blend && glc.bsf == s && glc.bdf == d) return;
  glc.have_blend = 1; glc.bsf = s; glc.bdf = d;
  glBlendFunc(s, d);
}
static void glBlendFuncSeparate_c(GLenum sc, GLenum dc, GLenum sa, GLenum da) {
  glc.have_blend = 0; // don't reconcile with the glBlendFunc cache
  glBlendFuncSeparate(sc, dc, sa, da);
}
static void glDepthFunc_c(GLenum f) {
  if (glc_enabled && glc.have_dfunc && glc.dfunc == f) return;
  glc.have_dfunc = 1; glc.dfunc = f;
  glDepthFunc(f);
}
static void glDepthMask_c(GLboolean m) {
  if (glc_enabled && glc.have_dmask && glc.dmask == m) return;
  glc.have_dmask = 1; glc.dmask = m;
  glDepthMask(m);
}
static void glCullFace_c(GLenum m) {
  if (glc_enabled && glc.have_cull && glc.cull == m) return;
  glc.have_cull = 1; glc.cull = m;
  glCullFace(m);
}
static void glFrontFace_c(GLenum m) {
  if (glc_enabled && glc.have_front && glc.front == m) return;
  glc.have_front = 1; glc.front = m;
  glFrontFace(m);
}
static void glColorMask_c(GLboolean r, GLboolean g, GLboolean b, GLboolean a) {
  if (glc_enabled && glc.have_cmask && glc.cr == r && glc.cg == g &&
      glc.cb == b && glc.ca == a)
    return;
  glc.have_cmask = 1; glc.cr = r; glc.cg = g; glc.cb = b; glc.ca = a;
  glColorMask(r, g, b, a);
}
static void glActiveTexture_c(GLenum unit) {
  if (glc_enabled && glc.have_active && glc.active == unit) return;
  glc.have_active = 1; glc.active = unit;
  glActiveTexture(unit);
}
static void glBindTexture_c(GLenum target, GLuint tex) {
  if (glc_enabled && target == GL_TEXTURE_2D && glc.have_active) {
    unsigned idx = (unsigned)(glc.active - GL_TEXTURE0);
    if (idx < 8) {
      if (glc.have_tex2d[idx] && glc.tex2d[idx] == tex) return;
      glc.have_tex2d[idx] = 1; glc.tex2d[idx] = tex;
    }
  }
  glBindTexture(target, tex);
}
static void glUseProgram_c(GLuint p) {
  if (glc_enabled && glc.have_prog && glc.prog == p) return;
  glc.have_prog = 1; glc.prog = p;
  glUseProgram(p);
}
static void glDeleteTextures_c(GLsizei n, const GLuint *t) {
  memset(glc.have_tex2d, 0, sizeof(glc.have_tex2d)); // a deleted bound tex must
  glDeleteTextures(n, t);                            // not be skipped when reused
}
static void glDeleteProgram_c(GLuint p) {
  if (glc.have_prog && glc.prog == p) glc.have_prog = 0;
  glDeleteProgram(p);
}

// Frame boundary: invalidate the state cache once per frame, then run the real
// swap hook. The wrapper's own direct GL there (movie player / FPS overlay) goes
// around the cache, so this keeps the game's next frame from trusting a stale
// entry. Kept in this TU so no cross-file symbol is needed. eglSwapBuffersHook is
// defined in movie_player.c (already referenced by the import table below).
extern unsigned int eglSwapBuffersHook(void *display, void *surface);
static SDL_Window *g_sdl_window;
static SDL_GLContext g_sdl_context;
static EGLDisplay g_sdl_egl_display;
static EGLConfig g_sdl_egl_config;
static EGLSurface g_sdl_egl_surface;
static EGLContext g_sdl_egl_context;
static bool g_sdl_native_context;

static bool is_render_queue_thread(void) {
  char name[16] = {0};
  pthread_getname_np(pthread_self(), name, sizeof(name));
  return strcmp(name, "RenderQueue") == 0;
}

void linux_release_sdl_context(void) {
  if (!g_sdl_native_context || !g_sdl_window)
    return;
  bool ok = SDL_GL_MakeCurrent(g_sdl_window, NULL);
  debugPrintf("EGL: release main SDL context before RenderQueue: %d: %s\n",
              ok, ok ? "ok" : SDL_GetError());
}

void linux_set_sdl_context(SDL_Window *window, void *context) {
  g_sdl_window = window;
  g_sdl_context = context;
  g_sdl_egl_display = (EGLDisplay)SDL_EGL_GetCurrentDisplay();
  g_sdl_egl_config = (EGLConfig)SDL_EGL_GetCurrentConfig();
  g_sdl_egl_surface = (EGLSurface)SDL_EGL_GetWindowSurface(window);
  g_sdl_egl_context = (EGLContext)SDL_GL_GetCurrentContext();
  const char *video_driver = SDL_GetCurrentVideoDriver();
  g_sdl_native_context = video_driver && strcmp(video_driver, "sdl2") != 0;
  debugPrintf("EGL: SDL handles display=%p config=%p surface=%p context=%p\n",
              (void *)g_sdl_egl_display, (void *)g_sdl_egl_config,
              (void *)g_sdl_egl_surface, (void *)g_sdl_egl_context);
  debugPrintf("EGL: SDL video driver=%s native=%d\n",
              video_driver ? video_driver : "unknown", g_sdl_native_context);
}

static unsigned int eglSwapBuffers_cache(void *display, void *surface) {
  static unsigned long frames;
  gl_state_cache_reset();
  (void)display;
  (void)surface;
  SDL_GL_SwapWindow(g_sdl_window);
  unsigned int result = EGL_TRUE;
  if ((++frames % 60) == 0)
    debugPrintf("EGL: presented frame %lu (result=%u)\n", frames, result);
  return result;
}

static EGLDisplay eglGetDisplay_trace(EGLNativeDisplayType native) {
  debugPrintf("EGL: eglGetDisplay(%p)\n", native);
  EGLDisplay dpy;
  if (native == EGL_DEFAULT_DISPLAY && g_sdl_egl_display) {
    dpy = g_sdl_egl_display;
    debugPrintf("EGL: using SDL-owned display\n");
  } else if (native == EGL_DEFAULT_DISPLAY) {
    // KMSD…8333 tokens truncated…t)&iswupper_l_fake },
  { "iswxdigit_l", (uintptr_t)&iswxdigit_l_fake },
  { "towlower_l", (uintptr_t)&towlower_l_fake },
  { "towupper_l", (uintptr_t)&towupper_l_fake },
  { "wcscoll_l", (uintptr_t)&wcscoll_l_fake },
  { "wcsxfrm_l", (uintptr_t)&wcsxfrm_l_fake },

  { "wctob", (uintptr_t)&wctob },
  { "wctype", (uintptr_t)&wctype },
  { "wcsxfrm", (uintptr_t)&wcsxfrm },
  { "iswctype", (uintptr_t)&iswctype },
  { "wcscoll", (uintptr_t)&wcscoll },
  { "wcsftime", (uintptr_t)&wcsftime },
  { "mbrtowc", (uintptr_t)&mbrtowc },
  { "mbrlen", (uintptr_t)&mbrlen },
  { "mbtowc", (uintptr_t)&mbtowc },
  { "mbsrtowcs", (uintptr_t)&mbsrtowcs },
  { "mbsnrtowcs", (uintptr_t)&mbsnrtowcs_fake },
  { "wcsnrtombs", (uintptr_t)&wcsnrtombs_fake },
  { "wcrtomb", (uintptr_t)&wcrtomb },
  { "wcslen", (uintptr_t)&wcslen },
  { "btowc", (uintptr_t)&btowc },
  { "wcstod", (uintptr_t)&wcstod },
  { "wcstof", (uintptr_t)&wcstof },
  { "wcstol", (uintptr_t)&wcstol },
  { "wcstold", (uintptr_t)&wcstold },
  { "wcstoll", (uintptr_t)&wcstoll },
  { "wcstoul", (uintptr_t)&wcstoul },
  { "wcstoull", (uintptr_t)&wcstoull },

  // --- CTW 4.4.243 additions ---

  // libGame.so extras over the Max Payne 2.1.131 import set
  { "__read_chk", (uintptr_t)&__read_chk },
  { "__write_chk", (uintptr_t)&__write_chk },
  { "atan", (uintptr_t)&atan },
  { "expf", (uintptr_t)&expf },
  { "frexp", (uintptr_t)&frexp },
  { "logf", (uintptr_t)&logf },
  { "modf", (uintptr_t)&modf },
  { "gmtime", (uintptr_t)&gmtime },
  { "getpid", (uintptr_t)&getpid_fake },
  { "putchar", (uintptr_t)&putchar },
  { "puts", (uintptr_t)&puts },
  { "glBlendEquation", (uintptr_t)&glBlendEquation },
  { "glLineWidth", (uintptr_t)&glLineWidth },
  { "glUniform4f", (uintptr_t)&glUniform4f },
  { "glVertexAttrib2f", (uintptr_t)&glVertexAttrib2f },
  { "glVertexAttrib3f", (uintptr_t)&glVertexAttrib3f },
  { "glVertexAttrib4f", (uintptr_t)&glVertexAttrib4f },
  { "alBufferi", (uintptr_t)&alBufferi },
  { "alcGetProcAddress", (uintptr_t)&alcGetProcAddress },
  { "alcProcessContext", (uintptr_t)&alcProcessContext },
  { "alcSuspendContext", (uintptr_t)&alcSuspendContext },
  { "mpg123_param", (uintptr_t)&mpg123_param_fuzzy }, // FuzzySeek (see wrapper)

  // imports of the C++ runtime donor (the APK's libopenal.so)
  { "__assert2", (uintptr_t)&__assert2 },
  { "__readlink_chk", (uintptr_t)&retm1 },
  { "atan2", (uintptr_t)&atan2 },
  { "cbrtf", (uintptr_t)&cbrtf },
  { "exp2f", (uintptr_t)&exp2f },
  { "hypot", (uintptr_t)&hypot },
  { "ldexpf", (uintptr_t)&ldexpf },
  { "log2f", (uintptr_t)&log2f },
  { "sinh", (uintptr_t)&sinh },
  { "sinhf", (uintptr_t)&sinhf },
  { "sincos", (uintptr_t)&sincos_fake },
  { "clearerr", (uintptr_t)&clearerr },
  { "rewind", (uintptr_t)&rewind },
  { "raise", (uintptr_t)&raise },
  { "sched_yield", (uintptr_t)&sched_yield_fake },
  { "slCreateEngine", (uintptr_t)&slCreateEngine_fake },
  { "SL_IID_ANDROIDCONFIGURATION", (uintptr_t)&SL_IID_fake },
  { "SL_IID_ANDROIDSIMPLEBUFFERQUEUE", (uintptr_t)&SL_IID_fake },
  { "SL_IID_ENGINE", (uintptr_t)&SL_IID_fake },
  { "SL_IID_PLAY", (uintptr_t)&SL_IID_fake },
  { "SL_IID_RECORD", (uintptr_t)&SL_IID_fake },
  // thread_local init wrapper; safe to no-op (TLS pointer is zero-initialized)
  { "_ZTHN10ALCcontext13sLocalContextE", (uintptr_t)&ret0 },

  // ======================================================================
  // LCS 2.4.379 additions over the CTW import set
  // (the older GTAJNIlib engine + its renderer/netcode pull in more symbols)
  // ======================================================================

  // -- GLESv2 functions the LCS renderer uses (native, -lGLESv2) --
  { "glBlendColor", (uintptr_t)&glBlendColor },
  { "glBlendEquationSeparate", (uintptr_t)&glBlendEquationSeparate },
  { "glBufferSubData", (uintptr_t)&glBufferSubData },
  { "glCompressedTexSubImage2D", (uintptr_t)&glCompressedTexSubImage2D },
  { "glCopyTexImage2D", (uintptr_t)&glCopyTexImage2D },
  { "glCopyTexSubImage2D", (uintptr_t)&glCopyTexSubImage2D },
  { "glDetachShader", (uintptr_t)&glDetachShader },
  { "glFlush", (uintptr_t)&glFlush },
  { "glGenerateMipmap", (uintptr_t)&glGenerateMipmap },
  { "glGetActiveAttrib", (uintptr_t)&glGetActiveAttrib },
  { "glGetActiveUniform", (uintptr_t)&glGetActiveUniform },
  { "glGetAttachedShaders", (uintptr_t)&glGetAttachedShaders },
  { "glGetBufferParameteriv", (uintptr_t)&glGetBufferParameteriv },
  { "glGetFloatv", (uintptr_t)&glGetFloatv },
  { "glGetFramebufferAttachmentParameteriv", (uintptr_t)&glGetFramebufferAttachmentParameteriv },
  { "glGetRenderbufferParameteriv", (uintptr_t)&glGetRenderbufferParameteriv },
  { "glGetShaderPrecisionFormat", (uintptr_t)&glGetShaderPrecisionFormat },
  { "glGetShaderSource", (uintptr_t)&glGetShaderSource },
  { "glGetTexParameterfv", (uintptr_t)&glGetTexParameterfv },
  { "glGetTexParameteriv", (uintptr_t)&glGetTexParameteriv },
  { "glGetUniformfv", (uintptr_t)&glGetUniformfv },
  { "glGetUniformiv", (uintptr_t)&glGetUniformiv },
  { "glGetVertexAttribfv", (uintptr_t)&glGetVertexAttribfv },
  { "glGetVertexAttribiv", (uintptr_t)&glGetVertexAttribiv },
  { "glGetVertexAttribPointerv", (uintptr_t)&glGetVertexAttribPointerv },
  { "glIsBuffer", (uintptr_t)&glIsBuffer },
  { "glIsFramebuffer", (uintptr_t)&glIsFramebuffer },
  { "glIsRenderbuffer", (uintptr_t)&glIsRenderbuffer },
  { "glIsShader", (uintptr_t)&glIsShader },
  { "glPixelStorei", (uintptr_t)&glPixelStorei },
  { "glReleaseShaderCompiler", (uintptr_t)&glReleaseShaderCompiler },
  { "glSampleCoverage", (uintptr_t)&glSampleCoverage },
  { "glShaderBinary", (uintptr_t)&glShaderBinary },
  { "glStencilFunc", (uintptr_t)&glStencilFunc },
  { "glStencilFuncSeparate", (uintptr_t)&glStencilFuncSeparate },
  { "glStencilMask", (uintptr_t)&glStencilMask },
  { "glStencilMaskSeparate", (uintptr_t)&glStencilMaskSeparate },
  { "glStencilOp", (uintptr_t)&glStencilOp },
  { "glStencilOpSeparate", (uintptr_t)&glStencilOpSeparate },
  { "glTexParameterfv", (uintptr_t)&glTexParameterfv },
  { "glTexParameteriv", (uintptr_t)&glTexParameteriv },
  { "glTexSubImage2D", (uintptr_t)&glTexSubImage2D },
  { "glUniform1iv", (uintptr_t)&glUniform1iv },
  { "glUniform2f", (uintptr_t)&glUniform2f },
  { "glUniform2i", (uintptr_t)&glUniform2i },
  { "glUniform2iv", (uintptr_t)&glUniform2iv },
  { "glUniform3i", (uintptr_t)&glUniform3i },
  { "glUniform3iv", (uintptr_t)&glUniform3iv },
  { "glUniform4i", (uintptr_t)&glUniform4i },
  { "glUniform4iv", (uintptr_t)&glUniform4iv },
  { "glUniformMatrix2fv", (uintptr_t)&glUniformMatrix2fv },
  { "glValidateProgram", (uintptr_t)&glValidateProgram },
  { "glVertexAttrib1f", (uintptr_t)&glVertexAttrib1f },
  { "glVertexAttrib1fv", (uintptr_t)&glVertexAttrib1fv },
  { "glVertexAttrib2fv", (uintptr_t)&glVertexAttrib2fv },
  { "glVertexAttrib3fv", (uintptr_t)&glVertexAttrib3fv },

  // -- BSD sockets / net (Social Club + cloud). native via libnx -lnx;
  //    socketInitializeDefault() is called once at boot in main.c --
  { "socket", (uintptr_t)&socket },
  { "bind", (uintptr_t)&bind },
  { "connect", (uintptr_t)&connect },
  { "accept", (uintptr_t)&accept },
  { "listen", (uintptr_t)&listen },
  { "recvfrom", (uintptr_t)&recvfrom },
  { "sendto", (uintptr_t)&sendto },
  { "setsockopt", (uintptr_t)&setsockopt_fake },
  { "shutdown", (uintptr_t)&shutdown },
  { "getaddrinfo", (uintptr_t)&getaddrinfo },
  { "inet_pton", (uintptr_t)&inet_pton },
  { "inet_ntop", (uintptr_t)&inet_ntop },
  { "select", (uintptr_t)&select },
  { "fcntl", (uintptr_t)&fcntl_fake },

  // -- named POSIX semaphores (mapped to the same FakeSem as the unnamed ones) --
  { "sem_open", (uintptr_t)&sem_open_fake },
  { "sem_close", (uintptr_t)&sem_close_fake },
  { "sem_unlink", (uintptr_t)&sem_unlink_fake },

  // -- extra bionic _FORTIFY_SOURCE wrappers --
  { "__memset_chk", (uintptr_t)&__memset_chk_fake },
  { "__strrchr_chk", (uintptr_t)&__strrchr_chk_fake },
  { "__fread_chk", (uintptr_t)&__fread_chk_fake },
  { "__FD_SET_chk", (uintptr_t)&__FD_SET_chk_fake },
  { "__FD_ISSET_chk", (uintptr_t)&__FD_ISSET_chk_fake },

  // -- misc --
  { "__android_log_assert", (uintptr_t)&__android_log_assert },
  { "stdout", (uintptr_t)&fake_stdout },
  { "mktime", (uintptr_t)&mktime },
  { "pthread_attr_setdetachstate", (uintptr_t)&ret0 },
  { "pthread_attr_setstacksize", (uintptr_t)&ret0 },

  // -- C++ runtime donor imports not provided by libGame.so --
  { "wmemcpy", (uintptr_t)&wmemcpy },
  { "wmemset", (uintptr_t)&wmemset },
  { "wmemmove", (uintptr_t)&wmemmove },
  { "pthread_equal", (uintptr_t)&pthread_equal },
  { "isdigit_l", (uintptr_t)&isdigit_l_fake },
  { "isxdigit_l", (uintptr_t)&isxdigit_l_fake },
  { "islower_l", (uintptr_t)&islower_l_fake },
  { "isupper_l", (uintptr_t)&isupper_l_fake },
  { "toupper_l", (uintptr_t)&toupper_l_fake },
  { "tolower_l", (uintptr_t)&tolower_l_fake },

  // ======================================================================
  // GTA: San Andreas 2.11.311 additions over the CTW/LCS import set.
  // Everything else SA imports is either above or resolves from the C++ runtime
  // donor (libc++_shared.so), so only these four are new here.
  // ======================================================================
  { "ctime", (uintptr_t)&ctime },
  { "modff", (uintptr_t)&modff },
  { "mpg123_length", (uintptr_t)&mpg123_length },
  { "mpg123_set_filesize", (uintptr_t)&mpg123_set_filesize },
};

size_t dynlib_numfunctions = sizeof(dynlib_functions) / sizeof(*dynlib_functions);

void update_imports(void) {
  // only install the hook when the config option is enabled
  if (config.trilinear_filter)
    so_find_import(dynlib_functions, dynlib_numfunctions, "glTexParameteri")->func = (uintptr_t)glTexParameteriHook;
}
