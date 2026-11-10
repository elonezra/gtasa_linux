/* Diagnostic only: retain fatal stack checks while recording the failing caller.
 * No Android payload or game assets are needed to compile or test this library.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static atomic_flag reporting = ATOMIC_FLAG_INIT;

__attribute__((noreturn, noinline)) void __stack_chk_fail(void)
{
    if (!atomic_flag_test_and_set(&reporting)) {
        void *caller = __builtin_extract_return_addr(__builtin_return_address(0));
        Dl_info info = {0};
        const int found = dladdr(caller, &info);
        char message[768];
        int size = snprintf(message, sizeof(message),
            "STACK_GUARD_FAILURE caller=%p object=%s offset=0x%lx symbol=%s\n",
            caller, found && info.dli_fname ? info.dli_fname : "anonymous/custom-loader",
            (unsigned long)(found ? (uintptr_t)caller - (uintptr_t)info.dli_fbase : 0),
            found && info.dli_sname ? info.dli_sname : "unknown");
        if (size > 0) {
            size_t length = (size_t)size < sizeof(message) ? (size_t)size : sizeof(message)-1;
            (void)write(STDERR_FILENO, message, length);
        }
    }
    /* Never suppress, bypass, or return from the failed stack check. */
    abort();
}
