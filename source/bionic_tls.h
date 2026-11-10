#ifndef GTASA_BIONIC_TLS_H
#define GTASA_BIONIC_TLS_H
#include <stddef.h>
#include "so_util.h"

int bionic_tls_prepare_thread(void);
int bionic_tls_guard_offset(size_t *offset);
int bionic_tls_patch_module(so_module *module);
#endif
